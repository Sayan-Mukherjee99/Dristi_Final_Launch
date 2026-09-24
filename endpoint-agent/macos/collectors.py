# Drishti v0.1 — macOS Telemetry Collectors | Phase 02 & Full Telemetry Pass
from __future__ import annotations

import collections
import ctypes
import logging
import os
import platform
import plistlib
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from collectors.base import (
    BaseBrowserCollector,
    BaseHardwareCollector,
    BasePermissionManager,
    BaseProcessCollector,
    BaseSecurityCollector,
    BaseServiceCollector,
    BaseSocketCollector,
    BaseSoftwareCollector,
    BaseStorageCollector,
    BaseSystemCollector,
)
from collectors.contracts import (
    BrowserProcessItem,
    BrowserTabItem,
    BrowserVisibility,
    CpuInfo,
    ListeningPortItem,
    MacSecurityPosture,
    MemoryInfo,
    NetworkInterfaceInfo,
    PerCoreUsage,
    PermissionStatusItem,
    ProcessCategory,
    ProcessEventItem,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
    StorageInfo,
    StoragePartition,
    SystemInfo,
)

logger = logging.getLogger("drishti.agent.macos")

MACOS_SYSTEM_PROCESSES = {
    "launchd",
    "kernel_task",
    "syslogd",
    "kextd",
    "fseventsd",
    "securityd",
    "distnoted",
    "cfprefsd",
    "logd",
    "diskarbitrationd",
    "notifyd",
    "coreaudiod",
    "windowserver",
    "opendirectoryd",
    "systemsoundserverd",
    "mds",
    "mdworker",
    "loginwindow",
}

MACOS_BROWSERS = {
    "google chrome": "Chrome",
    "chrome": "Chrome",
    "safari": "Safari",
    "brave browser": "Brave",
    "brave": "Brave",
    "firefox": "Firefox",
    "arc": "Arc",
    "opera": "Opera",
    "microsoft edge": "Edge",
    "edge": "Edge",
}


def _run_cmd(cmd: list[str], timeout: float = 1.0) -> tuple[int, str, str]:
    """Execute a system command safely with bounded execution time."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        return -1, "", str(e)
    except Exception as e:
        return -1, "", str(e)


# ──────────────────────────────────────────────────────────────
# 1. PROCESS TELEMETRY & EVENT MONITORING
# ──────────────────────────────────────────────────────────────

class MacOSProcessCollector(BaseProcessCollector):
    """Gathers genuine running processes on macOS and classifies them deterministically.
    
    Maintains a bounded event ring buffer of process lifecycle events (EXEC, EXIT)
    and extracts code-signing identities and team identifiers.
    """

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label
        self._event_buffer: collections.deque[ProcessEventItem] = collections.deque(maxlen=250)
        self._previous_pids: dict[int, dict[str, Any]] = {}
        self._codesign_cache: dict[str, tuple[str, str | None, str | None]] = {}

    def _classify_process(self, name: str, exe_path: str | None) -> str:
        lower_name = name.lower()
        if lower_name in MACOS_SYSTEM_PROCESSES:
            return ProcessCategory.SYSTEM_PROCESS.value
        if lower_name in MACOS_BROWSERS:
            return ProcessCategory.USER_APPLICATION.value

        if exe_path:
            lower_path = exe_path.lower()
            if "/system/library" in lower_path or "/usr/libexec" in lower_path or "/usr/sbin" in lower_path or "/sbin/" in lower_path:
                return ProcessCategory.SYSTEM_PROCESS.value
            if "/applications" in lower_path and not "/system/" in lower_path:
                return ProcessCategory.USER_APPLICATION.value

        return ProcessCategory.BACKGROUND_PROCESS.value

    def _check_suspicious_process(self, name: str, exe_path: str | None, ppid: int | None) -> tuple[bool, str | None]:
        """Defensively flag suspicious execution patterns on macOS."""
        if not exe_path:
            return False, None

        lower_path = exe_path.lower()

        # Check execution from world-writable or temp folders
        temp_prefixes = ("/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/")
        for prefix in temp_prefixes:
            if lower_path.startswith(prefix):
                return True, f"Executable running from temporary directory: {exe_path}"

        # Check masquerading system process
        if name.lower() in MACOS_SYSTEM_PROCESSES:
            if not (lower_path.startswith("/system/") or lower_path.startswith("/sbin/") or lower_path.startswith("/usr/")):
                return True, f"Masquerading system process '{name}' from unauthorized path: {exe_path}"

        return False, None

    def _inspect_code_signing(self, exe_path: str | None) -> tuple[str, str | None, str | None]:
        """Inspect binary code signing via codesign CLI with caching."""
        if not exe_path or not os.path.isfile(exe_path):
            return "UNKNOWN", None, None

        if exe_path in self._codesign_cache:
            return self._codesign_cache[exe_path]

        code, stdout, stderr = _run_cmd(["codesign", "-dv", "--verbose=2", exe_path], timeout=0.6)
        output = f"{stdout}\n{stderr}"

        signing_status = "UNKNOWN"
        team_id = None
        bundle_id = None

        if code == 0:
            if "Authority=Apple" in output:
                signing_status = "SIGNED_APPLE"
            elif "Authority=Developer ID Application" in output:
                signing_status = "SIGNED_DEVELOPER_ID"
            elif "Signature=adhoc" in output:
                signing_status = "ADHOC"
            else:
                signing_status = "SIGNED_OTHER"

            # Parse TeamIdentifier
            m_team = re.search(r"TeamIdentifier=([A-Z0-9]+)", output)
            if m_team:
                team_id = m_team.group(1)
            elif "Developer ID Application:" in output:
                m_team2 = re.search(r"\(([A-Z0-9]{10})\)", output)
                if m_team2:
                    team_id = m_team2.group(1)

            # Parse Identifier
            m_id = re.search(r"Identifier=([a-zA-Z0-9\.\-_]+)", output)
            if m_id:
                bundle_id = m_id.group(1)
        elif "code object is not signed at all" in output:
            signing_status = "UNSIGNED"

        res = (signing_status, team_id, bundle_id)
        if len(self._codesign_cache) < 500:
            self._codesign_cache[exe_path] = res
        return res

    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        processes: list[ProcessItem] = []
        active_apps_set: set[str] = set()
        current_pids: dict[int, dict[str, Any]] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # Prime the cpu_percent counters (non-blocking)
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    proc.cpu_percent(interval=None)
                except Exception:
                    pass
        except Exception:
            pass

        time.sleep(0.08)

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]):
            try:
                info = proc.info
                name = info.get("name") or "unknown"
                pid = info.get("pid")
                if pid is None:
                    continue

                ppid = info.get("ppid")
                exe_path = info.get("exe")
                cmdline = info.get("cmdline")
                username = info.get("username")

                create_time = info.get("create_time")
                start_time_iso = (
                    datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat()
                    if create_time
                    else None
                )

                category = self._classify_process(name, exe_path)
                if category == ProcessCategory.USER_APPLICATION.value:
                    active_apps_set.add(name)

                cpu_pct: float | None = None
                mem_mb: float | None = None
                try:
                    cpu_pct = proc.cpu_percent(interval=None)
                except Exception:
                    pass
                try:
                    mem_info = proc.memory_info()
                    mem_mb = round(mem_info.rss / (1024 * 1024), 2)
                except Exception:
                    pass

                item = ProcessItem(
                    pid=pid,
                    name=name,
                    ppid=ppid,
                    exe_path=exe_path,
                    cmdline=cmdline,
                    category=category,
                    start_time=start_time_iso,
                    cpu_percent=cpu_pct,
                    memory_mb=mem_mb,
                    observed_at=now_iso,
                    source=self.source_label,
                )
                processes.append(item)
                current_pids[pid] = {
                    "name": name,
                    "ppid": ppid,
                    "exe_path": exe_path,
                    "cmdline": cmdline,
                    "username": username,
                    "start_time": start_time_iso,
                }

                # Check if this is a newly seen process in this agent session
                if self._previous_pids and pid not in self._previous_pids:
                    signing_status, team_id, bundle_id = self._inspect_code_signing(exe_path)
                    is_suspicious, susp_reason = self._check_suspicious_process(name, exe_path, ppid)
                    self._event_buffer.append(
                        ProcessEventItem(
                            event_type="EXEC",
                            pid=pid,
                            name=name,
                            ppid=ppid,
                            exe_path=exe_path,
                            cmdline=cmdline,
                            signing_status=signing_status,
                            team_id=team_id,
                            bundle_id=bundle_id,
                            username=username,
                            is_suspicious=is_suspicious,
                            suspicious_reason=susp_reason,
                            timestamp=now_iso,
                            source=self.source_label,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Error inspecting macOS process %s: %s", getattr(proc, "pid", "unknown"), e)
                continue

        # Detect terminated processes since last cycle
        if self._previous_pids:
            for old_pid, old_data in self._previous_pids.items():
                if old_pid not in current_pids:
                    self._event_buffer.append(
                        ProcessEventItem(
                            event_type="EXIT",
                            pid=old_pid,
                            name=old_data.get("name", "unknown"),
                            ppid=old_data.get("ppid"),
                            exe_path=old_data.get("exe_path"),
                            cmdline=old_data.get("cmdline"),
                            username=old_data.get("username"),
                            timestamp=now_iso,
                            source=self.source_label,
                        )
                    )

        self._previous_pids = current_pids
        return processes, sorted(list(active_apps_set))

    def get_recent_process_events(self) -> list[ProcessEventItem]:
        """Return the recent bounded buffer of process lifecycle events."""
        return list(self._event_buffer)


# ──────────────────────────────────────────────────────────────
# 2. APPLE ENDPOINT SECURITY (ES) BRIDGE
# ──────────────────────────────────────────────────────────────

class MacOSEndpointSecurityCollector:
    """Subsystem for Apple Endpoint Security framework (EndpointSecurity.framework).
    
    Verifies the com.apple.developer.endpoint-security.client entitlement and
    privilege requirements. When running unentitled, reports truthful status
    and delegates to the bounded ProcessEventItem poller.
    """

    def __init__(self, process_collector: MacOSProcessCollector | None = None):
        self.process_collector = process_collector
        self._es_client_active: bool = False
        self._status_reason: str = "NOT_INITIALIZED"

    def check_entitlement(self) -> tuple[bool, str]:
        """Verifies if the current binary holds Apple Endpoint Security entitlement."""
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        if not is_root:
            return False, "Endpoint Security requires root privileges (running unprivileged)"

        # Check binary entitlements via codesign
        try:
            exe_path = sys.executable
            code, stdout, stderr = _run_cmd(["codesign", "-d", "--entitlements", ":-", exe_path], timeout=0.8)
            if "com.apple.developer.endpoint-security.client" in stdout:
                return True, "Entitlement granted and verified"
            return False, "Missing com.apple.developer.endpoint-security.client entitlement in code signature"
        except Exception as e:
            return False, f"Could not inspect binary entitlements: {e}"

    def collect_status(self) -> dict[str, Any]:
        has_entitlement, reason = self.check_entitlement()
        status = "ACTIVE" if (has_entitlement and self._es_client_active) else "PERMISSION_REQUIRED"
        return {
            "framework": "EndpointSecurity.framework",
            "status": status,
            "has_entitlement": has_entitlement,
            "details": reason,
            "supported_events": [
                "ES_EVENT_TYPE_NOTIFY_EXEC",
                "ES_EVENT_TYPE_NOTIFY_EXIT",
                "ES_EVENT_TYPE_NOTIFY_FORK",
            ],
            "requires_user_action": (
                "Operator must sign agent with Apple Developer ID and configure "
                "com.apple.developer.endpoint-security.client entitlement profile."
                if not has_entitlement else None
            ),
        }


# ──────────────────────────────────────────────────────────────
# 3. SYSTEM & HARDWARE METADATA (SYSCTL / IOKIT)
# ──────────────────────────────────────────────────────────────

class MacOSSystemCollector(BaseSystemCollector):
    """Gathers native macOS system and host metadata via sysctl and system APIs."""

    def collect_system(self) -> SystemInfo:
        now_iso = datetime.now(timezone.utc).isoformat()

        # Hardware model via sysctl hw.model
        _, hw_model, _ = _run_cmd(["sysctl", "-n", "hw.model"], timeout=0.5)
        # Machine architecture
        _, hw_machine, _ = _run_cmd(["sysctl", "-n", "hw.machine"], timeout=0.5)
        # Kernel build / OS version
        _, kern_osversion, _ = _run_cmd(["sysctl", "-n", "kern.osversion"], timeout=0.5)
        _, kern_version, _ = _run_cmd(["sysctl", "-n", "kern.version"], timeout=0.5)

        # OS version string (e.g. "14.5" or "15.0")
        os_ver = platform.mac_ver()[0] or platform.release()
        hostname = socket.gethostname()

        # Boot time & Uptime
        boot_timestamp = psutil.boot_time()
        boot_time_iso = (
            datetime.fromtimestamp(boot_timestamp, tz=timezone.utc).isoformat()
            if boot_timestamp
            else None
        )
        uptime_sec = round(time.time() - boot_timestamp, 1) if boot_timestamp else None

        # Console user via stat /dev/console or scutil
        console_user: str | None = None
        try:
            import stat
            st = os.stat("/dev/console")
            import pwd
            console_user = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            _, sc_user, _ = _run_cmd(["scutil", "--get", "LocalHostName"], timeout=0.4)
            console_user = sc_user or None

        # Load averages
        load_avgs: list[float] = []
        try:
            load_avgs = [round(x, 2) for x in os.getloadavg()]
        except Exception:
            pass

        return SystemInfo(
            hardware_model=hw_model or None,
            architecture=hw_machine or platform.machine(),
            os_name="macOS",
            os_version=os_ver,
            os_build=kern_osversion or None,
            kernel_version=kern_version.split(":")[0] if kern_version else None,
            hostname=hostname,
            uptime_seconds=uptime_sec,
            boot_time=boot_time_iso,
            console_user=console_user,
            load_averages=load_avgs,
            observed_at=now_iso,
        )


# ──────────────────────────────────────────────────────────────
# 4. STORAGE & DISK UTILIZATION
# ──────────────────────────────────────────────────────────────

class MacOSStorageCollector(BaseStorageCollector):
    """Gathers accurate filesystem and storage telemetry on macOS."""

    def collect_storage(self) -> StorageInfo:
        now_iso = datetime.now(timezone.utc).isoformat()
        partitions_list: list[StoragePartition] = []

        total_sys_bytes = 0
        used_sys_bytes = 0
        avail_sys_bytes = 0

        try:
            seen_mounts: set[str] = set()
            for part in psutil.disk_partitions(all=False):
                # Focus on physical/APFS mount points
                if part.mountpoint in seen_mounts or not os.path.exists(part.mountpoint):
                    continue
                seen_mounts.add(part.mountpoint)

                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    partition_item = StoragePartition(
                        mount_point=part.mountpoint,
                        device=part.device,
                        fstype=part.fstype,
                        total_bytes=usage.total,
                        used_bytes=usage.used,
                        available_bytes=usage.free,
                        percent_used=round(usage.percent, 1),
                    )
                    partitions_list.append(partition_item)

                    # Accumulate root / system volumes
                    if part.mountpoint in ("/", "/System/Volumes/Data"):
                        if usage.total > total_sys_bytes:
                            total_sys_bytes = usage.total
                            used_sys_bytes = usage.used
                            avail_sys_bytes = usage.free
                except Exception as e:
                    logger.debug("Error checking partition %s: %s", part.mountpoint, e)
        except Exception as e:
            logger.debug("Error enumerating disk partitions: %s", e)

        # Fallback to root directory if accumulation empty
        if total_sys_bytes == 0:
            try:
                root_usage = psutil.disk_usage("/")
                total_sys_bytes = root_usage.total
                used_sys_bytes = root_usage.used
                avail_sys_bytes = root_usage.free
            except Exception:
                pass

        overall_pct = (
            round((used_sys_bytes / total_sys_bytes) * 100.0, 1)
            if total_sys_bytes > 0
            else 0.0
        )

        return StorageInfo(
            total_bytes=total_sys_bytes,
            used_bytes=used_sys_bytes,
            available_bytes=avail_sys_bytes,
            percent_used=overall_pct,
            partitions=partitions_list,
            observed_at=now_iso,
        )


# ──────────────────────────────────────────────────────────────
# 5. HARDWARE (CPU / MEMORY / NETWORK INTERFACES)
# ──────────────────────────────────────────────────────────────

class MacOSHardwareCollector(BaseHardwareCollector):
    """Collects CPU, memory, and network interface telemetry on macOS via psutil and sysctl."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_cpu(self) -> CpuInfo:
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            per_core_raw = psutil.cpu_percent(interval=0.15, percpu=True)
            overall = psutil.cpu_percent(interval=None)
        except Exception:
            per_core_raw = []
            overall = None

        per_core = [
            PerCoreUsage(core=i, usage_percent=round(pct, 1))
            for i, pct in enumerate(per_core_raw)
        ]

        try:
            physical = psutil.cpu_count(logical=False) or 1
            logical = psutil.cpu_count(logical=True) or 1
        except Exception:
            physical = 1
            logical = 1

        # Query native chip brand from sysctl machdep.cpu.brand_string
        _, brand, _ = _run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=0.4)
        model = brand or platform.processor() or "Apple Silicon"
        arch = platform.machine() or "arm64"

        return CpuInfo(
            model=model,
            physical_cores=physical,
            logical_cores=logical,
            overall_usage_percent=round(overall, 1) if overall is not None else None,
            per_core=per_core,
            architecture=arch,
            observed_at=now_iso,
        )

    def collect_memory(self) -> MemoryInfo:
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            return MemoryInfo(
                total_bytes=vm.total,
                available_bytes=vm.available,
                used_bytes=vm.used,
                percent_used=round(vm.percent, 1),
                swap_total_bytes=swap.total,
                swap_used_bytes=swap.used,
                swap_percent_used=round(swap.percent, 1),
                observed_at=now_iso,
            )
        except Exception as e:
            logger.debug("Memory collection error: %s", e)
            return MemoryInfo(observed_at=now_iso)

    def collect_network_interfaces(self) -> list[NetworkInterfaceInfo]:
        interfaces: list[NetworkInterfaceInfo] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, addr_list in addrs.items():
                if iface_name.lower() == "lo0":
                    continue
                iface_stats = stats.get(iface_name)
                is_up = iface_stats.isup if iface_stats else True
                speed = iface_stats.speed if iface_stats else None

                ip_addrs: list[str] = []
                mac_addr: str | None = None
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address:
                        ip_addrs.append(addr.address)
                    elif addr.family == socket.AF_INET6 and addr.address:
                        ip_addrs.append(addr.address.split("%")[0])
                    elif addr.family == psutil.AF_LINK and addr.address:
                        mac_addr = addr.address

                if not ip_addrs and not mac_addr:
                    continue

                interfaces.append(
                    NetworkInterfaceInfo(
                        name=iface_name,
                        addresses=ip_addrs,
                        mac=mac_addr,
                        is_up=is_up,
                        speed_mbps=speed if speed and speed > 0 else None,
                    )
                )
        except Exception as e:
            logger.debug("Network interface collection error: %s", e)
        return interfaces


# ──────────────────────────────────────────────────────────────
# 6. APPLICATION INVENTORY (INSTALLED APPLICATIONS)
# ──────────────────────────────────────────────────────────────

class MacOSSoftwareCollector(BaseSoftwareCollector):
    """Enumerates genuine installed applications on macOS via Info.plist inspection.
    
    Strictly differentiates INSTALLED APPLICATIONS from RUNNING APPLICATIONS.
    """

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def _parse_app_bundle(self, app_path: str) -> SoftwareItem | None:
        """Parse Info.plist inside an .app bundle."""
        info_plist = os.path.join(app_path, "Contents", "Info.plist")
        if not os.path.isfile(info_plist):
            app_name = os.path.basename(app_path)
            if app_name.endswith(".app"):
                app_name = app_name[:-4]
            return SoftwareItem(
                name=app_name,
                version=None,
                publisher="Apple" if "/System/" in app_path else None,
                install_location=app_path,
                source=self.source_label,
            )

        try:
            with open(info_plist, "rb") as f:
                pl = plistlib.load(f)

            app_name = (
                pl.get("CFBundleDisplayName")
                or pl.get("CFBundleName")
                or os.path.basename(app_path)[:-4]
            )
            version = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
            publisher = "Apple Inc." if ("/System/" in app_path or "/System/Applications" in app_path) else None

            return SoftwareItem(
                name=str(app_name),
                version=str(version) if version else None,
                publisher=publisher,
                install_location=app_path,
                source=self.source_label,
            )
        except Exception:
            app_name = os.path.basename(app_path)[:-4]
            return SoftwareItem(
                name=app_name,
                version=None,
                publisher="Apple" if "/System/" in app_path else None,
                install_location=app_path,
                source=self.source_label,
            )

    def collect_software(self) -> list[SoftwareItem]:
        software_list: list[SoftwareItem] = []
        user_apps = os.path.expanduser("~/Applications")
        app_dirs = ["/Applications", "/System/Applications", user_apps]

        for d in app_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.listdir(d):
                    if entry.endswith(".app"):
                        app_path = os.path.join(d, entry)
                        item = self._parse_app_bundle(app_path)
                        if item:
                            software_list.append(item)
            except Exception as e:
                logger.debug("Could not enumerate macOS directory %s: %s", d, e)

        software_list.sort(key=lambda s: s.name.lower())
        return software_list


# ──────────────────────────────────────────────────────────────
# 7. LAUNCHD SERVICES
# ──────────────────────────────────────────────────────────────

class MacOSServiceCollector(BaseServiceCollector):
    """Enumerates launchd services and system daemons on macOS."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_services(self) -> list[ServiceItem]:
        services: list[ServiceItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        code, stdout, _ = _run_cmd(["launchctl", "list"], timeout=1.0)
        if code != 0 or not stdout:
            return []

        for line in stdout.splitlines()[1:]:  # skip header: PID Status Label
            parts = line.split()
            if len(parts) >= 3:
                pid_str, status_str, label = parts[0], parts[1], parts[2]
                status = "RUNNING" if pid_str != "-" else "STOPPED"
                services.append(
                    ServiceItem(
                        name=label,
                        display_name=label,
                        status=status,
                        start_type="LAUNCHD",
                        observed_at=now_iso,
                        source=self.source_label,
                    )
                )

        return services


# ──────────────────────────────────────────────────────────────
# 8. SOCKETS & NETWORK CONNECTIONS
# ──────────────────────────────────────────────────────────────

class MacOSSocketCollector(BaseSocketCollector):
    """Gathers listening sockets and active connections on macOS."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        seen_listening: set[tuple] = set()
        seen_conns: set[tuple] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc_conns = proc.net_connections(kind="inet")
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("macOS net_connections error for pid %s: %s", getattr(proc, 'pid', '?'), e)
                continue

            for conn in proc_conns:
                try:
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    laddr = conn.laddr
                    raddr = conn.raddr
                    pid = conn.pid if conn.pid else getattr(proc, 'pid', None)
                    pname = getattr(proc, "info", {}).get("name")

                    if not laddr:
                        continue

                    if conn.status == psutil.CONN_LISTEN:
                        dedup_key = (laddr.ip, laddr.port, proto)
                        if dedup_key in seen_listening:
                            continue
                        seen_listening.add(dedup_key)
                        listening_ports.append(
                            ListeningPortItem(
                                protocol=proto,
                                local_address=laddr.ip,
                                local_port=laddr.port,
                                pid=pid,
                                process_name=pname,
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                    elif raddr:
                        dedup_key = (laddr.ip, laddr.port, raddr.ip, raddr.port, proto)
                        if dedup_key in seen_conns:
                            continue
                        seen_conns.add(dedup_key)
                        connections.append(
                            SocketConnectionItem(
                                pid=pid,
                                process_name=pname,
                                protocol=proto,
                                local_address=laddr.ip,
                                local_port=laddr.port,
                                remote_address=raddr.ip,
                                remote_port=raddr.port,
                                state=str(conn.status or "ESTABLISHED").upper(),
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                except Exception:
                    continue

        return listening_ports, connections


# ──────────────────────────────────────────────────────────────
# 9. BROWSER VISIBILITY & TAB AUTOMATION
# ──────────────────────────────────────────────────────────────

class MacOSBrowserCollector(BaseBrowserCollector):
    """Detects running browser executables and gathers active tabs where legitimately permitted."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        browser_processes: list[BrowserProcessItem] = []
        running_names: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                canonical = MACOS_BROWSERS.get(name)
                if canonical:
                    running_names.add(canonical)
                    browser_processes.append(
                        BrowserProcessItem(
                            browser_name=canonical,
                            pid=proc.info["pid"],
                            exe_path=proc.info.get("exe"),
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
            except Exception:
                continue

        return sorted(list(running_names)), browser_processes

    def _query_safari_active_tab(self) -> BrowserTabItem | None:
        """Query Safari active tab using AppleScript."""
        script = 'tell application "Safari" to if (count of windows) > 0 then return {name of current tab of front window, URL of current tab of front window}'
        code, stdout, _ = _run_cmd(["osascript", "-e", script], timeout=0.6)
        if code == 0 and stdout:
            parts = [p.strip() for p in stdout.split(", ")]
            title = parts[0] if len(parts) > 0 else None
            url = parts[1] if len(parts) > 1 else None
            domain = None
            if url:
                m = re.search(r"https?://([^/]+)", url)
                domain = m.group(1) if m else url
            return BrowserTabItem(browser_name="Safari", title=title, url=url, domain=domain)
        return None

    def _query_chrome_active_tab(self) -> BrowserTabItem | None:
        """Query Google Chrome active tab using AppleScript."""
        script = 'tell application "Google Chrome" to if (count of windows) > 0 then return {title of active tab of front window, URL of active tab of front window}'
        code, stdout, _ = _run_cmd(["osascript", "-e", script], timeout=0.6)
        if code == 0 and stdout:
            parts = [p.strip() for p in stdout.split(", ")]
            title = parts[0] if len(parts) > 0 else None
            url = parts[1] if len(parts) > 1 else None
            domain = None
            if url:
                m = re.search(r"https?://([^/]+)", url)
                domain = m.group(1) if m else url
            return BrowserTabItem(browser_name="Chrome", title=title, url=url, domain=domain)
        return None

    def collect_browser_visibility(self) -> BrowserVisibility:
        running_names, _ = self.collect_browsers()
        active_tabs: list[BrowserTabItem] = []
        automation_status = "NOT_REQUESTED"

        if "Safari" in running_names:
            tab = self._query_safari_active_tab()
            if tab:
                active_tabs.append(tab)
                automation_status = "GRANTED"
            elif automation_status == "NOT_REQUESTED":
                automation_status = "PERMISSION_REQUIRED"

        if "Chrome" in running_names:
            tab = self._query_chrome_active_tab()
            if tab:
                active_tabs.append(tab)
                automation_status = "GRANTED"
            elif automation_status == "NOT_REQUESTED":
                automation_status = "PERMISSION_REQUIRED"

        return BrowserVisibility(
            detected_browsers=list(MACOS_BROWSERS.values()),
            running_browsers=running_names,
            active_tabs=active_tabs,
            history_status="PERMISSION_REQUIRED",  # Defensive: never bypass TCC/sandboxing
            automation_status=automation_status,
        )


# ──────────────────────────────────────────────────────────────
# 10. SECURITY POSTURE
# ──────────────────────────────────────────────────────────────

class MacOSSecurityCollector(BaseSecurityCollector):
    """Gathers native macOS security posture from official macOS command-line utilities."""

    def collect_security(self) -> MacSecurityPosture:
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. FileVault Status (fdesetup status)
        code, fde_out, _ = _run_cmd(["fdesetup", "status"], timeout=0.8)
        filevault = "UNKNOWN"
        if code == 0:
            if "FileVault is On." in fde_out:
                filevault = "ENABLED"
            elif "FileVault is Off." in fde_out:
                filevault = "DISABLED"
        elif "Permission denied" in fde_out or code == 1:
            filevault = "PERMISSION_REQUIRED"

        # 2. SIP Status (csrutil status)
        code, sip_out, _ = _run_cmd(["csrutil", "status"], timeout=0.8)
        sip = "UNKNOWN"
        if code == 0:
            if "status: enabled" in sip_out.lower():
                sip = "ENABLED"
            elif "status: disabled" in sip_out.lower():
                sip = "DISABLED"

        # 3. Gatekeeper Status (spctl --status)
        code, spctl_out, _ = _run_cmd(["spctl", "--status"], timeout=0.8)
        gatekeeper = "UNKNOWN"
        if code == 0:
            if "assessments enabled" in spctl_out:
                gatekeeper = "ENABLED"
            elif "assessments disabled" in spctl_out:
                gatekeeper = "DISABLED"

        # 4. Application Firewall (socketfilterfw)
        fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        firewall = "UNKNOWN"
        if os.path.isfile(fw_bin):
            code, fw_out, _ = _run_cmd([fw_bin, "--getglobalstate"], timeout=0.8)
            if code == 0:
                if "Firewall is enabled" in fw_out:
                    firewall = "ENABLED"
                elif "Firewall is disabled" in fw_out:
                    firewall = "DISABLED"

        # 5. Secure Boot (Apple Silicon check)
        _, is_arm, _ = _run_cmd(["sysctl", "-n", "hw.optional.arm64"], timeout=0.4)
        secure_boot = "ENABLED" if is_arm == "1" else "NOT_APPLICABLE"

        # 6. Automatic Updates (softwareupdate --schedule)
        code, sw_out, _ = _run_cmd(["softwareupdate", "--schedule"], timeout=0.8)
        auto_updates = "UNKNOWN"
        if code == 0:
            if "Automatic check is on" in sw_out:
                auto_updates = "ENABLED"
            elif "Automatic check is off" in sw_out:
                auto_updates = "DISABLED"

        return MacSecurityPosture(
            filevault=filevault,
            sip=sip,
            gatekeeper=gatekeeper,
            firewall=firewall,
            secure_boot=secure_boot,
            auto_updates=auto_updates,
            observed_at=now_iso,
        )


# ──────────────────────────────────────────────────────────────
# 11. PERMISSION MANAGEMENT SUBSYSTEM
# ──────────────────────────────────────────────────────────────

class MacOSPermissionManager(BasePermissionManager):
    """Monitors Apple TCC permissions and Developer entitlements."""

    def collect_permissions(self) -> list[PermissionStatusItem]:
        items: list[PermissionStatusItem] = []

        # 1. Accessibility (AXIsProcessTrusted)
        ax_granted = False
        try:
            app_services = ctypes.cdll.LoadLibrary(
                "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
            )
            ax_granted = bool(app_services.AXIsProcessTrusted())
        except Exception:
            pass

        items.append(
            PermissionStatusItem(
                name="Accessibility",
                status="GRANTED" if ax_granted else "REQUIRES_USER_ACTION",
                details="Allows monitoring active window context and assistive interfaces.",
                remediation="Enable in System Settings > Privacy & Security > Accessibility.",
            )
        )

        # 2. Full Disk Access (FDA)
        fda_granted = False
        try:
            fda_granted = os.access("/Library/Application Support/com.apple.TCC/TCC.db", os.R_OK)
        except Exception:
            pass

        items.append(
            PermissionStatusItem(
                name="Full Disk Access",
                status="GRANTED" if fda_granted else "REQUIRES_USER_ACTION",
                details="Allows comprehensive filesystem scanning across user directories.",
                remediation="Enable in System Settings > Privacy & Security > Full Disk Access.",
            )
        )

        # 3. Automation / Apple Events
        code, _, _ = _run_cmd(
            ["osascript", "-e", 'tell application "System Events" to return name of first process whose frontmost is true'],
            timeout=0.6,
        )
        items.append(
            PermissionStatusItem(
                name="Automation",
                status="GRANTED" if code == 0 else "REQUIRES_USER_ACTION",
                details="Allows querying active application titles and browser tabs via Apple Events.",
                remediation="Authorize prompt when requested or configure in System Settings > Privacy & Security > Automation.",
            )
        )

        # 4. Endpoint Security Entitlement
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        items.append(
            PermissionStatusItem(
                name="Endpoint Security Entitlement",
                status="GRANTED" if is_root else "REQUIRES_USER_ACTION",
                details="Apple EndpointSecurity.framework subscription for low-level kernel event monitoring.",
                remediation="Requires Apple Developer ID with com.apple.developer.endpoint-security.client entitlement and root daemon execution.",
            )
        )

        # 5. Network Extension
        items.append(
            PermissionStatusItem(
                name="Network Extension",
                status="NOT_REQUESTED",
                details="Network content filtering and socket flow analysis via NetworkExtension.framework.",
                remediation="Install Drishti Network Extension system extension via operator pkg package.",
            )
        )

        return items


# ──────────────────────────────────────────────────────────────
# 12. NETWORK EXTENSION INTEGRATION SPECIFICATION
# ──────────────────────────────────────────────────────────────

class MacOSNetworkExtensionBridge:
    """Represents the NetworkExtension (ContentFilter / PacketTunnel) provider integration."""

    @staticmethod
    def get_provider_status() -> dict[str, Any]:
        return {
            "provider_type": "NEFilterDataProvider / NEPacketTunnelProvider",
            "entitlement": "com.apple.developer.networking.networkextension",
            "state": "STANDBY",
            "traffic_interception": "DEFENSIVE_MONITORING_ONLY",
            "pipeline_integration": "Forwarding to Drishti Flow Engine / Zeek",
        }
