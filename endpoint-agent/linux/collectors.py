# Drishti v0.1 — Linux Telemetry Collectors | Phase 02 & Multi-Platform Support
from __future__ import annotations

import collections
import logging
import os
import platform
import socket
import subprocess
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
    BrowserVisibility,
    CpuInfo,
    ListeningPortItem,
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

logger = logging.getLogger("drishti.agent.linux")

LINUX_SYSTEM_PROCESSES = {
    "systemd",
    "init",
    "kthreadd",
    "systemd-journald",
    "systemd-udevd",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-networkd",
    "systemd-logind",
    "dbus-daemon",
    "dbus-broker",
    "rsyslogd",
    "syslogd",
    "cron",
    "crond",
    "sshd",
    "polkitd",
    "agetty",
    "login",
    "udevd",
    "containerd",
    "dockerd",
    "networkmanager",
    "accounts-daemon",
    "avahi-daemon",
    "wpa_supplicant",
    "auditd",
    "firewalld",
}

LINUX_BROWSERS = {
    "chrome": "Chrome",
    "google-chrome": "Chrome",
    "google-chrome-stable": "Chrome",
    "chromium": "Chromium",
    "chromium-browser": "Chromium",
    "firefox": "Firefox",
    "firefox-esr": "Firefox",
    "brave": "Brave",
    "brave-browser": "Brave",
    "microsoft-edge": "Edge",
    "microsoft-edge-stable": "Edge",
    "opera": "Opera",
    "vivaldi": "Vivaldi",
    "epiphany": "Epiphany",
}

DEVELOPER_TOOLS = {
    "python",
    "python3",
    "node",
    "nodejs",
    "npm",
    "git",
    "docker",
    "docker-compose",
    "podman",
    "go",
    "cargo",
    "rustc",
    "gcc",
    "g++",
    "clang",
    "make",
    "cmake",
    "code",
    "code-server",
    "nvim",
    "vim",
    "zsh",
    "bash",
}


def _run_cmd(cmd: list[str], timeout: float = 2.0) -> tuple[int, str, str]:
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

class LinuxProcessCollector(BaseProcessCollector):
    """Gathers running processes on Linux, tracks lifecycle events, and categorizes processes."""

    def __init__(self, source_label: str = "linux_endpoint"):
        self.source_label = source_label
        self._event_buffer: collections.deque[ProcessEventItem] = collections.deque(maxlen=250)
        self._previous_pids: dict[int, dict[str, Any]] = {}

    def _classify_process(self, name: str, exe_path: str | None) -> str:
        lower_name = name.lower()
        if lower_name in LINUX_SYSTEM_PROCESSES or lower_name.startswith(("kworker", "ksoftirqd", "migration/")):
            return ProcessCategory.SYSTEM_PROCESS.value
        if lower_name in LINUX_BROWSERS:
            return ProcessCategory.USER_APPLICATION.value
        if lower_name in DEVELOPER_TOOLS:
            return ProcessCategory.USER_APPLICATION.value

        if exe_path:
            lower_path = exe_path.lower()
            if lower_path.startswith(("/sbin/", "/usr/sbin/", "/lib/systemd/", "/usr/lib/systemd/")):
                return ProcessCategory.SYSTEM_PROCESS.value
            if lower_path.startswith(("/usr/bin/", "/opt/", "/snap/", "/var/lib/flatpak/")):
                return ProcessCategory.USER_APPLICATION.value

        return ProcessCategory.BACKGROUND_PROCESS.value

    def _check_suspicious_process(self, name: str, exe_path: str | None, ppid: int | None) -> tuple[bool, str | None]:
        """Flag suspicious Linux execution behavior (e.g. running from /tmp, /dev/shm, deleted binary)."""
        if not exe_path:
            return False, None

        lower_path = exe_path.lower()
        temp_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
        for prefix in temp_prefixes:
            if lower_path.startswith(prefix):
                return True, f"Execution from temporary/shared memory location: {prefix}"

        if "(deleted)" in lower_path:
            return True, "Execution of unlinked/deleted binary from memory"

        basename = os.path.basename(exe_path)
        if basename.startswith(".") and len(basename) > 1:
            return True, f"Hidden binary execution name: {basename}"

        return False, None

    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        items: list[ProcessItem] = []
        active_user_apps: set[str] = set()
        current_pids: dict[int, dict[str, Any]] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "exe",
                "cmdline",
                "username",
                "cpu_percent",
                "memory_percent",
                "memory_info",
                "status",
                "create_time",
            ]
        ):
            try:
                pinfo = proc.info
                pid = pinfo["pid"]
                ppid = pinfo.get("ppid") or 0
                name = pinfo.get("name") or "unknown"
                exe = pinfo.get("exe") or None
                cmdline_list = pinfo.get("cmdline") or []
                username = pinfo.get("username") or "root"
                cpu_pct = float(pinfo.get("cpu_percent") or 0.0)

                mem_info = pinfo.get("memory_info")
                mem_mb = float(mem_info.rss / (1024 * 1024)) if mem_info else 0.0

                create_time = pinfo.get("create_time") or 0.0
                created_iso = datetime.fromtimestamp(create_time, timezone.utc).isoformat() if create_time else now_iso

                category = self._classify_process(name, exe)
                is_suspicious, susp_reason = self._check_suspicious_process(name, exe, ppid)

                current_pids[pid] = {
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline_list,
                    "username": username,
                    "created_at": created_iso,
                    "ppid": ppid,
                    "is_suspicious": is_suspicious,
                    "suspicious_reason": susp_reason,
                }

                if category == ProcessCategory.USER_APPLICATION.value:
                    active_user_apps.add(name)

                items.append(
                    ProcessItem(
                        pid=pid,
                        name=name,
                        ppid=ppid,
                        exe_path=exe,
                        cmdline=cmdline_list,
                        category=category,
                        start_time=created_iso,
                        cpu_percent=cpu_pct,
                        memory_mb=mem_mb,
                        source="linux_process_collector",
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Failed to inspect Linux process: %s", e)
                continue

        # Detect Lifecycle EXEC events
        for pid, pdata in current_pids.items():
            if pid not in self._previous_pids:
                self._event_buffer.append(
                    ProcessEventItem(
                        event_type="EXEC",
                        pid=pid,
                        name=pdata["name"],
                        ppid=pdata["ppid"],
                        exe_path=pdata["exe"],
                        cmdline=pdata["cmdline"],
                        username=pdata["username"],
                        signing_status="UNSIGNED",
                        is_suspicious=pdata["is_suspicious"],
                        suspicious_reason=pdata["suspicious_reason"],
                        timestamp=pdata["created_at"],
                        source="linux_event_tracker",
                    )
                )

        # Detect Lifecycle EXIT events
        for pid, pdata in self._previous_pids.items():
            if pid not in current_pids:
                self._event_buffer.append(
                    ProcessEventItem(
                        event_type="EXIT",
                        pid=pid,
                        name=pdata["name"],
                        ppid=pdata["ppid"],
                        exe_path=pdata["exe"],
                        cmdline=pdata["cmdline"],
                        username=pdata["username"],
                        signing_status="UNSIGNED",
                        timestamp=now_iso,
                        source="linux_event_tracker",
                    )
                )

        self._previous_pids = current_pids
        return items, sorted(list(active_user_apps))

    def get_recent_process_events(self) -> list[ProcessEventItem]:
        return list(self._event_buffer)


# ──────────────────────────────────────────────────────────────
# 2. SOFTWARE INVENTORY COLLECTOR
# ──────────────────────────────────────────────────────────────

class LinuxSoftwareCollector(BaseSoftwareCollector):
    """Enumerates installed software via dpkg, rpm, pacman, snap, and flatpak."""

    def collect_software(self) -> list[SoftwareItem]:
        software: list[SoftwareItem] = []

        # 1. Debian / Ubuntu (dpkg-query)
        ret, stdout, _ = _run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\n"], timeout=5.0)
        if ret == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    name = parts[0].strip()
                    ver = parts[1].strip()
                    vendor = parts[3].strip() if len(parts) >= 4 else "Debian/Ubuntu Maintainers"
                    software.append(
                        SoftwareItem(
                            name=name,
                            version=ver,
                            publisher=vendor,
                            install_location=f"/usr/bin/{name}",
                            source="dpkg",
                        )
                    )
            if software:
                return software

        # 2. RedHat / Fedora / CentOS (rpm)
        ret, stdout, _ = _run_cmd(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], timeout=5.0)
        if ret == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    name = parts[0].strip()
                    ver = parts[1].strip()
                    vendor = parts[2].strip() if len(parts) >= 3 else "RPM Package"
                    software.append(
                        SoftwareItem(
                            name=name,
                            version=ver,
                            publisher=vendor,
                            install_location=f"/usr/bin/{name}",
                            source="rpm",
                        )
                    )
            if software:
                return software

        # 3. Arch Linux (pacman)
        ret, stdout, _ = _run_cmd(["pacman", "-Q"], timeout=5.0)
        if ret == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    software.append(
                        SoftwareItem(
                            name=parts[0].strip(),
                            version=parts[1].strip(),
                            publisher="Arch Linux",
                            install_location=f"/usr/bin/{parts[0].strip()}",
                            source="pacman",
                        )
                    )
            if software:
                return software

        # 4. Fallback: inspect /usr/bin for installed binaries
        try:
            usr_bin = Path("/usr/bin")
            if usr_bin.exists():
                count = 0
                for bin_file in usr_bin.iterdir():
                    if bin_file.is_file() and os.access(bin_file, os.X_OK):
                        software.append(
                            SoftwareItem(
                                name=bin_file.name,
                                version="1.0",
                                publisher="System Binary",
                                install_location=str(bin_file),
                                source="bin_dir",
                            )
                        )
                        count += 1
                        if count >= 100:
                            break
        except Exception:
            pass

        return software


# ──────────────────────────────────────────────────────────────
# 3. SYSTEMD SERVICES COLLECTOR
# ──────────────────────────────────────────────────────────────

class LinuxServiceCollector(BaseServiceCollector):
    """Enumerates systemd services or sysvinit scripts on Linux."""

    def collect_services(self) -> list[ServiceItem]:
        services: list[ServiceItem] = []

        # 1. systemctl list-units --type=service
        ret, stdout, _ = _run_cmd(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            timeout=3.0,
        )
        if ret == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit_name = parts[0].strip()
                    if not unit_name.endswith(".service"):
                        continue
                    clean_name = unit_name.removesuffix(".service")
                    load_state = parts[1].strip()
                    active_state = parts[2].strip()
                    sub_state = parts[3].strip()
                    desc = parts[4].strip() if len(parts) >= 5 else clean_name

                    status = "RUNNING" if active_state == "active" and sub_state == "running" else "STOPPED"
                    services.append(
                        ServiceItem(
                            name=clean_name,
                            display_name=desc,
                            status=status,
                            start_type=load_state,
                            source="systemd",
                        )
                    )
            if services:
                return services

        # 2. Fallback: Inspect /etc/systemd/system or /lib/systemd/system
        for sdir in ("/etc/systemd/system", "/lib/systemd/system"):
            try:
                p = Path(sdir)
                if p.exists():
                    for f in p.glob("*.service"):
                        services.append(
                            ServiceItem(
                                name=f.stem,
                                display_name=f.stem,
                                status="UNKNOWN",
                                start_type="enabled",
                                source="systemd_unit",
                            )
                        )
                    if services:
                        return services
            except Exception:
                pass

        return services


# ──────────────────────────────────────────────────────────────
# 4. NETWORK SOCKETS & CONNECTIONS COLLECTOR
# ──────────────────────────────────────────────────────────────

class LinuxSocketCollector(BaseSocketCollector):
    """Enumerates listening ports and active network socket connections."""

    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []

        try:
            net_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Access denied when reading all network connections via psutil")
            net_conns = []

        pid_name_cache: dict[int, str] = {}

        def get_proc_name(pid: int | None) -> str | None:
            if not pid:
                return None
            if pid not in pid_name_cache:
                try:
                    p = psutil.Process(pid)
                    pid_name_cache[pid] = p.name()
                except Exception:
                    pid_name_cache[pid] = "unknown"
            return pid_name_cache[pid]

        for conn in net_conns:
            try:
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                state = conn.status if hasattr(conn, "status") else "UNKNOWN"
                laddr = conn.laddr.ip if hasattr(conn, "laddr") and conn.laddr else ""
                lport = conn.laddr.port if hasattr(conn, "laddr") and conn.laddr else 0
                raddr = conn.raddr.ip if hasattr(conn, "raddr") and conn.raddr else None
                rport = conn.raddr.port if hasattr(conn, "raddr") and conn.raddr else None
                pname = get_proc_name(conn.pid)

                if state == "LISTEN" or (proto == "UDP" and not raddr):
                    listening_ports.append(
                        ListeningPortItem(
                            protocol=proto,
                            local_address=laddr,
                            local_port=lport,
                            pid=conn.pid,
                            process_name=pname,
                            source="linux_sockets",
                        )
                    )
                else:
                    if raddr and raddr != "0.0.0.0" and raddr != "::":
                        connections.append(
                            SocketConnectionItem(
                                pid=conn.pid,
                                process_name=pname,
                                protocol=proto,
                                local_address=laddr,
                                local_port=lport,
                                remote_address=raddr,
                                remote_port=rport or 0,
                                state=state,
                                source="linux_sockets",
                            )
                        )
            except Exception as e:
                logger.debug("Failed to parse Linux socket connection: %s", e)
                continue

        return listening_ports, connections


# ──────────────────────────────────────────────────────────────
# 5. BROWSER TELEMETRY
# ──────────────────────────────────────────────────────────────

class LinuxBrowserCollector(BaseBrowserCollector):
    """Enumerates running Linux web browser processes."""

    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        installed_or_running: set[str] = set()
        procs: list[BrowserProcessItem] = []

        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or [])
                canonical = None
                for key, val in LINUX_BROWSERS.items():
                    if key == name or key in cmdline.lower():
                        canonical = val
                        break

                if canonical:
                    installed_or_running.add(canonical)
                    procs.append(
                        BrowserProcessItem(
                            browser_name=canonical,
                            pid=proc.info["pid"],
                            exe_path=proc.info.get("exe"),
                            source="linux_browser_collector",
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return sorted(list(installed_or_running)), procs

    def collect_browser_visibility(self) -> BrowserVisibility:
        running_names, _ = self.collect_browsers()
        return BrowserVisibility(
            detected_browsers=list(LINUX_BROWSERS.values()),
            running_browsers=running_names,
            active_tabs=[],
            history_status="PERMISSION_REQUIRED",
            automation_status="NOT_REQUESTED",
        )


# ──────────────────────────────────────────────────────────────
# 6. HARDWARE TELEMETRY (CPU, MEMORY, INTERFACES)
# ──────────────────────────────────────────────────────────────

class LinuxHardwareCollector(BaseHardwareCollector):
    """Genuine Linux hardware metrics using psutil, /proc, and sysfs."""

    def collect_cpu(self) -> CpuInfo:
        overall_usage = float(psutil.cpu_percent(interval=None))
        per_core_raw = psutil.cpu_percent(interval=None, percpu=True)
        per_core: list[PerCoreUsage] = [
            PerCoreUsage(core=idx, usage_percent=float(val))
            for idx, val in enumerate(per_core_raw)
        ]

        physical_cores = psutil.cpu_count(logical=False) or 1
        logical_cores = psutil.cpu_count(logical=True) or 1

        model_name = "Linux Processor"
        try:
            p_cpu = Path("/proc/cpuinfo")
            if p_cpu.exists():
                for line in p_cpu.read_text(encoding="utf-8").splitlines():
                    if "model name" in line:
                        model_name = line.split(":", 1)[1].strip()
                        break
        except Exception:
            pass

        return CpuInfo(
            model=model_name,
            physical_cores=physical_cores,
            logical_cores=logical_cores,
            overall_usage_percent=overall_usage,
            per_core=per_core,
            architecture=platform.machine(),
        )

    def collect_memory(self) -> MemoryInfo:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return MemoryInfo(
            total_bytes=vm.total,
            available_bytes=vm.available,
            used_bytes=vm.used,
            percent_used=float(vm.percent),
            swap_total_bytes=swap.total,
            swap_used_bytes=swap.used,
            swap_percent_used=float(swap.percent),
        )

    def collect_network_interfaces(self) -> list[NetworkInterfaceInfo]:
        results: list[NetworkInterfaceInfo] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for iface_name, addr_list in addrs.items():
                if iface_name == "lo":
                    continue

                mac: str | None = None
                addresses: list[str] = []

                for addr in addr_list:
                    if addr.family in (socket.AF_INET, socket.AF_INET6):
                        addresses.append(addr.address)
                    elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                        mac = addr.address

                iface_stat = stats.get(iface_name)
                is_up = iface_stat.isup if iface_stat else True
                speed = iface_stat.speed if iface_stat else 0

                results.append(
                    NetworkInterfaceInfo(
                        name=iface_name,
                        addresses=addresses,
                        mac=mac,
                        is_up=is_up,
                        speed_mbps=speed,
                    )
                )
        except Exception as e:
            logger.debug("Failed to enumerate Linux network interfaces: %s", e)

        return results


# ──────────────────────────────────────────────────────────────
# 7. SYSTEM, STORAGE, SECURITY & PERMISSION POSTURE
# ──────────────────────────────────────────────────────────────

class LinuxSystemCollector(BaseSystemCollector):
    """Collects Linux kernel release, hostname, uptime, and load averages."""

    def collect_system(self) -> SystemInfo:
        boot_time = psutil.boot_time()
        uptime_seconds = max(0.0, time.time() - boot_time)

        load_avgs: list[float] = []
        try:
            load_avgs = list(os.getloadavg())
        except Exception:
            pass

        return SystemInfo(
            hardware_model=f"Linux ({platform.machine()})",
            architecture=platform.machine(),
            os_name="Linux",
            os_version=platform.release(),
            os_build=platform.version(),
            kernel_version=platform.release(),
            hostname=socket.gethostname(),
            uptime_seconds=uptime_seconds,
            boot_time=datetime.fromtimestamp(boot_time, timezone.utc).isoformat(),
            load_averages=load_avgs,
        )


class LinuxStorageCollector(BaseStorageCollector):
    """Collects disk partitions, mounts, and filesystem storage usage."""

    def collect_storage(self) -> StorageInfo:
        partitions: list[StoragePartition] = []
        total_b = 0
        used_b = 0
        avail_b = 0

        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                total_b += usage.total
                used_b += usage.used
                avail_b += usage.free

                partitions.append(
                    StoragePartition(
                        mount_point=part.mountpoint,
                        device=part.device,
                        fstype=part.fstype,
                        total_bytes=usage.total,
                        used_bytes=usage.used,
                        available_bytes=usage.free,
                        percent_used=float(usage.percent),
                    )
                )
            except Exception:
                continue

        percent = float(used_b / total_b * 100.0) if total_b > 0 else 0.0
        return StorageInfo(
            total_bytes=total_b,
            used_bytes=used_b,
            available_bytes=avail_b,
            percent_used=percent,
            partitions=partitions,
        )


class LinuxSecurityCollector(BaseSecurityCollector):
    """Collects security posture: firewall (ufw/iptables), SELinux, AppArmor."""

    def collect_security(self) -> dict[str, Any]:
        firewall_active = False
        firewall_name = "none"

        ret, stdout, _ = _run_cmd(["ufw", "status"], timeout=1.0)
        if ret == 0 and "Status: active" in stdout:
            firewall_active = True
            firewall_name = "ufw"
        else:
            ret_fwd, _, _ = _run_cmd(["firewall-cmd", "--state"], timeout=1.0)
            if ret_fwd == 0:
                firewall_active = True
                firewall_name = "firewalld"
            else:
                ret_ipt, stdout_ipt, _ = _run_cmd(["iptables", "-L", "-n"], timeout=1.0)
                if ret_ipt == 0 and "Chain" in stdout_ipt:
                    firewall_active = True
                    firewall_name = "iptables"

        selinux_mode = "Disabled"
        try:
            p_se = Path("/sys/fs/selinux/enforce")
            if p_se.exists():
                val = p_se.read_text(encoding="utf-8").strip()
                selinux_mode = "Enforcing" if val == "1" else "Permissive"
        except Exception:
            pass

        apparmor_active = False
        try:
            p_aa = Path("/sys/kernel/security/apparmor/profiles")
            if p_aa.exists():
                apparmor_active = True
        except Exception:
            pass

        return {
            "firewall_active": firewall_active,
            "firewall_type": firewall_name,
            "selinux_mode": selinux_mode,
            "apparmor_active": apparmor_active,
            "secure_boot": os.path.exists("/sys/firmware/efi/efivars"),
        }


class LinuxPermissionManager(BasePermissionManager):
    """Reports Linux root privilege and capability status."""

    def collect_permissions(self) -> list[PermissionStatusItem]:
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        return [
            PermissionStatusItem(
                name="Root / Superuser Access",
                status="GRANTED" if is_root else "NOT_REQUESTED",
                details="Allows unrestricted process and socket packet inspection",
            ),
            PermissionStatusItem(
                name="Kernel Packet Capture (CAP_NET_RAW)",
                status="GRANTED" if is_root else "DENIED",
                details="Enables raw socket deep flow tracking",
            ),
        ]
