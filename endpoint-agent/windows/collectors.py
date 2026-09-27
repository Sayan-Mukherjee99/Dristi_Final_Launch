# Drishti v0.1 — Windows Telemetry Collectors | Phase 02
from __future__ import annotations

import logging
import os
import socket
import sys
from datetime import datetime, timezone
from typing import Any

import psutil

from collectors.base import (
    BaseBrowserCollector,
    BaseHardwareCollector,
    BaseProcessCollector,
    BaseServiceCollector,
    BaseSocketCollector,
    BaseSoftwareCollector,
)
from collectors.contracts import (
    BrowserProcessItem,
    CpuInfo,
    ListeningPortItem,
    MemoryInfo,
    NetworkInterfaceInfo,
    PerCoreUsage,
    ProcessCategory,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
)

logger = logging.getLogger("drishti.agent.windows")

# Standard Windows system binaries & core services
SYSTEM_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "dasHost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "ctfmon.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
    "searchindexer.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
}

# Known browser binaries mapping to canonical names
KNOWN_BROWSERS = {
    "chrome.exe": "Chrome",
    "msedge.exe": "Edge",
    "brave.exe": "Brave",
    "firefox.exe": "Firefox",
    "arc.exe": "Arc",
    "opera.exe": "Opera",
}

# Standard user-interactive software indicators
KNOWN_USER_APPS = {
    "code.exe": "Visual Studio Code",
    "devenv.exe": "Visual Studio",
    "notepad.exe": "Notepad",
    "notepad++.exe": "Notepad++",
    "calc.exe": "Calculator",
    "calculatorapp.exe": "Calculator",
    "slack.exe": "Slack",
    "discord.exe": "Discord",
    "teams.exe": "Microsoft Teams",
    "spotify.exe": "Spotify",
    "steam.exe": "Steam",
    "windowsterminal.exe": "Windows Terminal",
    "cmd.exe": "Command Prompt",
    "powershell.exe": "PowerShell",
    "pwsh.exe": "PowerShell Core",
    "python.exe": "Python",
    "node.exe": "Node.js",
    "git.exe": "Git",
    "docker.exe": "Docker",
}


class WindowsProcessCollector(BaseProcessCollector):
    """Gathers genuine Windows running processes and classifies them deterministically."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def _classify_process(self, name: str, exe_path: str | None, username: str | None) -> str:
        lower_name = name.lower()
        if lower_name in SYSTEM_PROCESS_NAMES:
            return ProcessCategory.SYSTEM_PROCESS.value
        if lower_name in KNOWN_BROWSERS or lower_name in KNOWN_USER_APPS:
            return ProcessCategory.USER_APPLICATION.value

        # Path heuristics: system32 / syswow64 / Windows folder usually system/background
        if exe_path:
            lower_path = exe_path.lower()
            if "\\windows\\system32" in lower_path or "\\windows\\syswow64" in lower_path:
                return ProcessCategory.SYSTEM_PROCESS.value
            if "\\program files" in lower_path or "\\appdata\\local\\programs" in lower_path:
                return ProcessCategory.USER_APPLICATION.value

        return ProcessCategory.BACKGROUND_PROCESS.value

    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        processes: list[ProcessItem] = []
        active_apps_set: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        # First pass: trigger cpu_percent monitoring with interval=None (non-blocking)
        pid_cpu: dict[int, float] = {}
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    proc.cpu_percent(interval=None)
                except Exception:
                    pass
        except Exception:
            pass

        # Short sleep so the next cpu_percent call returns a real delta
        import time
        time.sleep(0.12)

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

                category = self._classify_process(name, exe_path, username)

                if category == ProcessCategory.USER_APPLICATION.value:
                    friendly_name = KNOWN_BROWSERS.get(name.lower()) or KNOWN_USER_APPS.get(name.lower()) or name
                    active_apps_set.add(friendly_name)

                # Collect per-process CPU and RSS memory
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

                processes.append(
                    ProcessItem(
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
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Error inspecting process PID %s: %s", getattr(proc, "pid", "unknown"), e)
                continue

        return processes, sorted(list(active_apps_set))


class WindowsSoftwareCollector(BaseSoftwareCollector):
    """Gathers genuine installed software inventory from Windows Registry uninstall keys."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_software(self) -> list[SoftwareItem]:
        software_list: list[SoftwareItem] = []
        seen_keys: set[tuple[str, str | None]] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        if not sys.platform.startswith("win"):
            return software_list

        import winreg

        registry_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        ]

        for root_hive, subkey_path, flags in registry_targets:
            try:
                with winreg.OpenKey(root_hive, subkey_path, 0, winreg.KEY_READ | flags) as root_key:
                    num_subkeys = winreg.QueryInfoKey(root_key)[0]
                    for idx in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(root_key, idx)
                            with winreg.OpenKey(root_key, subkey_name, 0, winreg.KEY_READ | flags) as app_key:
                                try:
                                    display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                except FileNotFoundError:
                                    continue  # Skip entries with no display name

                                if not display_name or not isinstance(display_name, str) or not display_name.strip():
                                    continue

                                display_name = display_name.strip()

                                # Skip Windows updates / Hotfixes without proper application titles
                                if display_name.startswith("KB") and display_name[2:].isdigit():
                                    continue

                                try:
                                    display_version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                    display_version = str(display_version).strip() if display_version else None
                                except FileNotFoundError:
                                    display_version = None

                                try:
                                    publisher, _ = winreg.QueryValueEx(app_key, "Publisher")
                                    publisher = str(publisher).strip() if publisher else None
                                except FileNotFoundError:
                                    publisher = None

                                try:
                                    install_loc, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                                    install_loc = str(install_loc).strip() if install_loc else None
                                except FileNotFoundError:
                                    install_loc = None

                                dedupe_key = (display_name.lower(), display_version)
                                if dedupe_key in seen_keys:
                                    continue
                                seen_keys.add(dedupe_key)

                                software_list.append(
                                    SoftwareItem(
                                        name=display_name,
                                        version=display_version,
                                        publisher=publisher,
                                        install_location=install_loc,
                                        observed_at=now_iso,
                                        source=self.source_label,
                                    )
                                )
                        except Exception:
                            continue
            except Exception as e:
                logger.debug("Could not inspect registry hive %s\\%s: %s", root_hive, subkey_path, e)
                continue

        software_list.sort(key=lambda s: s.name.lower())
        return software_list


class WindowsServiceCollector(BaseServiceCollector):
    """Enumerates local Windows services via psutil."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_services(self) -> list[ServiceItem]:
        services: list[ServiceItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if not hasattr(psutil, "win_service_iter"):
            return services

        try:
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    name = info.get("name") or "unknown"
                    display_name = info.get("display_name") or name
                    status = str(info.get("status") or "UNKNOWN").upper()
                    start_type = str(info.get("start_type") or "UNKNOWN").upper()

                    services.append(
                        ServiceItem(
                            name=name,
                            display_name=display_name,
                            status=status,
                            start_type=start_type,
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Error enumerating Windows services: %s", e)

        services.sort(key=lambda x: x.name.lower())
        return services


import ipaddress
import struct

# Cache reverse DNS lookups to avoid per-cycle latency
_REVERSE_DNS_CACHE: dict[str, str | None] = {}


def _is_internet_address(ip_str: str) -> bool:
    """Returns True if IP address is a public, routable internet address."""
    if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "::", "::1", "*", "localhost"):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def _resolve_internet_host(ip_str: str) -> str | None:
    """Resolves IP to domain name / hostname using cached reverse DNS."""
    if not _is_internet_address(ip_str):
        return None
    if ip_str in _REVERSE_DNS_CACHE:
        return _REVERSE_DNS_CACHE[ip_str]
    try:
        host, _ = socket.getnameinfo((ip_str, 0), socket.NI_NAMEREQD)
        _REVERSE_DNS_CACHE[ip_str] = host
        return host
    except Exception:
        _REVERSE_DNS_CACHE[ip_str] = None
        return None


def _infer_website_url(remote_ip: str, remote_port: int, destination_host: str | None = None) -> str | None:
    """Infers website URL from remote IP/port/host if web protocol is detected."""
    target = destination_host or remote_ip
    if remote_port == 443:
        return f"https://{target}"
    elif remote_port == 80:
        return f"http://{target}"
    elif remote_port in (8080, 8443, 8000, 8888, 3000):
        proto = "https" if remote_port in (8443,) else "http"
        return f"{proto}://{target}:{remote_port}"
    elif _is_internet_address(remote_ip):
        proto = "https" if remote_port == 443 else "http"
        return f"{proto}://{target}:{remote_port}"
    return None


def _query_windows_kernel_tcp_table() -> list[dict[str, Any]]:
    """Directly queries tcpip.sys kernel socket structures in memory via iphlpapi.GetExtendedTcpTable.

    Provides true kernel-level TCP table inspection with exact owning PID, connection state,
    and 5-tuple without requiring third-party drivers.
    """
    if not sys.platform.startswith("win"):
        return []
    try:
        import ctypes
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable

        # TCP_TABLE_OWNER_PID_ALL = 5, AF_INET = 2
        pdwSize = ctypes.c_ulong(0)
        res = GetExtendedTcpTable(None, ctypes.byref(pdwSize), False, 2, 5, 0)
        if res != 122 and res != 0:  # 122 = ERROR_INSUFFICIENT_BUFFER
            return []

        buf = ctypes.create_string_buffer(pdwSize.value)
        res = GetExtendedTcpTable(buf, ctypes.byref(pdwSize), False, 2, 5, 0)
        if res != 0:
            return []

        num_entries = struct.unpack_from("<I", buf.raw, 0)[0]
        row_size = 24  # MIB_TCPROW_OWNER_PID is 6 x DWORD = 24 bytes
        offset = 4

        tcp_states = {
            1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
            5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
            8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
            11: "TIME_WAIT", 12: "DELETE_TCB"
        }

        results = []
        for _ in range(num_entries):
            if offset + row_size > len(buf.raw):
                break
            state_code, local_addr_int, local_port_int, remote_addr_int, remote_port_int, pid = struct.unpack_from(
                "<IIIIII", buf.raw, offset
            )
            offset += row_size

            # In MIB_TCPROW, ports are stored in network byte order in lower 16 bits
            local_port = ((local_port_int & 0xFF) << 8) | ((local_port_int >> 8) & 0xFF)
            remote_port = ((remote_port_int & 0xFF) << 8) | ((remote_port_int >> 8) & 0xFF)
            local_ip = socket.inet_ntoa(struct.pack("<I", local_addr_int))
            remote_ip = socket.inet_ntoa(struct.pack("<I", remote_addr_int))
            state = tcp_states.get(state_code, "UNKNOWN")

            results.append({
                "pid": pid,
                "protocol": "TCP",
                "local_address": local_ip,
                "local_port": local_port,
                "remote_address": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "source": "windows_kernel_tcpip",
            })
        return results
    except Exception as e:
        logger.debug("Windows kernel extended TCP table inspection failed: %s", e)
        return []


def _query_windows_kernel_udp_table() -> list[dict[str, Any]]:
    """Directly queries tcpip.sys kernel UDP socket structures via iphlpapi.GetExtendedUdpTable."""
    if not sys.platform.startswith("win"):
        return []
    try:
        import ctypes
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        GetExtendedUdpTable = iphlpapi.GetExtendedUdpTable

        # UDP_TABLE_OWNER_PID = 1, AF_INET = 2
        pdwSize = ctypes.c_ulong(0)
        res = GetExtendedUdpTable(None, ctypes.byref(pdwSize), False, 2, 1, 0)
        if res != 122 and res != 0:
            return []

        buf = ctypes.create_string_buffer(pdwSize.value)
        res = GetExtendedUdpTable(buf, ctypes.byref(pdwSize), False, 2, 1, 0)
        if res != 0:
            return []

        num_entries = struct.unpack_from("<I", buf.raw, 0)[0]
        row_size = 12  # MIB_UDPROW_OWNER_PID is 3 x DWORD = 12 bytes
        offset = 4

        results = []
        for _ in range(num_entries):
            if offset + row_size > len(buf.raw):
                break
            local_addr_int, local_port_int, pid = struct.unpack_from("<III", buf.raw, offset)
            offset += row_size
            local_port = ((local_port_int & 0xFF) << 8) | ((local_port_int >> 8) & 0xFF)
            local_ip = socket.inet_ntoa(struct.pack("<I", local_addr_int))
            results.append({
                "pid": pid,
                "protocol": "UDP",
                "local_address": local_ip,
                "local_port": local_port,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "OPEN",
                "source": "windows_kernel_tcpip",
            })
        return results
    except Exception as e:
        logger.debug("Windows kernel extended UDP table inspection failed: %s", e)
        return []


class WindowsSocketCollector(BaseSocketCollector):
    """Gathers local listening sockets and process network connections using Windows kernel APIs."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build quick PID -> Process Name cache
        pid_names: dict[int, str] = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[p.info["pid"]] = p.info["name"]
            except Exception:
                continue

        # 1. Primary: Windows kernel socket table extraction from tcpip.sys
        kernel_conns = _query_windows_kernel_tcp_table() + _query_windows_kernel_udp_table()

        if kernel_conns:
            for item in kernel_conns:
                pid = item.get("pid")
                proc_name = pid_names.get(pid) if pid else None
                proto = item["protocol"]
                local_ip = item["local_address"]
                local_port = item["local_port"]
                remote_ip = item["remote_address"]
                remote_port = item["remote_port"]
                state = item["state"]
                src_label = item.get("source", "windows_kernel_tcpip")

                if state == "LISTEN" or (proto == "UDP" and remote_ip in ("0.0.0.0", "*", "")):
                    listening_ports.append(
                        ListeningPortItem(
                            protocol=proto,
                            local_address=local_ip,
                            local_port=local_port,
                            pid=pid,
                            process_name=proc_name,
                            observed_at=now_iso,
                            source=src_label,
                        )
                    )
                elif remote_ip and remote_ip not in ("0.0.0.0", "*"):
                    dest_host = _resolve_internet_host(remote_ip)
                    web_url = _infer_website_url(remote_ip, remote_port, dest_host)
                    connections.append(
                        SocketConnectionItem(
                            pid=pid,
                            process_name=proc_name,
                            protocol=proto,
                            local_address=local_ip,
                            local_port=local_port,
                            remote_address=remote_ip,
                            remote_port=remote_port,
                            state=state,
                            destination_host=dest_host,
                            website_url=web_url,
                            observed_at=now_iso,
                            source=src_label,
                        )
                    )
        else:
            # 2. Fallback: psutil net_connections & netstat
            net_conns = []
            try:
                net_conns = psutil.net_connections(kind="inet")
            except Exception as e:
                logger.debug("psutil.net_connections failed: %s, falling back to per-process enumeration", e)
                for p in psutil.process_iter(["pid", "name"]):
                    try:
                        for c in p.net_connections(kind="inet"):
                            net_conns.append(c)
                    except Exception:
                        continue

            # If still empty on Windows, parse netstat -ano fallback
            if not net_conns and sys.platform.startswith("win"):
                try:
                    import subprocess
                    res = subprocess.run(
                        ["netstat", "-ano"],
                        capture_output=True,
                        text=True,
                        timeout=3.0,
                    )
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.strip().split()
                            if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                                proto = parts[0].upper()
                                l_str = parts[1]
                                r_str = parts[2]
                                st = parts[3] if proto == "TCP" and len(parts) >= 5 else "ESTABLISHED"
                                pid_str = parts[-1]
                                try:
                                    pid = int(pid_str)
                                except ValueError:
                                    pid = None
                                pname = pid_names.get(pid) if pid else None

                                if ":" in l_str:
                                    lip, lport_s = l_str.rsplit(":", 1)
                                    try:
                                        lport = int(lport_s)
                                    except ValueError:
                                        continue
                                else:
                                    continue

                                if st.upper() == "LISTENING":
                                    listening_ports.append(
                                        ListeningPortItem(
                                            protocol=proto,
                                            local_address=lip,
                                            local_port=lport,
                                            pid=pid,
                                            process_name=pname,
                                            observed_at=now_iso,
                                            source=self.source_label,
                                        )
                                    )
                                elif ":" in r_str and r_str != "*:*":
                                    rip, rport_s = r_str.rsplit(":", 1)
                                    try:
                                        rport = int(rport_s)
                                    except ValueError:
                                        continue
                                    dhost = _resolve_internet_host(rip)
                                    wurl = _infer_website_url(rip, rport, dhost)
                                    connections.append(
                                        SocketConnectionItem(
                                            pid=pid,
                                            process_name=pname,
                                            protocol=proto,
                                            local_address=lip,
                                            local_port=lport,
                                            remote_address=rip,
                                            remote_port=rport,
                                            state=st.upper(),
                                            destination_host=dhost,
                                            website_url=wurl,
                                            observed_at=now_iso,
                                            source=self.source_label,
                                        )
                                    )
                except Exception as ex:
                    logger.debug("netstat fallback encountered error: %s", ex)

            for conn in net_conns:
                try:
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    laddr = conn.laddr
                    raddr = conn.raddr
                    pid = conn.pid
                    proc_name = pid_names.get(pid) if pid else None

                    if not laddr:
                        continue

                    local_ip = laddr.ip
                    local_port = laddr.port

                    if conn.status == psutil.CONN_LISTEN:
                        listening_ports.append(
                            ListeningPortItem(
                                protocol=proto,
                                local_address=local_ip,
                                local_port=local_port,
                                pid=pid,
                                process_name=proc_name,
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                    elif raddr:
                        remote_ip = raddr.ip
                        remote_port = raddr.port
                        state = str(conn.status or "ESTABLISHED").upper()
                        dest_host = _resolve_internet_host(remote_ip)
                        web_url = _infer_website_url(remote_ip, remote_port, dest_host)

                        connections.append(
                            SocketConnectionItem(
                                pid=pid,
                                process_name=proc_name,
                                protocol=proto,
                                local_address=local_ip,
                                local_port=local_port,
                                remote_address=remote_ip,
                                remote_port=remote_port,
                                state=state,
                                destination_host=dest_host,
                                website_url=web_url,
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                except Exception:
                    continue

        # Sort for deterministic reporting
        listening_ports.sort(key=lambda x: (x.local_port, x.protocol))
        connections.sort(key=lambda x: (x.remote_address, x.remote_port))
        return listening_ports, connections


class WindowsBrowserCollector(BaseBrowserCollector):
    """Detects running browser executables without fabricating tabs or active URLs."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        browser_processes: list[BrowserProcessItem] = []
        running_browser_names: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                canonical = KNOWN_BROWSERS.get(name)
                if canonical:
                    running_browser_names.add(canonical)
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

        return sorted(list(running_browser_names)), browser_processes


class WindowsHardwareCollector(BaseHardwareCollector):
    """Collects CPU, memory, and network interface telemetry on Windows via psutil."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_cpu(self) -> CpuInfo:
        import platform
        now_iso = datetime.now(timezone.utc).isoformat()

        # Per-core blocking measurement with a short interval
        try:
            per_core_raw = psutil.cpu_percent(interval=0.2, percpu=True)
            overall = psutil.cpu_percent(interval=None)
        except Exception:
            per_core_raw = []
            overall = None

        per_core = [
            PerCoreUsage(core=i, usage_percent=round(pct, 1))
            for i, pct in enumerate(per_core_raw)
        ]

        try:
            freq = psutil.cpu_freq()
        except Exception:
            freq = None

        try:
            physical = psutil.cpu_count(logical=False) or 1
            logical = psutil.cpu_count(logical=True) or 1
        except Exception:
            physical = 1
            logical = 1

        model: str | None = None
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                model, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                model = model.strip()
        except Exception:
            model = platform.processor() or None

        arch = platform.machine() or None

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
                iface_stats = stats.get(iface_name)
                is_up = iface_stats.isup if iface_stats else True
                speed = iface_stats.speed if iface_stats else None

                ip_addrs: list[str] = []
                mac_addr: str | None = None
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address:
                        ip_addrs.append(addr.address)
                    elif addr.family == socket.AF_INET6 and addr.address:
                        # Strip scope id (%ifname) from IPv6
                        ip_addrs.append(addr.address.split("%")[0])
                    elif addr.family == psutil.AF_LINK and addr.address:
                        mac_addr = addr.address

                # Skip loopback and purely MAC-only interfaces with no IPs
                if iface_name.lower() in ("lo", "loopback") or (not ip_addrs and not mac_addr):
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
