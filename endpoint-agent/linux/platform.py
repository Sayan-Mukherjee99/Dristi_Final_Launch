# Drishti v0.1 — Linux Platform Adapter | Phase 01 & Multi-Platform Support
from __future__ import annotations

import os
import platform
import socket
import uuid
from pathlib import Path

from common.platform import BasePlatformAdapter


class LinuxPlatformAdapter(BasePlatformAdapter):
    """Genuine Linux hardware, machine identity, and OS metadata collector."""

    def get_hostname(self) -> str:
        try:
            h = socket.gethostname()
            if h:
                return h
        except Exception:
            pass

        try:
            p = Path("/etc/hostname")
            if p.exists():
                text = p.read_text(encoding="utf-8").strip()
                if text:
                    return text
        except Exception:
            pass

        return "linux-host"

    def get_os_name(self) -> str:
        return "linux"

    def get_os_version(self) -> str:
        # 1. Standard Python 3.10+ freedesktop os-release
        try:
            if hasattr(platform, "freedesktop_os_release"):
                info = platform.freedesktop_os_release()
                if "PRETTY_NAME" in info and info["PRETTY_NAME"]:
                    return info["PRETTY_NAME"]
                if "NAME" in info:
                    ver = info.get("VERSION_ID", info.get("VERSION", ""))
                    return f"{info['NAME']} {ver}".strip()
        except Exception:
            pass

        # 2. Parse /etc/os-release or /usr/lib/os-release manually
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                p = Path(path)
                if p.exists():
                    lines = p.read_text(encoding="utf-8").splitlines()
                    props = {}
                    for line in lines:
                        if "=" in line and not line.startswith("#"):
                            k, v = line.split("=", 1)
                            props[k.strip()] = v.strip().strip('"').strip("'")
                    if "PRETTY_NAME" in props:
                        return props["PRETTY_NAME"]
                    if "NAME" in props:
                        ver = props.get("VERSION_ID", props.get("VERSION", ""))
                        return f"{props['NAME']} {ver}".strip()
            except Exception:
                pass

        # 3. Legacy RedHat / Debian files
        try:
            p_rh = Path("/etc/redhat-release")
            if p_rh.exists():
                return p_rh.read_text(encoding="utf-8").strip()
            p_deb = Path("/etc/debian_version")
            if p_deb.exists():
                return f"Debian {p_deb.read_text(encoding='utf-8').strip()}"
        except Exception:
            pass

        # 4. Kernel release fallback
        try:
            return f"Linux {platform.release()} ({platform.machine()})"
        except Exception:
            return "Linux Unknown"

    def get_mac_address(self) -> str | None:
        # 1. Read from sysfs /sys/class/net/*/address
        try:
            net_path = Path("/sys/class/net")
            if net_path.exists() and net_path.is_dir():
                for iface_dir in sorted(net_path.iterdir()):
                    iface_name = iface_dir.name
                    # Skip loopback, virtual, and docker bridges
                    if iface_name in ("lo", "docker0") or iface_name.startswith(("veth", "virbr", "br-")):
                        continue
                    addr_file = iface_dir / "address"
                    if addr_file.exists():
                        mac = addr_file.read_text(encoding="utf-8").strip().lower()
                        if mac and mac != "00:00:00:00:00:00" and len(mac) == 17:
                            return mac
        except Exception:
            pass

        # 2. uuid.getnode() fallback
        try:
            node = uuid.getnode()
            if not ((node >> 40) & 1):  # not multicast / randomized
                mac_hex = f"{node:012x}"
                return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))
        except Exception:
            pass

        return None

    def get_current_ip(self) -> str | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return None
        finally:
            s.close()

    def get_machine_id(self) -> str | None:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                path = Path(p)
                if path.exists():
                    mid = path.read_text(encoding="utf-8").strip()
                    if mid:
                        return mid
            except Exception:
                pass
        return None
