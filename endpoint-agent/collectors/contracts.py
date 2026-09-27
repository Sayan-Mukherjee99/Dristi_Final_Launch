# Drishti v0.1 — Endpoint Telemetry Data Contracts | Phase 02 (rev 2 — CPU/Memory/Network)
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ProcessCategory(str, Enum):
    USER_APPLICATION = "USER_APPLICATION"
    BACKGROUND_PROCESS = "BACKGROUND_PROCESS"
    SYSTEM_PROCESS = "SYSTEM_PROCESS"


@dataclass
class ProcessItem:
    pid: int
    name: str
    ppid: int | None = None
    exe_path: str | None = None
    cmdline: list[str] | None = None
    category: str = ProcessCategory.BACKGROUND_PROCESS.value
    start_time: str | None = None
    cpu_percent: float | None = None       # NEW: per-process CPU %
    memory_mb: float | None = None        # NEW: resident set size in MB
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_collector"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["started_at"] = self.start_time
        return d


@dataclass
class SoftwareItem:
    name: str
    version: str | None = None
    publisher: str | None = None
    install_location: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_inventory"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["vendor"] = self.publisher
        return d


@dataclass
class ServiceItem:
    name: str
    display_name: str | None = None
    status: str = "UNKNOWN"  # RUNNING, STOPPED, PAUSED, etc.
    start_type: str | None = None  # AUTO, MANUAL, DISABLED, etc.
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_services"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ListeningPortItem:
    protocol: str  # TCP, UDP
    local_address: str
    local_port: int
    pid: int | None = None
    process_name: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_sockets"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["port"] = self.local_port
        d["bind_address"] = self.local_address
        return d


@dataclass
class SocketConnectionItem:
    pid: int | None
    process_name: str | None
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # ESTABLISHED, SYN_SENT, TIME_WAIT, etc.
    destination_host: str | None = None
    website_url: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_sockets"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserProcessItem:
    browser_name: str  # Chrome, Edge, Brave, Firefox, Arc
    pid: int
    exe_path: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_browser"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────
# NEW: Hardware telemetry data contracts
# ──────────────────────────────────────────────────────────────

@dataclass
class PerCoreUsage:
    """CPU usage for a single logical core."""
    core: int
    usage_percent: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CpuInfo:
    """System-wide CPU information collected by the endpoint agent."""
    model: str | None = None
    physical_cores: int | None = None
    logical_cores: int | None = None
    overall_usage_percent: float | None = None
    per_core: list[PerCoreUsage] = field(default_factory=list)
    architecture: str | None = None  # e.g. "x86_64", "arm64"
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["per_core"] = [pc.to_dict() if hasattr(pc, "to_dict") else pc for pc in self.per_core]
        return d


@dataclass
class MemoryInfo:
    """System-wide memory information collected by the endpoint agent."""
    total_bytes: int | None = None
    available_bytes: int | None = None
    used_bytes: int | None = None
    percent_used: float | None = None
    swap_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    swap_percent_used: float | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkInterfaceInfo:
    """A single network interface on the endpoint host."""
    name: str
    addresses: list[str] = field(default_factory=list)  # list of IP/CIDR strings
    mac: str | None = None
    is_up: bool = True
    speed_mbps: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────
# NEW: Extended macOS & Platform Telemetry Data Contracts
# ──────────────────────────────────────────────────────────────

@dataclass
class ProcessEventItem:
    """A process lifecycle or execution event."""
    event_type: str  # EXEC, EXIT, FORK, UNKNOWN
    pid: int
    name: str
    ppid: int | None = None
    exe_path: str | None = None
    cmdline: list[str] | None = None
    signing_status: str = "UNKNOWN"  # SIGNED_APPLE, SIGNED_DEVELOPER_ID, UNSIGNED, ADHOC, UNKNOWN
    team_id: str | None = None
    bundle_id: str | None = None
    username: str | None = None
    is_suspicious: bool = False
    suspicious_reason: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "macos_es_or_poller"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StoragePartition:
    """A mounted storage partition/volume."""
    mount_point: str
    device: str
    fstype: str
    total_bytes: int
    used_bytes: int
    available_bytes: int
    percent_used: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StorageInfo:
    """Storage metrics across local volumes."""
    total_bytes: int = 0
    used_bytes: int = 0
    available_bytes: int = 0
    percent_used: float = 0.0
    partitions: list[StoragePartition] = field(default_factory=list)
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "available_bytes": self.available_bytes,
            "percent_used": self.percent_used,
            "partitions": [p.to_dict() for p in self.partitions],
            "observed_at": self.observed_at,
        }


@dataclass
class SystemInfo:
    """Host-level operating system and hardware metadata."""
    hardware_model: str | None = None      # e.g., "MacBookPro18,1"
    architecture: str | None = None        # e.g., "arm64"
    os_name: str = "macOS"
    os_version: str = "unknown"            # e.g., "14.5"
    os_build: str | None = None            # e.g., "23F79"
    kernel_version: str | None = None      # Darwin 23.5.0
    hostname: str = "unknown"
    uptime_seconds: float | None = None
    boot_time: str | None = None
    console_user: str | None = None
    load_averages: list[float] = field(default_factory=list)
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MacSecurityPosture:
    """macOS Built-in Security Configuration and Status."""
    filevault: str = "UNKNOWN"          # ENABLED, DISABLED, UNKNOWN, PERMISSION_REQUIRED
    sip: str = "UNKNOWN"                # ENABLED, DISABLED, UNKNOWN, PERMISSION_REQUIRED
    gatekeeper: str = "UNKNOWN"         # ENABLED, DISABLED, UNKNOWN, PERMISSION_REQUIRED
    firewall: str = "UNKNOWN"           # ENABLED, DISABLED, UNKNOWN, PERMISSION_REQUIRED
    secure_boot: str = "UNKNOWN"        # ENABLED, DISABLED, UNKNOWN, NOT_APPLICABLE, PERMISSION_REQUIRED
    auto_updates: str = "UNKNOWN"       # ENABLED, DISABLED, UNKNOWN, PERMISSION_REQUIRED
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PermissionStatusItem:
    """Status of an Apple TCC or system permission."""
    name: str                           # Accessibility, Full Disk Access, Automation, Endpoint Security, Network Extension
    status: str                         # GRANTED, DENIED, NOT_REQUESTED, REQUIRES_USER_ACTION, NOT_SUPPORTED
    details: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserTabItem:
    """An active browser tab accessed through supported automation APIs."""
    browser_name: str
    window_index: int = 0
    tab_index: int = 0
    title: str | None = None
    url: str | None = None
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserVisibility:
    """SOC-relevant browser visibility."""
    detected_browsers: list[str] = field(default_factory=list)
    running_browsers: list[str] = field(default_factory=list)
    active_tabs: list[BrowserTabItem] = field(default_factory=list)
    history_status: str = "PERMISSION_REQUIRED"  # PERMISSION_REQUIRED, NOT_AVAILABLE, ACCESSIBLE, UNKNOWN
    automation_status: str = "NOT_REQUESTED"     # GRANTED, PERMISSION_REQUIRED, DENIED, NOT_REQUESTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_browsers": self.detected_browsers,
            "running_browsers": self.running_browsers,
            "active_tabs": [t.to_dict() for t in self.active_tabs],
            "history_status": self.history_status,
            "automation_status": self.automation_status,
        }


@dataclass
class TelemetryBatch:
    agent_id: str
    device_id: str
    hostname: str
    os_name: str
    os_version: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    endpoint_processes: list[ProcessItem] = field(default_factory=list)
    active_apps: list[str] = field(default_factory=list)
    installed_software: list[SoftwareItem] = field(default_factory=list)
    services: list[ServiceItem] = field(default_factory=list)
    listening_ports: list[ListeningPortItem] = field(default_factory=list)
    process_connections: list[SocketConnectionItem] = field(default_factory=list)
    installed_browsers: list[str] = field(default_factory=list)
    browser_processes: list[BrowserProcessItem] = field(default_factory=list)
    os_info: str | None = None
    # Hardware telemetry fields
    cpu_info: CpuInfo | None = None
    memory_info: MemoryInfo | None = None
    network_interfaces: list[NetworkInterfaceInfo] = field(default_factory=list)
    # NEW macOS & Platform Telemetry fields
    storage_info: StorageInfo | None = None
    system_info: SystemInfo | None = None
    security_posture: MacSecurityPosture | None = None
    permissions: list[PermissionStatusItem] = field(default_factory=list)
    process_events: list[ProcessEventItem] = field(default_factory=list)
    browser_visibility: BrowserVisibility | None = None
    macos_telemetry: dict[str, Any] | None = None
    network_flows: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        # Formulate structured macOS telemetry block
        macos_block = self.macos_telemetry or {
            "system": self.system_info.to_dict() if self.system_info else None,
            "cpu": self.cpu_info.to_dict() if self.cpu_info else None,
            "memory": self.memory_info.to_dict() if self.memory_info else None,
            "storage": self.storage_info.to_dict() if self.storage_info else None,
            "network": {
                "interfaces": [ni.to_dict() for ni in self.network_interfaces]
            } if self.network_interfaces else None,
            "processes": [p.to_dict() for p in self.endpoint_processes],
            "process_events": [pe.to_dict() for pe in self.process_events],
            "applications": [s.to_dict() for s in self.installed_software],
            "browsers": self.browser_visibility.to_dict() if self.browser_visibility else {
                "detected": self.installed_browsers,
                "running": [bp.to_dict() for bp in self.browser_processes],
            },
            "security": self.security_posture.to_dict() if self.security_posture else None,
            "permissions": [p.to_dict() for p in self.permissions],
            "agent": {
                "agent_id": self.agent_id,
                "device_id": self.device_id,
                "hostname": self.hostname,
                "os_name": self.os_name,
                "os_version": self.os_version,
                "timestamp": self.timestamp,
            },
        }

        return {
            "agent_id": self.agent_id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "timestamp": self.timestamp,
            "endpoint_processes": [p.to_dict() for p in self.endpoint_processes],
            "active_apps": self.active_apps,
            "installed_software": [s.to_dict() for s in self.installed_software],
            "services": [s.to_dict() for s in self.services],
            "listening_ports": [lp.to_dict() for lp in self.listening_ports],
            "process_connections": [pc.to_dict() for pc in self.process_connections],
            "installed_browsers": self.installed_browsers,
            "browser_processes": [bp.to_dict() for bp in self.browser_processes],
            "os_info": self.os_info,
            "cpu_info": self.cpu_info.to_dict() if self.cpu_info else None,
            "memory_info": self.memory_info.to_dict() if self.memory_info else None,
            "network_info": {
                "interfaces": [ni.to_dict() for ni in self.network_interfaces]
            } if self.network_interfaces else None,
            # Extended / macOS additive fields
            "system_info": self.system_info.to_dict() if self.system_info else None,
            "storage_info": self.storage_info.to_dict() if self.storage_info else None,
            "device_info": self.system_info.to_dict() if self.system_info else None,
            "uptime_info": {
                "uptime_seconds": self.system_info.uptime_seconds if self.system_info else None,
                "boot_time": self.system_info.boot_time if self.system_info else None,
            } if self.system_info else None,
            "security_posture": self.security_posture.to_dict() if self.security_posture else None,
            "capability_status": [p.to_dict() for p in self.permissions],
            "browser_visibility": self.browser_visibility.to_dict() if self.browser_visibility else None,
            "process_events": [pe.to_dict() for pe in self.process_events],
            "macos_telemetry": macos_block,
            "network_flows": self.network_flows,
        }

    @property
    def capability_status(self) -> list[PermissionStatusItem]:
        return self.permissions

    def to_payload(self) -> dict[str, Any]:
        return self.to_dict()


