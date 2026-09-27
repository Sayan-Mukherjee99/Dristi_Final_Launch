# Drishti — Linux Endpoint Agent Telemetry Unit & Integration Tests
from __future__ import annotations

import sys
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from collectors.contracts import (
    BrowserProcessItem,
    BrowserVisibility,
    CpuInfo,
    ListeningPortItem,
    MemoryInfo,
    NetworkInterfaceInfo,
    PermissionStatusItem,
    ProcessCategory,
    ProcessEventItem,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
    StorageInfo,
    SystemInfo,
    TelemetryBatch,
)
from collectors.manager import CollectorManager
from common.identity import create_new_identity
from linux.collectors import (
    LinuxBrowserCollector,
    LinuxHardwareCollector,
    LinuxPermissionManager,
    LinuxProcessCollector,
    LinuxSecurityCollector,
    LinuxServiceCollector,
    LinuxSocketCollector,
    LinuxSoftwareCollector,
    LinuxStorageCollector,
    LinuxSystemCollector,
)
from linux.platform import LinuxPlatformAdapter


@pytest.fixture
def linux_identity():
    return create_new_identity(
        hostname="ubuntu-srv-01",
        os_name="linux",
        os_version="Ubuntu 24.04 LTS",
        mac="00:15:5d:01:23:45",
        current_ip="192.168.1.180",
        agent_version="0.1.0",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Linux Platform Adapter Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_platform_adapter_basic():
    adapter = LinuxPlatformAdapter()
    assert adapter.get_os_name() == "linux"
    hostname = adapter.get_hostname()
    assert isinstance(hostname, str) and len(hostname) > 0
    version = adapter.get_os_version()
    assert isinstance(version, str) and len(version) > 0


def test_linux_platform_adapter_os_release_mock():
    adapter = LinuxPlatformAdapter()
    mock_content = 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
    with patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.read_text", return_value=mock_content):
        ver = adapter.get_os_version()
        assert "Ubuntu" in ver


# ─────────────────────────────────────────────────────────────────────────────
# 2. Linux Process Telemetry & Classification Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_process_categorization():
    collector = LinuxProcessCollector()

    assert collector._classify_process("systemd", "/usr/lib/systemd/systemd") == ProcessCategory.SYSTEM_PROCESS.value
    assert collector._classify_process("sshd", "/usr/sbin/sshd") == ProcessCategory.SYSTEM_PROCESS.value
    assert collector._classify_process("firefox", "/usr/bin/firefox") == ProcessCategory.USER_APPLICATION.value
    assert collector._classify_process("python3", "/usr/bin/python3") == ProcessCategory.USER_APPLICATION.value
    assert collector._classify_process("kworker/0:1", None) == ProcessCategory.SYSTEM_PROCESS.value


def test_linux_suspicious_process_detection():
    collector = LinuxProcessCollector()

    is_susp, reason = collector._check_suspicious_process("miner", "/tmp/miner", 100)
    assert is_susp is True
    assert "temporary" in reason.lower()

    is_susp2, reason2 = collector._check_suspicious_process("stealth", "/dev/shm/.stealth", 100)
    assert is_susp2 is True

    is_susp3, reason3 = collector._check_suspicious_process("daemon", "/usr/bin/python3 (deleted)", 100)
    assert is_susp3 is True
    assert "deleted" in reason3.lower()

    is_clean, _ = collector._check_suspicious_process("sshd", "/usr/sbin/sshd", 1)
    assert is_clean is False


def test_linux_process_collector_lifecycle_events():
    collector = LinuxProcessCollector()
    procs, active_apps = collector.collect_processes()
    assert isinstance(procs, list)
    assert isinstance(active_apps, list)

    events = collector.get_recent_process_events()
    assert isinstance(events, list)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Linux Software Inventory Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_software_collector_dpkg():
    collector = LinuxSoftwareCollector()
    dpkg_output = "curl\t7.88.1-10\tamd64\tDebian Developers\ngit\t2.39.2-1\tamd64\tGit Team\n"
    with patch("linux.collectors._run_cmd", return_value=(0, dpkg_output, "")):
        software = collector.collect_software()
        assert len(software) == 2
        assert software[0].name == "curl"
        assert software[0].version == "7.88.1-10"
        assert software[1].name == "git"


def test_linux_software_collector_rpm():
    collector = LinuxSoftwareCollector()
    rpm_output = "kernel-core\t6.8.5-301.fc40\tFedora Project\n"
    with patch("linux.collectors._run_cmd") as mock_cmd:
        # First call dpkg fails, second call rpm succeeds
        mock_cmd.side_effect = [(-1, "", "not found"), (0, rpm_output, "")]
        software = collector.collect_software()
        assert len(software) == 1
        assert software[0].name == "kernel-core"
        assert software[0].publisher == "Fedora Project"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Linux Service Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_service_collector_systemctl():
    collector = LinuxServiceCollector()
    systemctl_output = (
        "ssh.service loaded active running OpenBSD Secure Shell server\n"
        "cron.service loaded active running Regular background program processing daemon\n"
        "ufw.service loaded inactive dead CLI to manipulate netfilter\n"
    )
    with patch("linux.collectors._run_cmd", return_value=(0, systemctl_output, "")):
        services = collector.collect_services()
        assert len(services) == 3
        assert services[0].name == "ssh"
        assert services[0].status == "RUNNING"
        assert services[2].name == "ufw"
        assert services[2].status == "STOPPED"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Linux Socket Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_socket_collector():
    collector = LinuxSocketCollector()
    ports, conns = collector.collect_sockets()
    assert isinstance(ports, list)
    assert isinstance(conns, list)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Linux Browser Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_browser_collector():
    collector = LinuxBrowserCollector()
    browsers, procs = collector.collect_browsers()
    assert isinstance(browsers, list)
    assert isinstance(procs, list)
    vis = collector.collect_browser_visibility()
    assert isinstance(vis, BrowserVisibility)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Linux Hardware Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_hardware_collector():
    collector = LinuxHardwareCollector()
    cpu = collector.collect_cpu()
    assert isinstance(cpu, CpuInfo)
    assert cpu.physical_cores is not None and cpu.physical_cores >= 1
    assert cpu.logical_cores is not None and cpu.logical_cores >= 1

    mem = collector.collect_memory()
    assert isinstance(mem, MemoryInfo)
    assert mem.total_bytes is not None and mem.total_bytes > 0

    ifaces = collector.collect_network_interfaces()
    assert isinstance(ifaces, list)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Linux Security & Permissions Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_security_collector():
    collector = LinuxSecurityCollector()
    sec = collector.collect_security()
    assert isinstance(sec, dict)
    assert "firewall_active" in sec
    assert "selinux_mode" in sec
    assert "apparmor_active" in sec


def test_linux_permissions_manager():
    mgr = LinuxPermissionManager()
    perms = mgr.collect_permissions()
    assert len(perms) >= 2
    assert perms[0].name == "Root / Superuser Access"


# ─────────────────────────────────────────────────────────────────────────────
# 9. End-to-End Integration in CollectorManager
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_collector_manager_e2e(linux_identity):
    mgr = CollectorManager(identity=linux_identity)
    assert mgr.identity.os == "linux"
    assert isinstance(mgr.process_collector, LinuxProcessCollector)
    assert isinstance(mgr.software_collector, LinuxSoftwareCollector)
    assert isinstance(mgr.service_collector, LinuxServiceCollector)
    assert isinstance(mgr.socket_collector, LinuxSocketCollector)
    assert isinstance(mgr.browser_collector, LinuxBrowserCollector)
    assert isinstance(mgr.hardware_collector, LinuxHardwareCollector)

    batch = mgr.collect_all(force_slow_collect=True)
    assert isinstance(batch, TelemetryBatch)
    assert batch.os_name == "linux"
    assert batch.hostname == "ubuntu-srv-01"
    assert batch.cpu_info is not None
    assert batch.memory_info is not None
    assert isinstance(batch.endpoint_processes, list)
    assert isinstance(batch.services, list)
    assert isinstance(batch.network_flows, list)
