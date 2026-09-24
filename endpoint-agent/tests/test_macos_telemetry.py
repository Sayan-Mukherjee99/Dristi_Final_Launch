# Drishti — macOS Endpoint Agent Telemetry Unit & Integration Tests
from __future__ import annotations

import sys
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from collectors.contracts import (
    BrowserTabItem,
    BrowserVisibility,
    MacSecurityPosture,
    PermissionStatusItem,
    ProcessCategory,
    ProcessEventItem,
    StorageInfo,
    SystemInfo,
    TelemetryBatch,
)
from collectors.manager import CollectorManager
from common.identity import create_new_identity
from macos.collectors import (
    MacOSEndpointSecurityCollector,
    MacOSBrowserCollector,
    MacOSHardwareCollector,
    MacOSPermissionManager,
    MacOSProcessCollector,
    MacOSSecurityCollector,
    MacOSServiceCollector,
    MacOSSocketCollector,
    MacOSSoftwareCollector,
    MacOSStorageCollector,
    MacOSSystemCollector,
)


@pytest.fixture
def mac_identity():
    return create_new_identity(
        hostname="macbook-pro.local",
        os_name="darwin",
        os_version="15.0",
        mac="00:33:bb:44:cc:66",
        current_ip="192.168.1.120",
        agent_version="0.1.0",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Process Telemetry & Lifecycle Ring Buffer Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_process_categorization():
    collector = MacOSProcessCollector()

    # User Application in /Applications
    assert collector._classify_process("Safari", "/Applications/Safari.app/Contents/MacOS/Safari") == ProcessCategory.USER_APPLICATION.value
    assert collector._classify_process("Visual Studio Code", "/Applications/Visual Studio Code.app/Contents/MacOS/Electron") == ProcessCategory.USER_APPLICATION.value

    # System Process in /System or /usr
    assert collector._classify_process("launchd", "/sbin/launchd") == ProcessCategory.SYSTEM_PROCESS.value
    assert collector._classify_process("WindowServer", "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer") == ProcessCategory.SYSTEM_PROCESS.value

    # Background Service
    assert collector._classify_process("drishti_daemon", "/Library/Application Support/Drishti/daemon") == ProcessCategory.BACKGROUND_PROCESS.value


def test_macos_suspicious_process_detection():
    collector = MacOSProcessCollector()

    # Suspicious execution from /tmp or /var/tmp
    is_susp, reason = collector._check_suspicious_process(
        name="miner",
        exe_path="/tmp/miner",
        ppid=1,
    )
    assert is_susp is True
    assert "temporary directory" in reason

    # Masquerading system process from non-system path
    is_susp2, reason2 = collector._check_suspicious_process(
        name="launchd",
        exe_path="/Users/tester/Downloads/launchd",
        ppid=500,
    )
    assert is_susp2 is True
    assert "Masquerading system process" in reason2

    # Benign system process
    is_susp3, reason3 = collector._check_suspicious_process(
        name="launchd",
        exe_path="/sbin/launchd",
        ppid=1,
    )
    assert is_susp3 is False
    assert reason3 is None


def test_macos_process_lifecycle_ring_buffer():
    collector = MacOSProcessCollector()

    # Initially ring buffer is empty
    assert len(collector._event_buffer) == 0

    # Simulate process collection: inject events directly or via collect_processes
    collector._event_buffer.append(
        ProcessEventItem(
            event_type="EXEC",
            pid=1001,
            name="Calculator",
            timestamp="2026-09-22T10:00:00Z",
        )
    )
    collector._event_buffer.append(
        ProcessEventItem(
            event_type="EXIT",
            pid=1002,
            name="OldTool",
            timestamp="2026-09-22T10:01:00Z",
        )
    )

    events = collector.get_recent_process_events()
    assert len(events) == 2
    assert events[0].event_type == "EXEC"
    assert events[1].event_type == "EXIT"

    # Ensure buffer length never exceeds 250
    for i in range(300):
        collector._event_buffer.append(
            ProcessEventItem(
                event_type="EXEC",
                pid=2000 + i,
                name=f"proc_{i}",
                timestamp="2026-09-22T10:02:00Z",
            )
        )
    assert len(collector._event_buffer) == 250
    assert len(collector.get_recent_process_events()) == 250


# ─────────────────────────────────────────────────────────────────────────────
# 2. Endpoint Security Entitlement & Status Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_endpoint_security_entitlement_check():
    collector = MacOSEndpointSecurityCollector()
    has_entitlement, reason = collector.check_entitlement()

    assert isinstance(has_entitlement, bool)
    assert isinstance(reason, str)
    # When running as non-root without developer entitlement, must cleanly fail
    status = collector.collect_status()
    assert "framework" in status
    assert "status" in status
    assert status["status"] in ["ACTIVE", "PERMISSION_REQUIRED"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Native System Collector & sysctl Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_system_collector_parsing():
    collector = MacOSSystemCollector()
    info = collector.collect_system()

    assert isinstance(info, SystemInfo)
    assert info.os_name == "macOS"
    assert info.architecture is not None
    assert isinstance(info.load_averages, list)
    if info.uptime_seconds is not None:
        assert info.uptime_seconds >= 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Multi-Mount Storage Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_storage_collector():
    collector = MacOSStorageCollector()
    storage = collector.collect_storage()

    assert isinstance(storage, StorageInfo)
    assert storage.total_bytes > 0
    assert storage.used_bytes > 0
    assert storage.available_bytes > 0
    assert len(storage.partitions) >= 1
    # Check root mount "/"
    root_mount = next((p for p in storage.partitions if p.mount_point == "/"), None)
    assert root_mount is not None
    assert root_mount.total_bytes > 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Native Security Posture Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_security_collector_posture():
    collector = MacOSSecurityCollector()
    posture = collector.collect_security()

    assert isinstance(posture, MacSecurityPosture)
    # Posture values must be standard strings, not empty
    assert posture.filevault in ["ENABLED", "DISABLED", "PERMISSION_REQUIRED", "UNKNOWN"]
    assert posture.sip in ["ENABLED", "DISABLED", "UNKNOWN"]
    assert posture.gatekeeper in ["ENABLED", "DISABLED", "UNKNOWN"]
    assert posture.firewall in ["ENABLED", "DISABLED", "UNKNOWN"]
    assert posture.auto_updates in ["ENABLED", "DISABLED", "UNKNOWN"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. TCC Permission Manager Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_permission_manager_audit():
    mgr = MacOSPermissionManager()
    perms = mgr.collect_permissions()

    assert isinstance(perms, list)
    assert len(perms) >= 4

    perm_names = [p.name for p in perms]
    assert "Accessibility" in perm_names
    assert "Full Disk Access" in perm_names
    assert "Automation" in perm_names
    assert "Endpoint Security Entitlement" in perm_names

    for p in perms:
        assert isinstance(p, PermissionStatusItem)
        assert p.status in ["GRANTED", "PERMISSION_REQUIRED", "REQUIRES_USER_ACTION", "NOT_REQUESTED"]
        assert len(p.remediation) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Browser Visibility Collector Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_browser_visibility_defensive():
    collector = MacOSBrowserCollector()
    vis = collector.collect_browser_visibility()

    assert isinstance(vis, BrowserVisibility)
    assert isinstance(vis.detected_browsers, list)
    assert isinstance(vis.running_browsers, list)
    assert isinstance(vis.active_tabs, list)
    assert vis.history_status == "PERMISSION_REQUIRED"
    # Zero fabrication check: tabs must only be populated if genuine AppleScript succeeds
    for tab in vis.active_tabs:
        assert isinstance(tab, BrowserTabItem)
        assert tab.browser_name != ""


# ─────────────────────────────────────────────────────────────────────────────
# 8. Full Collector Manager Integration & TelemetryBatch Serialization Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_macos_collector_manager_full_pipeline(mac_identity):
    mgr = CollectorManager(
        identity=mac_identity,
        process_collector=MacOSProcessCollector(),
        software_collector=MacOSSoftwareCollector(),
        service_collector=MacOSServiceCollector(),
        socket_collector=MacOSSocketCollector(),
        browser_collector=MacOSBrowserCollector(),
        system_collector=MacOSSystemCollector(),
        storage_collector=MacOSStorageCollector(),
        security_collector=MacOSSecurityCollector(),
        permission_manager=MacOSPermissionManager(),
        hardware_collector=MacOSHardwareCollector(),
    )

    batch = mgr.collect_all(force_slow_collect=True)

    assert isinstance(batch, TelemetryBatch)
    assert batch.system_info is not None
    assert batch.storage_info is not None
    assert batch.security_posture is not None
    assert isinstance(batch.capability_status, list)
    assert isinstance(batch.process_events, list)
    assert batch.browser_visibility is not None

    payload = batch.to_payload()
    assert "system_info" in payload
    assert "storage_info" in payload
    assert "security_posture" in payload
    assert "capability_status" in payload
    assert "process_events" in payload
    assert "browser_visibility" in payload
    assert payload["system_info"]["os_name"] == "macOS"
