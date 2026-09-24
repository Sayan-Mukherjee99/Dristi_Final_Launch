from datetime import datetime, timezone
import pytest

from app.models.endpoint import EndpointAgent
from app.models.live import NetworkDevice
from app.schemas.endpoint import EndpointTelemetrySubmitRequest, SocketConnectionTelemetryItem
import app.services.endpoint_telemetry as ep_telem_svc
from app.services.traffic.capture_adapter import TrafficVisibilityChecker
from app.services.traffic.session_manager import tracking_manager


def test_paired_endpoint_traffic_session_lifecycle(db_session, seed_acme_org):
    """Verify live traffic scanning for a paired target PC ingests socket telemetry and flows."""
    db = db_session
    org_id = seed_acme_org.id
    now = datetime.now(timezone.utc)

    # 1. Register a paired Windows target PC
    agent = EndpointAgent(
        org_id=org_id,
        agent_id="agent-win-pc-test-1",
        device_id="dev-win-pc-test-1",
        hostname="DESKTOP-TARGET-PC",
        os="Windows",
        os_version="11.0.22631",
        mac="00:15:5d:2a:bc:99",
        current_ip="192.168.1.17",
        agent_version="0.1.0",
        status="ONLINE",
        agent_token_hash="dummy-hash",
        paired_at=now,
        registered_at=now,
        last_heartbeat=now,
    )
    db.add(agent)
    db.commit()

    # 2. Ingest telemetry from target PC with active process socket connections and flows
    telem_payload = EndpointTelemetrySubmitRequest(
        agent_id="agent-win-pc-test-1",
        device_id="dev-win-pc-test-1",
        timestamp=now,
        hostname="DESKTOP-TARGET-PC",
        os_name="Windows",
        process_connections=[
            SocketConnectionTelemetryItem(
                pid=1234,
                process_name="chrome.exe",
                protocol="TCP",
                local_address="192.168.1.17",
                local_port=54321,
                remote_address="142.250.190.46",
                remote_port=443,
                state="ESTABLISHED",
                observed_at=now.isoformat(),
                source="windows_endpoint",
            ),
            SocketConnectionTelemetryItem(
                pid=5678,
                process_name="svchost.exe",
                protocol="UDP",
                local_address="192.168.1.17",
                local_port=5353,
                remote_address="192.168.1.1",
                remote_port=53,
                state="ESTABLISHED",
                observed_at=now.isoformat(),
                source="windows_endpoint",
            ),
        ],
        network_flows=[
            {
                "id": "flow-1",
                "src_ip": "192.168.1.17",
                "dst_ip": "1.1.1.1",
                "src_port": 50123,
                "dst_port": 443,
                "protocol": "TCP",
                "packets": 15,
                "bytes": 1024,
                "state": "ESTABLISHED",
                "destination_ip": "1.1.1.1",
                "destination_port": 443,
                "process_name": "chrome.exe",
            }
        ],
    )
    ep_telem_svc.record_telemetry(
        org_id=org_id,
        agent_id="agent-win-pc-test-1",
        device_id="dev-win-pc-test-1",
        payload=telem_payload,
    )

    # 3. User initiates "Start live traffic scan" on target PC (192.168.1.17)
    session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-win-pc-test-1",
        ip="192.168.1.17",
        hostname="DESKTOP-TARGET-PC",
    )

    assert session.status == "LIVE"
    assert "ENDPOINT AGENT (WINDOWS)" in session.capture_source

    active = tracking_manager._active_sessions[session.tracking_session_id]
    assert active.has_endpoint_agent is True

    # 4. Fetch live results
    results = tracking_manager.get_results(db=db, org_id=org_id, session_id=session.tracking_session_id)

    # Verify packets, flows, and volume are received and non-zero
    assert results.metrics.packet_count > 0
    assert results.metrics.flow_count > 0
    assert results.metrics.byte_count > 0
    assert results.network_visibility == "VISIBLE"
    assert "Endpoint Agent telemetry" in results.visibility_reason

    # Verify protocol breakdown
    assert results.protocols.tcp > 0 or results.protocols.http_https > 0
    assert len(results.top_destinations) >= 1

    # Verify evidence records attribute the capture source correctly
    assert any("ENDPOINT AGENT" in ev.source for ev in results.evidence)

    # Clean up
    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=session.tracking_session_id)


def test_dynamic_telemetry_push_while_session_active(db_session, seed_acme_org):
    """Verify that when a session is active and the agent uploads fresh sockets, they stream into the session immediately."""
    db = db_session
    org_id = seed_acme_org.id
    now = datetime.now(timezone.utc)

    # 1. Register agent
    agent = EndpointAgent(
        org_id=org_id,
        agent_id="agent-win-pc-test-2",
        device_id="dev-win-pc-test-2",
        hostname="DESKTOP-DYNAMIC",
        os="Windows",
        os_version="11.0",
        mac="00:15:5d:2a:bc:aa",
        current_ip="192.168.1.18",
        status="ONLINE",
        agent_token_hash="dummy-hash-2",
        paired_at=now,
        registered_at=now,
        last_heartbeat=now,
    )
    db.add(agent)
    db.commit()

    # 2. Start tracking session before telemetry arrives
    session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-win-pc-test-2",
        ip="192.168.1.18",
        hostname="DESKTOP-DYNAMIC",
    )
    assert session.status == "LIVE"

    # Initial state before telemetry:
    active = tracking_manager._active_sessions[session.tracking_session_id]
    init_pkts = active.aggregator.total_packets

    # 3. Agent sends new telemetry
    telem_payload = EndpointTelemetrySubmitRequest(
        agent_id="agent-win-pc-test-2",
        device_id="dev-win-pc-test-2",
        timestamp=now,
        process_connections=[
            SocketConnectionTelemetryItem(
                pid=999,
                process_name="edge.exe",
                protocol="TCP",
                local_address="192.168.1.18",
                local_port=59000,
                remote_address="8.8.8.8",
                remote_port=443,
                state="ESTABLISHED",
                observed_at=now.isoformat(),
                source="windows_endpoint",
            )
        ],
    )
    ep_telem_svc.record_telemetry(
        org_id=org_id,
        agent_id="agent-win-pc-test-2",
        device_id="dev-win-pc-test-2",
        payload=telem_payload,
    )

    # Packets immediately increased in active session via push bridge!
    assert active.aggregator.total_packets > init_pkts

    res = tracking_manager.get_results(db=db, org_id=org_id, session_id=session.tracking_session_id)
    assert res.metrics.packet_count > 0
    assert any(d.destination_ip == "8.8.8.8" for d in res.top_destinations)

    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=session.tracking_session_id)


def test_windows_endpoint_telemetry_schema_resilience():
    """Verify raw Windows agent payloads with missing/null attributes validate cleanly."""
    raw_payload = {
        "agent_id": "win-agent-123",
        "device_id": "win-dev-123",
        "hostname": "LAPTOP-BTE1GJID",
        "os_name": "Windows",
        "os_version": "10.0.22631",
        "timestamp": "2026-09-22T14:00:00Z",
        "endpoint_processes": [
            {
                "pid": 4,
                "name": "System",
                "category": "SYSTEM_PROCESS",
                "start_time": "2026-09-22T08:00:00Z",
                "cpu_percent": 0.5,
                "memory_mb": 12.0,
            }
        ],
        "installed_software": [
            {
                "name": "Git",
                "version": "2.44.0",
                "publisher": "The Git Development Community",
            }
        ],
        "services": [
            {
                "name": "AppReadiness",
                "display_name": None,
                "status": "STOPPED",
                "start_type": None,
            }
        ],
        "listening_ports": [
            {
                "protocol": "TCP",
                "local_address": "0.0.0.0",
                "local_port": 135,
                "pid": 880,
                "process_name": "svchost.exe",
            }
        ],
        "process_connections": [
            {
                "pid": None,
                "process_name": None,
                "protocol": "TCP",
                "local_address": "192.168.1.17",
                "local_port": 54321,
                "remote_address": "142.250.190.46",
                "remote_port": 443,
                "state": "ESTABLISHED",
            }
        ],
    }

    req = EndpointTelemetrySubmitRequest(**raw_payload)
    assert req.agent_id == "win-agent-123"
    assert req.endpoint_processes[0].started_at == "2026-09-22T08:00:00Z"
    assert req.installed_software[0].vendor == "The Git Development Community"
    assert req.services[0].display_name is None
    assert req.listening_ports[0].port == 135
    assert req.process_connections[0].pid is None

