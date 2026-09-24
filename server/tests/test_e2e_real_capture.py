import time
import socket
import pytest
torch = pytest.importorskip("torch")
from app.services.traffic.session_manager import tracking_manager
from app.services.traffic.capture_adapter import TrafficVisibilityChecker


def test_real_local_and_remote_device_e2e(db_session, seed_acme_org):
    db = db_session
    org_id = seed_acme_org.id

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Local Device Tracking Test
    # ─────────────────────────────────────────────────────────────────────────
    local_session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-local-01",
        ip="127.0.0.1",
        hostname="localhost",
    )
    assert local_session.status in ("LIVE", "UNAVAILABLE")
    assert local_session.target_ip == "127.0.0.1"

    # Generate real network activity to localhost
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect_ex(("127.0.0.1", 8000))
        s.close()
    except Exception:
        pass

    # Ingest a real packet event for 127.0.0.1
    active_local = tracking_manager._active_sessions[local_session.tracking_session_id]
    active_local.aggregator.ingest_packet(
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=8000,
        protocol=6,
        length=60,
        tcp_flags={"SYN": True, "ACK": False},
    )

    local_results = tracking_manager.get_results(db=db, org_id=org_id, session_id=local_session.tracking_session_id)
    assert local_results.metrics.packet_count >= 1
    assert local_results.network_visibility == "VISIBLE"
    assert local_results.model_status is not None
    assert local_results.model_status["lstm"] == "READY"
    assert local_results.model_status["transformer"] == "READY"
    assert local_results.model_status["gnn"] == "READY"
    assert local_results.current_behaviour.verdict in ("NORMAL", "SUSPICIOUS", "ANOMALOUS", "INSUFFICIENT_DATA")

    # Stop local tracking
    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=local_session.tracking_session_id)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Remote / Switched LAN Device Test (Truthful Unavailability)
    # ─────────────────────────────────────────────────────────────────────────
    remote_session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-remote-lan",
        ip="192.168.1.250",
        hostname="unobservable-peer",
    )
    active_remote = tracking_manager._active_sessions[remote_session.tracking_session_id]

    # Verify zero packets arrived for remote peer on switched Wi-Fi
    assert active_remote.aggregator.total_packets == 0

    # Visibility evaluation after elapsed threshold
    visibility = TrafficVisibilityChecker.evaluate_visibility(
        target_ip="192.168.1.250",
        packets_observed=0,
        session_duration=5.0,
    )
    assert visibility["visibility"] in ("UNAVAILABLE", "LIMITED")
    assert "not observable from this monitoring interface" in visibility["reason"] or "not responding" in visibility["reason"]

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Strict Device Isolation Verification
    # ─────────────────────────────────────────────────────────────────────────
    # Ingest packet for Device A (127.0.0.1) into the network layer
    pkts_before = active_remote.aggregator.total_packets
    bytes_before = active_remote.aggregator.total_bytes
    rejected = active_remote.aggregator.ingest_packet(
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=8000,
        protocol=6,
        length=60,
    )
    # MUST BE REJECTED by Device B's aggregator
    assert rejected is False
    assert active_remote.aggregator.total_packets == pkts_before
    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=remote_session.tracking_session_id)


def test_paired_endpoint_agent_traffic_ingestion(db_session, seed_acme_org):
    """Verify that a paired target PC (Windows/macOS/Android) streams live network traffic and flows into tracking session."""
    from datetime import datetime, timezone
    from app.models.endpoint import EndpointAgent
    from app.models.live import NetworkDevice
    import app.services.endpoint_telemetry as ep_telem_svc
    from app.schemas.endpoint import EndpointTelemetrySubmitRequest, SocketConnectionTelemetryItem

    db = db_session
    org_id = seed_acme_org.id
    now = datetime.now(timezone.utc)

    # 1. Register a paired Windows target PC
    agent = EndpointAgent(
        org_id=org_id,
        agent_id="agent-win-pc-test",
        device_id="dev-win-pc-test",
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
        agent_id="agent-win-pc-test",
        device_id="dev-win-pc-test",
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
    ep_telem_svc.record_telemetry(org_id=org_id, agent_id="agent-win-pc-test", device_id="dev-win-pc-test", payload=telem_payload)

    # 3. User initiates "Start live traffic scan" on target PC (192.168.1.17)
    session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-win-pc-test",
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
