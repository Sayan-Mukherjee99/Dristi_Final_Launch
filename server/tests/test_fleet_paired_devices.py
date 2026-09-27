"""Fleet-Wide Paired Devices Deep Learning & Multi-Step Forecasting Test Suite.

Verifies:
- Autonomous synchronization of all paired endpoint devices (Windows, macOS, Android, Linux)
- High-throughput batched deep learning forward passes across the fleet
- Enterprise communication graph & cross-device lateral movement detection (MITRE T1021 / CAPEC-292)
- Zero memory drift under sustained concurrent multi-device streaming
- Unified device security profile & API surface integration
"""
from __future__ import annotations

import gc
import time
import tracemalloc
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.models.endpoint import EndpointAgent
from app.models.live import NetworkDevice
from app.services.traffic.fleet_coordinator import fleet_coordinator
from app.services.traffic.fleet_graph import fleet_graph_engine
from ml.forecasting.fleet_engine import fleet_forecasting_engine
from app.services.traffic.session_manager import tracking_manager
from app.services.live import list_devices
import app.services.endpoint_telemetry as ep_telem_svc


def _seed_fleet_paired_agents(db: Session, org_id: str) -> list[EndpointAgent]:
    """Helper to seed 4 heterogeneous paired endpoint agents."""
    now = datetime.now(timezone.utc)
    specs = [
        ("agent-win-01", "dev-win-01", "192.168.1.101", "AA:BB:CC:11:22:33", "desktop-finance-win", "Windows", "11 Pro"),
        ("agent-mac-02", "dev-mac-02", "192.168.1.105", "AA:BB:CC:44:55:66", "macbook-eng-sayan", "macOS", "14.4"),
        ("agent-android-03", "dev-and-03", "192.168.1.150", "AA:BB:CC:77:88:99", "pixel-executive", "Android", "14"),
        ("agent-linux-04", "dev-lin-04", "192.168.1.200", "AA:BB:CC:AA:BB:CC", "ubuntu-prod-db", "Linux", "22.04"),
    ]

    agents: list[EndpointAgent] = []
    for ag_id, dev_id, ip, mac, hostname, os_name, os_ver in specs:
        # Create or update NetworkDevice
        net_dev = db.get(NetworkDevice, dev_id)
        if not net_dev:
            net_dev = NetworkDevice(
                id=dev_id,
                org_id=org_id,
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor="FleetDevice",
                source_agent_id=ag_id,
                online=True,
                last_seen=now,
            )
            db.add(net_dev)

        # Create EndpointAgent row
        from sqlalchemy import select
        agent = db.scalar(select(EndpointAgent).where(EndpointAgent.org_id == org_id, EndpointAgent.agent_id == ag_id))
        if not agent:
            agent = EndpointAgent(
                org_id=org_id,
                agent_id=ag_id,
                device_id=dev_id,
                hostname=hostname,
                os=os_name,
                os_version=os_ver,
                mac=mac,
                current_ip=ip,
                status="ONLINE",
                agent_token_hash="fake_hash",
                paired_at=now,
                registered_at=now,
                last_heartbeat=now,
            )
            db.add(agent)
        agents.append(agent)

    db.commit()
    return agents


def test_fleet_paired_devices_synchronization(db_session: Session, seed_acme_org) -> None:
    """Verify that fleet_coordinator discovers all paired agents and initializes isolated sessions."""
    db = db_session
    org_id = seed_acme_org.id
    agents = _seed_fleet_paired_agents(db, org_id)

    # Sync fleet devices
    sessions = fleet_coordinator.sync_paired_devices(db, org_id)
    assert len(sessions) >= 4

    session_device_ids = {s.device_id for s in sessions}
    for ag in agents:
        assert ag.device_id in session_device_ids
        active_sess = tracking_manager.get_active_session_for_device(org_id, ag.device_id)
        assert active_sess is not None
        assert active_sess.status == "LIVE"


def test_fleet_batched_neural_inference_throughput_and_latency(db_session: Session, seed_acme_org) -> None:
    """Verify high-throughput batched forward pass across all paired devices simultaneously."""
    db = db_session
    org_id = seed_acme_org.id
    _ = _seed_fleet_paired_agents(db, org_id)

    sessions = fleet_coordinator.sync_paired_devices(db, org_id)
    assert len(sessions) >= 4

    # Ingest synthetic packet flows into each device across simulated time window
    now = time.time()
    for idx, s in enumerate(sessions):
        s.window_engine.start_time = now - 30.0
        for p in range(10):
            ts = now - 20.0 + (p * 2.0)
            s.aggregator.ingest_packet(
                src_ip=s.target_ip,
                dst_ip=f"10.0.0.{p % 3}",
                src_port=50000 + p,
                dst_port=80,
                protocol=6,
                length=64,
                timestamp=ts,
            )
            s.window_engine.ingest_event(
                src_ip=s.target_ip,
                dst_ip=f"10.0.0.{p % 3}",
                src_port=50000 + p,
                dst_port=80,
                protocol=6,
                length=64,
                timestamp=ts,
            )
        s.window_engine.slide_and_compute(now)

    # Measure batched neural execution latency across all devices
    t0 = time.perf_counter()
    fleet_results = fleet_forecasting_engine.evaluate_fleet_batch(sessions)
    dur_ms = (time.perf_counter() - t0) * 1000

    assert len(fleet_results) >= 4
    for s in sessions:
        assert s.device_id in fleet_results
        res = fleet_results[s.device_id]
        assert "detection" in res
        assert "forecast" in res
        assert res["forecast"].is_available is True
        assert len(res["forecast"].horizon_steps) == 3

    # Batched forward pass must execute well under 20 ms
    assert dur_ms < 20.0, f"Batched forward pass latency ({dur_ms:.2f} ms) exceeded 20 ms threshold"


def test_cross_device_lateral_movement_detection(db_session: Session, seed_acme_org) -> None:
    """Verify that inter-paired-device communications are captured in FleetGraphEngine with pivot attribution."""
    db = db_session
    org_id = seed_acme_org.id
    _ = _seed_fleet_paired_agents(db, org_id)

    sessions = fleet_coordinator.sync_paired_devices(db, org_id)
    win_sess = next(s for s in sessions if s.target_ip == "192.168.1.101")
    linux_sess = next(s for s in sessions if s.target_ip == "192.168.1.200")

    # Simulate anomalous port sweep on win_sess, followed by lateral connection to linux_sess over SMB (445)
    for p in range(10):
        win_sess.aggregator.ingest_packet(
            src_ip="192.168.1.101",
            dst_ip=f"10.0.0.{p}",
            src_port=45000 + p,
            dst_port=80 + p,
            protocol=6,
            length=60,
            tcp_flags={"SYN": True},
        )

    # Windows workstation initiates connection to Linux DB server on port 445
    win_sess.aggregator.ingest_packet(
        src_ip="192.168.1.101",
        dst_ip="192.168.1.200",
        src_port=49152,
        dst_port=445,
        protocol=6,
        length=256,
        tcp_flags={"SYN": True, "ACK": False},
    )

    # Run fleet evaluation
    _ = fleet_forecasting_engine.evaluate_fleet_batch(sessions)
    lateral_events = fleet_graph_engine.update_from_fleet_sessions(sessions)

    # Assert pivot detection
    assert len(lateral_events) >= 1
    pivot = next(e for e in lateral_events if e["source_ip"] == "192.168.1.101" and e["destination_ip"] == "192.168.1.200")
    assert pivot["port"] == 445
    assert pivot["service"] == "SMB"
    assert pivot["mitre_technique_id"] == "T1021"
    assert pivot["capec_id"] == "CAPEC-292"


def test_fleet_memory_stability_zero_drift(db_session: Session, seed_acme_org) -> None:
    """Verify zero memory drift across concurrent multi-device streaming."""
    db = db_session
    org_id = seed_acme_org.id
    _ = _seed_fleet_paired_agents(db, org_id)
    sessions = fleet_coordinator.sync_paired_devices(db, org_id)

    tracemalloc.start()
    gc.collect()

    # Warmup under tracemalloc so steady-state buffers are tracked
    for s in sessions:
        for i in range(2500):
            s.aggregator.ingest_packet(s.target_ip, f"10.0.0.{i % 5}", 5000 + i, 80, 6, 64)
            s.window_engine.ingest_event(s.target_ip, f"10.0.0.{i % 5}", 5000 + i, 80, 6, 64)
        s.window_engine.slide_and_compute()

    gc.collect()
    mem_steady, _ = tracemalloc.get_traced_memory()

    # Ingest 20,000 packets distributed across all fleet sessions
    for i in range(5000):
        for s in sessions:
            s.aggregator.ingest_packet(s.target_ip, "10.0.0.1", 5000, 80, 6, 64)
            s.window_engine.ingest_event(s.target_ip, "10.0.0.1", 5000, 80, 6, 64)
            if i % 1000 == 0:
                s.window_engine.slide_and_compute()

    gc.collect()
    mem_end, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    drift_kb = (mem_end - mem_steady) / 1024
    assert drift_kb < 25.0, f"Memory drift across fleet too large: {drift_kb:.2f} KB"


def test_list_devices_surfaces_fleet_ai_state(db_session: Session, seed_acme_org) -> None:
    """Verify list_devices() cleanly surfaces AI detection and multi-step forecast across all paired devices."""
    db = db_session
    org_id = seed_acme_org.id
    agents = _seed_fleet_paired_agents(db, org_id)
    sessions = fleet_coordinator.sync_paired_devices(db, org_id)

    # Ingest across multiple windows and evaluate
    now = time.time()
    for s in sessions:
        s.window_engine.start_time = now - 30.0
        for p in range(6):
            ts = now - 15.0 + (p * 2.5)
            s.aggregator.ingest_packet(s.target_ip, "10.0.0.1", 5000, 80, 6, 64, timestamp=ts)
            s.window_engine.ingest_event(s.target_ip, "10.0.0.1", 5000, 80, 6, 64, timestamp=ts)
        s.window_engine.slide_and_compute(now)
    _ = fleet_forecasting_engine.evaluate_fleet_batch(sessions)

    devices = list_devices(db, org_id)
    paired_dev_ids = {a.device_id for a in agents}

    for d in devices:
        if d.id in paired_dev_ids:
            assert d.ai_tracking_active is True
            assert d.ai_tracking_session_id is not None
            assert d.ai_detection is not None
            assert d.ai_forecast is not None
            assert d.device_security_score is not None


def test_fleet_api_endpoints(client: TestClient, db_session: Session, seed_acme_org, user_headers) -> None:
    """Verify REST API fleet endpoints: /live/fleet/track-all, /status, /lateral-graph, /stop-all."""
    db = db_session
    org_id = seed_acme_org.id
    _ = _seed_fleet_paired_agents(db, org_id)

    # 1. Track all
    resp_track = client.post("/api/v1/live/fleet/track-all", headers=user_headers)
    assert resp_track.status_code == 200
    data_track = resp_track.json()
    assert data_track["active_tracking_sessions"] >= 4

    # 2. Fleet status
    resp_status = client.get("/api/v1/live/fleet/status", headers=user_headers)
    assert resp_status.status_code == 200
    data_status = resp_status.json()
    assert data_status["total_paired_agents"] >= 4

    # 3. Lateral graph
    resp_graph = client.get("/api/v1/live/fleet/lateral-graph", headers=user_headers)
    assert resp_graph.status_code == 200
    data_graph = resp_graph.json()
    assert "total_nodes" in data_graph
    assert "lateral_movement_events" in data_graph

    # 4. Stop all
    resp_stop = client.post("/api/v1/live/fleet/stop-all", headers=user_headers)
    assert resp_stop.status_code == 200
    data_stop = resp_stop.json()
    assert data_stop["stopped_sessions_count"] >= 4
