# Drishti v0.1 — per-device tracking session manager | Phase 01
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models.base import utcnow
from app.models.tracking import LiveTrackingSession
from app.schemas.tracking import (
    CurrentBehaviourOut,
    FlaggedPacketOut,
    ForecastResultOut,
    LiveTrafficMetrics,
    ProtocolBreakdown,
    TopDestinationItem,
    TrackingResultsOut,
    TrackingSessionOut,
    TrafficEvidenceItem,
)
from app.services.traffic.capture_adapter import ScapyCaptureAdapter, TrafficVisibilityChecker
from app.services.traffic.detection_engine import TrafficDetectionEngine
from app.services.traffic.feature_extractor import extract_session_features
from app.services.traffic.flow_aggregator import FlowAggregator
from app.services.traffic.graph_engine import NetworkGraphEngine
from app.services.traffic.time_window import TimeWindowEngine
from ml.forecasting.engine import forecasting_engine
from ml.inference.engine import inference_engine

logger = logging.getLogger("drishti")

# Global URL Threat Cache: maps URL -> (monotonic_timestamp, UrlAnalysisResult)
_GLOBAL_URL_THREAT_CACHE: dict[str, tuple[float, Any]] = {}


class ActiveTrackingSession:
    """In-memory active tracking instance strictly bound to one target device and session."""

    def __init__(
        self,
        session_id: str,
        org_id: str,
        device_id: str,
        target_ip: str,
        target_mac: str | None = None,
        target_hostname: str | None = None,
        capture_source: str = "SCAPY / MONITORED INTERFACE",
        has_endpoint_agent: bool = False,
        agent_id: str | None = None,
        endpoint_device_id: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.org_id = org_id
        self.device_id = device_id
        self.target_ip = target_ip.strip()
        self.target_mac = target_mac
        self.target_hostname = target_hostname
        self.started_at = datetime.now(timezone.utc)
        self.ended_at: datetime | None = None
        self.status = "LIVE"
        self.capture_source = capture_source
        self.has_endpoint_agent = has_endpoint_agent
        self.agent_id = agent_id
        self.endpoint_device_id = endpoint_device_id
        self.status_message: str | None = None
        self.previous_features: dict[str, float] | None = None

        # Phase 04: cache latest detection + forecast so list_devices() can read
        # them without triggering a new inference pass. These are set inside
        # get_results() and are always CURRENT DETECTION / FORECAST labels —
        # never confirmed attack status.
        self.last_detection: CurrentBehaviourOut | None = None
        self.last_forecast: ForecastResultOut | None = None

        self.aggregator = FlowAggregator(target_ip=self.target_ip, device_id=device_id, session_id=session_id)
        self.window_engine = TimeWindowEngine(target_device_id=device_id, target_ip=self.target_ip)
        self.graph_engine = NetworkGraphEngine(target_ip=self.target_ip)
        self.detection_engine = TrafficDetectionEngine()

        def _on_packet_ingest(**kwargs):
            accepted = self.aggregator.ingest_packet(**kwargs)
            if accepted:
                self.window_engine.ingest_event(
                    src_ip=kwargs.get("src_ip", ""),
                    dst_ip=kwargs.get("dst_ip", ""),
                    src_port=kwargs.get("src_port", 0),
                    dst_port=kwargs.get("dst_port", 0),
                    protocol=kwargs.get("protocol", 6),
                    length=kwargs.get("length", 0),
                    tcp_flags=kwargs.get("tcp_flags"),
                    timestamp=kwargs.get("timestamp"),
                )

        self.capture_adapter = ScapyCaptureAdapter(
            target_ip=self.target_ip,
            on_packet=_on_packet_ingest,
        )

    def ingest_telemetry(
        self,
        process_connections: list[Any] | None = None,
        network_flows: list[Any] | None = None,
        listening_ports: list[Any] | None = None,
    ) -> int:
        """Ingest endpoint socket connections and network flows into aggregator and time window engine."""
        ingested = 0
        now = time.time()

        if process_connections:
            for conn in process_connections:
                if isinstance(conn, dict):
                    laddr = conn.get("local_address") or self.target_ip
                    raddr = conn.get("remote_address")
                    lport = conn.get("local_port") or 0
                    rport = conn.get("remote_port") or 0
                    proto = conn.get("protocol") or "TCP"
                    state = conn.get("state") or "ESTABLISHED"
                else:
                    laddr = getattr(conn, "local_address", None) or self.target_ip
                    raddr = getattr(conn, "remote_address", None)
                    lport = getattr(conn, "local_port", 0) or 0
                    rport = getattr(conn, "remote_port", 0) or 0
                    proto = getattr(conn, "protocol", "TCP") or "TCP"
                    state = getattr(conn, "state", "ESTABLISHED") or "ESTABLISHED"

                # Filter out empty or listening local-only without remote
                if not raddr or raddr in ("0.0.0.0", "::", "127.0.0.1", "localhost") and laddr in ("0.0.0.0", "::", "127.0.0.1"):
                    continue

                proto_num = 6 if str(proto).upper() == "TCP" else (17 if str(proto).upper() == "UDP" else 6)
                is_estab = "ESTAB" in str(state).upper()
                tcp_flags = {
                    "ESTABLISHED": is_estab,
                    "SYN": "SYN" in str(state).upper(),
                    "ACK": is_estab,
                    "FIN": "FIN" in str(state).upper() or "CLOSE" in str(state).upper(),
                    "RST": "RESET" in str(state).upper(),
                    "PSH": is_estab,
                    "URG": False,
                }

                # Forward packet: target -> remote
                acc = self.aggregator.ingest_packet(
                    src_ip=self.target_ip,
                    dst_ip=str(raddr).strip(),
                    src_port=int(lport),
                    dst_port=int(rport),
                    protocol=proto_num,
                    length=64,
                    tcp_flags=tcp_flags,
                    timestamp=now,
                )
                if acc:
                    self.window_engine.ingest_event(
                        src_ip=self.target_ip,
                        dst_ip=str(raddr).strip(),
                        src_port=int(lport),
                        dst_port=int(rport),
                        protocol=proto_num,
                        length=64,
                        tcp_flags=tcp_flags,
                        timestamp=now,
                    )
                    # Reverse packet: remote -> target (establish bidirectional flow)
                    self.aggregator.ingest_packet(
                        src_ip=str(raddr).strip(),
                        dst_ip=self.target_ip,
                        src_port=int(rport),
                        dst_port=int(lport),
                        protocol=proto_num,
                        length=128,
                        tcp_flags={"ACK": True, "ESTABLISHED": is_estab},
                        timestamp=now,
                    )
                    ingested += 1

                # If connection has website URL or internet port, analyze against vulnerable/malicious URLs
                w_url = conn.get("website_url") if isinstance(conn, dict) else getattr(conn, "website_url", None)
                d_host = conn.get("destination_host") if isinstance(conn, dict) else getattr(conn, "destination_host", None)
                p_name = conn.get("process_name") if isinstance(conn, dict) else getattr(conn, "process_name", None)
                if (self.has_endpoint_agent or getattr(self, "paired_at", None)) and (w_url or d_host or int(rport) in (80, 443, 8080, 8443)):
                    self._evaluate_website_url(w_url, d_host, p_name, str(raddr), int(rport), int(lport))

        if network_flows:
            for flow in network_flows:
                if isinstance(flow, dict):
                    src = flow.get("src_ip") or self.target_ip
                    dst = flow.get("dst_ip") or flow.get("destination_ip") or ""
                    sport = flow.get("src_port") or flow.get("source_port") or 0
                    dport = flow.get("dst_port") or flow.get("destination_port") or 0
                    proto = flow.get("protocol") or 6
                    bytes_val = flow.get("bytes") or flow.get("total_bytes") or 64
                else:
                    src = getattr(flow, "src_ip", None) or self.target_ip
                    dst = getattr(flow, "dst_ip", None) or getattr(flow, "destination_ip", "")
                    sport = getattr(flow, "src_port", 0) or getattr(flow, "source_port", 0) or 0
                    dport = getattr(flow, "dst_port", 0) or getattr(flow, "destination_port", 0) or 0
                    proto = getattr(flow, "protocol", 6) or 6
                    bytes_val = getattr(flow, "bytes", 64) or getattr(flow, "total_bytes", 64) or 64

                if not dst:
                    continue

                proto_num = 6 if str(proto).upper() == "TCP" or proto == 6 else (17 if str(proto).upper() == "UDP" or proto == 17 else 1)
                acc = self.aggregator.ingest_packet(
                    src_ip=str(src).strip(),
                    dst_ip=str(dst).strip(),
                    src_port=int(sport),
                    dst_port=int(dport),
                    protocol=proto_num,
                    length=int(bytes_val),
                    timestamp=now,
                )
                if acc:
                    self.window_engine.ingest_event(
                        src_ip=str(src).strip(),
                        dst_ip=str(dst).strip(),
                        src_port=int(sport),
                        dst_port=int(dport),
                        protocol=proto_num,
                        length=int(bytes_val),
                        timestamp=now,
                    )
                    ingested += 1

                # If flow has website URL or internet port, analyze against vulnerable/malicious URLs
                w_url = flow.get("website_url") if isinstance(flow, dict) else getattr(flow, "website_url", None)
                d_host = flow.get("destination_host") if isinstance(flow, dict) else getattr(flow, "destination_host", None)
                p_name = flow.get("process_name") if isinstance(flow, dict) else getattr(flow, "process_name", None)
                if (self.has_endpoint_agent or getattr(self, "paired_at", None)) and (w_url or d_host or int(dport) in (80, 443, 8080, 8443)):
                    self._evaluate_website_url(w_url, d_host, p_name, str(dst), int(dport), int(sport))

        return ingested

    def _evaluate_website_url(
        self,
        website_url: str | None,
        destination_host: str | None,
        process_name: str | None,
        dst_ip: str,
        dst_port: int,
        src_port: int = 0,
    ) -> None:
        """Analyzes website URL accessed by paired device; if high-risk or malicious, alerts via Telegram."""
        target_url = website_url
        if not target_url and (dst_port in (80, 443, 8080, 8443) or destination_host):
            host = destination_host or dst_ip
            if host and host not in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
                scheme = "https" if dst_port in (443, 8443) else "http"
                target_url = f"{scheme}://{host}" if dst_port in (80, 443) else f"{scheme}://{host}:{dst_port}"

        if not target_url or "localhost" in target_url or "127.0.0.1" in target_url:
            return

        now_mono = time.monotonic()
        cached = _GLOBAL_URL_THREAT_CACHE.get(target_url)
        if cached and (now_mono - cached[0] < 300):
            res = cached[1]
        else:
            try:
                from app.services.urltrust.analyzer import analyze
                res = analyze(db=None, org_id=self.org_id, raw_url=target_url)
                _GLOBAL_URL_THREAT_CACHE[target_url] = (now_mono, res)
            except Exception as ex:
                logger.debug("URL trust evaluation failed for %s: %s", target_url, ex)
                return

        # If malicious, dangerous, or suspicious
        if res and (getattr(res, "band", "") in ("Dangerous", "Suspicious") or getattr(res, "score", 100.0) <= 40.0):
            logger.warning(
                "[Paired Device URL Alert] Flagged website access on %s (%s): %s [Band: %s, Score: %.1f]",
                self.target_ip,
                self.target_hostname or "Paired Endpoint",
                res.url,
                res.band,
                res.score,
            )
            try:
                from app.services.telegram_alerts import notify_paired_device_packet_risk

                risk_score = round(max(0.75, (100.0 - float(res.score)) / 100.0), 2)
                packet_info = {
                    "src_ip": self.target_ip,
                    "dst_ip": dst_ip or (res.website.get("host") if isinstance(res.website, dict) else getattr(res.website, "host", "External Web")),
                    "src_port": src_port,
                    "dst_port": dst_port or (443 if str(res.url).startswith("https") else 80),
                    "protocol": "TCP",
                    "packets": 1,
                    "bytes": 512,
                    "process_name": process_name,
                    "website_url": res.url,
                    "destination_host": (res.website.get("host") if isinstance(res.website, dict) else getattr(res.website, "host", None)) or destination_host,
                    "url_trust_score": float(res.score),
                    "url_risk_band": str(res.band),
                    "summary": f"{process_name or 'Process'} accessed {str(res.band).lower()} website: {res.url}",
                }
                threat_details = (
                    f"Paired device accessed suspicious/malicious website: {res.url}\n"
                    f"Trust Score: {res.score:.1f}/100 (Band: {res.band})\n"
                    f"Forensic Analysis: {res.ai_summary or 'Flagged by URL vulnerability heuristics and reputation feeds.'}"
                )
                recommended_action = (
                    f"Block outbound access to {res.url} and investigate process {process_name or 'PID'} on {self.target_ip}."
                )

                notify_paired_device_packet_risk(
                    org_id=self.org_id,
                    device_ip=self.target_ip,
                    packet_info=packet_info,
                    device_name=self.target_hostname or self.target_ip,
                    device_id=self.device_id,
                    risk_score=risk_score,
                    verdict="ANOMALOUS",
                    attack_category="MALICIOUS_WEBSITE",
                    threat_details=threat_details,
                    forecast_progression="Web Connection ➔ Malicious Payload Download / Phishing ➔ Host Compromise",
                    recommended_action=recommended_action,
                )
            except Exception as e:
                logger.debug("Failed sending paired device website threat alert: %s", e)

    def start(self) -> None:
        success = self.capture_adapter.start()
        if not success:
            if self.has_endpoint_agent:
                # Scapy is secondary; primary capture source is Endpoint Agent
                self.status = "LIVE"
                self.status_message = None
            elif not self.capture_adapter.available:
                self.status = "UNAVAILABLE"
                self.status_message = self.capture_adapter.error_message or "Live traffic capture unavailable from this monitoring point."
                self.capture_source = "UNAVAILABLE"
            else:
                self.status = "ERROR"
                self.status_message = "Failed to initiate packet sniffing."
        else:
            if not self.has_endpoint_agent and self.capture_adapter.capture_source:
                self.capture_source = self.capture_adapter.capture_source

    def stop(self) -> None:
        self.status = "STOPPED"
        self.ended_at = datetime.now(timezone.utc)
        self.capture_adapter.stop()


class SessionManager:
    """Coordinates per-device live network traffic tracking sessions.

    Maintains strict device isolation: Session A and Session B never share state or flows.
    """

    def __init__(self) -> None:
        self._active_sessions: dict[str, ActiveTrackingSession] = {}

    def start_tracking(
        self,
        db: Session,
        org_id: str,
        device_id: str,
        ip: str,
        mac: str | None = None,
        hostname: str | None = None,
    ) -> TrackingSessionOut:
        session_id = str(uuid4())

        # Check if target device has an authorized EndpointAgent
        from app.models.endpoint import EndpointAgent
        from app.models.live import NetworkDevice
        import app.services.endpoint_telemetry as ep_telem_svc

        agent = db.scalar(
            select(EndpointAgent).where(
                EndpointAgent.org_id == org_id,
                (EndpointAgent.device_id == device_id)
                | ((EndpointAgent.current_ip.is_not(None)) & (EndpointAgent.current_ip == ip))
                | ((EndpointAgent.mac.is_not(None)) & (EndpointAgent.mac == mac))
                | ((EndpointAgent.hostname.is_not(None)) & (EndpointAgent.hostname == hostname))
                | (EndpointAgent.agent_id == device_id)
            )
        )
        if not agent:
            net_dev = db.get(NetworkDevice, device_id)
            if net_dev and net_dev.source_agent_id:
                agent = db.scalar(
                    select(EndpointAgent).where(
                        EndpointAgent.org_id == org_id,
                        EndpointAgent.agent_id == net_dev.source_agent_id
                    )
                )

        has_endpoint_agent = False
        agent_id = None
        endpoint_device_id = None
        if agent:
            has_endpoint_agent = True
            agent_id = agent.agent_id
            endpoint_device_id = agent.device_id
            os_label = (agent.os or "HOST").upper()
            capture_source = f"ENDPOINT AGENT ({os_label}) / TELEMETRY INGESTION"
        else:
            capture_source = "SCAPY / MONITORED INTERFACE"

        # Create active in-memory session
        active = ActiveTrackingSession(
            session_id=session_id,
            org_id=org_id,
            device_id=device_id,
            target_ip=ip,
            target_mac=mac,
            target_hostname=hostname,
            capture_source=capture_source,
            has_endpoint_agent=has_endpoint_agent,
            agent_id=agent_id,
            endpoint_device_id=endpoint_device_id,
        )
        active.start()

        # Ingest existing endpoint telemetry immediately if present
        if has_endpoint_agent:
            existing_telem = ep_telem_svc.get_telemetry_for_device(org_id, endpoint_device_id or device_id)
            if not existing_telem and agent and agent.device_id:
                existing_telem = ep_telem_svc.get_telemetry_for_device(org_id, agent.device_id)
            if existing_telem:
                active.ingest_telemetry(
                    process_connections=existing_telem.process_connections,
                    network_flows=existing_telem.network_flows,
                    listening_ports=existing_telem.listening_ports,
                )

        self._active_sessions[session_id] = active

        # Persist session row in database
        row = LiveTrackingSession(
            id=session_id,
            org_id=org_id,
            device_id=device_id,
            target_ip=ip,
            target_mac=mac,
            target_hostname=hostname,
            status=active.status,
            capture_source=active.capture_source,
            status_message=active.status_message,
            started_at=active.started_at,
        )
        db.add(row)
        db.commit()

        return self._to_session_out(active)

    def stop_tracking(self, db: Session, org_id: str, session_id: str) -> TrackingSessionOut:
        active = self._active_sessions.get(session_id)
        if active and active.org_id == org_id:
            active.stop()
            summary = active.aggregator.get_summary_metrics()
            # Update database
            row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
            if row:
                row.status = "STOPPED"
                row.ended_at = active.ended_at
                row.packet_count = summary["packet_count"]
                row.flow_count = summary["flow_count"]
                row.byte_count = summary["byte_count"]
                row.last_event_at = datetime.fromtimestamp(active.aggregator.last_event_time, tz=timezone.utc) if active.aggregator.last_event_time else None
                db.commit()
            return self._to_session_out(active)

        # If not active in memory, check DB
        row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
        if row is None:
            raise NotFoundError("Tracking session not found")
        row.status = "STOPPED"
        row.ended_at = utcnow()
        db.commit()
        return TrackingSessionOut(
            tracking_session_id=row.id,
            device_id=row.device_id,
            target_ip=row.target_ip,
            target_mac=row.target_mac,
            target_hostname=row.target_hostname,
            status=row.status,
            capture_source=row.capture_source,
            status_message=row.status_message,
            started_at=row.started_at,
            ended_at=row.ended_at,
            last_event_at=row.last_event_at,
            packet_count=row.packet_count,
            flow_count=row.flow_count,
            byte_count=row.byte_count,
        )

    def get_active_session_for_device(
        self, org_id: str, device_id: str
    ) -> "ActiveTrackingSession | None":
        """Phase 04: return the active tracking session for a device if one exists.

        Strictly device + org scoped — never returns another org's session.
        Returns None if no active LIVE session exists for this device.
        """
        for session in self._active_sessions.values():
            if (
                session.org_id == org_id
                and session.status == "LIVE"
                and (
                    session.device_id == device_id
                    or getattr(session, "endpoint_device_id", None) == device_id
                    or getattr(session, "agent_id", None) == device_id
                )
            ):
                return session
        return None

    def get_active_sessions_for_org(self, org_id: str) -> list["ActiveTrackingSession"]:
        """Return all active LIVE tracking sessions belonging to the given org."""
        return [
            session for session in self._active_sessions.values()
            if session.org_id == org_id and session.status == "LIVE"
        ]

    def get_session(self, db: Session, org_id: str, session_id: str) -> TrackingSessionOut:
        active = self._active_sessions.get(session_id)
        if active and active.org_id == org_id:
            return self._to_session_out(active)

        row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
        if row is None:
            raise NotFoundError("Tracking session not found")
        return TrackingSessionOut(
            tracking_session_id=row.id,
            device_id=row.device_id,
            target_ip=row.target_ip,
            target_mac=row.target_mac,
            target_hostname=row.target_hostname,
            status=row.status,
            capture_source=row.capture_source,
            status_message=row.status_message,
            started_at=row.started_at,
            ended_at=row.ended_at,
            last_event_at=row.last_event_at,
            packet_count=row.packet_count,
            flow_count=row.flow_count,
            byte_count=row.byte_count,
        )

    def get_results(self, db: Session, org_id: str, session_id: str) -> TrackingResultsOut:
        active = self._active_sessions.get(session_id)
        if not active or active.org_id != org_id:
            # Fallback to DB stored historical row
            row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
            if row is None:
                raise NotFoundError("Tracking session not found")
            sess_out = TrackingSessionOut(
                tracking_session_id=row.id,
                device_id=row.device_id,
                target_ip=row.target_ip,
                target_mac=row.target_mac,
                target_hostname=row.target_hostname,
                status=row.status,
                capture_source=row.capture_source,
                status_message=row.status_message,
                started_at=row.started_at,
                ended_at=row.ended_at,
                last_event_at=row.last_event_at,
                packet_count=row.packet_count,
                flow_count=row.flow_count,
                byte_count=row.byte_count,
            )
            return TrackingResultsOut(
                session=sess_out,
                metrics=LiveTrafficMetrics(
                    packet_count=row.packet_count,
                    flow_count=row.flow_count,
                    byte_count=row.byte_count,
                ),
                protocols=ProtocolBreakdown(),
                top_destinations=[],
                current_behaviour=CurrentBehaviourOut(
                    verdict="INSUFFICIENT_DATA",
                    confidence=0.0,
                    signals=["Session stopped; historical counters preserved."],
                ),
                evidence=[],
                features=None,
                forecast=None,
                flagged_packets=[],
                harmful_packet_count=0,
                suspicious_packet_count=0,
                normal_packet_count=0,
            )

        # If this device has an endpoint agent, re-sync latest telemetry to ingest fresh sockets
        if active.has_endpoint_agent or active.endpoint_device_id:
            import app.services.endpoint_telemetry as ep_telem_svc
            latest_telem = ep_telem_svc.get_telemetry_for_device(org_id, active.endpoint_device_id or active.device_id)
            if not latest_telem and active.endpoint_device_id:
                latest_telem = ep_telem_svc.get_telemetry_for_device(org_id, active.endpoint_device_id)
            if latest_telem:
                active.ingest_telemetry(
                    process_connections=latest_telem.process_connections,
                    network_flows=latest_telem.network_flows,
                    listening_ports=latest_telem.listening_ports,
                )

        summary = active.aggregator.get_summary_metrics()
        protocols_dict = active.aggregator.get_protocols()
        top_dest_raw = active.aggregator.get_top_destinations(limit=10)
        features = extract_session_features(active.aggregator)

        # Update graph topology with observed flows and record temporal graph snapshot
        active.graph_engine.update_from_flows(active.aggregator.get_all_flows())
        active.graph_engine.snapshot()

        # Slide time windows and format sequence tensor
        seq_tensor = active.window_engine.get_sequence_tensor(preprocessor=inference_engine.preprocessor)
        graph_tensors = active.graph_engine.get_graph_tensors()

        # Evaluate through AI Model Inference Engine (LSTM / Transformer / GNN / Fusion)
        current_behaviour = inference_engine.evaluate_live_traffic(
            seq_tensor=seq_tensor,
            graph_tensors=graph_tensors,
            total_packets=summary["packet_count"],
            flow_count=summary["flow_count"],
            features=features,
        )

        # Contextualize packet inspection with neural model's active attack category
        active.aggregator.set_active_attack_category(current_behaviour.attack_category)

        # Evaluate through Phase 03 Future Network Behaviour Forecasting Engine
        forecast = forecasting_engine.forecast_progression(
            seq_tensor=seq_tensor,
            graph_engine=active.graph_engine,
            current_features=features,
            previous_features=active.previous_features,
            current_verdict=current_behaviour.verdict,
            current_category=current_behaviour.attack_category,
            window_count=len(active.window_engine._windows),
            horizon=3,
        )
        active.previous_features = dict(features)

        # Phase 04: persist latest detection and forecast so device profile
        # can include AI state without re-running inference on every poll.
        # These are labeled CURRENT DETECTION / FORECAST — not confirmed attack.
        active.last_detection = current_behaviour
        active.last_forecast = forecast

        # Dispatch real-time Telegram alert if paired device exhibits high-risk packet flow
        if (active.has_endpoint_agent or getattr(active, "paired_at", None)) and current_behaviour.verdict in ("ANOMALOUS", "SUSPICIOUS"):
            try:
                from app.services.telegram_alerts import notify_paired_device_packet_risk
                top_d = active.aggregator.get_top_destinations(limit=1)
                all_f = active.aggregator.get_all_flows()
                pkt_data = {
                    "src_ip": active.target_ip,
                    "dst_ip": top_d[0]["destination_ip"] if top_d else "Internal Network",
                    "src_port": getattr(all_f[0], "src_port", 0) if all_f else 0,
                    "dst_port": top_d[0]["destination_port"] if top_d else 0,
                    "protocol": top_d[0]["protocol"] if top_d else "TCP",
                    "packets": top_d[0]["connection_count"] if top_d else 1,
                    "bytes": top_d[0]["connection_count"] * 64 if top_d else 64,
                    "summary": f"High risk packet sequence from {active.target_ip}",
                }
                notify_paired_device_packet_risk(
                    org_id=active.org_id,
                    device_ip=active.target_ip,
                    packet_info=pkt_data,
                    device_name=getattr(active, "hostname", None) or active.target_ip,
                    device_id=active.device_id,
                    risk_score=getattr(current_behaviour, "confidence", 0.88),
                    verdict=current_behaviour.verdict,
                    attack_category=current_behaviour.attack_category or "SUSPICIOUS_PACKET",
                    threat_details=current_behaviour.details or "Neural model classified live packet sequence as anomalous.",
                    forecast_progression=forecast.predicted_progression if forecast else None,
                    recommended_action="Inspect active connections on endpoint agent and consider network quarantine.",
                )
            except Exception as e:
                logger.debug("Failed sending paired device packet risk telegram alert: %s", e)

        # Check truthful capture status & network visibility
        now = time.time()
        elapsed = now - active.started_at.timestamp()
        visibility_info = TrafficVisibilityChecker.evaluate_visibility(
            target_ip=active.target_ip,
            packets_observed=summary["packet_count"],
            session_duration=elapsed,
            has_endpoint_agent=active.has_endpoint_agent,
        )
        if visibility_info["visibility"] == "UNAVAILABLE" and active.status == "LIVE":
            active.status_message = visibility_info["reason"]
        elif visibility_info["visibility"] == "VISIBLE" and active.status == "LIVE":
            active.status_message = None

        # Build evidence items strictly retaining source identity
        evidence_items: list[TrafficEvidenceItem] = []
        for dest in top_dest_raw[:5]:
            evidence_items.append(
                TrafficEvidenceItem(
                    evidence_type="NETWORK_TRAFFIC",
                    source=active.capture_source,
                    observed_at=dest.get("last_seen") or datetime.now(timezone.utc),
                    device_id=active.device_id,
                    confidence="high",
                    details={
                        "destination_ip": dest["destination_ip"],
                        "destination_port": dest["destination_port"],
                        "protocol": dest["protocol"],
                        "connection_count": dest["connection_count"],
                    },
                )
            )

        top_dest_models = [
            TopDestinationItem(
                destination_ip=d["destination_ip"],
                destination_port=d["destination_port"],
                protocol=d["protocol"],
                connection_count=d["connection_count"],
                last_seen=d.get("last_seen"),
            )
            for d in top_dest_raw
        ]

        sess_out = self._to_session_out(active)
        return TrackingResultsOut(
            session=sess_out,
            metrics=LiveTrafficMetrics(
                packet_count=summary["packet_count"],
                flow_count=summary["flow_count"],
                byte_count=summary["byte_count"],
                packets_per_sec=summary["packets_per_sec"],
                bytes_per_sec=summary["bytes_per_sec"],
                active_connections=summary["active_connections"],
            ),
            protocols=ProtocolBreakdown(
                tcp=protocols_dict["tcp"],
                udp=protocols_dict["udp"],
                icmp=protocols_dict["icmp"],
                dns=protocols_dict["dns"],
                http_https=protocols_dict["http_https"],
                other=protocols_dict["other"],
            ),
            top_destinations=top_dest_models,
            current_behaviour=current_behaviour,
            evidence=evidence_items,
            features=features,
            model_status=inference_engine.get_status(),
            network_visibility=visibility_info["visibility"],
            visibility_reason=visibility_info["reason"],
            window_count=len(active.window_engine._windows),
            graph_summary=active.graph_engine.to_dict(),
            forecast=forecast,
            flagged_packets=active.aggregator.get_flagged_packets(limit=100),
            harmful_packet_count=active.aggregator.get_packet_harm_stats()["harmful"],
            suspicious_packet_count=active.aggregator.get_packet_harm_stats()["suspicious"],
            normal_packet_count=active.aggregator.get_packet_harm_stats()["normal"],
        )


    def ingest_endpoint_telemetry(
        self,
        org_id: str,
        device_id: str,
        ip: str | None = None,
        process_connections: list[Any] | None = None,
        network_flows: list[Any] | None = None,
        listening_ports: list[Any] | None = None,
    ) -> int:
        """Find active sessions matching (org_id, device_id) or (org_id, ip) and ingest telemetry immediately."""
        total_ingested = 0
        for session in self._active_sessions.values():
            if session.org_id != org_id or session.status != "LIVE":
                continue
            matches = (
                session.device_id == device_id
                or session.endpoint_device_id == device_id
                or (ip and session.target_ip == ip)
            )
            if matches:
                session.has_endpoint_agent = True
                if not session.endpoint_device_id:
                    session.endpoint_device_id = device_id
                n = session.ingest_telemetry(
                    process_connections=process_connections,
                    network_flows=network_flows,
                    listening_ports=listening_ports,
                )
                total_ingested += n
        return total_ingested

    def _to_session_out(self, active: ActiveTrackingSession) -> TrackingSessionOut:
        if not active.has_endpoint_agent and active.capture_adapter and active.capture_adapter.capture_source:
            active.capture_source = active.capture_adapter.capture_source
        summary = active.aggregator.get_summary_metrics()
        last_ev = (
            datetime.fromtimestamp(active.aggregator.last_event_time, tz=timezone.utc)
            if active.aggregator.last_event_time
            else None
        )
        return TrackingSessionOut(
            tracking_session_id=active.session_id,
            device_id=active.device_id,
            target_ip=active.target_ip,
            target_mac=active.target_mac,
            target_hostname=active.target_hostname,
            status=active.status,
            capture_source=active.capture_source,
            status_message=active.status_message,
            started_at=active.started_at,
            ended_at=active.ended_at,
            last_event_at=last_ev,
            packet_count=summary["packet_count"],
            flow_count=summary["flow_count"],
            byte_count=summary["byte_count"],
        )


# Global singleton manager instance
tracking_manager = SessionManager()
session_manager = tracking_manager
