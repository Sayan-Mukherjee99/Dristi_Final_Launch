# Drishti v0.1 — autonomous fleet tracking coordinator | Phase 04 Fleet Paired Devices
from __future__ import annotations

import logging
import threading
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.endpoint import EndpointAgent
from app.models.live import NetworkDevice
from app.schemas.tracking import TrackingSessionOut
from app.services.traffic.session_manager import tracking_manager, ActiveTrackingSession
import app.services.endpoint_telemetry as ep_telem_svc

logger = logging.getLogger("drishti")


class FleetTrackingCoordinator:
    """Coordinates autonomous tracking, telemetry ingestion, and neural monitoring
    across all paired endpoint devices (Windows, macOS, Linux, Android) in an organization.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def sync_paired_devices(self, db: Session, org_id: str) -> list[ActiveTrackingSession]:
        """Discovers all authorized paired endpoint agents and ensures each has an active,
        running tracking session with zero duplicate allocations.
        """
        with self._lock:
            # Query all registered agents that are paired or online
            agents = db.scalars(
                select(EndpointAgent).where(
                    EndpointAgent.org_id == org_id,
                    EndpointAgent.status.in_(["ONLINE", "PAIRED", "STALE"]),
                )
            ).all()

            active_sessions: list[ActiveTrackingSession] = []

            for agent in agents:
                dev_id = agent.device_id or agent.agent_id
                target_ip = (agent.current_ip or "127.0.0.1").strip()
                mac = agent.mac
                hostname = agent.hostname

                # Check if session is already active
                existing = tracking_manager.get_active_session_for_device(org_id, dev_id)
                if existing and existing.status == "LIVE":
                    # Re-sync fresh telemetry
                    self._sync_existing_telemetry(org_id, existing, agent)
                    active_sessions.append(existing)
                    continue

                # Ensure NetworkDevice row exists or is associated
                net_dev = db.get(NetworkDevice, dev_id)
                if not net_dev and target_ip:
                    net_dev = db.scalar(
                        select(NetworkDevice).where(
                            NetworkDevice.org_id == org_id,
                            NetworkDevice.ip == target_ip,
                        )
                    )

                try:
                    # Start tracking session for this paired device
                    sess_out = tracking_manager.start_tracking(
                        db=db,
                        org_id=org_id,
                        device_id=dev_id,
                        ip=target_ip,
                        mac=mac,
                        hostname=hostname,
                    )
                    active = tracking_manager._active_sessions.get(sess_out.tracking_session_id)
                    if active:
                        self._sync_existing_telemetry(org_id, active, agent)
                        active_sessions.append(active)
                        logger.info("Autonomous fleet tracking started for paired device %s (%s)", dev_id, target_ip)
                except Exception as ex:
                    logger.warning("Failed starting tracking for paired agent %s: %s", dev_id, ex)

            return active_sessions

    def _sync_existing_telemetry(
        self, org_id: str, session: ActiveTrackingSession, agent: EndpointAgent
    ) -> None:
        """Helper to stream cached endpoint telemetry into active session."""
        telem = ep_telem_svc.get_telemetry_for_device(org_id, agent.device_id)
        if not telem and agent.agent_id:
            telem = ep_telem_svc.get_telemetry_for_device(org_id, agent.agent_id)
        if telem:
            session.ingest_telemetry(
                process_connections=telem.process_connections,
                network_flows=telem.network_flows,
                listening_ports=telem.listening_ports,
            )

    def get_fleet_sessions(self, org_id: str) -> list[ActiveTrackingSession]:
        """Returns all currently live tracking sessions belonging to the org."""
        return tracking_manager.get_active_sessions_for_org(org_id)

    def stop_fleet_tracking(self, db: Session, org_id: str) -> list[TrackingSessionOut]:
        """Stops all active tracking sessions for the organization."""
        with self._lock:
            active_list = tracking_manager.get_active_sessions_for_org(org_id)
            stopped: list[TrackingSessionOut] = []
            for s in active_list:
                try:
                    out = tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=s.session_id)
                    stopped.append(out)
                except Exception as ex:
                    logger.warning("Error stopping session %s: %s", s.session_id, ex)
            return stopped

    def get_fleet_status_summary(self, db: Session, org_id: str) -> dict[str, Any]:
        """Returns a consolidated summary of fleet monitoring status."""
        active = self.get_fleet_sessions(org_id)
        agents = db.scalars(
            select(EndpointAgent).where(EndpointAgent.org_id == org_id)
        ).all()

        total_packets = sum(s.aggregator.total_packets for s in active)
        total_flows = sum(len(s.aggregator.flows) for s in active)
        anomalous_count = sum(1 for s in active if s.last_detection and s.last_detection.verdict in ("ANOMALOUS", "SUSPICIOUS"))

        return {
            "total_paired_agents": len(agents),
            "active_tracking_sessions": len(active),
            "total_fleet_packets": total_packets,
            "total_fleet_flows": total_flows,
            "anomalous_devices_count": anomalous_count,
            "tracked_devices": [
                {
                    "device_id": s.device_id,
                    "target_ip": s.target_ip,
                    "hostname": s.target_hostname,
                    "status": s.status,
                    "packet_count": s.aggregator.total_packets,
                    "flow_count": len(s.aggregator.flows),
                    "current_verdict": s.last_detection.verdict if s.last_detection else "INSUFFICIENT_DATA",
                    "top_forecast": s.last_forecast.horizon_steps[0].state if (s.last_forecast and s.last_forecast.horizon_steps) else None,
                    "composite_risk_score": s.last_forecast.composite_risk_score if s.last_forecast else 0.0,
                }
                for s in active
            ],
        }


# Global singleton fleet tracking coordinator
fleet_coordinator = FleetTrackingCoordinator()
