# Drishti v0.1 — live per-device tracking API endpoints | Phase 01
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org
from app.db import get_db
from app.models import Organization
from app.schemas.tracking import (
    TrackingResultsOut,
    TrackingSessionOut,
    TrackingStartRequest,
    TrackingStopRequest,
)
from app.services.traffic.session_manager import tracking_manager

router = APIRouter()


@router.post("/live/tracking/start", response_model=TrackingSessionOut)
def start_tracking(
    body: TrackingStartRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Start live network traffic tracking explicitly bound to the selected authorized device."""
    return tracking_manager.start_tracking(
        db=db,
        org_id=org.id,
        device_id=body.device_id,
        ip=body.ip,
        mac=body.mac,
        hostname=body.hostname,
    )


@router.post("/live/tracking/stop", response_model=TrackingSessionOut)
def stop_tracking(
    body: TrackingStopRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Stop active live network traffic tracking for a session and preserve historical results."""
    return tracking_manager.stop_tracking(
        db=db,
        org_id=org.id,
        session_id=body.tracking_session_id,
    )


@router.get("/live/tracking/{session_id}", response_model=TrackingSessionOut)
def get_tracking_session(
    session_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Retrieve metadata and status for a specific tracking session."""
    return tracking_manager.get_session(
        db=db,
        org_id=org.id,
        session_id=session_id,
    )


@router.get("/live/tracking/{session_id}/results", response_model=TrackingResultsOut)
@router.get("/live/tracking/results/{session_id}", response_model=TrackingResultsOut)
def get_tracking_results(
    session_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingResultsOut:
    """Retrieve live flow metrics, protocol breakdown, top destinations, and current detection."""
    return tracking_manager.get_results(
        db=db,
        org_id=org.id,
        session_id=session_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 04 Fleet Paired Devices Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/live/fleet/track-all")
def track_all_fleet_devices(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Synchronizes and activates live tracking across all authorized paired endpoint devices,
    executing a batched neural forward pass and updating the fleet communication graph.
    """
    from app.services.traffic.fleet_coordinator import fleet_coordinator
    from app.services.traffic.fleet_graph import fleet_graph_engine
    from ml.forecasting.fleet_engine import fleet_forecasting_engine

    sessions = fleet_coordinator.sync_paired_devices(db, org.id)
    if sessions:
        # Batched multi-device forward pass
        _ = fleet_forecasting_engine.evaluate_fleet_batch(sessions)
        # Fleet lateral movement graph update
        lateral_events = fleet_graph_engine.update_from_fleet_sessions(sessions)
    else:
        lateral_events = []

    summary = fleet_coordinator.get_fleet_status_summary(db, org.id)
    summary["lateral_movement_events"] = lateral_events
    return summary


@router.get("/live/fleet/status")
def get_fleet_tracking_status(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve current consolidated fleet tracking status across all paired devices."""
    from app.services.traffic.fleet_coordinator import fleet_coordinator
    return fleet_coordinator.get_fleet_status_summary(db, org.id)


@router.post("/live/fleet/stop-all")
def stop_all_fleet_devices(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Stop active live tracking across all paired devices in the organization."""
    from app.services.traffic.fleet_coordinator import fleet_coordinator
    stopped = fleet_coordinator.stop_fleet_tracking(db, org.id)
    return {
        "stopped_sessions_count": len(stopped),
        "stopped_sessions": [s.model_dump() for s in stopped],
    }


@router.get("/live/fleet/lateral-graph")
def get_fleet_lateral_graph(
    org: Organization = Depends(get_current_org),
) -> dict[str, Any]:
    """Retrieve the enterprise communication graph and detected lateral movement pivot events."""
    from app.services.traffic.fleet_coordinator import fleet_coordinator
    from app.services.traffic.fleet_graph import fleet_graph_engine

    sessions = fleet_coordinator.get_fleet_sessions(org.id)
    lateral_events = fleet_graph_engine.update_from_fleet_sessions(sessions)

    return {
        "total_nodes": fleet_graph_engine.fleet_graph.number_of_nodes(),
        "total_edges": fleet_graph_engine.fleet_graph.number_of_edges(),
        "lateral_movement_events": lateral_events,
    }
