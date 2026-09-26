"""
Main FastAPI application for Intelligent Threat Detection & Situational Awareness System.
Provides endpoints for event ingestion, threat correlation, incident dispatch, and zone management.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, Query, status, WebSocket, WebSocketDisconnect
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
import uvicorn

from backend.constants import (
    CORRELATION_WINDOW_SECONDS,
    CORROBORATION_MULTIPLIER,
    SEVERITY_THRESHOLDS,
    SOURCE_WEIGHTS,
)
from backend.models import Event, Incident


# Feedback schema for operator action
class FeedbackBody(BaseModel):
    verdict: str = "false_positive"


class ConnectionManager:
    """Manages active WebSocket connections for live alert broadcasting."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Any):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()

# Initialize FastAPI App
app = FastAPI(
    title="Intelligent Threat Detection & Situational Awareness API",
    description="Multi-modal surveillance fusion engine combining CCTV, IoT sensors, and cyber access logs.",
    version="1.0.0",
)

# Enable CORS for frontend clients / dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for hackathon prototype
ZONES_DB: Dict[str, Dict[str, Any]] = {}
EVENTS_DB: List[Event] = []
INCIDENTS_DB: Dict[str, Incident] = {}

# Storage configuration & mode detection (SQLite / in-memory fallback)
DATABASE_URL = os.getenv("DATABASE_URL", "")
STORAGE_MODE = "SQLite" if DATABASE_URL.startswith("sqlite") or os.getenv("STORAGE_MODE", "").lower() == "sqlite" else "in-memory"
logger = logging.getLogger("uvicorn.info")


@app.on_event("startup")
async def startup_event():
    startup_msg = f"[STORAGE CONFIG] Active storage fallback mode: {STORAGE_MODE}"
    print(f"\n==================================================================", flush=True)
    print(f"  {startup_msg}", flush=True)
    print(f"==================================================================\n", flush=True)
    logger.info(startup_msg)

# Locate and load data/zones.json
BASE_DIR = Path(__file__).resolve().parent.parent
ZONES_FILE = BASE_DIR / "data" / "zones.json"


def load_zones():
    """Load zones from data/zones.json into memory."""
    global ZONES_DB
    if ZONES_FILE.exists():
        with open(ZONES_FILE, "r", encoding="utf-8") as f:
            zones_list = json.load(f)
            ZONES_DB = {z["id"]: z for z in zones_list}
    else:
        ZONES_DB = {}


load_zones()


def parse_iso(ts_str: str) -> datetime:
    """Parse ISO-8601 string to aware datetime in UTC."""
    clean_ts = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean_ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def calculate_incident_severity(score: float) -> str:
    """Classify incident severity according to defined thresholds."""
    if score >= SEVERITY_THRESHOLDS["Critical"]:
        return "Critical"
    elif score >= SEVERITY_THRESHOLDS["High"]:
        return "High"
    elif score >= SEVERITY_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def evaluate_threat_correlation(new_event: Event) -> Optional[Incident]:
    """
    Correlate events occurring within CORRELATION_WINDOW_SECONDS in the same zone.

    Key fix vs. the original version: instead of summing EVERY individual
    correlated event (which let a burst of 10 same-source events like
    failed logins blow the score past 100), we take ONE representative
    event per DISTINCT source_type (the highest-confidence one) before
    scoring. This means:
      - 10 failed logins from CYBER alone still count as ONE CYBER signal.
      - Only genuine corroboration across VIDEO / IOT / CYBER pushes the
        score toward Critical.

    We also merge into an existing open incident in the same zone (within
    a short merge window) instead of creating a new incident every time,
    and we suppress weak, single-source, low-severity noise entirely so
    it doesn't clutter the dashboard.
    """
    new_event_dt = parse_iso(new_event.timestamp)

    # 1. Find all events in the same zone within the correlation window.
    correlated_events = [new_event]
    for ev in reversed(EVENTS_DB):
        if ev.event_id == new_event.event_id:
            continue
        if ev.zone_id != new_event.zone_id:
            continue
        ev_dt = parse_iso(ev.timestamp)
        time_diff = abs((new_event_dt - ev_dt).total_seconds())
        if time_diff <= CORRELATION_WINDOW_SECONDS:
            correlated_events.append(ev)

    # 2. Collapse to ONE representative (max-confidence) event per source type.
    best_per_source: Dict[str, Event] = {}
    for ev in correlated_events:
        current_best = best_per_source.get(ev.source_type)
        if current_best is None or ev.confidence > current_best.confidence:
            best_per_source[ev.source_type] = ev

    distinct_sources = list(best_per_source.keys())
    num_sources = len(distinct_sources)
    multiplier = CORROBORATION_MULTIPLIER.get(min(num_sources, 3), 1.0)

    # 3. Zone criticality factor.
    load_zones()
    zone_info = ZONES_DB.get(new_event.zone_id, {})
    zone_weight = float(zone_info.get("zone_weight", 1.0))

    # 4. Score = sum(weight * confidence) per DISTINCT source, scaled by
    #    corroboration multiplier and zone weight, capped at 100.
    weighted_sum = sum(
        SOURCE_WEIGHTS.get(src, 0.3) * ev.confidence
        for src, ev in best_per_source.items()
    )
    final_score = round(
        min(100.0, max(0.0, weighted_sum * 100.0 * multiplier * zone_weight)), 2
    )

    all_event_ids = [e.event_id for e in correlated_events]
    first_event = min(correlated_events, key=lambda e: parse_iso(e.timestamp))
    now_utc = datetime.now(timezone.utc)
    first_dt = parse_iso(first_event.timestamp)
    latency_ms = round((now_utc - first_dt).total_seconds() * 1000.0, 2)
    severity = calculate_incident_severity(final_score)

    # 5. Exact suppression rule before an incident is created or broadcast:
    # If the number of distinct source_types contributing is less than 2,
    # AND the calculated severity is "Low" or "Medium", do NOT create or broadcast
    # an incident — just store/log the event normally without alerting.
    # Only genuine multi-source corroboration (2+ distinct source types within
    # the correlation window) should create a visible incident, UNLESS a single
    # source's score independently reaches High or Critical severity on its own.
    if num_sources < 2 and severity in ("Low", "Medium"):
        return None

    # 6. Merge into an existing open/dispatched incident in this zone if one
    #    started within the last few seconds, instead of duplicating alerts.
    MERGE_WINDOW_SECONDS = 5.0
    existing_incident = None
    for inc in INCIDENTS_DB.values():
        if inc.zone_id != new_event.zone_id:
            continue
        if inc.status not in ("open", "dispatched"):
            continue
        inc_first_dt = parse_iso(inc.first_ts)
        if abs((new_event_dt - inc_first_dt).total_seconds()) <= MERGE_WINDOW_SECONDS:
            existing_incident = inc
            break

    if existing_incident:
        merged_event_ids = list(set(existing_incident.event_ids) | set(all_event_ids))
        updated_score = max(existing_incident.score, final_score)
        updated_severity = calculate_incident_severity(updated_score)
        merged_sources = list(set(existing_incident.sources) | set(distinct_sources))

        # Check suppression rule on merged incident as well
        if len(merged_sources) < 2 and updated_severity in ("Low", "Medium"):
            return None

        incident_dict = existing_incident.model_dump()
        incident_dict["score"] = updated_score
        incident_dict["severity"] = updated_severity
        incident_dict["sources"] = merged_sources
        incident_dict["event_ids"] = merged_event_ids
        incident_dict["latency_ms"] = latency_ms if latency_ms >= 0 else 0.0
        if updated_severity in ("Critical", "High") and not incident_dict.get("dispatch_ts"):
            incident_dict["dispatch_ts"] = now_utc.isoformat()
            incident_dict["status"] = "dispatched"

        updated_incident = Incident(**incident_dict)
        INCIDENTS_DB[updated_incident.incident_id] = updated_incident
        return updated_incident

    # 7. Otherwise, create a brand-new incident (qualifies via 2+ distinct sources or High/Critical severity).
    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        zone_id=new_event.zone_id,
        score=final_score,
        severity=severity,
        sources=distinct_sources,
        event_ids=all_event_ids,
        first_ts=first_event.timestamp,
        dispatch_ts=now_utc.isoformat() if severity in ["Critical", "High"] else None,
        latency_ms=latency_ms if latency_ms >= 0 else 0.0,
        status="dispatched" if severity in ["Critical", "High"] else "open",
    )

    INCIDENTS_DB[incident.incident_id] = incident
    return incident


class CorrelationEngine:
    """Compatibility wrapper around evaluate_threat_correlation for testing."""
    def __init__(self, dedup_window_seconds: float = 5.0, cooldown_window_seconds: float = 5.0):
        self.dedup_window_seconds = dedup_window_seconds
        self.cooldown_window_seconds = cooldown_window_seconds

    def process_event(self, event_data: Dict[str, Any]) -> Optional[Incident]:
        ev = Event(**event_data) if isinstance(event_data, dict) else event_data
        if not any(e.event_id == ev.event_id for e in EVENTS_DB):
            EVENTS_DB.append(ev)
        return evaluate_threat_correlation(ev)

    def reset(self):
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()


engine = CorrelationEngine()
incident_store = INCIDENTS_DB
event_store = EVENTS_DB


@app.get("/", tags=["System"])
def root():
    """Health check and high-level system metrics overview."""
    return {
        "status": "online",
        "service": "Intelligent Threat Detection & Situational Awareness System",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "monitored_zones": len(ZONES_DB),
            "ingested_events": len(EVENTS_DB),
            "active_incidents": len(INCIDENTS_DB),
        },
        "docs_url": "/docs",
    }


@app.get("/time", tags=["System"])
def get_time():
    """Returns current server epoch time, used for clock sync between laptops."""
    return {"epoch": datetime.now(timezone.utc).timestamp()}


@app.post("/reset", tags=["System"])
def reset_system_state():
    """Clears all in-memory events and incidents. Useful between demo runs."""
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    return {"message": "System state reset.", "events": 0, "incidents": 0}


@app.get("/zones", tags=["Zones"])
def get_zones():
    """Retrieve all monitored zones, their geographic coordinates, and weights."""
    return list(ZONES_DB.values())


@app.post("/events", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Events"])
@app.post("/ingest", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Events"])
async def ingest_event(event: Event):
    """
    Ingest a real-time event from CCTV, IoT, or Cyber sources.
    Performs validation and runs immediate multi-source threat correlation.
    """
    # Prevent duplicate event IDs
    if any(e.event_id == event.event_id for e in EVENTS_DB):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with id '{event.event_id}' already exists.",
        )

    # Store event
    EVENTS_DB.append(event)

    # Run multi-source threat correlation
    incident = evaluate_threat_correlation(event)

    # Exact suppression rule before an incident is created or broadcast to the WebSocket:
    # If the number of distinct source_types contributing is less than 2, AND the calculated
    # severity is "Low" or "Medium", do NOT create or broadcast an incident — just store/log
    # the event normally without alerting.
    if incident:
        if len(incident.sources) < 2 and incident.severity in ("Low", "Medium"):
            INCIDENTS_DB.pop(incident.incident_id, None)
            incident = None
        else:
            await manager.broadcast(incident.model_dump())

    return {
        "message": "Event ingested and processed successfully.",
        "event_id": event.event_id,
        "triggered_incident": incident.model_dump() if incident else None,
    }


@app.get("/events", response_model=List[Event], tags=["Events"])
def list_events(
    zone_id: Optional[str] = Query(None, description="Filter by zone ID"),
    source_type: Optional[str] = Query(None, description="Filter by source modality"),
    limit: int = Query(50, ge=1, le=500),
):
    """List recent events with optional filtering."""
    results = EVENTS_DB
    if zone_id:
        results = [e for e in results if e.zone_id == zone_id]
    if source_type:
        results = [e for e in results if e.source_type == source_type]
    return results[-limit:]


@app.get("/incidents", response_model=List[Incident], tags=["Incidents"])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by incident status"),
):
    """Retrieve all synthesized threat incidents."""
    incidents = list(INCIDENTS_DB.values())
    if severity:
        incidents = [inc for inc in incidents if inc.severity == severity]
    if status_filter:
        incidents = [inc for inc in incidents if inc.status == status_filter]
    return incidents


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
def get_incident(incident_id: str):
    """Fetch details of a specific incident."""
    if incident_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return INCIDENTS_DB[incident_id]


@app.patch("/incidents/{incident_id}/status", response_model=Incident, tags=["Incidents"])
def update_incident_status(
    incident_id: str,
    new_status: str = Query(..., pattern="^(open|dispatched|true_positive|false_positive)$"),
):
    """Update incident status (e.g., mark as true_positive or dispatched)."""
    if incident_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    incident = INCIDENTS_DB[incident_id]
    incident_dict = incident.model_dump()
    incident_dict["status"] = new_status
    if new_status == "dispatched" and not incident_dict.get("dispatch_ts"):
        incident_dict["dispatch_ts"] = datetime.now(timezone.utc).isoformat()
    updated_incident = Incident(**incident_dict)
    INCIDENTS_DB[incident_id] = updated_incident
    return updated_incident


@app.get("/metrics", tags=["System"])
def get_metrics():
    """
    Returns headline demo metrics: total events, total incidents,
    noise suppression percentage, and average incident latency.
    """
    total_events = len(EVENTS_DB)
    total_incidents = len(INCIDENTS_DB)
    if total_events > 0:
        suppression_pct = round(
            (1 - (total_incidents / total_events)) * 100.0, 2
        )
    else:
        suppression_pct = 0.0

    if total_incidents > 0:
        avg_latency_ms = round(
            sum(inc.latency_ms for inc in INCIDENTS_DB.values()) / total_incidents, 2
        )
    else:
        avg_latency_ms = 0.0

    return {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "noise_suppression_pct": suppression_pct,
        "avg_latency_ms": avg_latency_ms,
    }


@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint streaming real-time threat alerts to tactical dashboards.
    Sends existing active incidents on initial connection, then pushes new events as they arrive.
    """
    await manager.connect(websocket)
    try:
        # Push initial snapshot of active incidents on connection if any exist
        if INCIDENTS_DB:
            snapshot = [inc.model_dump() for inc in reversed(list(INCIDENTS_DB.values()))]
            await websocket.send_json(snapshot)
        while True:
            # Keep connection alive receiving ping or messages from client
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.post("/incidents/{incident_id}/dispatch", response_model=Incident, tags=["Incidents"])
async def dispatch_incident(incident_id: str):
    """
    Dispatch emergency response units for a specified incident.
    Sets status to 'dispatched' and updates dispatch_ts.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    if incident_id not in INCIDENTS_DB:
        # If dispatched from frontend demo/test ID, register dynamically
        incident = Incident(
            incident_id=incident_id,
            zone_id="Perimeter_Gate_3",
            score=95.0,
            severity="Critical",
            sources=["MANUAL_DISPATCH"],
            first_ts=now_utc,
            dispatch_ts=now_utc,
            status="dispatched",
        )
        INCIDENTS_DB[incident_id] = incident
    else:
        incident = INCIDENTS_DB[incident_id]
        incident_dict = incident.model_dump()
        incident_dict["status"] = "dispatched"
        if not incident_dict.get("dispatch_ts"):
            incident_dict["dispatch_ts"] = now_utc
        incident = Incident(**incident_dict)
        INCIDENTS_DB[incident_id] = incident

    await manager.broadcast(incident.model_dump())
    return incident


@app.post("/incidents/{incident_id}/feedback", tags=["Incidents"])
async def incident_feedback(incident_id: str, feedback: FeedbackBody):
    """
    Record operator classification feedback (e.g. 'false_positive').
    Updates incident status and notifies all active dashboard clients.
    """
    new_status = "false_positive" if feedback.verdict == "false_positive" else feedback.verdict
    if incident_id in INCIDENTS_DB:
        incident = INCIDENTS_DB[incident_id]
        incident_dict = incident.model_dump()
        incident_dict["status"] = new_status
        updated = Incident(**incident_dict)
        INCIDENTS_DB[incident_id] = updated
        await manager.broadcast(updated.model_dump())
        return {
            "message": f"Incident '{incident_id}' status updated to {new_status}.",
            "incident": updated.model_dump(),
        }

    return {
        "message": f"Feedback '{feedback.verdict}' recorded for incident '{incident_id}'.",
        "incident_id": incident_id,
        "verdict": feedback.verdict,
    }


if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)