"""
Main FastAPI application for Gryffindor- Intelligent Threat Detection & Situational Awareness System.
Provides endpoints for event ingestion, real-time threat correlation, temporal queries, and incident management.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
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
    title="Gryffindor API",
    description="Intelligent Threat Detection & Situational Awareness System - Multi-modal surveillance fusion engine combining CCTV, IoT sensors, and cyber access logs.",
    version="1.0.0",
)

# 1. Enable CORS for all origins (so React frontend on different computers / ports can connect)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for hackathon prototype
event_store: List[Dict[str, Any]] = []
ZONES_DB: Dict[str, Dict[str, Any]] = {}
INCIDENTS_DB: Dict[str, Incident] = {}

# Locate and load data/zones.json
BASE_DIR = Path(__file__).resolve().parent.parent
ZONES_FILE = BASE_DIR / "data" / "zones.json"
if not ZONES_FILE.exists():
    ZONES_FILE = Path("data") / "zones.json"


def load_zones():
    """Load zones from data/zones.json into memory."""
    global ZONES_DB
    if ZONES_FILE.exists():
        try:
            with open(ZONES_FILE, "r", encoding="utf-8") as f:
                zones_list = json.load(f)
                ZONES_DB = {z["id"]: z for z in zones_list}
        except Exception as e:
            print(f"[WARNING] Failed to load zones from {ZONES_FILE}: {e}")
            ZONES_DB = {}
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


def evaluate_threat_correlation(new_event_dict: Dict[str, Any]) -> Optional[Incident]:
    """
    Correlate events occurring within CORRELATION_WINDOW_SECONDS in the same zone.
    Computes weighted threat score incorporating modality weights, distinct source
    corroboration multiplier, and zone critical weights.
    """
    new_event_dt = parse_iso(new_event_dict["timestamp"])

    # Find temporally correlated events in the same zone within the correlation window
    correlated_events = [new_event_dict]
    for ev in reversed(event_store):
        if ev.get("event_id") == new_event_dict.get("event_id"):
            continue
        if ev.get("zone_id") != new_event_dict.get("zone_id"):
            continue
        ev_dt = parse_iso(ev["timestamp"])
        time_diff = abs((new_event_dt - ev_dt).total_seconds())
        if time_diff <= CORRELATION_WINDOW_SECONDS:
            correlated_events.append(ev)

    distinct_sources = list({ev["source_type"] for ev in correlated_events})
    num_sources = len(distinct_sources)
    multiplier = CORROBORATION_MULTIPLIER.get(min(num_sources, 3), 1.0)

    # Zone criticality factor
    zone_info = ZONES_DB.get(new_event_dict.get("zone_id", ""), {})
    zone_weight = float(zone_info.get("zone_weight", 1.0))

    # Base weighted confidence score: sum(source_weight * confidence)
    base_score = 0.0
    for ev in correlated_events:
        weight = SOURCE_WEIGHTS.get(ev["source_type"], 0.3)
        base_score += float(ev["confidence"]) * weight * 100.0

    # Normalize base score by number of events and scale by multiplier & zone weight
    normalized_score = (base_score / len(correlated_events)) * multiplier * (zone_weight / 1.5)
    final_score = round(min(100.0, max(0.0, normalized_score)), 2)

    # First event timestamp and latency calculation
    first_event = min(correlated_events, key=lambda e: parse_iso(e["timestamp"]))
    now_utc = datetime.now(timezone.utc)
    first_dt = parse_iso(first_event["timestamp"])
    latency_ms = round((now_utc - first_dt).total_seconds() * 1000.0, 2)

    severity = calculate_incident_severity(final_score)

    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        zone_id=new_event_dict["zone_id"],
        score=final_score,
        severity=severity,
        sources=distinct_sources,
        event_ids=[e["event_id"] for e in correlated_events],
        first_ts=first_event["timestamp"],
        dispatch_ts=now_utc.isoformat() if severity in ["Critical", "High"] else None,
        latency_ms=latency_ms if latency_ms >= 0 else 0.0,
        status="dispatched" if severity in ["Critical", "High"] else "open",
    )

    INCIDENTS_DB[incident.incident_id] = incident
    return incident


# ==============================================================================
# API Endpoints
# ==============================================================================

@app.get("/", tags=["System"])
def root():
    """
    Root endpoint indicating server health and operational status.
    """
    return {"message": "Gryffindor backend is running"}


@app.get("/time", tags=["System"])
def get_time():
    """
    Returns current server time as a unix epoch timestamp float.
    Used for clock synchronization across distributed nodes and frontends.
    """
    return {"epoch": time.time()}


@app.post("/ingest", status_code=status.HTTP_200_OK, tags=["Events"])
def ingest_event(event: Event):
    """
    Ingest a security observation event from CCTV, IoT sensors, or cyber logs.
    - Validates payload structure automatically using the Event Pydantic model
    - Appends server-side UTC ingest_ts
    - Logs the event payload to console
    - Stores the event in-memory within event_store
    - Runs multi-source threat correlation
    - Returns acknowledgment JSON with event_id
    """
    # 1. Server-side UTC ingest timestamp
    ingest_ts = datetime.now(timezone.utc).isoformat()
    event_data = event.model_dump()
    event_data["ingest_ts"] = ingest_ts

    # 2. Print received event to console
    print(f"\n[EVENT INGESTED] ID: {event.event_id} | Type: {event.event_type} | Source: {event.source_type} | Zone: {event.zone_id}")
    print(json.dumps(event_data, indent=2))

    # 3. Store in Python list in-memory
    event_store.append(event_data)

    # 4. Trigger threat correlation
    try:
        evaluate_threat_correlation(event_data)
    except Exception as err:
        print(f"[CORRELATION ERROR] {err}")

    # 5. Return JSON response
    return {
        "status": "received",
        "event_id": event.event_id,
    }


@app.post("/events", status_code=status.HTTP_200_OK, tags=["Events"], include_in_schema=False)
def ingest_event_alias(event: Event):
    """Compatibility alias endpoint for /ingest."""
    return ingest_event(event)


@app.get("/events", response_model=List[Dict[str, Any]], tags=["Events"])
def get_events():
    """
    Returns all events currently stored in event_store, ordered most recent first.
    """
    return list(reversed(event_store))


@app.get("/zones", tags=["Zones"])
def get_zones():
    """Retrieve all monitored zones, their geographic coordinates, and weights."""
    return list(ZONES_DB.values())



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
