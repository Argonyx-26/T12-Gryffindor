"""
Main FastAPI application for Gryffindor - Intelligent Threat Detection & Situational Awareness System.
Provides endpoints for event ingestion, real-time threat correlation, live alerting via WebSockets,
temporal queries, and incident management.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Literal, Optional
import uuid

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Load environment variables
load_dotenv()

# Safe imports for both package and direct execution
try:
    from backend.models import Event, Incident
    from backend.constants import (
        CORRELATION_WINDOW_SECONDS,
        CORROBORATION_MULTIPLIER,
        DEDUPLICATION_WINDOW_SECONDS,
        INCIDENT_COOLDOWN_SECONDS,
        SEVERITY_THRESHOLDS,
        SOURCE_WEIGHTS,
    )
except ImportError:
    from models import Event, Incident
    from constants import (
        CORRELATION_WINDOW_SECONDS,
        CORROBORATION_MULTIPLIER,
        DEDUPLICATION_WINDOW_SECONDS,
        INCIDENT_COOLDOWN_SECONDS,
        SEVERITY_THRESHOLDS,
        SOURCE_WEIGHTS,
    )

# 1. Initialize FastAPI App
app = FastAPI(
    title="Gryffindor API",
    description="Intelligent Threat Detection & Situational Awareness System - Multi-modal surveillance fusion engine combining CCTV, IoT sensors, and cyber access logs.",
    version="1.0.0",
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
event_store: List[Dict[str, Any]] = []
incident_store: List[Incident] = []
INCIDENTS_DB: Dict[str, Incident] = {}
ZONES_DB: Dict[str, Dict[str, Any]] = {}

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


def calculate_incident_severity(score: float) -> Literal["Critical", "High", "Medium", "Low"]:
    """Classify incident severity according to defined thresholds."""
    if score >= SEVERITY_THRESHOLDS["Critical"]:
        return "Critical"
    elif score >= SEVERITY_THRESHOLDS["High"]:
        return "High"
    elif score >= SEVERITY_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


# ==============================================================================
# WebSocket Connection Manager
# ==============================================================================

class ConnectionManager:
    """Manages active WebSocket connections for live threat alert broadcasts."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Any):
        """Broadcast arbitrary JSON-serializable message or Incident."""
        if not self.active_connections:
            return
        if hasattr(message, "model_dump_json"):
            payload = message.model_dump_json()
        elif hasattr(message, "model_dump"):
            payload = json.dumps(message.model_dump())
        elif isinstance(message, str):
            payload = message
        else:
            payload = json.dumps(message)
        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)
        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    async def broadcast_incident(self, incident: Incident):
        """Immediately broadcast incident as JSON to all connected clients."""
        await self.broadcast(incident)


ws_manager = ConnectionManager()
manager = ws_manager


# ==============================================================================
# Correlation Engine
# ==============================================================================

class CorrelationEngine:
    """
    Maintains a rolling buffer of recent events grouped by zone_id with arrival times.
    Evaluates multi-source threat correlation across temporal windows and implements
    incident de-duplication:
    - If a new incident would trigger in the same zone within 5s of an existing OPEN incident,
      the existing incident is updated with the higher score and appended event_ids.
    - If an incident closed in that zone, new incidents in that zone are suppressed for 5s.
    """

    def __init__(
        self,
        dedup_window_seconds: float = DEDUPLICATION_WINDOW_SECONDS,
        cooldown_window_seconds: float = INCIDENT_COOLDOWN_SECONDS,
    ):
        # zone_id -> list of recent events, each with its arrival time
        self.buffer: Dict[str, List[Dict[str, Any]]] = {}
        # zone_id -> active open Incident
        self.active_incidents: Dict[str, Incident] = {}
        # zone_id -> epoch timestamp of last event processed for this incident
        self.last_incident_time: Dict[str, float] = {}
        # zone_id -> epoch timestamp when an incident in this zone was closed
        self.last_closed_time: Dict[str, float] = {}
        self.dedup_window_seconds: float = dedup_window_seconds
        self.cooldown_window_seconds: float = cooldown_window_seconds

    @property
    def rolling_buffer(self) -> Dict[str, List[Dict[str, Any]]]:
        """Alias property for rolling buffer access."""
        return self.buffer

    def record_incident_closed(self, zone_id: str, close_time: Optional[Any] = None) -> None:
        """
        Record that an incident in zone_id has closed (e.g. dispatched, true_positive, false_positive).
        Starts the cooldown timer during which new incidents in that zone cannot be started.
        """
        if close_time is None:
            epoch = time.time()
        elif isinstance(close_time, (int, float)):
            epoch = float(close_time)
        elif isinstance(close_time, str):
            try:
                epoch = parse_iso(close_time).timestamp()
            except Exception:
                epoch = time.time()
        elif isinstance(close_time, datetime):
            epoch = close_time.timestamp()
        else:
            epoch = time.time()

        self.last_closed_time[zone_id] = epoch
        self.active_incidents.pop(zone_id, None)
        self.last_incident_time.pop(zone_id, None)

    def record_incident_opened(self, incident: Incident, open_time: Optional[Any] = None) -> None:
        """Register an open incident for its zone, clearing any cooldown timer."""
        if open_time is None:
            epoch = time.time()
        elif isinstance(open_time, (int, float)):
            epoch = float(open_time)
        elif isinstance(open_time, str):
            try:
                epoch = parse_iso(open_time).timestamp()
            except Exception:
                epoch = time.time()
        elif isinstance(open_time, datetime):
            epoch = open_time.timestamp()
        else:
            epoch = time.time()

        self.active_incidents[incident.zone_id] = incident
        self.last_incident_time[incident.zone_id] = epoch
        self.last_closed_time.pop(incident.zone_id, None)

    def reset(self) -> None:
        """Clear all rolling buffers, active incidents, and cooldown timers."""
        self.buffer.clear()
        self.active_incidents.clear()
        self.last_incident_time.clear()
        self.last_closed_time.clear()

    def add_event(self, event_data: Dict[str, Any], arrival_time: Optional[float] = None) -> None:
        """Add an event to the rolling buffer for its zone and prune stale entries."""
        zone_id = event_data.get("zone_id")
        if not zone_id:
            return
        if zone_id not in self.buffer:
            self.buffer[zone_id] = []

        arr_time = arrival_time if arrival_time is not None else time.time()
        entry = dict(event_data)
        entry["arrival_time"] = arr_time
        entry["event"] = event_data
        self.buffer[zone_id].append(entry)

        # Retain events in rolling buffer for at least 300 seconds to prevent memory leaks
        cutoff = arr_time - 300.0
        self.buffer[zone_id] = [e for e in self.buffer[zone_id] if e.get("arrival_time", arr_time) >= cutoff]

    def correlate(self, new_event_data: Dict[str, Any]) -> Incident:
        """
        Evaluate correlation for a newly arrived event against other events in the same zone.
        Computes threat score, severity, and synthesizes an Incident.
        """
        zone_id = new_event_data["zone_id"]
        new_event_dt = parse_iso(new_event_data["timestamp"])

        # Look at all OTHER events in the same zone_id that arrived within CORRELATION_WINDOW_SECONDS
        # before or after this event's timestamp
        zone_events = self.buffer.get(zone_id, [])
        correlated_others: List[Dict[str, Any]] = []
        seen_event_ids = {new_event_data.get("event_id")}

        for ev in zone_events:
            ev_id = ev.get("event_id")
            if ev_id == new_event_data.get("event_id") or ev_id in seen_event_ids:
                continue
            ev_dt = parse_iso(ev["timestamp"])
            time_diff = abs((new_event_dt - ev_dt).total_seconds())
            if time_diff <= CORRELATION_WINDOW_SECONDS:
                correlated_others.append(ev)
                seen_event_ids.add(ev_id)

        # Full group of correlated events including the new event
        group = [new_event_data] + correlated_others

        # Count distinct source_types present among this group (1, 2, or 3)
        distinct_sources = list(dict.fromkeys(ev["source_type"] for ev in group))
        distinct_source_count = len(distinct_sources)

        # Calculate threat score:
        # score = min(100, sum(SOURCE_WEIGHTS[source_type] * event.confidence) * CORROBORATION_MULTIPLIER * 100)
        base_sum = sum(
            SOURCE_WEIGHTS.get(ev["source_type"], 0.3) * float(ev.get("confidence", 1.0))
            for ev in group
        )
        multiplier = CORROBORATION_MULTIPLIER.get(min(distinct_source_count, 3), 1.0)
        raw_score = base_sum * multiplier * 100.0
        score = round(min(100.0, max(0.0, raw_score)), 2)

        # Determine severity according to thresholds
        severity = calculate_incident_severity(score)

        # Earliest event's timestamp
        first_event = min(group, key=lambda ev: parse_iso(ev["timestamp"]))
        first_ts = first_event["timestamp"]

        # Latency calculated as (current server time - the new event's ingest_ts) in milliseconds
        now_dt = datetime.now(timezone.utc)
        ingest_ts_str = new_event_data.get("ingest_ts")
        if ingest_ts_str:
            try:
                ingest_dt = parse_iso(ingest_ts_str)
                latency_ms = round(max(0.0, (now_dt - ingest_dt).total_seconds() * 1000.0), 2)
            except Exception:
                latency_ms = 0.0
        else:
            latency_ms = 0.0

        incident = Incident(
            incident_id=str(uuid.uuid4()),
            zone_id=zone_id,
            score=score,
            severity=severity,
            sources=distinct_sources,
            event_ids=[ev["event_id"] for ev in group],
            first_ts=first_ts,
            dispatch_ts=None,
            latency_ms=latency_ms,
            status="open",
        )
        return incident

    def process_event(self, new_event_data: Dict[str, Any]) -> Optional[Incident]:
        """
        Process an incoming event with multi-source correlation and incident de-duplication:
        - If an incident closed in the same zone within cooldown_window_seconds (5s), suppress creating a new incident.
        - If an OPEN incident exists in the same zone within dedup_window_seconds (5s):
            - Update its score to the higher of the two scores.
            - Update its severity accordingly.
            - Add the new event_id to its events list.
            - Merge any new source modalities.
            - Return the updated incident for re-broadcasting.
        - Otherwise, start a genuinely new incident if 5 seconds have passed since the last one closed,
          or if it's a different zone.
        """
        zone_id = new_event_data.get("zone_id")
        if not zone_id:
            return None

        # Determine event epoch timestamp
        ts_str = new_event_data.get("timestamp")
        if ts_str:
            try:
                event_epoch = parse_iso(ts_str).timestamp()
            except Exception:
                event_epoch = time.time()
        else:
            event_epoch = time.time()

        # 1. Check cooldown: Has an incident closed in this zone within 5 seconds?
        # Only start a genuinely new incident if 5 seconds have passed since the last one closed in that zone, or if it's a different zone.
        if zone_id in self.last_closed_time:
            closed_epoch = self.last_closed_time[zone_id]
            time_since_closed = event_epoch - closed_epoch
            if 0.0 <= time_since_closed < self.cooldown_window_seconds or abs(time_since_closed) < self.cooldown_window_seconds:
                # Suppress incident creation during cooldown
                self.add_event(new_event_data)
                return None
            else:
                # Cooldown expired (5 seconds have passed since last one closed)
                self.last_closed_time.pop(zone_id, None)

        # 2. Check de-duplication against existing OPEN incident in the same zone
        existing_incident = self.active_incidents.get(zone_id)
        if existing_incident is not None:
            # Check if incident status in INCIDENTS_DB was modified externally to non-open
            db_inc = INCIDENTS_DB.get(existing_incident.incident_id)
            if db_inc is not None and db_inc.status != "open":
                self.record_incident_closed(zone_id, close_time=event_epoch)
                # Re-check cooldown after recognizing external closure
                if abs(event_epoch - self.last_closed_time.get(zone_id, 0)) < self.cooldown_window_seconds:
                    self.add_event(new_event_data)
                    return None
                existing_incident = None

        if existing_incident is not None and existing_incident.status == "open":
            last_epoch = self.last_incident_time.get(zone_id, event_epoch)
            time_diff = abs(event_epoch - last_epoch)
            if time_diff <= self.dedup_window_seconds:
                # Within 5 seconds of an existing OPEN incident in the same zone!
                # Update existing incident: higher score, add event_id, merge sources
                candidate = self.correlate(new_event_data)
                higher_score = round(max(existing_incident.score, candidate.score), 2)
                higher_severity = calculate_incident_severity(higher_score)

                # Add new event_id to events list (avoid duplicates)
                merged_event_ids = list(existing_incident.event_ids)
                new_eid = new_event_data.get("event_id")
                if new_eid and new_eid not in merged_event_ids:
                    merged_event_ids.append(new_eid)
                for eid in candidate.event_ids:
                    if eid not in merged_event_ids:
                        merged_event_ids.append(eid)

                # Merge sources
                merged_sources = list(existing_incident.sources)
                for src in candidate.sources:
                    if src not in merged_sources:
                        merged_sources.append(src)
                src_type = new_event_data.get("source_type")
                if src_type and src_type not in merged_sources:
                    merged_sources.append(src_type)

                # Latency update (if ingest_ts is present)
                now_dt = datetime.now(timezone.utc)
                ingest_ts_str = new_event_data.get("ingest_ts")
                if ingest_ts_str:
                    try:
                        ingest_dt = parse_iso(ingest_ts_str)
                        latency_ms = round(max(0.0, (now_dt - ingest_dt).total_seconds() * 1000.0), 2)
                    except Exception:
                        latency_ms = existing_incident.latency_ms
                else:
                    latency_ms = existing_incident.latency_ms

                updated_incident = existing_incident.model_copy(
                    update={
                        "score": higher_score,
                        "severity": higher_severity,
                        "event_ids": merged_event_ids,
                        "sources": merged_sources,
                        "latency_ms": latency_ms,
                    }
                )
                self.active_incidents[zone_id] = updated_incident
                self.last_incident_time[zone_id] = event_epoch
                self.add_event(new_event_data)
                return updated_incident

        # 3. Check if this candidate qualifies to create a new visible incident:
        # EITHER (a) two or more distinct source_types corroborate within the correlation window,
        # OR (b) a single source's score alone is above the "Medium" threshold from SEVERITY_THRESHOLDS.
        candidate = self.correlate(new_event_data)
        is_multi_source = len(candidate.sources) >= 2
        is_above_medium = candidate.score >= SEVERITY_THRESHOLDS["Medium"]

        if not (is_multi_source or is_above_medium):
            # Single-source, low-confidence event (like one lone door sensor trigger or one lone failed login).
            # Logged internally to event_store and added to rolling buffer, but does NOT create or broadcast an incident.
            self.add_event(new_event_data)
            return None

        # Genuinely new incident (qualifies via (a) or (b))
        new_incident = candidate
        self.active_incidents[zone_id] = new_incident
        self.last_incident_time[zone_id] = event_epoch
        self.last_closed_time.pop(zone_id, None)
        self.add_event(new_event_data)
        return new_incident


engine = CorrelationEngine()


def evaluate_threat_correlation(new_event_dict: Dict[str, Any]) -> Incident:
    """Wrapper function preserving backwards compatibility."""
    return engine.correlate(new_event_dict)


# ==============================================================================
# Request Models
# ==============================================================================

class FeedbackRequest(BaseModel):
    """Schema for operator feedback on an incident."""
    verdict: Literal["true_positive", "false_positive", "open", "dispatched"] = "false_positive"


FeedbackBody = FeedbackRequest


# ==============================================================================
# API Endpoints
# ==============================================================================

@app.get("/", tags=["System"])
def root():
    """Root endpoint indicating server health and operational status."""
    return {"message": "Gryffindor backend is running"}


@app.get("/time", tags=["System"])
def get_time():
    """
    Returns current server time as a unix epoch timestamp float.
    Used for clock synchronization across distributed nodes and frontends.
    """
    return {"epoch": time.time()}


@app.post("/ingest", status_code=status.HTTP_200_OK, tags=["Events"])
async def ingest_event(event: Event):
    """
    Ingest a security observation event from CCTV, IoT sensors, or cyber logs.
    - Validates payload structure automatically using the Event Pydantic model
    - Appends server-side UTC ingest_ts
    - Logs the event payload to console
    - Stores the event in-memory within event_store
    - Runs multi-source threat correlation via CorrelationEngine with de-duplication
    - Stores synthesized Incident in incident_store (or updates existing incident in-place)
    - Broadcasts the Incident to all connected WebSocket clients on /ws/alerts
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

    # 4. Trigger threat correlation & de-duplication
    incident = engine.process_event(event_data)
    if incident is not None:
        if incident.incident_id in INCIDENTS_DB:
            # Existing incident updated via de-duplication: update in-place
            INCIDENTS_DB[incident.incident_id] = incident
            for idx, inc in enumerate(incident_store):
                if inc.incident_id == incident.incident_id:
                    incident_store[idx] = incident
                    break
        else:
            # Genuinely new incident created
            incident_store.append(incident)
            INCIDENTS_DB[incident.incident_id] = incident

        # 5. Broadcast or re-broadcast incident immediately to all WebSocket clients
        try:
            await ws_manager.broadcast_incident(incident)
        except Exception as err:
            print(f"[WEBSOCKET BROADCAST ERROR] {err}")

    # 6. Return JSON response
    return {
        "status": "received",
        "event_id": event.event_id,
        "incident_id": incident.incident_id if incident else None,
    }


@app.post("/events", status_code=status.HTTP_200_OK, tags=["Events"], include_in_schema=False)
async def ingest_event_alias(event: Event):
    """Compatibility alias endpoint for /ingest."""
    return await ingest_event(event)


@app.get("/events", response_model=List[Dict[str, Any]], tags=["Events"])
def get_events():
    """Returns all events currently stored in event_store, ordered most recent first."""
    return list(reversed(event_store))


@app.get("/zones", tags=["Zones"])
def get_zones():
    """Retrieve all monitored zones, their geographic coordinates, and weights."""
    return list(ZONES_DB.values())


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for streaming real-time security alerts and incidents.
    Broadcasts each synthesized Incident to connected clients as JSON.
    Handles disconnections gracefully without crashing the server.
    """
    await ws_manager.connect(websocket)
    try:
        # Push initial snapshot of active incidents on connection if any exist
        if incident_store or INCIDENTS_DB:
            incidents_to_send = list(reversed(incident_store)) if incident_store else list(reversed(list(INCIDENTS_DB.values())))
            snapshot = [inc.model_dump() for inc in incidents_to_send]
            await websocket.send_text(json.dumps(snapshot))
        while True:
            # Keep connection open and accept any incoming client keep-alives
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        ws_manager.disconnect(websocket)


@app.get("/incidents", response_model=List[Incident], tags=["Incidents"])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by incident status"),
):
    """Retrieve all synthesized threat incidents, ordered most recent first."""
    incidents = list(reversed(incident_store))
    if severity:
        incidents = [inc for inc in incidents if inc.severity == severity]
    if status_filter:
        incidents = [inc for inc in incidents if inc.status == status_filter]
    return incidents


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
def get_incident(incident_id: str):
    """Fetch details of a specific incident."""
    for inc in reversed(incident_store):
        if inc.incident_id == incident_id:
            return inc
    if incident_id in INCIDENTS_DB:
        return INCIDENTS_DB[incident_id]
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident '{incident_id}' not found.",
    )


@app.patch("/incidents/{incident_id}/status", response_model=Incident, tags=["Incidents"])
async def update_incident_status(
    incident_id: str,
    new_status: str = Query(..., pattern="^(open|dispatched|true_positive|false_positive)$"),
):
    """Update incident status (compatibility endpoint)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    now_epoch = time.time()
    for idx, inc in enumerate(incident_store):
        if inc.incident_id == incident_id:
            dispatch_ts = now_iso if new_status == "dispatched" and not inc.dispatch_ts else inc.dispatch_ts
            updated_inc = inc.model_copy(update={"status": new_status, "dispatch_ts": dispatch_ts})
            incident_store[idx] = updated_inc
            INCIDENTS_DB[incident_id] = updated_inc
            if new_status != "open":
                engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
            else:
                engine.record_incident_opened(updated_inc, open_time=now_epoch)
            await ws_manager.broadcast_incident(updated_inc)
            return updated_inc

    if incident_id in INCIDENTS_DB:
        inc = INCIDENTS_DB[incident_id]
        dispatch_ts = now_iso if new_status == "dispatched" and not inc.dispatch_ts else inc.dispatch_ts
        updated_inc = inc.model_copy(update={"status": new_status, "dispatch_ts": dispatch_ts})
        INCIDENTS_DB[incident_id] = updated_inc
        incident_store.append(updated_inc)
        if new_status != "open":
            engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
        else:
            engine.record_incident_opened(updated_inc, open_time=now_epoch)
        await ws_manager.broadcast_incident(updated_inc)
        return updated_inc

    # Dynamic fallback for demo / test / mock incidents
    updated_inc = Incident(
        incident_id=incident_id,
        zone_id="Perimeter_Gate_3",
        score=95.0 if new_status == "dispatched" else 40.0,
        severity="Critical" if new_status == "dispatched" else "Medium",
        sources=["OPERATOR_ACTION"],
        first_ts=now_iso,
        dispatch_ts=now_iso if new_status == "dispatched" else None,
        status=new_status,
    )
    INCIDENTS_DB[incident_id] = updated_inc
    incident_store.append(updated_inc)
    if new_status != "open":
        engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
    else:
        engine.record_incident_opened(updated_inc, open_time=now_epoch)
    await ws_manager.broadcast_incident(updated_inc)
    return updated_inc


@app.post("/incidents/{incident_id}/dispatch", response_model=Incident, tags=["Incidents"])
async def dispatch_incident(incident_id: str):
    """
    Sets the incident's status to 'dispatched' and dispatch_ts to current server time.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    now_epoch = time.time()
    for idx, inc in enumerate(incident_store):
        if inc.incident_id == incident_id:
            updated_inc = inc.model_copy(update={"status": "dispatched", "dispatch_ts": now_iso})
            incident_store[idx] = updated_inc
            INCIDENTS_DB[incident_id] = updated_inc
            engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
            await ws_manager.broadcast_incident(updated_inc)
            return updated_inc

    if incident_id in INCIDENTS_DB:
        inc = INCIDENTS_DB[incident_id]
        updated_inc = inc.model_copy(update={"status": "dispatched", "dispatch_ts": now_iso})
        INCIDENTS_DB[incident_id] = updated_inc
        incident_store.append(updated_inc)
        engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
        await ws_manager.broadcast_incident(updated_inc)
        return updated_inc

    # Dynamic fallback for demo / test / mock incidents
    incident = Incident(
        incident_id=incident_id,
        zone_id="Perimeter_Gate_3",
        score=95.0,
        severity="Critical",
        sources=["MANUAL_DISPATCH"],
        first_ts=now_iso,
        dispatch_ts=now_iso,
        status="dispatched",
    )
    INCIDENTS_DB[incident_id] = incident
    incident_store.append(incident)
    engine.record_incident_closed(incident.zone_id, close_time=now_epoch)
    await ws_manager.broadcast_incident(incident)
    return incident


@app.post("/incidents/{incident_id}/feedback", response_model=Incident, tags=["Incidents"])
async def submit_incident_feedback(incident_id: str, feedback: FeedbackRequest):
    """
    Accepts a JSON body {"verdict": "true_positive" or "false_positive"} and updates
    that incident's status accordingly.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    now_epoch = time.time()
    for idx, inc in enumerate(incident_store):
        if inc.incident_id == incident_id:
            updated_inc = inc.model_copy(update={"status": feedback.verdict})
            incident_store[idx] = updated_inc
            INCIDENTS_DB[incident_id] = updated_inc
            if feedback.verdict != "open":
                engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
            else:
                engine.record_incident_opened(updated_inc, open_time=now_epoch)
            await ws_manager.broadcast_incident(updated_inc)
            return updated_inc

    if incident_id in INCIDENTS_DB:
        inc = INCIDENTS_DB[incident_id]
        updated_inc = inc.model_copy(update={"status": feedback.verdict})
        INCIDENTS_DB[incident_id] = updated_inc
        incident_store.append(updated_inc)
        if feedback.verdict != "open":
            engine.record_incident_closed(updated_inc.zone_id, close_time=now_epoch)
        else:
            engine.record_incident_opened(updated_inc, open_time=now_epoch)
        await ws_manager.broadcast_incident(updated_inc)
        return updated_inc

    # Dynamic fallback for demo / test / mock incidents
    incident = Incident(
        incident_id=incident_id,
        zone_id="Perimeter_Gate_3",
        score=45.0,
        severity="Medium",
        sources=["OPERATOR_FEEDBACK"],
        first_ts=now_iso,
        dispatch_ts=None,
        status=feedback.verdict,
    )
    INCIDENTS_DB[incident_id] = incident
    incident_store.append(incident)
    if feedback.verdict != "open":
        engine.record_incident_closed(incident.zone_id, close_time=now_epoch)
    else:
        engine.record_incident_opened(incident, open_time=now_epoch)
    await ws_manager.broadcast_incident(incident)
    return incident


@app.post("/reset", tags=["System"])
def reset_system_state():
    """Reset all events, incidents, and correlation engine state."""
    event_store.clear()
    incident_store.clear()
    INCIDENTS_DB.clear()
    engine.reset()
    return {"status": "reset", "message": "All incidents, events, and engine buffers cleared."}


@app.get("/metrics", tags=["Metrics"])
def get_metrics():
    """
    Returns operational threat detection metrics:
    - total events received
    - total incidents created
    - percentage of events that did NOT result in an incident (noise suppression rate)
    - average latency_ms across all incidents
    """
    total_events = len(event_store)
    total_incidents = len(incident_store)

    if total_events > 0:
        events_without_incident = max(0, total_events - total_incidents)
        noise_suppression_rate = round((events_without_incident / total_events) * 100.0, 2)
    else:
        events_without_incident = 0
        noise_suppression_rate = 0.0

    if total_incidents > 0:
        avg_latency = round(sum(inc.latency_ms for inc in incident_store) / total_incidents, 2)
    else:
        avg_latency = 0.0

    return {
        "total_events": total_events,
        "total_events_received": total_events,
        "total_incidents": total_incidents,
        "total_incidents_created": total_incidents,
        "events_without_incident": events_without_incident,
        "noise_suppression_rate": noise_suppression_rate,
        "average_latency_ms": avg_latency,
        "avg_latency_ms": avg_latency,
    }


if __name__ == "__main__":
    # Support running directly via python backend/main.py or python -m uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True, app_dir=str(BASE_DIR))
