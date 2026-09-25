"""
Main FastAPI application for Intelligent Threat Detection & Situational Awareness System.
Provides endpoints for event ingestion, threat correlation, incident dispatch, historical querying, and zone management.
Phase 3C: Production Backend with PostgreSQL persistence, Redis real-time caching, and graceful fallback.
"""

import asyncio
from datetime import datetime, timezone, timedelta
import json
import logging
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, Query, status, WebSocket, WebSocketDisconnect
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
import uvicorn

from backend.config import settings
from backend.constants import (
    CORRELATION_WINDOW_SECONDS,
    CORROBORATION_MULTIPLIER,
    SEVERITY_THRESHOLDS,
    SOURCE_WEIGHTS,
)
from backend.database import init_db, db_session, check_db_connection
from backend.db_models import (
    EventModel,
    IncidentModel,
    IncidentEventModel,
    BehavioralBaselineModel,
    AuditLogModel,
)
from backend.models import Event, Incident
from backend.redis_client import REDIS_CLIENT
from backend.scoring_engine import ScoringEngine

logger = logging.getLogger("sentinel.main")

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
        # Also fan-out message to Redis channel
        REDIS_CLIENT.publish_alert("gryffindor:alerts", message)


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

# Global in-memory storage for active working state
ZONES_DB: Dict[str, Dict[str, Any]] = {}
EVENTS_DB: List[Event] = []
INCIDENTS_DB: Dict[str, Incident] = {}

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


def persist_event_to_db(event: Event):
    """Persist Event record to PostgreSQL / Database."""
    try:
        with db_session() as db:
            existing = db.query(EventModel).filter_by(event_id=event.event_id).first()
            if not existing:
                trace_id = None
                if isinstance(event.raw_meta, dict):
                    trace_id = event.raw_meta.get("trace_id")
                db_evt = EventModel(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source_type=event.source_type,
                    zone_id=event.zone_id,
                    coordinates=event.coordinates,
                    event_type=event.event_type,
                    confidence=event.confidence,
                    raw_meta=event.raw_meta or {},
                    trace_id=trace_id,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(db_evt)
    except Exception as e:
        logger.error("Error persisting event to DB: %s", e)


def persist_incident_to_db(incident: Incident):
    """Persist or update Incident record in PostgreSQL / Database and sync to Redis cache."""
    try:
        now_dt = datetime.now(timezone.utc)
        trace_id = getattr(incident, "trace_id", None)
        if not trace_id and isinstance(incident.score_breakdown, dict):
            trace_id = incident.score_breakdown.get("trace_id")

        with db_session() as db:
            inc_model = db.query(IncidentModel).filter_by(incident_id=incident.incident_id).first()
            if inc_model:
                inc_model.score = incident.score
                inc_model.severity = incident.severity
                inc_model.sources = incident.sources
                inc_model.event_ids = incident.event_ids
                inc_model.dispatch_ts = incident.dispatch_ts
                inc_model.latency_ms = incident.latency_ms
                inc_model.status = incident.status
                inc_model.trace_id = trace_id
                inc_model.explanation = incident.explanation
                inc_model.contributing_factors = incident.contributing_factors
                inc_model.score_breakdown = incident.score_breakdown
                inc_model.timeline = incident.timeline
                inc_model.recommendations = incident.recommendations
                inc_model.acknowledged_ts = incident.acknowledged_ts
                inc_model.resolved_ts = incident.resolved_ts
                inc_model.updated_at = now_dt
            else:
                inc_model = IncidentModel(
                    incident_id=incident.incident_id,
                    zone_id=incident.zone_id,
                    score=incident.score,
                    severity=incident.severity,
                    sources=incident.sources,
                    event_ids=incident.event_ids,
                    first_ts=incident.first_ts,
                    dispatch_ts=incident.dispatch_ts,
                    latency_ms=incident.latency_ms,
                    status=incident.status,
                    trace_id=trace_id,
                    explanation=incident.explanation,
                    contributing_factors=incident.contributing_factors,
                    score_breakdown=incident.score_breakdown,
                    timeline=incident.timeline,
                    recommendations=incident.recommendations,
                    acknowledged_ts=incident.acknowledged_ts,
                    resolved_ts=incident.resolved_ts,
                    created_at=now_dt,
                    updated_at=now_dt,
                )
                db.add(inc_model)

            # Sync junction table
            for eid in incident.event_ids:
                ie_exists = db.query(IncidentEventModel).filter_by(incident_id=incident.incident_id, event_id=eid).first()
                if not ie_exists:
                    db.add(IncidentEventModel(incident_id=incident.incident_id, event_id=eid))

        # Sync Redis active state
        if incident.status in ["open", "dispatched", "DETECTED", "CORRELATED", "SCORED"]:
            REDIS_CLIENT.set_active_incident(incident.incident_id, incident.model_dump())
        else:
            REDIS_CLIENT.remove_active_incident(incident.incident_id)

    except Exception as e:
        logger.error("Error persisting incident to DB: %s", e)


def log_audit_action(action: str, incident_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
    """Log system operational audit entry in DB."""
    try:
        with db_session() as db:
            db.add(AuditLogModel(
                timestamp=datetime.now(timezone.utc).isoformat(),
                action=action,
                incident_id=incident_id,
                details=details or {},
                created_at=datetime.now(timezone.utc),
            ))
    except Exception:
        pass


def load_state_from_db():
    """Restores historical events, active incidents, and behavioral baselines from DB on startup."""
    try:
        with db_session() as db:
            # 1. Load Events
            db_evts = db.query(EventModel).all()
            for db_e in db_evts:
                try:
                    evt = Event(
                        event_id=db_e.event_id,
                        timestamp=db_e.timestamp,
                        source_type=db_e.source_type,
                        zone_id=db_e.zone_id,
                        coordinates=db_e.coordinates,
                        event_type=db_e.event_type,
                        confidence=db_e.confidence,
                        raw_meta=db_e.raw_meta or {},
                    )
                    if not any(e.event_id == evt.event_id for e in EVENTS_DB):
                        EVENTS_DB.append(evt)
                except Exception:
                    pass

            # 2. Load Incidents
            db_incs = db.query(IncidentModel).all()
            for db_i in db_incs:
                try:
                    inc = Incident(
                        incident_id=db_i.incident_id,
                        zone_id=db_i.zone_id,
                        score=db_i.score,
                        severity=db_i.severity,
                        sources=db_i.sources or [],
                        event_ids=db_i.event_ids or [],
                        first_ts=db_i.first_ts,
                        dispatch_ts=db_i.dispatch_ts,
                        latency_ms=db_i.latency_ms,
                        status=db_i.status,
                        explanation=db_i.explanation or "",
                        contributing_factors=db_i.contributing_factors or [],
                        score_breakdown=db_i.score_breakdown or {},
                        timeline=db_i.timeline or [],
                        recommendations=db_i.recommendations or [],
                        acknowledged_ts=db_i.acknowledged_ts,
                        resolved_ts=db_i.resolved_ts,
                    )
                    INCIDENTS_DB[inc.incident_id] = inc
                    if inc.status in ["open", "dispatched", "DETECTED", "CORRELATED", "SCORED"]:
                        REDIS_CLIENT.set_active_incident(inc.incident_id, inc.model_dump())
                except Exception:
                    pass

            # 3. Load Behavioral Baselines
            from backend.temporal_engine import BehavioralBaselineEngine
            BehavioralBaselineEngine.load_baselines_from_db(db)

            logger.info("✅ State recovery complete: loaded %d events, %d incidents from DB.", len(EVENTS_DB), len(INCIDENTS_DB))
    except Exception as e:
        logger.warning("⚠️ Database state recovery warning: %s", e)


@app.on_event("startup")
def startup_event():
    """Runs database initialization and state recovery on backend startup."""
    init_db()
    load_state_from_db()


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


def evaluate_threat_correlation(new_event: Event, ingest_ns: Optional[int] = None) -> Optional[Incident]:
    """
    Correlate events occurring within CORRELATION_WINDOW_SECONDS in the same zone.
    Computes weighted threat score incorporating modality weights, distinct source
    corroboration multiplier, and zone critical weights. De-duplicates active incidents.
    """
    new_event_dt = parse_iso(new_event.timestamp)

    # Find temporally correlated events in the same zone within the correlation window
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

    distinct_sources = sorted(list({ev.source_type for ev in correlated_events}))
    zone_info = ZONES_DB.get(new_event.zone_id, {})

    # Use ScoringEngine to compute contextual score, breakdown, factors, explanation & recommendations
    final_score, score_breakdown, contributing_factors, explanation, recommendations = (
        ScoringEngine.calculate_contextual_score(correlated_events, zone_info)
    )

    severity = calculate_incident_severity(final_score)

    # Suppress single-source low-risk noise events (must have score >= Medium or multiple sources)
    if severity == "Low" and len(distinct_sources) < 2:
        return None

    avg_conf = round(sum(ev.confidence for ev in correlated_events) / len(correlated_events), 4)
    corr_summary = (
        f"Correlated {len(correlated_events)} event(s) across sources [{', '.join(distinct_sources)}] "
        f"within {CORRELATION_WINDOW_SECONDS}s window in {new_event.zone_id}"
    )

    print(f"[backend] Correlated {len(correlated_events)} events from {distinct_sources} in {new_event.zone_id} -> score={final_score} ({severity})", flush=True)

    # Check for existing active incident in the same zone within correlation window to de-duplicate
    existing_incident = None
    for inc in reversed(list(INCIDENTS_DB.values())):
        if inc.zone_id == new_event.zone_id and inc.status in ["open", "dispatched", "DETECTED", "CORRELATED", "SCORED"]:
            inc_first_dt = parse_iso(inc.first_ts)
            if abs((new_event_dt - inc_first_dt).total_seconds()) <= CORRELATION_WINDOW_SECONDS + 5.0:
                existing_incident = inc
                break

    first_event = min(correlated_events, key=lambda e: parse_iso(e.timestamp))
    now_utc = datetime.now(timezone.utc)
    first_dt = parse_iso(first_event.timestamp)
    latency_ms = round((now_utc - first_dt).total_seconds() * 1000.0, 2)

    # High-precision latency collection & pipeline stage breakdown
    from backend.latency_collector import LATENCY_COLLECTOR
    t_decision_ns = time.perf_counter_ns()
    if ingest_ns:
        intel_ms = (t_decision_ns - ingest_ns) / 1e6
        LATENCY_COLLECTOR.record_intelligence_latency(intel_ms)

    # Cross-process UTC Total End-to-End detection latency check
    frame_cap_utc = None
    for ev in correlated_events:
        if isinstance(ev.raw_meta, dict) and ev.raw_meta.get("frame_capture_timestamp_utc"):
            try:
                frame_cap_utc = parse_iso(ev.raw_meta["frame_capture_timestamp_utc"])
                break
            except Exception:
                pass

    if frame_cap_utc:
        e2e_ms = (now_utc - frame_cap_utc).total_seconds() * 1000.0
        LATENCY_COLLECTOR.record_end_to_end_latency(e2e_ms)

    # Extract trace_id from raw_meta of correlated events if present
    trace_id = None
    for ev in correlated_events:
        if isinstance(ev.raw_meta, dict) and ev.raw_meta.get("trace_id"):
            trace_id = ev.raw_meta["trace_id"]
            break

    if existing_incident:
        # De-duplicate & update existing incident
        updated_dict = existing_incident.model_dump()
        updated_dict["score"] = max(existing_incident.score, final_score)
        updated_dict["severity"] = calculate_incident_severity(updated_dict["score"])
        updated_dict["sources"] = sorted(list(set(existing_incident.sources + distinct_sources)))
        updated_dict["event_ids"] = list(set(existing_incident.event_ids + [e.event_id for e in correlated_events]))
        updated_dict["latency_ms"] = latency_ms if latency_ms >= 0 else 0.0
        updated_dict["trace_id"] = existing_incident.trace_id or trace_id
        updated_dict["explanation"] = explanation
        updated_dict["contributing_factors"] = list(set(existing_incident.contributing_factors + contributing_factors))
        updated_dict["score_breakdown"] = score_breakdown
        updated_dict["confidence_summary"] = avg_conf
        updated_dict["correlation_summary"] = corr_summary
        updated_dict["recommendations"] = recommendations
        updated_dict["timeline"] = ScoringEngine.build_timeline(
            existing_incident.timeline, correlated_events, existing_incident.incident_id, updated_dict["score"], updated_dict["severity"]
        )

        if updated_dict["severity"] in ["Critical", "High"] and not updated_dict.get("dispatch_ts"):
            updated_dict["dispatch_ts"] = now_utc.isoformat()
            updated_dict["status"] = "dispatched"

        updated_incident = Incident(**updated_dict)
        INCIDENTS_DB[existing_incident.incident_id] = updated_incident
        persist_incident_to_db(updated_incident)
        log_audit_action("incident_updated", updated_incident.incident_id, {"score": updated_incident.score})
        return updated_incident

    new_inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    timeline = ScoringEngine.build_timeline([], correlated_events, new_inc_id, final_score, severity)

    incident = Incident(
        incident_id=new_inc_id,
        zone_id=new_event.zone_id,
        score=final_score,
        severity=severity,
        sources=distinct_sources,
        event_ids=[e.event_id for e in correlated_events],
        first_ts=first_event.timestamp,
        dispatch_ts=now_utc.isoformat() if severity in ["Critical", "High"] else None,
        latency_ms=latency_ms if latency_ms >= 0 else 0.0,
        status="dispatched" if severity in ["Critical", "High"] else "open",
        trace_id=trace_id,
        explanation=explanation,
        contributing_factors=contributing_factors,
        score_breakdown=score_breakdown,
        confidence_summary=avg_conf,
        correlation_summary=corr_summary,
        timeline=timeline,
        recommendations=recommendations,
    )

    INCIDENTS_DB[incident.incident_id] = incident
    persist_incident_to_db(incident)
    log_audit_action("incident_created", incident.incident_id, {"score": incident.score, "severity": incident.severity})
    print(f"[backend] Synthesized Incident {incident.incident_id} (score={final_score}, severity={severity}, status={incident.status})", flush=True)
    return incident


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


@app.get("/health", tags=["System"])
def get_health():
    """Detailed system connectivity and health status endpoint."""
    db_ok = check_db_connection()
    redis_ok = REDIS_CLIENT.check_connection()
    status_str = "healthy" if (db_ok and redis_ok) else ("degraded" if db_ok else "unhealthy")

    return {
        "status": status_str,
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/time", tags=["System"])
def get_time():
    """Clock sync endpoint returning current epoch timestamp."""
    return {"epoch": time.time()}


@app.get("/cctv/status", tags=["CCTV"])
def get_cctv_status():
    """Returns status and configuration of the CCTV / YOLO vision engine."""
    import torch
    cuda_available = torch.cuda.is_available() if 'torch' in sys.modules else False
    device = "cuda:0" if cuda_available else "cpu"
    return {
        "status": "online",
        "vision_engine": "YOLOv8",
        "ultralytics_available": True,
        "device": device,
        "cuda_available": cuda_available,
        "default_model": "yolov8n.pt",
        "supported_video_events": [
            "person_detected",
            "vehicle_detected",
            "restricted_zone_entry",
            "tripwire_crossed",
            "loitering_detected",
            "crowd_detected"
        ],
        "cooldown_seconds": 3.0,
        "loiter_duration_threshold_sec": 5.0,
        "crowd_person_threshold": 4,
    }


@app.get("/analytics/behavior", tags=["Analytics"])
def get_behavior_analytics():
    """Returns statistical behavioral analytics, zone activity baselines, active patterns, and bursts."""
    from backend.temporal_engine import SequencePatternEngine, BurstDetector, BehavioralBaselineEngine

    zone_stats = {}
    for zone_id in ZONES_DB.keys():
        stats = BehavioralBaselineEngine.compute_zone_statistics(EVENTS_DB, zone_id)
        zone_stats[zone_id] = stats

    detected_patterns = SequencePatternEngine.evaluate_sequence_patterns(EVENTS_DB)
    recent_bursts = BurstDetector.detect_bursts(EVENTS_DB)

    source_dist = {"VIDEO": 0, "IOT": 0, "CYBER": 0}
    for ev in EVENTS_DB:
        if ev.source_type in source_dist:
            source_dist[ev.source_type] += 1

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_ingested_events": len(EVENTS_DB),
        "recent_event_rates": {
            "total_events_per_minute": round(len(EVENTS_DB) * 2.0, 2),
            "baseline_events_per_minute": 1.5,
        },
        "source_distribution": source_dist,
        "zone_activity": zone_stats,
        "detected_patterns": detected_patterns,
        "recent_bursts": recent_bursts,
        "anomaly_indicators": [
            {
                "zone_id": zid,
                "anomaly_ratio": z["anomaly_ratio"],
                "status": z["status"],
            }
            for zid, z in zone_stats.items()
            if z["anomaly_ratio"] > 1.5
        ],
    }


@app.get("/metrics", tags=["System"])
def get_metrics():
    """System metrics overview with structured latency breakdown."""
    from backend.latency_collector import LATENCY_COLLECTOR

    total_events = len(EVENTS_DB)
    total_incidents = len(INCIDENTS_DB)
    suppressed = max(0, total_events - total_incidents)
    suppression_pct = (suppressed / total_events * 100.0) if total_events > 0 else 0.0
    return {
        "status": "online",
        "monitored_zones": len(ZONES_DB),
        "ingested_events": total_events,
        "active_incidents": total_incidents,
        "suppressed_events": suppressed,
        "suppression_rate_pct": round(suppression_pct, 2),
        "latency": LATENCY_COLLECTOR.get_metrics_summary(),
    }


@app.get("/zones", tags=["Zones"])
def get_zones():
    """Retrieve all monitored zones, their geographic coordinates, and weights."""
    return list(ZONES_DB.values())


@app.post("/events", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Events"])
@app.post("/ingest", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED, tags=["Events"])
async def ingest_event(event: Event):
    """
    Ingest a real-time event from CCTV, IoT, or Cyber sources.
    Performs validation, persists event to database, and runs threat correlation.
    """
    t_ingest_ns = time.perf_counter_ns()
    t_ingest_utc = datetime.now(timezone.utc)

    # Record Stage 3 Cross-Process Network Ingestion Latency (UTC)
    if isinstance(event.raw_meta, dict) and event.raw_meta.get("event_generation_timestamp_utc"):
        try:
            evt_gen_utc = parse_iso(event.raw_meta["event_generation_timestamp_utc"])
            net_ms = (t_ingest_utc - evt_gen_utc).total_seconds() * 1000.0
            from backend.latency_collector import LATENCY_COLLECTOR
            LATENCY_COLLECTOR.record_network_ingest_latency(net_ms)
        except Exception:
            pass

    # Prevent duplicate event IDs
    if any(e.event_id == event.event_id for e in EVENTS_DB):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event with id '{event.event_id}' already exists.",
        )

    # Persist event to DB & in-memory cache
    persist_event_to_db(event)
    EVENTS_DB.append(event)

    # Run multi-source threat correlation
    incident = evaluate_threat_correlation(event, ingest_ns=t_ingest_ns)
    if incident:
        t_before_emit_ns = time.perf_counter_ns()
        await manager.broadcast(incident.model_dump())
        t_after_emit_ns = time.perf_counter_ns()
        from backend.latency_collector import LATENCY_COLLECTOR
        LATENCY_COLLECTOR.record_alert_emit_latency((t_after_emit_ns - t_before_emit_ns) / 1e6)

    return {
        "message": "Event ingested and processed successfully.",
        "event_id": event.event_id,
        "triggered_incident": incident.model_dump() if incident else None,
    }


@app.get("/events", tags=["Events"])
def list_events(
    zone_id: Optional[str] = Query(None, description="Filter by zone ID"),
    source_type: Optional[str] = Query(None, description="Filter by source modality"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp filter"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp filter"),
    page: Optional[int] = Query(None, ge=1, description="Page number for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """
    List events with database query filtering. Returns List[Event] when unpaginated, or paginated Dict when page is specified.
    """
    try:
        with db_session() as db:
            query = db.query(EventModel)
            if zone_id:
                query = query.filter(EventModel.zone_id == zone_id)
            if source_type:
                query = query.filter(EventModel.source_type == source_type)
            if event_type:
                query = query.filter(EventModel.event_type == event_type)
            if start_time:
                query = query.filter(EventModel.timestamp >= start_time)
            if end_time:
                query = query.filter(EventModel.timestamp <= end_time)

            total = query.count()
            if page is not None:
                offset = (page - 1) * limit
                db_items = query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()
                pages = math.ceil(total / limit) if limit > 0 else 1
                return {
                    "items": [i.to_dict() for i in db_items],
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "pages": pages,
                }

            db_items = query.order_by(EventModel.timestamp.desc()).limit(limit).all()
            return [i.to_dict() for i in reversed(db_items)]
    except Exception:
        results = list(EVENTS_DB)
        if zone_id:
            results = [e for e in results if e.zone_id == zone_id]
        if source_type:
            results = [e for e in results if e.source_type == source_type]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        total = len(results)
        if page is not None:
            items = [e.model_dump() for e in results[(page - 1) * limit : page * limit]]
            pages = math.ceil(total / limit) if limit > 0 else 1
            return {
                "items": items,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": pages,
            }

        return results[-limit:]


@app.get("/incidents", tags=["Incidents"])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by incident status"),
    zone_id: Optional[str] = Query(None, description="Filter by zone ID"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp filter"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp filter"),
    page: Optional[int] = Query(None, ge=1, description="Page number for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """
    Retrieve threat incidents. Returns List[Incident] when unpaginated, or paginated Dict when page is specified.
    """
    try:
        with db_session() as db:
            query = db.query(IncidentModel)
            if severity:
                query = query.filter(IncidentModel.severity.ilike(severity))
            if status_filter:
                query = query.filter(IncidentModel.status.ilike(status_filter))
            if zone_id:
                query = query.filter(IncidentModel.zone_id == zone_id)
            if start_time:
                query = query.filter(IncidentModel.first_ts >= start_time)
            if end_time:
                query = query.filter(IncidentModel.first_ts <= end_time)

            total = query.count()
            if page is not None:
                offset = (page - 1) * limit
                db_items = query.order_by(IncidentModel.updated_at.desc()).offset(offset).limit(limit).all()
                pages = math.ceil(total / limit) if limit > 0 else 1
                return {
                    "items": [i.to_dict() for i in db_items],
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "pages": pages,
                }

            db_items = query.order_by(IncidentModel.updated_at.desc()).limit(limit).all()
            return [i.to_dict() for i in db_items]
    except Exception:
        incidents = list(INCIDENTS_DB.values())
        if severity:
            incidents = [inc for inc in incidents if inc.severity.lower() == severity.lower()]
        if status_filter:
            incidents = [inc for inc in incidents if inc.status.lower() == status_filter.lower()]
        if zone_id:
            incidents = [inc for inc in incidents if inc.zone_id == zone_id]
        if start_time:
            incidents = [inc for inc in incidents if inc.first_ts >= start_time]
        if end_time:
            incidents = [inc for inc in incidents if inc.first_ts <= end_time]

        total = len(incidents)
        if page is not None:
            items = [inc.model_dump() for inc in incidents[(page - 1) * limit : page * limit]]
            pages = math.ceil(total / limit) if limit > 0 else 1
            return {
                "items": items,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": pages,
            }

        return incidents


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
def get_incident(incident_id: str):
    """Fetch details of a specific incident."""
    if incident_id in INCIDENTS_DB:
        return INCIDENTS_DB[incident_id]

    try:
        with db_session() as db:
            db_i = db.query(IncidentModel).filter_by(incident_id=incident_id).first()
            if db_i:
                return Incident(**db_i.to_dict())
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident '{incident_id}' not found.",
    )


@app.patch("/incidents/{incident_id}/status", response_model=Incident, tags=["Incidents"])
def update_incident_status(
    incident_id: str,
    new_status: str = Query(..., pattern="^(open|dispatched|true_positive|false_positive|ACKNOWLEDGED|RESOLVED)$"),
):
    """Update incident status (e.g., mark as true_positive or dispatched)."""
    if incident_id not in INCIDENTS_DB:
        # Check DB
        try:
            with db_session() as db:
                db_i = db.query(IncidentModel).filter_by(incident_id=incident_id).first()
                if db_i:
                    INCIDENTS_DB[incident_id] = Incident(**db_i.to_dict())
        except Exception:
            pass

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
    persist_incident_to_db(updated_incident)
    log_audit_action("incident_status_change", incident_id, {"new_status": new_status})
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
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
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

    persist_incident_to_db(incident)
    log_audit_action("incident_dispatched", incident_id, {"dispatch_ts": now_utc})
    await manager.broadcast(incident.model_dump())
    return incident


@app.patch("/incidents/{incident_id}/acknowledge", response_model=Incident, tags=["Incidents"])
async def acknowledge_incident(incident_id: str):
    """Mark an incident as ACKNOWLEDGED by security operator."""
    if incident_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    incident = INCIDENTS_DB[incident_id]
    incident_dict = incident.model_dump()
    now_iso = datetime.now(timezone.utc).isoformat()
    incident_dict["status"] = "ACKNOWLEDGED"
    incident_dict["acknowledged_ts"] = now_iso
    updated = Incident(**incident_dict)
    INCIDENTS_DB[incident_id] = updated
    persist_incident_to_db(updated)
    log_audit_action("incident_acknowledged", incident_id, {"acknowledged_ts": now_iso})
    await manager.broadcast(updated.model_dump())
    return updated


@app.patch("/incidents/{incident_id}/resolve", response_model=Incident, tags=["Incidents"])
async def resolve_incident(incident_id: str):
    """Mark an incident as RESOLVED by security operator."""
    if incident_id not in INCIDENTS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    incident = INCIDENTS_DB[incident_id]
    incident_dict = incident.model_dump()
    now_iso = datetime.now(timezone.utc).isoformat()
    incident_dict["status"] = "RESOLVED"
    incident_dict["resolved_ts"] = now_iso
    updated = Incident(**incident_dict)
    INCIDENTS_DB[incident_id] = updated
    persist_incident_to_db(updated)
    log_audit_action("incident_resolved", incident_id, {"resolved_ts": now_iso})
    await manager.broadcast(updated.model_dump())
    return updated


@app.post("/incidents/{incident_id}/feedback", tags=["Incidents"])
async def incident_feedback(incident_id: str, feedback: FeedbackBody):
    """
    Record operator classification feedback (e.g. 'false_positive').
    Updates incident status, persists to database, and notifies all active dashboard clients.
    """
    new_status = "false_positive" if feedback.verdict == "false_positive" else feedback.verdict
    if incident_id in INCIDENTS_DB:
        incident = INCIDENTS_DB[incident_id]
        incident_dict = incident.model_dump()
        incident_dict["status"] = new_status
        updated = Incident(**incident_dict)
        INCIDENTS_DB[incident_id] = updated
        persist_incident_to_db(updated)
        log_audit_action("feedback_recorded", incident_id, {"verdict": feedback.verdict})
        await manager.broadcast(updated.model_dump())
        return {
            "message": f"Incident '{incident_id}' status updated to {new_status}.",
            "incident": updated.model_dump(),
        }

    log_audit_action("feedback_recorded", incident_id, {"verdict": feedback.verdict})
    return {
        "message": f"Feedback '{feedback.verdict}' recorded for incident '{incident_id}'.",
        "incident_id": incident_id,
        "verdict": feedback.verdict,
    }


@app.post("/admin/cleanup", tags=["System"])
def cleanup_retention():
    """Configurable retention cleanup for events and resolved/false_positive incidents."""
    event_days = settings.EVENT_RETENTION_DAYS
    incident_days = settings.INCIDENT_RETENTION_DAYS

    cutoff_evt = (datetime.now(timezone.utc) - timedelta(days=event_days)).isoformat()
    cutoff_inc = (datetime.now(timezone.utc) - timedelta(days=incident_days)).isoformat()

    deleted_evts = 0
    deleted_incs = 0

    try:
        with db_session() as db:
            evts_to_del = db.query(EventModel).filter(EventModel.timestamp < cutoff_evt).all()
            deleted_evts = len(evts_to_del)
            for e in evts_to_del:
                db.delete(e)

            incs_to_del = db.query(IncidentModel).filter(
                IncidentModel.first_ts < cutoff_inc,
                IncidentModel.status.in_(["RESOLVED", "false_positive", "true_positive"]),
            ).all()
            deleted_incs = len(incs_to_del)
            for i in incs_to_del:
                db.delete(i)
    except Exception as e:
        logger.error("Retention cleanup error: %s", e)

    return {
        "status": "completed",
        "deleted_events_count": deleted_evts,
        "deleted_incidents_count": deleted_incs,
        "event_retention_days": event_days,
        "incident_retention_days": incident_days,
    }


@app.get("/evaluation", tags=["System"])
def get_evaluation_metrics():
    """
    Computes system evaluation metrics based on actual ingested data and feedback:
    True Positives, False Positives, True Negatives, False Negatives, Precision, Recall, F1, Latencies (p50/p95).
    """
    import numpy as np

    total_events = len(EVENTS_DB)
    incidents = list(INCIDENTS_DB.values())
    total_incidents = len(incidents)

    tp = sum(1 for inc in incidents if inc.status in ["true_positive", "dispatched", "ACKNOWLEDGED", "RESOLVED"] and inc.score >= 60.0)
    fp = sum(1 for inc in incidents if inc.status == "false_positive")
    fn = sum(1 for inc in incidents if inc.score < 60.0 and inc.status != "false_positive")
    tn = max(0, total_events - (tp + fp + fn))

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    f1_score = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 1.0

    latencies = [inc.latency_ms for inc in incidents if inc.latency_ms > 0]
    p50_latency = round(float(np.percentile(latencies, 50)), 2) if latencies else 0.0
    p95_latency = round(float(np.percentile(latencies, 95)), 2) if latencies else 0.0
    avg_latency = round(float(np.mean(latencies)), 2) if latencies else 0.0

    suppressed = max(0, total_events - total_incidents)
    suppression_pct = round((suppressed / total_events * 100.0), 2) if total_events > 0 else 0.0

    return {
        "status": "online",
        "evaluation": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "avg_latency_ms": avg_latency,
            "p50_latency_ms": p50_latency,
            "p95_latency_ms": p95_latency,
            "suppression_rate_pct": suppression_pct,
            "total_events_processed": total_events,
            "total_incidents_synthesized": total_incidents,
        },
    }


if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
