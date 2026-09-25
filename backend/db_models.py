"""
Gryfffindor Sentinel — Database ORM Models (Phase 3C)

Defines persistent database schemas for PostgreSQL & SQLite:
- EventModel (events table)
- IncidentModel (incidents table)
- IncidentEventModel (incident_events junction table)
- BehavioralBaselineModel (behavioral_baselines table)
- AuditLogModel (audit_logs table)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    Text,
    DateTime,
    JSON,
    ForeignKey,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class EventModel(Base):
    """Stores incoming multi-modal security observations (VIDEO, IOT, CYBER)."""
    __tablename__ = "events"

    event_id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    source_type = Column(String(32), nullable=False, index=True)
    zone_id = Column(String(128), nullable=False, index=True)
    coordinates = Column(JSON, nullable=False)  # [lat, lon]
    event_type = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    raw_meta = Column(JSON, nullable=False, default=dict)
    trace_id = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    incidents = relationship("IncidentModel", secondary="incident_events", back_populates="events")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "zone_id": self.zone_id,
            "coordinates": self.coordinates,
            "event_type": self.event_type,
            "confidence": self.confidence,
            "raw_meta": self.raw_meta or {},
        }


class IncidentModel(Base):
    """Stores aggregated threat alert incidents."""
    __tablename__ = "incidents"

    incident_id = Column(String(128), primary_key=True, index=True)
    zone_id = Column(String(128), nullable=False, index=True)
    score = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    sources = Column(JSON, nullable=False, default=list)
    event_ids = Column(JSON, nullable=False, default=list)
    first_ts = Column(String(64), nullable=False, index=True)
    dispatch_ts = Column(String(64), nullable=True)
    latency_ms = Column(Float, nullable=False, default=0.0)
    status = Column(String(32), nullable=False, default="open", index=True)
    trace_id = Column(String(128), nullable=True, index=True)
    explanation = Column(Text, nullable=True, default="")
    contributing_factors = Column(JSON, nullable=True, default=list)
    score_breakdown = Column(JSON, nullable=True, default=dict)
    timeline = Column(JSON, nullable=True, default=list)
    recommendations = Column(JSON, nullable=True, default=list)
    acknowledged_ts = Column(String(64), nullable=True)
    resolved_ts = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    events = relationship("EventModel", secondary="incident_events", back_populates="incidents")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "zone_id": self.zone_id,
            "score": self.score,
            "severity": self.severity,
            "sources": self.sources or [],
            "event_ids": self.event_ids or [],
            "first_ts": self.first_ts,
            "dispatch_ts": self.dispatch_ts,
            "latency_ms": self.latency_ms,
            "status": self.status,
            "explanation": self.explanation or "",
            "contributing_factors": self.contributing_factors or [],
            "score_breakdown": self.score_breakdown or {},
            "timeline": self.timeline or [],
            "recommendations": self.recommendations or [],
            "acknowledged_ts": self.acknowledged_ts,
            "resolved_ts": self.resolved_ts,
        }


class IncidentEventModel(Base):
    """Junction table linking incidents to underlying events."""
    __tablename__ = "incident_events"

    incident_id = Column(String(128), ForeignKey("incidents.incident_id", ondelete="CASCADE"), primary_key=True, index=True)
    event_id = Column(String(128), ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class BehavioralBaselineModel(Base):
    """Stores persistent Phase 3B statistical zone baselines."""
    __tablename__ = "behavioral_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_id = Column(String(128), nullable=False, index=True)
    source_type = Column(String(32), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    time_bucket = Column(Integer, nullable=False, index=True)  # Hour of day (0-23)
    baseline_rate = Column(Float, nullable=False, default=1.5)
    observation_count = Column(Integer, nullable=False, default=1)
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("zone_id", "source_type", "event_type", "time_bucket", name="uq_baseline_bucket"),
    )


class AuditLogModel(Base):
    """Stores operational system audit logs."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(128), nullable=True, index=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
