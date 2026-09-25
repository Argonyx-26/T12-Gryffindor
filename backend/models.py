"""
Data models for Intelligent Threat Detection & Situational Awareness System.
Defines Pydantic models for incoming sensor/log events and correlated threat incidents.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Event(BaseModel):
    """
    Represents an incoming security observation from CCTV, IoT sensors, or cyber logs.
    """

    event_id: str = Field(
        ...,
        description="Unique identifier for the event",
        min_length=1,
    )
    timestamp: str = Field(
        ...,
        description="Event occurrence timestamp in ISO-8601 UTC format (e.g., '2026-09-24T10:15:03.412Z')",
    )
    source_type: Literal["VIDEO", "IOT", "CYBER"] = Field(
        ...,
        description="Originating modality of the event: VIDEO, IOT, or CYBER",
    )
    zone_id: str = Field(
        ...,
        description="Identifier of the monitored physical or logical zone (e.g., 'Perimeter_Gate_3')",
        min_length=1,
    )
    coordinates: List[float] = Field(
        ...,
        min_length=2,
        max_length=2,
        description="Geographic coordinates as [latitude, longitude]",
    )
    event_type: str = Field(
        ...,
        description="Specific detected activity or trigger (e.g., 'person_detected', 'door_open', 'login_failed')",
        min_length=1,
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence score between 0.0 and 1.0",
    )
    raw_meta: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary supplementary metadata payload (device info, bounding boxes, auth details)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_id": "evt-001",
                "timestamp": "2026-09-24T10:15:03.412Z",
                "source_type": "VIDEO",
                "zone_id": "Perimeter_Gate_3",
                "coordinates": [37.4320, -122.1745],
                "event_type": "person_detected",
                "confidence": 0.94,
                "raw_meta": {
                    "camera_id": "cam-gate-03-ext",
                    "bbox": [120, 80, 240, 310],
                },
            }
        }
    )

    @field_validator("timestamp")
    @classmethod
    def validate_iso8601_timestamp(cls, v: str) -> str:
        """Validate that timestamp conforms to ISO-8601 format."""
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Timestamp must be a non-empty string.")
        try:
            # Handle both Python 3.11+ native Z and older replace formats
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(
                f"Timestamp '{v}' is not a valid ISO-8601 format (e.g., '2026-09-24T10:15:03.412Z')."
            ) from e
        return v

    @field_validator("coordinates")
    @classmethod
    def validate_lat_lon_range(cls, v: List[float]) -> List[float]:
        """Validate latitude and longitude ranges."""
        if len(v) != 2:
            raise ValueError("Coordinates must contain exactly two numbers: [latitude, longitude].")
        lat, lon = v[0], v[1]
        if not (-90.0 <= lat <= 90.0):
            raise ValueError(f"Latitude {lat} must be between -90.0 and 90.0 degrees.")
        if not (-180.0 <= lon <= 180.0):
            raise ValueError(f"Longitude {lon} must be between -180.0 and 180.0 degrees.")
        return v


class Incident(BaseModel):
    """
    Represents an aggregated threat alert synthesized across multiple events and sources.
    """

    incident_id: str = Field(
        ...,
        description="Unique identifier for the generated incident alert",
        min_length=1,
    )
    zone_id: str = Field(
        ...,
        description="Zone where the suspicious activity or threat is located",
        min_length=1,
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated threat severity score between 0 and 100",
    )
    severity: Literal["Critical", "High", "Medium", "Low"] = Field(
        ...,
        description="Threat classification level: Critical, High, Medium, or Low",
    )
    sources: List[str] = Field(
        default_factory=list,
        description="Contributing source modalities (e.g., ['VIDEO', 'IOT'])",
    )
    event_ids: List[str] = Field(
        default_factory=list,
        description="Identifiers of underlying events linked to this incident",
    )
    first_ts: str = Field(
        ...,
        description="ISO-8601 timestamp of the first triggering event",
    )
    dispatch_ts: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when alert was dispatched to responders (null if undispatched)",
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Processing latency in milliseconds from first event to alert creation",
    )
    status: str = Field(
        default="open",
        description="Operational incident status: DETECTED, CORRELATED, SCORED, open, dispatched, ACKNOWLEDGED, RESOLVED, true_positive, false_positive",
    )
    explanation: str = Field(
        default="",
        description="Human-readable explanation of why this incident triggered",
    )
    contributing_factors: List[str] = Field(
        default_factory=list,
        description="List of key suspicious factors driving the threat score",
    )
    score_breakdown: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed score contribution breakdown per modality and multiplier",
    )
    confidence_summary: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Aggregated detection confidence across correlated events",
    )
    correlation_summary: str = Field(
        default="",
        description="Summary of correlated event sources and temporal window",
    )
    timeline: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Chronological event and system milestone log",
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Non-executing tactical response recommendations for operators",
    )
    acknowledged_ts: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when operator acknowledged the alert",
    )
    resolved_ts: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when incident was resolved",
    )
    description: Optional[str] = Field(
        default=None,
        description="Operational synopsis or tactical detection summary",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "incident_id": "inc-20260924-0042",
                "zone_id": "Server_Room",
                "score": 88.5,
                "severity": "Critical",
                "sources": ["VIDEO", "IOT", "CYBER"],
                "event_ids": ["evt-001", "evt-002", "evt-003"],
                "first_ts": "2026-09-24T10:15:03.412Z",
                "dispatch_ts": "2026-09-24T10:15:04.120Z",
                "latency_ms": 708.0,
                "status": "dispatched",
            }
        }
    )

    @field_validator("first_ts")
    @classmethod
    def validate_first_ts(cls, v: str) -> str:
        """Validate that first_ts conforms to ISO-8601 format."""
        if not isinstance(v, str) or not v.strip():
            raise ValueError("first_ts must be a non-empty string.")
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(
                f"first_ts '{v}' is not a valid ISO-8601 format."
            ) from e
        return v

    @field_validator("dispatch_ts", "acknowledged_ts", "resolved_ts")
    @classmethod
    def validate_optional_ts(cls, v: Optional[str]) -> Optional[str]:
        """Validate optional timestamp fields when present; permits None or empty string as unset."""
        if v is None or v == "":
            return None
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(
                f"Timestamp '{v}' is not a valid ISO-8601 format."
            ) from e
        return v
