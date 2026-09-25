"""
CCTV / Video Intelligence Interface & Adapter
Standardizes raw CCTV camera feeds, tripwire triggers, and YOLO detections into normalized Event models.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from backend.models import Event


class CCTVAdapter:
    """
    Adapter for converting raw CCTV video analytics and YOLO object detections
    into standardized, context-aware VIDEO Event models.
    """

    SUPPORTED_EVENT_TYPES = {
        "person_detected",
        "vehicle_detected",
        "restricted_zone_entry",
        "tripwire_crossed",
        "loitering_detected",
        "crowd_detected",
        "object_left",
        "object_removed",
    }

    @classmethod
    def format_detection_event(
        cls,
        zone_id: str,
        coordinates: List[float],
        event_type: str = "person_detected",
        confidence: float = 0.90,
        camera_id: str = "CAM-PRIMARY",
        bbox: Optional[List[int]] = None,
        object_class: str = "person",
        tracking_id: Optional[str] = None,
        restricted_zone: bool = False,
        tripwire_id: Optional[str] = None,
        dwell_time: float = 0.0,
        frame_id: Optional[int] = None,
        timestamp: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """
        Creates a validated VIDEO Event instance with rich CCTV intelligence metadata.
        """
        valid_event_type = event_type if event_type in cls.SUPPORTED_EVENT_TYPES else "person_detected"
        now_ts = timestamp or (datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

        raw_meta: Dict[str, Any] = {
            "camera_id": camera_id,
            "bbox": bbox or [0, 0, 0, 0],
            "object_class": object_class,
            "detection_confidence": round(confidence, 4),
            "tracking_id": tracking_id or f"trk-{uuid.uuid4().hex[:6]}",
            "restricted_zone": restricted_zone,
            "tripwire_id": tripwire_id,
            "dwell_time": max(0.0, float(dwell_time)),
            "frame_id": frame_id,
        }
        if extra_meta:
            raw_meta.update(extra_meta)

        return Event(
            event_id=f"evt-cctv-{uuid.uuid4().hex[:8]}",
            timestamp=now_ts,
            source_type="VIDEO",
            zone_id=zone_id,
            coordinates=coordinates,
            event_type=valid_event_type,
            confidence=max(0.0, min(1.0, float(confidence))),
            raw_meta=raw_meta,
        )
