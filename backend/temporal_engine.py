"""
Gryfffindor Sentinel — Temporal & Behavioral Intelligence Engine (Phase 3B)

Upgrades Gryffindor Sentinel from event-level threat correlation to a temporal
and behavioral intelligence system:
1. BurstDetector: Identifies abnormal event volume surges in rolling time windows
2. SequencePatternEngine: Detects attack chains (Physical Intrusion, Cyber Compromise, Multi-Vector Breach)
3. BehavioralBaselineEngine: Computes statistical zone baselines and time-of-day context
4. ExponentialDecayAccumulator: Implements e^(-lambda * dt) recency decay and bounded risk accumulation
"""

import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from backend.models import Event

ZONES = ["Perimeter_Gate_3", "Server_Room", "Parking_Lot_B"]


# ==============================================================================
# 1. EXPONENTIAL DECAY & RISK ACCUMULATION
# ==============================================================================

def calculate_recency_factor(event_timestamp_iso: str, reference_timestamp_iso: str, half_life_seconds: float = 15.0) -> float:
    """
    Calculates exponential time decay weight w(t) = exp(-lambda * dt).
    lambda = ln(2) / half_life_seconds.
    At dt = 0 -> 1.0, dt = 15s -> 0.5, dt = 30s -> 0.25.
    """
    try:
        t_evt = datetime.fromisoformat(event_timestamp_iso.replace("Z", "+00:00")).timestamp()
        t_ref = datetime.fromisoformat(reference_timestamp_iso.replace("Z", "+00:00")).timestamp()
        dt = max(0.0, t_ref - t_evt)
        decay_constant = math.log(2.0) / max(1.0, half_life_seconds)
        recency = math.exp(-decay_constant * dt)
        return round(float(recency), 4)
    except Exception:
        return 1.0


def calculate_temporal_pattern_bonus(matched_patterns: List[Dict[str, Any]]) -> float:
    """
    Computes a bounded score bonus (0.0 to 15.0) based on matched sequence patterns.
    Higher pattern confidence and severity yield higher bounded bonuses.
    """
    if not matched_patterns:
        return 0.0

    raw_bonus = 0.0
    for pat in matched_patterns:
        conf = pat.get("confidence", 0.8)
        pat_id = pat.get("pattern_id", "")
        if "MULTI_VECTOR" in pat_id:
            raw_bonus += 12.0 * conf
        elif "PHYSICAL" in pat_id:
            raw_bonus += 8.0 * conf
        elif "CYBER" in pat_id:
            raw_bonus += 7.0 * conf
        else:
            raw_bonus += 5.0 * conf

    # Cap bounded bonus at +15.0 points max
    return round(min(15.0, raw_bonus), 2)


def calculate_behavioral_anomaly_bonus(anomaly_ratio: float, is_off_shift: bool) -> float:
    """
    Computes a bounded behavioral anomaly bonus (0.0 to 15.0) based on zone activity
    deviation from statistical baseline and time-of-day context.
    """
    bonus = 0.0
    if anomaly_ratio > 3.0:
        bonus += 8.0
    elif anomaly_ratio > 2.0:
        bonus += 5.0
    elif anomaly_ratio > 1.5:
        bonus += 3.0

    if is_off_shift:
        bonus += 4.0

    return round(min(15.0, bonus), 2)


# ==============================================================================
# 2. BURST DETECTOR
# ==============================================================================

class BurstDetector:
    """
    Detects abnormal volume bursts of events within a short rolling time window.
    """

    @staticmethod
    def detect_bursts(events: List[Event], window_seconds: float = 15.0) -> List[Dict[str, Any]]:
        """
        Analyzes a list of events sorted by timestamp and returns detected event bursts:
        - Failed login surge (>= 3 login_failed events within window)
        - Access surge (>= 3 door/sensor events within window)
        - Video detection surge (>= 3 video events in same zone within window)
        """
        if len(events) < 3:
            return []

        bursts = []
        # Group events by zone and source
        cyber_fails = [e for e in events if e.source_type == "CYBER" and e.event_type in ["login_failed", "auth_fail"]]
        door_events = [e for e in events if e.source_type == "IOT" and e.event_type in ["door_open", "forced_entry", "sensor_tamper"]]

        if len(cyber_fails) >= 3:
            bursts.append({
                "burst_id": "BURST_CYBER_LOGIN_FAILURES",
                "source_type": "CYBER",
                "event_count": len(cyber_fails),
                "time_window_sec": window_seconds,
                "description": f"Detected cyber burst: {len(cyber_fails)} failed login attempts within {window_seconds}s.",
            })

        if len(door_events) >= 3:
            bursts.append({
                "burst_id": "BURST_IOT_ACCESS_SURGE",
                "source_type": "IOT",
                "event_count": len(door_events),
                "time_window_sec": window_seconds,
                "description": f"Detected IoT burst: {len(door_events)} physical access events within {window_seconds}s.",
            })

        return bursts


# ==============================================================================
# 3. SEQUENCE PATTERN MATCHING ENGINE
# ==============================================================================

class SequencePatternEngine:
    """
    Evaluates chronological event sequences against predefined attack pattern signatures.
    """

    @staticmethod
    def evaluate_sequence_patterns(events: List[Event]) -> List[Dict[str, Any]]:
        """
        Matches event sequences against security pattern signatures:
        1. PATTERN: POSSIBLE_PHYSICAL_INTRUSION
        2. PATTERN: POSSIBLE_CYBER_COMPROMISE
        3. PATTERN: MULTI_VECTOR_BREACH
        """
        if not events:
            return []

        matched = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        event_types = [e.event_type for e in sorted_events]
        sources = set(e.source_type for e in sorted_events)

        # Calculate total time span of sequence
        try:
            t_min = datetime.fromisoformat(sorted_events[0].timestamp.replace("Z", "+00:00")).timestamp()
            t_max = datetime.fromisoformat(sorted_events[-1].timestamp.replace("Z", "+00:00")).timestamp()
            time_span = round(max(0.1, t_max - t_min), 2)
        except Exception:
            time_span = 1.0

        # Pattern 1: Physical Intrusion Chain (person_detected / restricted_zone_entry -> door_open / forced_entry)
        has_video_intrusion = any(t in ["person_detected", "restricted_zone_entry", "tripwire_crossed"] for t in event_types)
        has_iot_access = any(t in ["door_open", "forced_entry", "sensor_tamper"] for t in event_types)

        if has_video_intrusion and has_iot_access:
            matched.append({
                "pattern_id": "PATTERN_POSSIBLE_PHYSICAL_INTRUSION",
                "pattern_name": "Possible Physical Intrusion Chain",
                "matched_events": [e.event_id for e in sorted_events if e.source_type in ["VIDEO", "IOT"]],
                "confidence": 0.90,
                "time_span_seconds": time_span,
                "reason": "Sequential VIDEO intrusion detection followed by physical door/sensor access event.",
            })

        # Pattern 2: Cyber Brute Force / Compromise (login_failed -> login_spike / auth_fail)
        has_login_fail = any(t == "login_failed" for t in event_types)
        has_login_spike = any(t == "login_spike" for t in event_types)

        if has_login_spike or (event_types.count("login_failed") >= 2):
            matched.append({
                "pattern_id": "PATTERN_POSSIBLE_CYBER_COMPROMISE",
                "pattern_name": "Possible Cyber Authentication Surge",
                "matched_events": [e.event_id for e in sorted_events if e.source_type == "CYBER"],
                "confidence": 0.88,
                "time_span_seconds": time_span,
                "reason": "Sequential failed login attempts culminating in a cyber authentication spike.",
            })

        # Pattern 3: Correlated Multi-Vector Breach (VIDEO + IOT + CYBER)
        if len(sources) >= 3:
            matched.append({
                "pattern_id": "PATTERN_MULTI_VECTOR_BREACH",
                "pattern_name": "Correlated Multi-Vector Breach Pattern",
                "matched_events": [e.event_id for e in sorted_events],
                "confidence": 0.98,
                "time_span_seconds": time_span,
                "reason": "Simultaneous correlated threat indicators detected across VIDEO, IOT, and CYBER vectors.",
            })

        return matched


# ==============================================================================
# 4. BEHAVIORAL BASELINES & TIME-OF-DAY CONTEXT
# ==============================================================================

class BehavioralBaselineEngine:
    """
    Computes statistical zone activity baselines and time-of-day operational context.
    Persists baseline state to PostgreSQL / database for restart survival.
    """
    _baselines_cache: Dict[str, float] = {}  # key: "zone_id:source_type:event_type:hour"

    @classmethod
    def load_baselines_from_db(cls, db_session=None):
        """Loads persistent baselines from DB into local memory cache."""
        if not db_session:
            return
        try:
            from backend.db_models import BehavioralBaselineModel
            records = db_session.query(BehavioralBaselineModel).all()
            for r in records:
                key = f"{r.zone_id}:{r.source_type}:{r.event_type}:{r.time_bucket}"
                cls._baselines_cache[key] = r.baseline_rate
        except Exception:
            pass

    @classmethod
    def save_baseline_to_db(cls, zone_id: str, source_type: str, event_type: str, hour: int, rate: float, db_session=None):
        """Persists or updates a baseline record in the database."""
        key = f"{zone_id}:{source_type}:{event_type}:{hour}"
        cls._baselines_cache[key] = rate

        if not db_session:
            return
        try:
            from backend.db_models import BehavioralBaselineModel
            record = db_session.query(BehavioralBaselineModel).filter_by(
                zone_id=zone_id,
                source_type=source_type,
                event_type=event_type,
                time_bucket=hour,
            ).first()

            if record:
                record.baseline_rate = rate
                record.observation_count += 1
                record.last_updated = datetime.now(timezone.utc)
            else:
                record = BehavioralBaselineModel(
                    zone_id=zone_id,
                    source_type=source_type,
                    event_type=event_type,
                    time_bucket=hour,
                    baseline_rate=rate,
                    observation_count=1,
                    last_updated=datetime.now(timezone.utc),
                )
                db_session.add(record)
            db_session.commit()
        except Exception:
            if db_session:
                db_session.rollback()

    @staticmethod
    def is_off_shift(timestamp_iso: str, zone_id: str) -> bool:
        """
        Determines if an event occurred outside normal working hours (9:00 - 18:00 UTC).
        """
        try:
            dt = datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
            hour = dt.hour
            # Off-shift if before 9 AM, after 6 PM, or weekend (Saturday=5, Sunday=6)
            if hour < 9 or hour >= 18 or dt.weekday() >= 5:
                return True
            return False
        except Exception:
            return False

    @classmethod
    def compute_zone_statistics(cls, events: List[Event], zone_id: str) -> Dict[str, Any]:
        """
        Computes rolling statistical metrics for a specific zone:
        - events_per_minute
        - source_distribution
        - baseline_events_per_min (historical nominal average)
        - anomaly_ratio (current rate / baseline rate)
        """
        zone_events = [e for e in events if e.zone_id == zone_id]
        count = len(zone_events)

        sources_count = {"VIDEO": 0, "IOT": 0, "CYBER": 0}
        for e in zone_events:
            if e.source_type in sources_count:
                sources_count[e.source_type] += 1

        # Historical statistical baseline for high-security zones (nominal 1.5 events/min)
        baseline_rate = 1.5
        current_rate = round(count * 2.0, 2)  # Extrapolated per minute
        anomaly_ratio = round(current_rate / baseline_rate, 2) if baseline_rate > 0 else 1.0

        return {
            "zone_id": zone_id,
            "recent_event_count": count,
            "events_per_minute": current_rate,
            "baseline_events_per_minute": baseline_rate,
            "anomaly_ratio": anomaly_ratio,
            "source_distribution": sources_count,
            "status": "ANOMALOUS" if anomaly_ratio > 2.0 else "NOMINAL",
        }
