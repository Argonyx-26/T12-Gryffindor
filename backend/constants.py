"""
Constants and scoring parameters for Intelligent Threat Detection & Situational Awareness System.
"""

from typing import Dict

# Weights assigned to individual event source modalities
SOURCE_WEIGHTS: Dict[str, float] = {
    "VIDEO": 0.35,
    "IOT": 0.35,
    "CYBER": 0.30,
}

# Multiplier applied based on the number of distinct corroborated sources
# (e.g. 1 source = 1.0x, 2 distinct sources = 1.5x, 3 distinct sources = 2.2x)
CORROBORATION_MULTIPLIER: Dict[int, float] = {
    1: 1.0,
    2: 1.5,
    3: 2.2,
}

# Minimum score thresholds for classifying incident severity levels
SEVERITY_THRESHOLDS: Dict[str, int] = {
    "Critical": 80,
    "High": 60,
    "Medium": 40,
    "Low": 0,
}

# Temporal correlation window in seconds to cluster multi-source events into a single incident
CORRELATION_WINDOW_SECONDS: float = 1.5

# Event risk profile weights per modality and event type
# Values scale raw risk contributions while keeping baseline weights intact
EVENT_RISK_PROFILES: Dict[str, Dict[str, float]] = {
    "VIDEO": {
        "person_detected": 0.50,
        "vehicle_detected": 0.45,
        "restricted_zone_entry": 0.90,
        "tripwire_crossed": 0.95,
        "loitering_detected": 0.80,
        "crowd_detected": 0.70,
        "object_left": 0.85,
        "object_removed": 0.85,
    },
    "IOT": {
        "door_open": 0.40,
        "motion": 0.30,
        "forced_entry": 0.95,
        "sensor_tamper": 0.90,
        "off_shift_access": 0.85,
    },
    "CYBER": {
        "login_success": 0.10,
        "login_failed": 0.35,
        "login_spike": 0.90,
        "unusual_login_time": 0.75,
        "new_device": 0.65,
        "privilege_change": 0.85,
        "multiple_account_failures": 0.85,
        "unusual_source": 0.75,
    },
}

# Fallback base risk factor for unknown event types
DEFAULT_EVENT_RISK: float = 0.50

# Shift schedule configuration (start_hour, end_hour in UTC)
DEFAULT_SHIFT_HOURS = (9, 18)
OFF_SHIFT_MULTIPLIER: float = 1.4
RESTRICTED_ZONE_MULTIPLIER: float = 1.35
REPEATED_EVENT_BOOST: float = 1.15
MAX_REPEATED_BOOST: float = 1.40

