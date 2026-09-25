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
