"""
Test Threat Scoring Engine (backend/test_scoring.py)
------------------------------------------------------
Validates threat correlation logic, multi-modality corroboration multiplier,
zone weighting (rescaled 0.85 - 1.05), noise suppression, and severity classification.

Simulates:
1. Single-source event (suppressed as non-incident noise)
2. Two-source corroborated event (realistic non-saturated score)
3. Three-source breach (lands in the 88-98 range with decimal precision, Critical severity)
"""

import os
import sys
import unittest
from datetime import datetime, timezone

# Add project root to sys.path for direct python execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.constants import SEVERITY_THRESHOLDS, SOURCE_WEIGHTS, CORROBORATION_MULTIPLIER
from backend.models import Event, Incident
from backend.main import evaluate_threat_correlation, calculate_incident_severity, EVENTS_DB, INCIDENTS_DB, ZONES_DB, load_zones
from backend.scoring_engine import ScoringEngine


class TestThreatScoring(unittest.TestCase):

    def setUp(self):
        """Reset databases and load zone weights directly from data/zones.json."""
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()
        load_zones()

    def test_severity_threshold_classification(self):
        """Verify severity level mapping according to thresholds."""
        self.assertEqual(calculate_incident_severity(85.0), "Critical")
        self.assertEqual(calculate_incident_severity(70.0), "High")
        self.assertEqual(calculate_incident_severity(50.0), "Medium")
        self.assertEqual(calculate_incident_severity(25.0), "Low")

    def test_single_source_noise_suppression(self):
        """Verify that single-source low risk noise events are suppressed (return None)."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        event = Event(
            event_id="test-evt-001",
            timestamp=now_str,
            source_type="IOT",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="door_open",
            confidence=0.8,
            raw_meta={}
        )
        
        EVENTS_DB.append(event)
        incident = evaluate_threat_correlation(event)
        
        # Should be suppressed (return None) because it's single-source Low severity
        self.assertIsNone(incident)
        self.assertEqual(len(INCIDENTS_DB), 0)

    def test_multi_source_corroboration(self):
        """Verify two-source corroboration creates an incident without premature saturation."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        vid_event = Event(
            event_id="test-evt-vid-1",
            timestamp=now_str,
            source_type="VIDEO",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="person_detected",
            confidence=0.90,
            raw_meta={}
        )
        
        iot_event = Event(
            event_id="test-evt-iot-1",
            timestamp=now_str,
            source_type="IOT",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="forced_entry",
            confidence=0.95,
            raw_meta={}
        )

        EVENTS_DB.append(vid_event)
        evaluate_threat_correlation(vid_event)
        
        EVENTS_DB.append(iot_event)
        multi_incident = evaluate_threat_correlation(iot_event)

        self.assertIsNotNone(multi_incident)
        self.assertIn("VIDEO", multi_incident.sources)
        self.assertIn("IOT", multi_incident.sources)
        self.assertEqual(len(multi_incident.sources), 2)
        self.assertGreaterEqual(multi_incident.score, 40.0)

    def test_three_source_breach_score_range(self):
        """
        Verify that a 3-source breach lands in the 88-98 score range with decimal precision,
        rather than clipping at a static 100/100.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        vid_event = Event(
            event_id="test-b-vid",
            timestamp=now_str,
            source_type="VIDEO",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="person_detected",
            confidence=0.90,
            raw_meta={}
        )
        iot_event = Event(
            event_id="test-b-iot",
            timestamp=now_str,
            source_type="IOT",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="door_open",
            confidence=1.00,
            raw_meta={}
        )
        cyber_event = Event(
            event_id="test-b-cyb",
            timestamp=now_str,
            source_type="CYBER",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="login_spike",
            confidence=0.95,
            raw_meta={"username": "admin"}
        )

        EVENTS_DB.extend([vid_event, iot_event, cyber_event])
        incident = evaluate_threat_correlation(cyber_event)

        self.assertIsNotNone(incident)
        self.assertEqual(len(incident.sources), 3)
        self.assertEqual(incident.severity, "Critical")
        self.assertTrue(88.0 <= incident.score <= 98.0, f"Expected 88-98, got {incident.score}")


def print_detailed_scoring_breakdown():
    """Prints a clear, step-by-step scoring report for the user."""
    load_zones()
    zone_info = ZONES_DB.get("Perimeter_Gate_3", {"zone_weight": 1.0})
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    print("=" * 70)
    print("  GRYFFINDOR THREAT SCORING FORMULA VERIFICATION")
    print(f"  Zone: Perimeter_Gate_3 (zone_weight = {zone_info.get('zone_weight', 1.0)})")
    print("=" * 70)

    # 1. Single source event
    ev1 = Event(
        event_id="demo-vid-01",
        timestamp=now_str,
        source_type="VIDEO",
        zone_id="Perimeter_Gate_3",
        coordinates=[12.9716, 77.5946],
        event_type="person_detected",
        confidence=0.90,
    )
    s1_score, s1_breakdown, _, _, _ = ScoringEngine.calculate_contextual_score([ev1], zone_info)
    s1_sev = calculate_incident_severity(s1_score)
    s1_suppressed = s1_sev in ("Low", "Medium")

    print("\n--- 1. SINGLE-SOURCE EVENT ---")
    print(f"  Source:     VIDEO (conf: 0.90, event_type: person_detected)")
    print(f"  Score:      {s1_score} / 100")
    print(f"  Severity:   {s1_sev}")
    print(f"  Status:     {'[SUPPRESSED] (Filtered as non-incident noise)' if s1_suppressed else 'VISIBLE INCIDENT'}")

    # 2. Two-source event
    ev2 = Event(
        event_id="demo-iot-01",
        timestamp=now_str,
        source_type="IOT",
        zone_id="Perimeter_Gate_3",
        coordinates=[12.9716, 77.5946],
        event_type="door_open",
        confidence=1.00,
    )
    s2_score, s2_breakdown, _, _, _ = ScoringEngine.calculate_contextual_score([ev1, ev2], zone_info)
    s2_sev = calculate_incident_severity(s2_score)

    print("\n--- 2. TWO-SOURCE CORROBORATED EVENT ---")
    print(f"  Sources:    VIDEO (0.90) + IOT (1.00)")
    print(f"  Score:      {s2_score} / 100")
    print(f"  Severity:   {s2_sev}")
    print(f"  Modality Contributions: {s2_breakdown.get('modality_contributions')}")
    print(f"  Corroboration Multiplier: {s2_breakdown.get('corroboration_multiplier')}x")

    # 3. Three-source breach
    ev3 = Event(
        event_id="demo-cyb-01",
        timestamp=now_str,
        source_type="CYBER",
        zone_id="Perimeter_Gate_3",
        coordinates=[12.9716, 77.5946],
        event_type="login_spike",
        confidence=0.95,
        raw_meta={"username": "admin"}
    )
    s3_score, s3_breakdown, _, _, _ = ScoringEngine.calculate_contextual_score([ev1, ev2, ev3], zone_info)
    s3_sev = calculate_incident_severity(s3_score)

    print("\n--- 3. FULL THREE-SOURCE BREACH ---")
    print(f"  Sources:    VIDEO (0.90) + IOT (1.00) + CYBER (0.95)")
    print(f"  Score:      {s3_score} / 100")
    print(f"  Severity:   {s3_sev}")
    print(f"  Modality Contributions: {s3_breakdown.get('modality_contributions')}")
    print(f"  Corroboration Multiplier: {s3_breakdown.get('corroboration_multiplier')}x")
    print(f"  Target Range (88-98): {'[PASS] Within realistic 88-98 range' if 88.0 <= s3_score <= 98.0 else 'Outside range'}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    print_detailed_scoring_breakdown()
    unittest.main()
