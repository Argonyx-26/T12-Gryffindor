"""
Test Threat Scoring Engine (backend/test_scoring.py)
------------------------------------------------------
Validates threat correlation logic, multi-modality corroboration multiplier,
zone weighting, noise suppression, and severity classification thresholds.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

# Add project root to sys.path for direct python execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.constants import SEVERITY_THRESHOLDS, SOURCE_WEIGHTS, CORROBORATION_MULTIPLIER
from backend.models import Event, Incident
from backend.main import evaluate_threat_correlation, calculate_incident_severity, EVENTS_DB, INCIDENTS_DB, ZONES_DB


class TestThreatScoring(unittest.TestCase):

    def setUp(self):
        """Clear memory databases before each test case."""
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()
        ZONES_DB["Perimeter_Gate_3"] = {
            "id": "Perimeter_Gate_3",
            "name": "Perimeter Gate 3",
            "zone_weight": 1.5
        }
        ZONES_DB["Server_Room"] = {
            "id": "Server_Room",
            "name": "Server Room",
            "zone_weight": 1.8
        }

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

    def test_multi_source_corroboration_multiplier(self):
        """Verify that multi-source events (IoT + Cyber) apply corroboration multiplier and create incident."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        iot_event = Event(
            event_id="test-evt-iot-1",
            timestamp=now_str,
            source_type="IOT",
            zone_id="Server_Room",
            coordinates=[12.9720, 77.5950],
            event_type="door_open",
            confidence=1.0,
            raw_meta={}
        )
        
        cyber_event = Event(
            event_id="test-evt-cyber-1",
            timestamp=now_str,
            source_type="CYBER",
            zone_id="Server_Room",
            coordinates=[12.9720, 77.5950],
            event_type="login_spike",
            confidence=0.95,
            raw_meta={"username": "admin"}
        )

        EVENTS_DB.append(iot_event)
        evaluate_threat_correlation(iot_event)
        
        EVENTS_DB.append(cyber_event)
        multi_incident = evaluate_threat_correlation(cyber_event)

        self.assertIsNotNone(multi_incident)
        self.assertIn("IOT", multi_incident.sources)
        self.assertIn("CYBER", multi_incident.sources)
        self.assertEqual(len(multi_incident.sources), 2)
        self.assertGreaterEqual(multi_incident.score, 40.0)


if __name__ == "__main__":
    print("======================================================================")
    print("  RUNNING THREAT DETECTION ENGINE & SCORING UNIT TESTS")
    print("======================================================================\n")
    unittest.main()
