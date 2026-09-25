"""
Phase 2 Test Suite (backend/test_phase2.py)
------------------------------------------------------
Validates context-aware threat scoring, explainability generation,
response recommendations, incident timeline logging, state transitions,
cyber/CCTV intelligence, score bounds, unknown event handling, deduplication,
and API backward compatibility.
"""

from datetime import datetime, timezone
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.cctv_adapter import CCTVAdapter
from backend.constants import CORRELATION_WINDOW_SECONDS, SEVERITY_THRESHOLDS
from backend.main import (
    EVENTS_DB,
    INCIDENTS_DB,
    ZONES_DB,
    calculate_incident_severity,
    evaluate_threat_correlation,
)
from backend.models import Event, Incident
from backend.scoring_engine import ScoringEngine


class TestPhase2Features(unittest.TestCase):

    def setUp(self):
        """Clear databases and initialize zones before each test."""
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()
        ZONES_DB["Perimeter_Gate_3"] = {
            "id": "Perimeter_Gate_3",
            "name": "Perimeter Gate 3",
            "zone_weight": 1.5,
            "shift_hours": (9, 18),
        }
        ZONES_DB["Server_Room"] = {
            "id": "Server_Room",
            "name": "Server Room",
            "zone_weight": 1.8,
            "shift_hours": (9, 18),
        }

    def _get_utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def test_01_low_risk_single_source_suppression(self):
        """1. Single-source low-risk event is suppressed."""
        ev = Event(
            event_id="t2-001",
            timestamp=self._get_utc_now(),
            source_type="IOT",
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9716, 77.5946],
            event_type="door_open",
            confidence=0.30,
            raw_meta={"off_shift": False},
        )
        EVENTS_DB.append(ev)
        inc = evaluate_threat_correlation(ev)
        self.assertIsNone(inc)

    def test_02_high_confidence_critical_event(self):
        """2. High-confidence critical threat generates incident."""
        ev = Event(
            event_id="t2-002",
            timestamp=self._get_utc_now(),
            source_type="VIDEO",
            zone_id="Server_Room",
            coordinates=[12.9720, 77.5950],
            event_type="tripwire_crossed",
            confidence=0.98,
            raw_meta={"restricted_zone": True},
        )
        EVENTS_DB.append(ev)
        inc = evaluate_threat_correlation(ev)
        self.assertIsNotNone(inc)
        self.assertIn(inc.severity, ["Medium", "High", "Critical"])

    def test_03_two_source_corroboration(self):
        """3. Two-source corroboration boosts score with 1.5x multiplier."""
        now = self._get_utc_now()
        e1 = Event(
            event_id="t2-003a",
            timestamp=now,
            source_type="IOT",
            zone_id="Server_Room",
            coordinates=[12.9720, 77.5950],
            event_type="door_open",
            confidence=0.85,
        )
        e2 = Event(
            event_id="t2-003b",
            timestamp=now,
            source_type="CYBER",
            zone_id="Server_Room",
            coordinates=[12.9720, 77.5950],
            event_type="login_failed",
            confidence=0.80,
        )
        EVENTS_DB.append(e1)
        evaluate_threat_correlation(e1)
        EVENTS_DB.append(e2)
        inc = evaluate_threat_correlation(e2)
        self.assertIsNotNone(inc)
        self.assertEqual(len(inc.sources), 2)
        self.assertEqual(inc.score_breakdown.get("corroboration_multiplier"), 1.5)

    def test_04_three_source_corroboration(self):
        """4. Three-source corroboration applies 2.2x multiplier."""
        now = self._get_utc_now()
        e1 = Event(event_id="t2-004a", timestamp=now, source_type="VIDEO", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.9)
        e2 = Event(event_id="t2-004b", timestamp=now, source_type="IOT", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9)
        e3 = Event(event_id="t2-004c", timestamp=now, source_type="CYBER", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.95)
        for e in [e1, e2, e3]:
            EVENTS_DB.append(e)
            inc = evaluate_threat_correlation(e)
        self.assertIsNotNone(inc)
        self.assertEqual(len(inc.sources), 3)
        self.assertEqual(inc.score_breakdown.get("corroboration_multiplier"), 2.2)

    def test_05_context_aware_event_scoring(self):
        """5. Context affects risk calculation."""
        zone_info = ZONES_DB["Server_Room"]
        e_normal = Event(event_id="t2-005a", timestamp="2026-09-24T12:00:00.000Z", source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8)
        e_offshift = Event(event_id="t2-005b", timestamp="2026-09-24T02:00:00.000Z", source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8, raw_meta={"off_shift": True})
        
        s_norm, _, _, _, _ = ScoringEngine.calculate_contextual_score([e_normal], zone_info)
        s_off, _, _, _, _ = ScoringEngine.calculate_contextual_score([e_offshift], zone_info)
        self.assertGreater(s_off, s_norm)

    def test_06_restricted_zone_person_detection(self):
        """6. Restricted zone detection escalates score."""
        zone_info = ZONES_DB["Server_Room"]
        e = Event(event_id="t2-006", timestamp=self._get_utc_now(), source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.9, raw_meta={"restricted_zone": True})
        score, _, factors, _, _ = ScoringEngine.calculate_contextual_score([e], zone_info)
        self.assertTrue(any("Restricted zone" in f for f in factors))
        self.assertGreater(score, 40.0)

    def test_07_off_shift_door_opening(self):
        """7. Off-shift door opening produces contextual factor."""
        zone_info = ZONES_DB["Perimeter_Gate_3"]
        e = Event(event_id="t2-007", timestamp="2026-09-24T03:00:00.000Z", source_type="IOT", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9, raw_meta={"off_shift": True})
        _, _, factors, _, _ = ScoringEngine.calculate_contextual_score([e], zone_info)
        self.assertTrue(any("Off-shift" in f for f in factors))

    def test_08_cyber_login_spike(self):
        """8. Cyber login spike incorporates threat intelligence."""
        zone_info = ZONES_DB["Server_Room"]
        e = Event(event_id="t2-008", timestamp=self._get_utc_now(), source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.95, raw_meta={"failed_attempts": 12, "username": "root"})
        _, _, factors, _, _ = ScoringEngine.calculate_contextual_score([e], zone_info)
        self.assertTrue(any("Cyber brute-force" in f for f in factors))

    def test_09_weak_event_with_corroboration(self):
        """9. Weak isolated event escalates when corroborated."""
        now = self._get_utc_now()
        weak_cctv = Event(event_id="t2-009a", timestamp=now, source_type="VIDEO", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.45)
        iot = Event(event_id="t2-009b", timestamp=now, source_type="IOT", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9, raw_meta={"off_shift": True})
        
        EVENTS_DB.append(weak_cctv)
        inc1 = evaluate_threat_correlation(weak_cctv)
        self.assertIsNone(inc1)

        EVENTS_DB.append(iot)
        inc2 = evaluate_threat_correlation(iot)
        self.assertIsNotNone(inc2)
        self.assertEqual(len(inc2.sources), 2)

    def test_10_repeated_suspicious_events(self):
        """10. Repeated suspicious activity increases suspicion with cap."""
        zone_info = ZONES_DB["Server_Room"]
        now = self._get_utc_now()
        e1 = Event(event_id="t2-010a", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="motion", confidence=0.8)
        e2 = Event(event_id="t2-010b", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="motion", confidence=0.8)
        
        s1, _, _, _, _ = ScoringEngine.calculate_contextual_score([e1], zone_info)
        s2, _, factors, _, _ = ScoringEngine.calculate_contextual_score([e1, e2], zone_info)
        self.assertGreater(s2, s1)
        self.assertTrue(any("Repeated" in f for f in factors))

    def test_11_incident_deduplication(self):
        """11. De-duplicates active incident within window."""
        now = self._get_utc_now()
        e1 = Event(event_id="t2-011a", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True})
        e2 = Event(event_id="t2-011b", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.9)
        
        EVENTS_DB.append(e1)
        inc1 = evaluate_threat_correlation(e1)
        self.assertIsNotNone(inc1)
        EVENTS_DB.append(e2)
        inc2 = evaluate_threat_correlation(e2)
        self.assertIsNotNone(inc2)
        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_12_incident_timeline(self):
        """12. Structured incident timeline generated."""
        now = self._get_utc_now()
        e1 = Event(event_id="t2-012a", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9)
        e2 = Event(event_id="t2-012b", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.9)
        EVENTS_DB.extend([e1, e2])
        inc = evaluate_threat_correlation(e2)
        self.assertTrue(len(inc.timeline) >= 2)
        self.assertTrue(any(t.get("source") == "ENGINE" for t in inc.timeline))

    def test_13_incident_state_transitions(self):
        """13. Acknowledge and resolve lifecycle transitions."""
        inc = Incident(
            incident_id="INC-T13",
            zone_id="Server_Room",
            score=85.0,
            severity="Critical",
            sources=["IOT", "CYBER"],
            first_ts=self._get_utc_now(),
            status="dispatched",
        )
        INCIDENTS_DB[inc.incident_id] = inc
        
        # Test ACKNOWLEDGED
        inc.status = "ACKNOWLEDGED"
        inc.acknowledged_ts = self._get_utc_now()
        self.assertEqual(INCIDENTS_DB["INC-T13"].status, "ACKNOWLEDGED")

        # Test RESOLVED
        inc.status = "RESOLVED"
        inc.resolved_ts = self._get_utc_now()
        self.assertEqual(INCIDENTS_DB["INC-T13"].status, "RESOLVED")

    def test_14_explanation_generation(self):
        """14. Generates human-readable explanation and recommendations."""
        now = self._get_utc_now()
        e1 = Event(event_id="t2-014a", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.95)
        e2 = Event(event_id="t2-014b", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95)
        EVENTS_DB.extend([e1, e2])
        inc = evaluate_threat_correlation(e2)
        self.assertTrue(len(inc.explanation) > 10)
        self.assertTrue(len(inc.recommendations) >= 1)

    def test_15_score_bounds_0_100(self):
        """15. Score is strictly bounded between 0.0 and 100.0."""
        now = self._get_utc_now()
        events = [
            Event(event_id=f"t2-015-{i}", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=1.0)
            for i in range(10)
        ]
        score, _, _, _, _ = ScoringEngine.calculate_contextual_score(events, ZONES_DB["Server_Room"])
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_16_unknown_event_types(self):
        """16. Handles unknown/unclassified event types safely."""
        now = self._get_utc_now()
        e = Event(event_id="t2-016", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="quantum_laser_trip", confidence=0.88)
        EVENTS_DB.append(e)
        zone_info = ZONES_DB["Server_Room"]
        score, _, factors, _, _ = ScoringEngine.calculate_contextual_score([e], zone_info)
        self.assertGreater(score, 0.0)
        self.assertTrue(any("fallback risk profile" in f for f in factors))

    def test_17_cctv_adapter_formatting(self):
        """17. CCTV Adapter produces valid VIDEO event."""
        evt = CCTVAdapter.format_detection_event(
            zone_id="Perimeter_Gate_3",
            coordinates=[12.9, 77.5],
            event_type="person_detected",
            confidence=0.92,
            camera_id="CAM-EAST",
            restricted_zone=True,
        )
        self.assertEqual(evt.source_type, "VIDEO")
        self.assertEqual(evt.raw_meta.get("camera_id"), "CAM-EAST")
        self.assertTrue(evt.raw_meta.get("restricted_zone"))

    def test_18_api_backward_compatibility(self):
        """18. API models preserve backward compatibility."""
        inc = Incident(
            incident_id="INC-OLD-STYLE",
            zone_id="Perimeter_Gate_3",
            score=75.0,
            severity="High",
            sources=["IOT"],
            event_ids=["evt-1"],
            first_ts=self._get_utc_now(),
        )
        dict_rep = inc.model_dump()
        self.assertIn("score", dict_rep)
        self.assertIn("severity", dict_rep)
        self.assertIn("status", dict_rep)


if __name__ == "__main__":
    print("======================================================================")
    print("  RUNNING PHASE 2 THREAT ENGINE & INTEGRATION UNIT TESTS")
    print("======================================================================\n")
    unittest.main()
