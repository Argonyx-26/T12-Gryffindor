"""
Gryfffindor Sentinel — Phase 3B Test Suite

Comprehensive 18-test automated test suite for Phase 3B Temporal & Behavioral Intelligence:
1. Temporal grouping
2. Event frequency tracking
3. Burst detection
4. Sequence pattern detection
5. Time-of-day contextual tagging
6. Behavioral baseline calculations
7. Zone anomaly detection
8. Exponential evidence decay (e^-lambda*dt)
9. Bounded temporal risk accumulation
10. False-positive protection
11. False-negative protection & escalation
12. Temporal explainability (XAI)
13. Score breakdown with temporal factors
14. Chronological incident timeline with pattern milestones
15. Delayed corroboration
16. Out-of-window event isolation
17. GET /analytics/behavior REST API endpoint
18. Controlled evaluation metrics execution
"""

import sys
import os
import time
import unittest
from datetime import datetime, timezone

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models import Event, Incident
from backend.temporal_engine import (
    BurstDetector,
    SequencePatternEngine,
    BehavioralBaselineEngine,
    calculate_recency_factor,
    calculate_temporal_pattern_bonus,
    calculate_behavioral_anomaly_bonus,
)
from backend.scoring_engine import ScoringEngine
from backend.main import evaluate_threat_correlation, EVENTS_DB, INCIDENTS_DB
from backend.evaluation_dataset import EvaluationBenchmark


class TestPhase3BTemporalIntelligence(unittest.TestCase):

    def setUp(self):
        """Reset global DB state before each test."""
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()

    def test_01_temporal_grouping(self):
        """Verify events are correctly grouped by zone and temporal proximity."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="t1_1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.9, raw_meta={})
        e2 = Event(event_id="t1_2", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={})
        EVENTS_DB.extend([e1, e2])

        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)
        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_02_event_frequency(self):
        """Verify zone event frequency rate calculation."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evs = [Event(event_id=f"f_{i}", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8, raw_meta={}) for i in range(5)]
        stats = BehavioralBaselineEngine.compute_zone_statistics(evs, "Server_Room")
        self.assertEqual(stats["recent_event_count"], 5)
        self.assertGreater(stats["events_per_minute"], 0.0)

    def test_03_burst_detection(self):
        """Verify detection of cyber failed login burst."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evs = [Event(event_id=f"b_{i}", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_failed", confidence=0.9, raw_meta={}) for i in range(4)]
        bursts = BurstDetector.detect_bursts(evs, window_seconds=15.0)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["burst_id"], "BURST_CYBER_LOGIN_FAILURES")

    def test_04_sequence_detection(self):
        """Verify attack sequence pattern matching (Physical Intrusion)."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="s1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.95, raw_meta={})
        e2 = Event(event_id="s2", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={})
        patterns = SequencePatternEngine.evaluate_sequence_patterns([e1, e2])
        pat_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("PATTERN_POSSIBLE_PHYSICAL_INTRUSION", pat_ids)

    def test_05_time_of_day_context(self):
        """Verify off-shift contextual tagging."""
        off_shift_ts = "2026-09-28T02:30:00.000Z"  # 2:30 AM Monday
        on_shift_ts = "2026-09-28T14:00:00.000Z"   # 2:00 PM Monday
        self.assertTrue(BehavioralBaselineEngine.is_off_shift(off_shift_ts, "Server_Room"))
        self.assertFalse(BehavioralBaselineEngine.is_off_shift(on_shift_ts, "Server_Room"))

    def test_06_behavioral_baseline(self):
        """Verify statistical zone activity baseline calculation."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evs = [Event(event_id=f"bb_{i}", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="motion", confidence=0.8, raw_meta={}) for i in range(2)]
        stats = BehavioralBaselineEngine.compute_zone_statistics(evs, "Server_Room")
        self.assertIn("baseline_events_per_minute", stats)
        self.assertIn("anomaly_ratio", stats)

    def test_07_zone_anomaly_detection(self):
        """Verify zone tagged ANOMALOUS when activity rate exceeds threshold."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evs = [Event(event_id=f"za_{i}", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9, raw_meta={}) for i in range(10)]
        stats = BehavioralBaselineEngine.compute_zone_statistics(evs, "Server_Room")
        self.assertEqual(stats["status"], "ANOMALOUS")

    def test_08_temporal_decay(self):
        """Verify exponential time decay w(t) = exp(-lambda * dt)."""
        t0 = "2026-09-26T12:00:00.000Z"
        t15 = "2026-09-26T12:00:15.000Z"
        recency = calculate_recency_factor(t0, t15, half_life_seconds=15.0)
        self.assertAlmostEqual(recency, 0.5, delta=0.05)

    def test_09_temporal_risk_accumulation(self):
        """Verify temporal pattern bonus is bounded to max +15.0 points."""
        patterns = [
            {"pattern_id": "PATTERN_MULTI_VECTOR_BREACH", "confidence": 1.0},
            {"pattern_id": "PATTERN_POSSIBLE_PHYSICAL_INTRUSION", "confidence": 1.0},
        ]
        bonus = calculate_temporal_pattern_bonus(patterns)
        self.assertLessEqual(bonus, 15.0)
        self.assertGreater(bonus, 0.0)

    def test_10_false_positive_protection(self):
        """Verify single benign event remains low/suppressed and does not create Critical incident."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="fp_1", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8, raw_meta={"off_shift": False})
        EVENTS_DB.append(e1)
        inc = evaluate_threat_correlation(e1)
        if inc:
            self.assertLess(inc.score, 60.0)

    def test_11_false_negative_protection(self):
        """Verify weak VIDEO + IOT + CYBER events synthesize Critical incident (score >= 80)."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="fn_1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.8, raw_meta={})
        e2 = Event(event_id="fn_2", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True})
        e3 = Event(event_id="fn_3", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.98, raw_meta={})

        EVENTS_DB.extend([e1, e2, e3])
        evaluate_threat_correlation(e1)
        evaluate_threat_correlation(e2)
        inc = evaluate_threat_correlation(e3)

        self.assertIsNotNone(inc)
        self.assertEqual(inc.severity, "Critical")
        self.assertGreaterEqual(inc.score, 80.0)

    def test_12_temporal_explainability(self):
        """Verify XAI explanation includes sequence pattern context."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="x1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.95, raw_meta={"restricted_zone": True})
        e2 = Event(event_id="x2", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={"off_shift": True})

        EVENTS_DB.extend([e1, e2])
        evaluate_threat_correlation(e1)
        inc = evaluate_threat_correlation(e2)

        self.assertIn("Matched sequence", inc.explanation)

    def test_13_score_breakdown(self):
        """Verify score breakdown contains temporal pattern bonus and recency factor."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="sb1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.95, raw_meta={})
        EVENTS_DB.append(e1)
        inc = evaluate_threat_correlation(e1)

        sb = inc.score_breakdown
        self.assertIn("temporal_pattern_bonus", sb)
        self.assertIn("behavioral_anomaly_bonus", sb)
        self.assertIn("recency_factor", sb)

    def test_14_chronological_incident_timeline(self):
        """Verify incident timeline includes sequence pattern milestone in chronological order."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="tl1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.95, raw_meta={})
        e2 = Event(event_id="tl2", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={})

        EVENTS_DB.extend([e1, e2])
        evaluate_threat_correlation(e1)
        inc = evaluate_threat_correlation(e2)

        timeline_sources = [t["source"] for t in inc.timeline]
        self.assertIn("TEMPORAL", timeline_sources)

    def test_15_delayed_corroboration(self):
        """Verify events separated by 0.8s within window correlate cleanly."""
        t0 = "2026-09-26T12:00:00.000Z"
        t0_8 = "2026-09-26T12:00:00.800Z"
        e1 = Event(event_id="dc1", timestamp=t0, source_type="VIDEO", zone_id="Parking_Lot_B", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.9, raw_meta={})
        e2 = Event(event_id="dc2", timestamp=t0_8, source_type="IOT", zone_id="Parking_Lot_B", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True})

        EVENTS_DB.extend([e1, e2])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)

        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_16_out_of_window_events(self):
        """Verify events separated by 10s are not correlated into same incident."""
        t0 = "2026-09-26T12:00:00.000Z"
        t10 = "2026-09-26T12:00:10.000Z"
        e1 = Event(event_id="ow1", timestamp=t0, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.9, raw_meta={})
        e2 = Event(event_id="ow2", timestamp=t10, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9, raw_meta={})

        EVENTS_DB.extend([e1, e2])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)

        if inc1 and inc2:
            self.assertNotEqual(inc1.incident_id, inc2.incident_id)

    def test_17_api_analytics_behavior(self):
        """Verify GET /analytics/behavior structure."""
        from backend.main import get_behavior_analytics
        res = get_behavior_analytics()
        self.assertIn("recent_event_rates", res)
        self.assertIn("zone_activity", res)
        self.assertIn("detected_patterns", res)
        self.assertIn("anomaly_indicators", res)

    def test_18_evaluation_metrics(self):
        """Verify controlled evaluation dataset execution yields high Precision and Recall."""
        res = EvaluationBenchmark.run_benchmark()
        metrics = res["metrics"]
        self.assertGreaterEqual(metrics["precision"], 0.85)
        self.assertGreaterEqual(metrics["recall"], 0.85)
        self.assertGreaterEqual(metrics["f1_score"], 0.85)


if __name__ == "__main__":
    unittest.main()
