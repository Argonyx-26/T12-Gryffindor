"""
Gryfffindor Sentinel — Controlled Evaluation Dataset & Benchmark Suite (Phase 3B)

Generates a reproducible synthetic evaluation dataset containing 10 scenarios (A through J):
A. Normal activity
B. Isolated noise
C. Repeated benign activity
D. Single suspicious event
E. Multi-event physical intrusion
F. Cyber burst
G. Multi-source breach
H. Delayed corroboration
I. Out-of-order events
J. Events outside correlation window

Computes metrics: Precision, Recall, F1 Score, TP, TN, FP, FN, Latency (ms), and Suppression Rate (%).
"""

import os
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models import Event, Incident
from backend.main import evaluate_threat_correlation, EVENTS_DB, INCIDENTS_DB


class EvaluationBenchmark:
    """
    Executes controlled evaluation scenarios and measures detection performance metrics.
    """

    @staticmethod
    def generate_timestamp(offset_seconds: float = 0.0) -> str:
        dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
        return dt.isoformat().replace("+00:00", "Z")

    @classmethod
    def run_benchmark(cls) -> Dict[str, Any]:
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()

        tp, tn, fp, fn = 0, 0, 0, 0
        latencies_ms = []

        scenarios = [
            # A. Normal activity (1 benign door open) -> TN
            {"name": "A. Normal Activity", "events": [
                Event(event_id="eval-A1", timestamp=cls.generate_timestamp(0), source_type="IOT", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.9, raw_meta={"off_shift": False})
            ], "expect_incident": False},

            # B. Isolated noise (1 low conf motion) -> TN
            {"name": "B. Isolated Noise", "events": [
                Event(event_id="eval-B1", timestamp=cls.generate_timestamp(0), source_type="IOT", zone_id="Parking_Lot_B", coordinates=[12.9, 77.5], event_type="motion", confidence=0.3, raw_meta={"off_shift": False})
            ], "expect_incident": False},

            # C. Repeated benign activity -> TN
            {"name": "C. Repeated Benign Activity", "events": [
                Event(event_id="eval-C1", timestamp=cls.generate_timestamp(0), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8, raw_meta={"off_shift": False}),
                Event(event_id="eval-C2", timestamp=cls.generate_timestamp(0.5), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.8, raw_meta={"off_shift": False}),
            ], "expect_incident": False},

            # D. Single suspicious event (1 off-shift forced entry) -> TP
            {"name": "D. Single Suspicious Event", "events": [
                Event(event_id="eval-D1", timestamp=cls.generate_timestamp(0), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True})
            ], "expect_incident": True},

            # E. Multi-event physical intrusion -> TP
            {"name": "E. Multi-event Physical Intrusion", "events": [
                Event(event_id="eval-E1", timestamp=cls.generate_timestamp(0), source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.9, raw_meta={}),
                Event(event_id="eval-E2", timestamp=cls.generate_timestamp(0.3), source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.92, raw_meta={"restricted_zone": True}),
                Event(event_id="eval-E3", timestamp=cls.generate_timestamp(0.6), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={"off_shift": True}),
            ], "expect_incident": True},

            # F. Cyber burst -> TP
            {"name": "F. Cyber Burst", "events": [
                Event(event_id="eval-F1", timestamp=cls.generate_timestamp(0), source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_failed", confidence=0.9, raw_meta={}),
                Event(event_id="eval-F2", timestamp=cls.generate_timestamp(0.2), source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_failed", confidence=0.9, raw_meta={}),
                Event(event_id="eval-F3", timestamp=cls.generate_timestamp(0.4), source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.98, raw_meta={"failed_count": 15}),
            ], "expect_incident": True},

            # G. Multi-source breach -> TP
            {"name": "G. Multi-Source Breach", "events": [
                Event(event_id="eval-G1", timestamp=cls.generate_timestamp(0), source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.96, raw_meta={"restricted_zone": True}),
                Event(event_id="eval-G2", timestamp=cls.generate_timestamp(0.3), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True}),
                Event(event_id="eval-G3", timestamp=cls.generate_timestamp(0.5), source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.98, raw_meta={}),
            ], "expect_incident": True},

            # H. Delayed corroboration (0.8s gap within 1.5s window) -> TP
            {"name": "H. Delayed Corroboration", "events": [
                Event(event_id="eval-H1", timestamp=cls.generate_timestamp(0), source_type="VIDEO", zone_id="Parking_Lot_B", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.88, raw_meta={}),
                Event(event_id="eval-H2", timestamp=cls.generate_timestamp(0.8), source_type="IOT", zone_id="Parking_Lot_B", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True}),
            ], "expect_incident": True},

            # I. Out-of-order events -> TP
            {"name": "I. Out-of-Order Events", "events": [
                Event(event_id="eval-I2", timestamp=cls.generate_timestamp(0.5), source_type="CYBER", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.95, raw_meta={}),
                Event(event_id="eval-I1", timestamp=cls.generate_timestamp(0.0), source_type="VIDEO", zone_id="Perimeter_Gate_3", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.92, raw_meta={}),
            ], "expect_incident": True},

            # J. Events outside correlation window (10s gap) -> TN for single correlated incident
            {"name": "J. Outside Window", "events": [
                Event(event_id="eval-J1", timestamp=cls.generate_timestamp(0), source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="person_detected", confidence=0.5, raw_meta={}),
                Event(event_id="eval-J2", timestamp=cls.generate_timestamp(10.0), source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="motion", confidence=0.4, raw_meta={}),
            ], "expect_incident": False},
        ]

        total_events_processed = 0

        for sc in scenarios:
            EVENTS_DB.clear()
            INCIDENTS_DB.clear()

            t_start = time.time()
            created_incidents = []
            for ev in sc["events"]:
                total_events_processed += 1
                EVENTS_DB.append(ev)
                inc = evaluate_threat_correlation(ev)
                if inc:
                    created_incidents.append(inc)
            lat_ms = (time.time() - t_start) * 1000.0
            latencies_ms.append(lat_ms)

            # Evaluate outcome
            has_incident = len(created_incidents) > 0 and any(inc.score >= 40.0 for inc in created_incidents)
            if sc["expect_incident"]:
                if has_incident:
                    tp += 1
                else:
                    fn += 1
            else:
                if not has_incident:
                    tn += 1
                else:
                    fp += 1

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
        avg_latency_ms = round(sum(latencies_ms) / max(1, len(latencies_ms)), 2)
        suppression_rate = round(((total_events_processed - (tp + fp)) / total_events_processed) * 100.0, 2)

        return {
            "evaluation_label": "Controlled Evaluation Results",
            "total_scenarios": len(scenarios),
            "total_events_processed": total_events_processed,
            "metrics": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "avg_intelligence_processing_latency_ms": avg_latency_ms,
                "noise_suppression_rate_pct": suppression_rate,
            }
        }


if __name__ == "__main__":
    results = EvaluationBenchmark.run_benchmark()
    print("=" * 60)
    print(f" {results['evaluation_label']} ")
    print("=" * 60)
    for k, v in results['metrics'].items():
        label_str = k.replace('_', ' ').title()
        print(f"  {label_str:<40}: {v}")
    print("=" * 60)
    for k, v in results["metrics"].items():
        print(f"  {k:30s}: {v}")
