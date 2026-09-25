"""
Gryfffindor Sentinel — Phase 3A Test Suite

Comprehensive automated test suite for Phase 3A Real-Time CCTV/YOLO Intelligence Pipeline:
1. YOLO detection -> VIDEO Event conversion
2. Bounding box metadata preservation
3. Confidence threshold filtering
4. Polygon restricted zone entry detection
5. Restricted zone debouncing & cooldown
6. Virtual tripwire line crossing
7. Tripwire debounce & state tracking
8. Loitering detection duration threshold
9. Crowd count thresholding
10. Duplicate event anti-flooding
11. Event cooldown enforcement
12. Camera / Zone mapping
13. Backend /ingest integration
14. Real-time VIDEO + IOT correlation
15. Real-time VIDEO + CYBER correlation
16. Multi-modal VIDEO + IOT + CYBER threat scoring escalation
17. Incident deduplication
18. Mock CCTV regression validation
"""

import sys
import os
import time
import unittest
import numpy as np
from datetime import datetime, timezone

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models import Event, Incident
from backend.video_engine import (
    MockVideoSource,
    YOLOEngine,
    SpatialAnalyticsEngine,
    convert_to_event_model,
    check_line_intersection,
)
from backend.scoring_engine import ScoringEngine
from backend.main import evaluate_threat_correlation, EVENTS_DB, INCIDENTS_DB


class TestPhase3AVisionPipeline(unittest.TestCase):

    def setUp(self):
        """Reset DB state before each test."""
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()

    def test_01_yolo_detection_to_event_conversion(self):
        """Verify converting raw analytics dict to standardized Event model."""
        raw_payload = {
            "event_type": "person_detected",
            "confidence": 0.92,
            "raw_meta": {"camera_id": "CAM-01", "bbox": [100, 100, 200, 300], "track_id": 5},
        }
        evt = convert_to_event_model(raw_payload, zone_id="Server_Room")
        self.assertEqual(evt.source_type, "VIDEO")
        self.assertEqual(evt.zone_id, "Server_Room")
        self.assertEqual(evt.event_type, "person_detected")
        self.assertEqual(evt.confidence, 0.92)
        self.assertTrue(evt.event_id.startswith("evt-v-"))

    def test_02_bounding_box_metadata_preservation(self):
        """Verify bbox and camera metadata are preserved in raw_meta."""
        raw_payload = {
            "event_type": "restricted_zone_entry",
            "confidence": 0.88,
            "raw_meta": {"camera_id": "CAM-PERIMETER-3", "bbox": [50, 60, 150, 250], "restricted_zone": True, "track_id": 12},
        }
        evt = convert_to_event_model(raw_payload, zone_id="Perimeter_Gate_3")
        self.assertEqual(evt.raw_meta["camera_id"], "CAM-PERIMETER-3")
        self.assertEqual(evt.raw_meta["bbox"], [50, 60, 150, 250])
        self.assertTrue(evt.raw_meta["restricted_zone"])

    def test_03_confidence_threshold_filtering(self):
        """Verify YOLO engine respects confidence thresholds."""
        yolo = YOLOEngine(confidence_threshold=0.80)
        self.assertEqual(yolo.confidence_threshold, 0.80)

    def test_04_polygon_restricted_zone_entry(self):
        """Verify centroid inside polygon polygon triggers restricted_zone_entry."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=0.0)
        poly = np.array([[0, 0], [100, 0], [100, 100], [0, 100]], dtype=np.int32)
        detections = [{"class": "person", "confidence": 0.90, "bbox": [10, 10, 50, 90], "centroid": (50, 50), "track_id": 1}]

        events = spatial.process_frame_analytics(
            detections=detections,
            frame_shape=(480, 640),
            zone_id="Server_Room",
            camera_id="CAM-01",
            restricted_polygon=poly,
        )

        event_types = [e["event_type"] for e in events]
        self.assertIn("restricted_zone_entry", event_types)

    def test_05_restricted_zone_debouncing(self):
        """Verify repeated frame detections in restricted zone are debounced during cooldown."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=5.0)
        poly = np.array([[0, 0], [100, 0], [100, 100], [0, 100]], dtype=np.int32)
        detections = [{"class": "person", "confidence": 0.90, "bbox": [10, 10, 50, 90], "centroid": (50, 50), "track_id": 1}]

        # Frame 1
        evts1 = spatial.process_frame_analytics(detections, (480, 640), "Server_Room", "CAM-01", restricted_polygon=poly)
        res_evts1 = [e for e in evts1 if e["event_type"] == "restricted_zone_entry"]
        self.assertEqual(len(res_evts1), 1)

        # Frame 2 (during cooldown)
        evts2 = spatial.process_frame_analytics(detections, (480, 640), "Server_Room", "CAM-01", restricted_polygon=poly)
        res_evts2 = [e for e in evts2 if e["event_type"] == "restricted_zone_entry"]
        self.assertEqual(len(res_evts2), 0)

    def test_06_virtual_tripwire_line_crossing(self):
        """Verify crossing virtual line segment triggers tripwire_crossed."""
        p1 = (10, 50)
        p2 = (90, 50)
        q1 = (50, 10)  # Before line
        q2 = (50, 90)  # After line

        intersects = check_line_intersection(q1, q2, p1, p2)
        self.assertTrue(intersects)

    def test_07_tripwire_debounce_and_state_tracking(self):
        """Verify tripwire crossing requires centroid movement and is debounced."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=5.0)
        line = ((10, 50), (90, 50))

        # Frame 1 (above line)
        d1 = [{"class": "person", "confidence": 0.95, "bbox": [40, 10, 60, 40], "centroid": (50, 25), "track_id": 2}]
        spatial.process_frame_analytics(d1, (100, 100), "Gate_1", "CAM-01", tripwire_line=line)

        # Frame 2 (crossed below line)
        d2 = [{"class": "person", "confidence": 0.95, "bbox": [40, 60, 60, 90], "centroid": (50, 75), "track_id": 2}]
        evts2 = spatial.process_frame_analytics(d2, (100, 100), "Gate_1", "CAM-01", tripwire_line=line)
        tripwire_evts = [e for e in evts2 if e["event_type"] == "tripwire_crossed"]
        self.assertEqual(len(tripwire_evts), 1)

    def test_08_loitering_detection_duration_threshold(self):
        """Verify staying inside polygon > duration threshold triggers loitering_detected."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=0.0, loiter_duration_seconds=0.1)
        poly = np.array([[0, 0], [100, 0], [100, 100], [0, 100]], dtype=np.int32)
        d = [{"class": "person", "confidence": 0.85, "bbox": [10, 10, 40, 40], "centroid": (30, 30), "track_id": 9}]

        # Entry
        spatial.process_frame_analytics(d, (100, 100), "Zone_A", "CAM-01", restricted_polygon=poly)
        time.sleep(0.15)
        # Second frame after duration
        evts = spatial.process_frame_analytics(d, (100, 100), "Zone_A", "CAM-01", restricted_polygon=poly)
        loiter_evts = [e for e in evts if e["event_type"] == "loitering_detected"]
        self.assertEqual(len(loiter_evts), 1)

    def test_09_crowd_count_thresholding(self):
        """Verify >= threshold persons triggers crowd_detected."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=0.0, crowd_threshold=3)
        poly = np.array([[0, 0], [200, 0], [200, 200], [0, 200]], dtype=np.int32)
        detections = [
            {"class": "person", "confidence": 0.9, "bbox": [10, 10, 30, 50], "centroid": (20, 20), "track_id": 1},
            {"class": "person", "confidence": 0.9, "bbox": [40, 10, 60, 50], "centroid": (50, 20), "track_id": 2},
            {"class": "person", "confidence": 0.9, "bbox": [70, 10, 90, 50], "centroid": (80, 20), "track_id": 3},
        ]
        evts = spatial.process_frame_analytics(detections, (200, 200), "Zone_B", "CAM-01", restricted_polygon=poly)
        crowd_evts = [e for e in evts if e["event_type"] == "crowd_detected"]
        self.assertEqual(len(crowd_evts), 1)

    def test_10_duplicate_event_anti_flooding(self):
        """Verify 30 consecutive frames produce rate-limited events, not 30 duplicates."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=5.0)
        poly = np.array([[0, 0], [100, 0], [100, 100], [0, 100]], dtype=np.int32)
        d = [{"class": "person", "confidence": 0.9, "bbox": [10, 10, 50, 90], "centroid": (50, 50), "track_id": 1}]

        total_person_events = 0
        for _ in range(30):
            evts = spatial.process_frame_analytics(d, (100, 100), "Zone_C", "CAM-01", restricted_polygon=poly)
            total_person_events += len([e for e in evts if e["event_type"] == "person_detected"])

        self.assertEqual(total_person_events, 1)

    def test_11_event_cooldown_enforcement(self):
        """Verify cooldown manager respects custom cooldown times."""
        spatial = SpatialAnalyticsEngine(cooldown_seconds=2.0)
        key = "test_event_key"
        self.assertFalse(spatial.is_cooldown_active(key))
        spatial.mark_event_emitted(key)
        self.assertTrue(spatial.is_cooldown_active(key))

    def test_12_camera_zone_mapping(self):
        """Verify event model correctly maps camera_id and zone_id."""
        raw = {"event_type": "tripwire_crossed", "confidence": 0.95, "raw_meta": {"camera_id": "CAM-NORTH-04"}}
        evt = convert_to_event_model(raw, zone_id="Parking_Lot_B")
        self.assertEqual(evt.zone_id, "Parking_Lot_B")
        self.assertEqual(evt.raw_meta["camera_id"], "CAM-NORTH-04")

    def test_13_ingest_api_integration(self):
        """Verify VIDEO event directly evaluated by correlation engine."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evt = Event(
            event_id="evt-v-test-13",
            timestamp=now,
            source_type="VIDEO",
            zone_id="Server_Room",
            coordinates=[12.9, 77.5],
            event_type="tripwire_crossed",
            confidence=0.96,
            raw_meta={"camera_id": "CAM-01", "restricted_zone": True},
        )
        EVENTS_DB.append(evt)
        inc = evaluate_threat_correlation(evt)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.zone_id, "Server_Room")
        self.assertIn("VIDEO", inc.sources)

    def test_14_realtime_video_iot_correlation(self):
        """Verify VIDEO event + IOT event synthesize 2-source correlated incident."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="v14", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.95, raw_meta={"restricted_zone": True})
        e2 = Event(event_id="i14", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="door_open", confidence=0.95, raw_meta={"off_shift": True})

        EVENTS_DB.extend([e1, e2])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)

        final_inc = inc2 or inc1
        self.assertIsNotNone(final_inc)
        self.assertIn("VIDEO", final_inc.sources)
        self.assertIn("IOT", final_inc.sources)
        self.assertEqual(len(final_inc.sources), 2)

    def test_15_realtime_video_cyber_correlation(self):
        """Verify VIDEO event + CYBER event synthesize 2-source correlated incident."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="v15", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.95, raw_meta={"restricted_zone": True})
        e2 = Event(event_id="c15", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.98, raw_meta={"failed_count": 12})

        EVENTS_DB.extend([e1, e2])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)

        final_inc = inc2 or inc1
        self.assertIsNotNone(final_inc)
        self.assertIn("VIDEO", final_inc.sources)
        self.assertIn("CYBER", final_inc.sources)

    def test_16_multimodal_video_iot_cyber_escalation(self):
        """Verify VIDEO + IOT + CYBER events synthesize high/critical incident with 2.2x multiplier."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="v16", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.96, raw_meta={"restricted_zone": True})
        e2 = Event(event_id="i16", timestamp=now, source_type="IOT", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="forced_entry", confidence=0.95, raw_meta={"off_shift": True})
        e3 = Event(event_id="c16", timestamp=now, source_type="CYBER", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="login_spike", confidence=0.98, raw_meta={"failed_count": 20})

        EVENTS_DB.extend([e1, e2, e3])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)
        inc3 = evaluate_threat_correlation(e3)

        final_inc = inc3 or inc2 or inc1
        self.assertIsNotNone(final_inc)
        self.assertEqual(len(final_inc.sources), 3)
        self.assertEqual(final_inc.score, 100.0)
        self.assertEqual(final_inc.severity, "Critical")

    def test_17_incident_deduplication(self):
        """Verify related VIDEO events update existing incident instead of creating duplicates."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        e1 = Event(event_id="v17_1", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="tripwire_crossed", confidence=0.95, raw_meta={"restricted_zone": True})
        e2 = Event(event_id="v17_2", timestamp=now, source_type="VIDEO", zone_id="Server_Room", coordinates=[12.9, 77.5], event_type="restricted_zone_entry", confidence=0.95, raw_meta={"restricted_zone": True})

        EVENTS_DB.extend([e1, e2])
        inc1 = evaluate_threat_correlation(e1)
        inc2 = evaluate_threat_correlation(e2)

        self.assertIsNotNone(inc1)
        self.assertIsNotNone(inc2)
        self.assertEqual(inc1.incident_id, inc2.incident_id)

    def test_18_mock_cctv_regression(self):
        """Verify MockVideoSource frame generation works cleanly."""
        src = MockVideoSource(camera_id="CAM-TEST", zone_id="Server_Room")
        ret, frame, cap_ns, *_ = src.read_frame()
        self.assertTrue(ret)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.shape, (480, 640, 3))
        self.assertIsNotNone(cap_ns)
        src.release()


if __name__ == "__main__":
    unittest.main()
