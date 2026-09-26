"""
tests/test_integrated_system.py
Integration & Regression Unit Test Suite for Master Full-Stack Integration.
Validates location configuration engine, primary location resolution, GET /locations API endpoint,
and multi-modal location attachment for VIDEO, IOT, and CYBER events.
"""

import unittest
import json
import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models import Event, Incident
from backend.location_config import (
    get_event_location,
    get_incident_primary_location,
    get_all_locations_payload,
    ZONES_CATALOG,
    CAMERAS_CATALOG,
    SENSORS_CATALOG,
)
from backend.main import app, evaluate_threat_correlation, EVENTS_DB, INCIDENTS_DB
from fastapi.testclient import TestClient

client = TestClient(app)


class TestFullStackIntegration(unittest.TestCase):

    def setUp(self):
        EVENTS_DB.clear()
        INCIDENTS_DB.clear()

    def test_01_location_config_catalog(self):
        """Verify that location catalog contains zones, cameras, sensors, and site bounds."""
        payload = get_all_locations_payload()
        self.assertIn("site", payload)
        self.assertIn("zones", payload)
        self.assertIn("cameras", payload)
        self.assertIn("sensors", payload)
        self.assertIn("cyber_nodes", payload)

        self.assertGreaterEqual(len(payload["zones"]), 3)
        self.assertGreaterEqual(len(payload["cameras"]), 3)
        self.assertGreaterEqual(len(payload["sensors"]), 2)

    def test_02_get_locations_api_endpoint(self):
        """Verify GET /locations endpoint returns HTTP 200 and structured location JSON."""
        response = client.get("/locations")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["site"]["site_id"], "campus-main")
        self.assertTrue(any(c["camera_id"] == "CAM-01" for c in data["cameras"]))

    def test_03_event_location_resolution_video(self):
        """Verify location resolution for physical VIDEO event."""
        evt = Event(
            event_id="evt-vid-01",
            timestamp="2026-09-26T03:00:00.000Z",
            source_type="VIDEO",
            zone_id="Perimeter_Gate_3",
            coordinates=[37.4320, -122.1745],
            event_type="person_detected",
            confidence=0.92,
            raw_meta={"camera_id": "CAM-01"}
        )
        loc = get_event_location(evt)
        self.assertEqual(loc["location_type"], "physical")
        self.assertEqual(loc["zone_id"], "Perimeter_Gate_3")
        self.assertEqual(loc["camera_id"], "CAM-01")
        self.assertAlmostEqual(loc["latitude"], 37.4320)

    def test_04_event_location_resolution_cyber(self):
        """Verify logical location resolution for CYBER event."""
        evt = Event(
            event_id="evt-cyb-01",
            timestamp="2026-09-26T03:00:00.000Z",
            source_type="CYBER",
            zone_id="Server_Room",
            coordinates=[0.0, 0.0],
            event_type="login_spike",
            confidence=0.88,
            raw_meta={"system_id": "CYBER-01"}
        )
        loc = get_event_location(evt)
        self.assertEqual(loc["location_type"], "logical")
        self.assertEqual(loc["zone_id"], "Server_Room")

    def test_05_incident_primary_location_deterministic_selection(self):
        """Verify primary location selection prioritizes highest confidence physical event."""
        ev_cctv = Event(
            event_id="ev-cctv-1",
            timestamp="2026-09-26T03:00:00.000Z",
            source_type="VIDEO",
            zone_id="Perimeter_Gate_3",
            coordinates=[37.4320, -122.1745],
            event_type="person_detected",
            confidence=0.95,
            raw_meta={"camera_id": "CAM-01"}
        )
        ev_iot = Event(
            event_id="ev-iot-1",
            timestamp="2026-09-26T03:00:00.500Z",
            source_type="IOT",
            zone_id="Perimeter_Gate_3",
            coordinates=[37.4320, -122.1745],
            event_type="motion",
            confidence=0.80,
            raw_meta={"sensor_id": "IOT-02"}
        )
        ev_cyber = Event(
            event_id="ev-cyb-1",
            timestamp="2026-09-26T03:00:01.000Z",
            source_type="CYBER",
            zone_id="Perimeter_Gate_3",
            coordinates=[0.0, 0.0],
            event_type="login_failed",
            confidence=0.90,
            raw_meta={"system_id": "CYBER-01"}
        )

        inc_loc = get_incident_primary_location(ev_cctv, [ev_cctv, ev_iot, ev_cyber])
        self.assertEqual(inc_loc["primary_location"]["camera_id"], "CAM-01")
        self.assertIn("CAM-01", inc_loc["contributing_cameras"])
        self.assertIn("IOT-02", inc_loc["contributing_iot"])
        self.assertIn("CYBER-01", inc_loc["contributing_cyber"])

    def test_06_e2e_correlation_location_enrichment(self):
        """Verify full threat correlation attaches structured location to generated incident."""
        ev1 = Event(
            event_id="ev-e2e-1",
            timestamp="2026-09-26T03:00:00.000Z",
            source_type="VIDEO",
            zone_id="Server_Room",
            coordinates=[37.4282, -122.1688],
            event_type="restricted_zone_entry",
            confidence=0.90,
            raw_meta={"camera_id": "CAM-03"}
        )
        ev2 = Event(
            event_id="ev-e2e-2",
            timestamp="2026-09-26T03:00:00.800Z",
            source_type="IOT",
            zone_id="Server_Room",
            coordinates=[37.4282, -122.1688],
            event_type="forced_entry",
            confidence=0.95,
            raw_meta={"sensor_id": "IOT-01"}
        )

        EVENTS_DB.append(ev1)
        inc = evaluate_threat_correlation(ev2)
        self.assertIsNotNone(inc)
        self.assertIsNotNone(inc.location)
        self.assertIn("primary_location", inc.location)
        self.assertEqual(inc.location["primary_location"]["zone_id"], "Server_Room")


if __name__ == "__main__":
    unittest.main()
