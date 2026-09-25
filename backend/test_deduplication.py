"""
Test suite for Incident De-Duplication in CorrelationEngine.

Validates the user requirements:
1. Within 5s of an existing OPEN incident in the same zone:
   - Do NOT create a new incident (same incident_id).
   - Take the higher score.
   - Add new event_id to events list.
   - Re-broadcast updated incident over WebSocket.
2. Different zone:
   - Starts a genuinely new incident.
3. Event arriving > 5s after the open incident in the same zone:
   - Starts a genuinely new incident.
4. Cooldown after closing:
   - If an incident closed in that zone, suppress new incident creation for 5s.
   - After 5s have passed since the last one closed, start a genuinely new incident.
5. Ingest API & Metrics:
   - Multiple events within 5s update the existing incident in-place in incident_store and INCIDENTS_DB.
   - Metrics noise_suppression_rate accurately reflects merged duplicate events.
"""

import sys
from pathlib import Path
import time
from datetime import datetime, timezone

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from backend.main import (
    app,
    engine,
    incident_store,
    event_store,
    INCIDENTS_DB,
    CorrelationEngine,
    calculate_incident_severity,
)


def test_deduplication_same_zone_within_5s():
    """Verify that events in the same zone within 5s update the existing incident with the higher score."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # Event 1 at T = 0s
    ev1 = {
        "event_id": "evt-001",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.50,
        "raw_meta": {},
    }
    inc1 = test_engine.process_event(ev1)
    assert inc1 is not None
    orig_incident_id = inc1.incident_id
    orig_score = inc1.score
    assert inc1.event_ids == ["evt-001"]
    assert inc1.status == "open"

    # Event 2 at T = 2s (same zone, higher confidence)
    ev2 = {
        "event_id": "evt-002",
        "timestamp": "2026-09-25T12:00:02.000Z",
        "source_type": "IOT",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.95,
        "raw_meta": {},
    }
    inc2 = test_engine.process_event(ev2)
    assert inc2 is not None
    # Must NOT create a new incident
    assert inc2.incident_id == orig_incident_id, "Expected same incident_id for deduplicated incident"
    # Must take the higher score
    assert inc2.score >= orig_score, f"Expected score to be at least {orig_score}, got {inc2.score}"
    # Must add new event_id to its events list
    assert "evt-002" in inc2.event_ids, "Expected evt-002 to be added to event_ids"
    assert "evt-001" in inc2.event_ids, "Expected original evt-001 to remain in event_ids"
    # Sources merged
    assert "VIDEO" in inc2.sources and "IOT" in inc2.sources

    # Event 3 at T = 3.5s (same zone, lower confidence single event)
    ev3 = {
        "event_id": "evt-003",
        "timestamp": "2026-09-25T12:00:03.500Z",
        "source_type": "VIDEO",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [37.4320, -122.1745],
        "event_type": "motion",
        "confidence": 0.10,
        "raw_meta": {},
    }
    inc3 = test_engine.process_event(ev3)
    assert inc3 is not None
    assert inc3.incident_id == orig_incident_id
    # Score should take the higher score (at least inc2.score)
    assert inc3.score >= inc2.score, f"Expected score >= {inc2.score}, got {inc3.score}"
    assert inc3.event_ids == ["evt-001", "evt-002", "evt-003"]
    print("[PASS] test_deduplication_same_zone_within_5s")


def test_different_zone_creates_new_incident():
    """Verify that an event in a different zone creates a genuinely new incident."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    ev_zone_a = {
        "event_id": "evt-zone-a-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Zone_Alpha",
        "coordinates": [37.4320, -122.1745],
        "event_type": "motion",
        "confidence": 0.80,
    }
    inc_a = test_engine.process_event(ev_zone_a)

    ev_zone_b = {
        "event_id": "evt-zone-b-1",
        "timestamp": "2026-09-25T12:00:01.000Z",
        "source_type": "VIDEO",
        "zone_id": "Zone_Beta",
        "coordinates": [37.4325, -122.1750],
        "event_type": "motion",
        "confidence": 0.80,
    }
    inc_b = test_engine.process_event(ev_zone_b)

    assert inc_a is not None and inc_b is not None
    assert inc_a.incident_id != inc_b.incident_id, "Different zones must yield different incident IDs"
    assert inc_a.zone_id == "Zone_Alpha"
    assert inc_b.zone_id == "Zone_Beta"
    print("[PASS] test_different_zone_creates_new_incident")


def test_new_incident_after_5s_elapsed():
    """Verify that if > 5s pass since the last event of an open incident, a new incident starts."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # Event 1 at T = 0s
    ev1 = {
        "event_id": "evt-time-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "motion",
        "confidence": 0.80,
    }
    inc1 = test_engine.process_event(ev1)
    assert inc1 is not None

    # Event 2 at T = 10s (> 5s later)
    ev2 = {
        "event_id": "evt-time-2",
        "timestamp": "2026-09-25T12:00:10.000Z",
        "source_type": "VIDEO",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "motion",
        "confidence": 0.80,
    }
    inc2 = test_engine.process_event(ev2)
    assert inc2 is not None
    assert inc2.incident_id != inc1.incident_id, "After 5s elapsed, a genuinely new incident must be created"
    assert inc2.event_ids == ["evt-time-2"]
    print("[PASS] test_new_incident_after_5s_elapsed")


def test_cooldown_after_incident_closed():
    """
    Verify:
    1. If an incident closed in that zone, events within 5s are suppressed.
    2. Only after 5s have passed since it closed, a genuinely new incident is started.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # 1. Open incident created at T = 0s
    ev1 = {
        "event_id": "evt-cd-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    inc1 = test_engine.process_event(ev1)
    assert inc1 is not None

    # 2. Incident closed at T = 2s (e.g. operator dispatched it)
    close_epoch = datetime.fromisoformat("2026-09-25T12:00:02.000+00:00").timestamp()
    test_engine.record_incident_closed("Vault_Entrance", close_time=close_epoch)

    # 3. Residual event arrives at T = 3.5s (1.5s after closing, within 5s cooldown)
    ev2 = {
        "event_id": "evt-cd-2",
        "timestamp": "2026-09-25T12:00:03.500Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    inc2 = test_engine.process_event(ev2)
    assert inc2 is None, "Expected residual event within 5s of closing to be suppressed (None)"

    # 4. Another residual event arrives at T = 6.0s (4s after closing, still < 5s cooldown)
    ev3 = {
        "event_id": "evt-cd-3",
        "timestamp": "2026-09-25T12:00:06.000Z",
        "source_type": "IOT",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_closed",
        "confidence": 0.80,
    }
    inc3 = test_engine.process_event(ev3)
    assert inc3 is None, "Expected event at 4s post-close to still be suppressed"

    # 5. Genuinely new event arrives at T = 8.0s (6s after closing, > 5s cooldown satisfied)
    ev4 = {
        "event_id": "evt-cd-4",
        "timestamp": "2026-09-25T12:00:08.000Z",
        "source_type": "CYBER",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "access_denied",
        "confidence": 0.85,
    }
    inc4 = test_engine.process_event(ev4)
    assert inc4 is not None, "Expected a genuinely new incident after 5s have passed since closing"
    assert inc4.incident_id != inc1.incident_id, "New incident must have a fresh incident_id"
    assert inc4.event_ids == ["evt-cd-4"]
    print("[PASS] test_cooldown_after_incident_closed")


def test_api_ingest_and_metrics_deduplication():
    """Verify that the FastAPI /ingest endpoint updates in-place and increases noise suppression."""
    client = TestClient(app)

    # Clear in-memory stores for clean testing
    engine.reset()
    incident_store.clear()
    event_store.clear()
    INCIDENTS_DB.clear()

    now_iso = datetime.now(timezone.utc).isoformat()

    # Event 1: First observation in Perimeter_Gate_3
    p1 = {
        "event_id": "api-evt-001",
        "timestamp": now_iso,
        "source_type": "VIDEO",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.60,
    }
    res1 = client.post("/ingest", json=p1)
    assert res1.status_code == 200
    assert len(incident_store) == 1
    first_incident_id = incident_store[0].incident_id
    first_score = incident_store[0].score

    # Event 2: Immediate follow-up frame (within 1 second) in same zone
    p2 = {
        "event_id": "api-evt-002",
        "timestamp": now_iso,
        "source_type": "IOT",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.95,
    }
    res2 = client.post("/ingest", json=p2)
    assert res2.status_code == 200

    # There should STILL only be 1 incident in incident_store (de-duplicated!)
    assert len(incident_store) == 1, f"Expected 1 incident, found {len(incident_store)}"
    updated_inc = incident_store[0]
    assert updated_inc.incident_id == first_incident_id, "Expected same incident_id"
    assert updated_inc.score >= first_score, "Expected updated higher score"
    assert "api-evt-001" in updated_inc.event_ids
    assert "api-evt-002" in updated_inc.event_ids

    # Check metrics
    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    metrics_data = metrics_res.json()
    assert metrics_data["total_events"] == 2
    assert metrics_data["total_incidents"] == 1
    assert metrics_data["noise_suppression_rate"] == 50.0  # (2 - 1) / 2 = 50%

    print("[PASS] test_api_ingest_and_metrics_deduplication")


def test_websocket_rebroadcast_and_cooldown_suppression():
    """Verify that updated incidents are re-broadcast over WebSocket and cooldown suppresses broadcast."""
    import json
    client = TestClient(app)

    # Clear state
    engine.reset()
    incident_store.clear()
    event_store.clear()
    INCIDENTS_DB.clear()

    now_iso = datetime.now(timezone.utc).isoformat()

    with client.websocket_connect("/ws/alerts") as ws:
        # Event 1: Ingest
        p1 = {
            "event_id": "ws-evt-001",
            "timestamp": now_iso,
            "source_type": "VIDEO",
            "zone_id": "Hangar_North",
            "coordinates": [37.4320, -122.1745],
            "event_type": "motion",
            "confidence": 0.50,
        }
        res1 = client.post("/ingest", json=p1)
        assert res1.status_code == 200

        # Receive first broadcast
        msg1_raw = ws.receive_text()
        msg1 = json.loads(msg1_raw)
        assert msg1["zone_id"] == "Hangar_North"
        assert msg1["event_ids"] == ["ws-evt-001"]
        orig_inc_id = msg1["incident_id"]
        orig_score = msg1["score"]

        # Event 2: Arrives within 1s in same zone (higher confidence)
        p2 = {
            "event_id": "ws-evt-002",
            "timestamp": now_iso,
            "source_type": "IOT",
            "zone_id": "Hangar_North",
            "coordinates": [37.4320, -122.1745],
            "event_type": "door_forced",
            "confidence": 0.95,
        }
        res2 = client.post("/ingest", json=p2)
        assert res2.status_code == 200

        # Receive re-broadcast of updated incident over WebSocket
        msg2_raw = ws.receive_text()
        msg2 = json.loads(msg2_raw)
        assert msg2["incident_id"] == orig_inc_id, "WebSocket re-broadcast must keep the same incident_id"
        assert msg2["score"] >= orig_score, "WebSocket re-broadcast must have higher score"
        assert "ws-evt-001" in msg2["event_ids"] and "ws-evt-002" in msg2["event_ids"]

        # Dispatch the incident (closes it)
        disp_res = client.post(f"/incidents/{orig_inc_id}/dispatch")
        assert disp_res.status_code == 200
        # Receive dispatch broadcast
        disp_msg_raw = ws.receive_text()
        disp_msg = json.loads(disp_msg_raw)
        assert disp_msg["status"] == "dispatched"

        # Event 3: Arrives 1 second after dispatch (within cooldown)
        p3 = {
            "event_id": "ws-evt-003",
            "timestamp": now_iso,
            "source_type": "VIDEO",
            "zone_id": "Hangar_North",
            "coordinates": [37.4320, -122.1745],
            "event_type": "residual_motion",
            "confidence": 0.70,
        }
        res3 = client.post("/ingest", json=p3)
        assert res3.status_code == 200
        assert res3.json()["incident_id"] is None, "Expected incident creation to be suppressed during cooldown"

    print("[PASS] test_websocket_rebroadcast_and_cooldown_suppression")


if __name__ == "__main__":
    print("=" * 60)
    print("  RUNNING INCIDENT DE-DUPLICATION TEST SUITE")
    print("=" * 60)
    test_deduplication_same_zone_within_5s()
    test_different_zone_creates_new_incident()
    test_new_incident_after_5s_elapsed()
    test_cooldown_after_incident_closed()
    test_api_ingest_and_metrics_deduplication()
    test_websocket_rebroadcast_and_cooldown_suppression()
    print("=" * 60)
    print("  ALL DE-DUPLICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
