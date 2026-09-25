"""
Comprehensive Test Suite for CorrelationEngine:
- Low-confidence single-source noise suppression (Condition a & b)
- Multi-source corroboration within correlation window
- Single-source high-severity qualification (>= Medium threshold)
- Incident de-duplication in same zone within 5s of an OPEN incident
- Different zone separation
- Cooldown period post-closure
- /metrics noise suppression rate calculation
- Live WebSocket alert broadcasting & re-broadcasting
"""

import sys
from pathlib import Path
import json
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
from backend.constants import SEVERITY_THRESHOLDS


def test_single_source_low_confidence_suppression():
    """
    Verify that single-source, low-confidence events:
    - Lone door sensor (IOT, conf 1.0, score 35 < 40)
    - Lone failed login (CYBER, conf 0.95, score 28.5 < 40)
    do NOT create a visible incident or appear in /incidents or WebSocket broadcasts,
    but ARE logged in event_store and counted in /metrics.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # 1. Lone door sensor trigger (IOT)
    ev_door = {
        "event_id": "lone-door-001",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "IOT",
        "zone_id": "Gate_Alpha",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_opened",
        "confidence": 1.00,  # score = 0.35 * 1.0 * 100 = 35.0 < 40 (Low)
    }
    inc_door = test_engine.process_event(ev_door)
    assert inc_door is None, "Expected lone door sensor (< Medium threshold) to be suppressed (None)"

    # 2. Lone failed login (CYBER)
    ev_login = {
        "event_id": "lone-cyber-001",
        "timestamp": "2026-09-25T12:00:10.000Z",
        "source_type": "CYBER",
        "zone_id": "Server_Room_Beta",
        "coordinates": [37.4320, -122.1745],
        "event_type": "failed_login",
        "confidence": 0.95,  # score = 0.30 * 0.95 * 100 = 28.5 < 40 (Low)
    }
    inc_login = test_engine.process_event(ev_login)
    assert inc_login is None, "Expected lone failed login (< Medium threshold) to be suppressed (None)"

    print("[PASS] test_single_source_low_confidence_suppression")


def test_multi_source_corroboration_creates_incident():
    """
    Condition (a): Two or more distinct source_types corroborate within the correlation window (1.5s).
    Even if the first event alone was low-confidence, when a second distinct source arrives within 1.5s,
    they corroborate to create a visible incident.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # Event 1 at T = 0s: Lone door sensor (IOT, conf 1.0, score 35.0 < 40)
    ev1 = {
        "event_id": "corr-iot-001",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "IOT",
        "zone_id": "Perimeter_North",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 1.00,
    }
    inc1 = test_engine.process_event(ev1)
    assert inc1 is None, "Event 1 alone is a single source below Medium, should not create an incident"

    # Event 2 at T = 0.5s: Camera detection (VIDEO, conf 0.90) in same zone
    ev2 = {
        "event_id": "corr-vid-001",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "VIDEO",
        "zone_id": "Perimeter_North",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    inc2 = test_engine.process_event(ev2)
    assert inc2 is not None, "Two distinct sources within correlation window MUST create a visible incident"
    assert "IOT" in inc2.sources and "VIDEO" in inc2.sources
    assert len(inc2.sources) == 2
    assert "corr-iot-001" in inc2.event_ids and "corr-vid-001" in inc2.event_ids
    assert inc2.score >= SEVERITY_THRESHOLDS["Medium"]

    print("[PASS] test_multi_source_corroboration_creates_incident")


def test_single_source_above_medium_creates_incident():
    """
    Condition (b): A single source's score alone is above the 'Medium' threshold (>= 40).
    For example, multiple consecutive frames of the same source (VIDEO) within 1.5s accumulate score >= 40.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # Frame 1: VIDEO conf 0.90 at T = 0s (score 31.5 < 40)
    ev1 = {
        "event_id": "video-frame-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Gate_Charlie",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    inc1 = test_engine.process_event(ev1)
    assert inc1 is None, "Frame 1 alone has score 31.5 < 40, should be suppressed"

    # Frame 2: VIDEO conf 0.90 at T = 0.5s (accumulated score: (0.35*0.9 + 0.35*0.9)*100 = 63.0 >= 40)
    ev2 = {
        "event_id": "video-frame-2",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "VIDEO",
        "zone_id": "Gate_Charlie",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    inc2 = test_engine.process_event(ev2)
    assert inc2 is not None, "Single source with accumulated score >= 40 MUST create a visible incident"
    assert inc2.sources == ["VIDEO"]
    assert inc2.score >= SEVERITY_THRESHOLDS["Medium"]
    assert "video-frame-1" in inc2.event_ids and "video-frame-2" in inc2.event_ids

    print("[PASS] test_single_source_above_medium_creates_incident")


def test_deduplication_same_zone_within_5s():
    """
    De-duplication: If a new incident would be created in the same zone within 5s of an existing OPEN incident:
    - Don't create a separate incident.
    - Update the existing incident's score (take higher score).
    - Merge the new event_id into its events list.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # 1. Establish an open incident via 2 corroborated sources at T = 0.0s & T = 0.5s
    ev1 = {
        "event_id": "dedup-vid-001",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Zulu",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    test_engine.process_event(ev1)

    ev2 = {
        "event_id": "dedup-iot-001",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "IOT",
        "zone_id": "Vault_Zulu",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 1.00,
    }
    open_inc = test_engine.process_event(ev2)
    assert open_inc is not None
    orig_incident_id = open_inc.incident_id
    orig_score = open_inc.score

    # 2. Third event arrives at T = 2.0s in same zone (CYBER, conf 0.95)
    ev3 = {
        "event_id": "dedup-cyb-001",
        "timestamp": "2026-09-25T12:00:02.000Z",
        "source_type": "CYBER",
        "zone_id": "Vault_Zulu",
        "coordinates": [37.4320, -122.1745],
        "event_type": "badge_brute_force",
        "confidence": 0.95,
    }
    updated_inc = test_engine.process_event(ev3)
    assert updated_inc is not None
    assert updated_inc.incident_id == orig_incident_id, "Must keep the same incident_id (deduplication)"
    assert updated_inc.score >= orig_score, "Must use the higher score value"
    assert "dedup-cyb-001" in updated_inc.event_ids, "Must merge new event_id into events list"
    assert "CYBER" in updated_inc.sources

    # 3. Fourth event arrives at T = 4.0s (within 5s of last event)
    ev4 = {
        "event_id": "dedup-vid-002",
        "timestamp": "2026-09-25T12:00:04.000Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Zulu",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.85,
    }
    updated_inc2 = test_engine.process_event(ev4)
    assert updated_inc2 is not None
    assert updated_inc2.incident_id == orig_incident_id
    assert updated_inc2.score >= updated_inc.score
    assert "dedup-vid-002" in updated_inc2.event_ids

    print("[PASS] test_deduplication_same_zone_within_5s")


def test_different_zone_creates_new_incident():
    """Verify that an event in a different zone creates a separate, genuinely new incident."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # Zone Alpha: 2-source incident
    test_engine.process_event({
        "event_id": "za-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Zone_Alpha",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc_a = test_engine.process_event({
        "event_id": "za-2",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "IOT",
        "zone_id": "Zone_Alpha",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.90,
    })
    assert inc_a is not None

    # Zone Beta: 2-source incident
    test_engine.process_event({
        "event_id": "zb-1",
        "timestamp": "2026-09-25T12:00:01.000Z",
        "source_type": "VIDEO",
        "zone_id": "Zone_Beta",
        "coordinates": [37.4325, -122.1750],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc_b = test_engine.process_event({
        "event_id": "zb-2",
        "timestamp": "2026-09-25T12:00:01.500Z",
        "source_type": "CYBER",
        "zone_id": "Zone_Beta",
        "coordinates": [37.4325, -122.1750],
        "event_type": "badge_brute_force",
        "confidence": 0.90,
    })
    assert inc_b is not None

    assert inc_a.incident_id != inc_b.incident_id, "Different zones must yield separate incident IDs"
    assert inc_a.zone_id == "Zone_Alpha"
    assert inc_b.zone_id == "Zone_Beta"
    print("[PASS] test_different_zone_creates_new_incident")


def test_new_incident_after_5s_elapsed():
    """Verify that if > 5s pass since the last event of an open incident, a new incident starts."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # First incident at T = 0.0s & 0.5s
    test_engine.process_event({
        "event_id": "time-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc1 = test_engine.process_event({
        "event_id": "time-2",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "IOT",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.90,
    })
    assert inc1 is not None

    # New burst at T = 10.0s & 10.5s (> 5s later)
    test_engine.process_event({
        "event_id": "time-3",
        "timestamp": "2026-09-25T12:00:10.000Z",
        "source_type": "VIDEO",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc2 = test_engine.process_event({
        "event_id": "time-4",
        "timestamp": "2026-09-25T12:00:10.500Z",
        "source_type": "CYBER",
        "zone_id": "Server_Room",
        "coordinates": [37.4320, -122.1745],
        "event_type": "failed_login",
        "confidence": 0.90,
    })
    assert inc2 is not None
    assert inc2.incident_id != inc1.incident_id, "After 5s elapsed, a genuinely new incident must be created"
    print("[PASS] test_new_incident_after_5s_elapsed")


def test_cooldown_after_incident_closed():
    """Verify that after an incident is closed, new incidents in that zone are suppressed for 5s."""
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # 1. Incident created at T = 0.0s & 0.5s
    test_engine.process_event({
        "event_id": "cd-1",
        "timestamp": "2026-09-25T12:00:00.000Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc1 = test_engine.process_event({
        "event_id": "cd-2",
        "timestamp": "2026-09-25T12:00:00.500Z",
        "source_type": "IOT",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.90,
    })
    assert inc1 is not None

    # 2. Incident closed at T = 2.0s
    close_epoch = datetime.fromisoformat("2026-09-25T12:00:02.000+00:00").timestamp()
    test_engine.record_incident_closed("Vault_Entrance", close_time=close_epoch)

    # 3. Residual event at T = 3.5s (1.5s post-closure < 5s cooldown)
    ev_res = {
        "event_id": "cd-res-1",
        "timestamp": "2026-09-25T12:00:03.500Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    }
    assert test_engine.process_event(ev_res) is None, "Should be suppressed during cooldown"

    # 4. Genuinely new event burst at T = 8.0s & 8.5s (6s post-closure > 5s cooldown)
    test_engine.process_event({
        "event_id": "cd-new-1",
        "timestamp": "2026-09-25T12:00:08.000Z",
        "source_type": "VIDEO",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "person_detected",
        "confidence": 0.90,
    })
    inc_new = test_engine.process_event({
        "event_id": "cd-new-2",
        "timestamp": "2026-09-25T12:00:08.500Z",
        "source_type": "IOT",
        "zone_id": "Vault_Entrance",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 0.90,
    })
    assert inc_new is not None, "New incident allowed after cooldown"
    assert inc_new.incident_id != inc1.incident_id
    print("[PASS] test_cooldown_after_incident_closed")


def test_api_ingest_metrics_and_websocket():
    """
    Test end-to-end FastAPI integration:
    - Low-confidence events are stored in event_store, not in incident_store, not broadcasted
    - Corroborated events create a visible incident and broadcast
    - Subsequent event within 5s updates existing incident in-place and re-broadcasts
    - /metrics accurately calculates noise suppression rate
    """
    client = TestClient(app)

    # Reset state
    engine.reset()
    incident_store.clear()
    event_store.clear()
    INCIDENTS_DB.clear()

    now_iso = datetime.now(timezone.utc).isoformat()

    with client.websocket_connect("/ws/alerts") as ws:
        # 1. Ingest lone low-confidence event (door sensor alone, conf 0.50, score 17.5 < 40)
        p_lone = {
            "event_id": "lone-iot-api",
            "timestamp": now_iso,
            "source_type": "IOT",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "door_opened",
            "confidence": 0.50,
        }
        res_lone = client.post("/ingest", json=p_lone)
        assert res_lone.status_code == 200
        assert res_lone.json()["incident_id"] is None
        # Verify NOT in incident_store
        assert len(incident_store) == 0
        assert len(event_store) == 1

        # Check metrics: 1 event, 0 incidents -> 100% noise suppression
        m1 = client.get("/metrics").json()
        assert m1["total_events"] == 1
        assert m1["total_incidents"] == 0
        assert m1["noise_suppression_rate"] == 100.0

        # 2. Ingest corroborating event (VIDEO, conf 0.90) in same zone within correlation window
        p_corroborate = {
            "event_id": "corr-vid-api",
            "timestamp": now_iso,
            "source_type": "VIDEO",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.90,
        }
        res_corr = client.post("/ingest", json=p_corroborate)
        assert res_corr.status_code == 200
        assert res_corr.json()["incident_id"] is not None
        inc_id = res_corr.json()["incident_id"]

        # 1 incident now created
        assert len(incident_store) == 1
        assert len(event_store) == 2

        # WebSocket received the new incident broadcast
        msg1 = json.loads(ws.receive_text())
        assert msg1["incident_id"] == inc_id
        assert "IOT" in msg1["sources"] and "VIDEO" in msg1["sources"]
        orig_score = msg1["score"]

        # Check metrics: 2 events, 1 incident -> (2 - 1) / 2 = 50% noise suppression
        m2 = client.get("/metrics").json()
        assert m2["total_events"] == 2
        assert m2["total_incidents"] == 1
        assert m2["noise_suppression_rate"] == 50.0

        # 3. Ingest third event (CYBER, conf 0.95) within 5s -> de-duplicates into existing incident
        p_dedup = {
            "event_id": "dedup-cyb-api",
            "timestamp": now_iso,
            "source_type": "CYBER",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "badge_brute_force",
            "confidence": 0.95,
        }
        res_dedup = client.post("/ingest", json=p_dedup)
        assert res_dedup.status_code == 200
        assert res_dedup.json()["incident_id"] == inc_id

        # Still only 1 incident (updated in-place)
        assert len(incident_store) == 1
        assert len(event_store) == 3

        # WebSocket received re-broadcast of updated incident
        msg2 = json.loads(ws.receive_text())
        assert msg2["incident_id"] == inc_id
        assert msg2["score"] >= orig_score
        assert "dedup-cyb-api" in msg2["event_ids"]

        # Check metrics: 3 events, 1 incident -> (3 - 1) / 3 = 66.67% noise suppression
        m3 = client.get("/metrics").json()
        assert m3["total_events"] == 3
        assert m3["total_incidents"] == 1
        assert m3["noise_suppression_rate"] == 66.67

    print("[PASS] test_api_ingest_metrics_and_websocket")


if __name__ == "__main__":
    print("=" * 65)
    print("  RUNNING COMPREHENSIVE CORRELATION & DE-DUPLICATION TEST SUITE")
    print("=" * 65)
    test_single_source_low_confidence_suppression()
    test_multi_source_corroboration_creates_incident()
    test_single_source_above_medium_creates_incident()
    test_deduplication_same_zone_within_5s()
    test_different_zone_creates_new_incident()
    test_new_incident_after_5s_elapsed()
    test_cooldown_after_incident_closed()
    test_api_ingest_metrics_and_websocket()
    print("=" * 65)
    print("  ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 65)
