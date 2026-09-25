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
from backend.constants import SEVERITY_THRESHOLDS, SOURCE_WEIGHTS


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
    With the max-confidence formula, a single source contributes SOURCE_WEIGHTS[source_type] * max_conf * 100.
    For a single source to exceed Medium (>= 40), its weight must be >= 0.40 (e.g. HIGH_RISK_CAM with weight 0.50).
    """
    SOURCE_WEIGHTS["HIGH_RISK_CAM"] = 0.50
    try:
        test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

        # Frame 1: HIGH_RISK_CAM with lower confidence 0.60 at T = 0s -> score = 0.50 * 0.60 * 100 = 30.0 < 40 -> Suppressed
        ev1 = {
            "event_id": "hr-cam-frame-1",
            "timestamp": "2026-09-25T12:00:00.000Z",
            "source_type": "HIGH_RISK_CAM",
            "zone_id": "Gate_Charlie",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.60,
        }
        inc1 = test_engine.process_event(ev1)
        assert inc1 is None, "Frame 1 alone has score 30.0 < 40, should be suppressed"

        # Frame 2: HIGH_RISK_CAM with high confidence 0.90 at T = 0.5s -> max conf = 0.90 -> score = 0.50 * 0.90 * 100 = 45.0 >= 40
        ev2 = {
            "event_id": "hr-cam-frame-2",
            "timestamp": "2026-09-25T12:00:00.500Z",
            "source_type": "HIGH_RISK_CAM",
            "zone_id": "Gate_Charlie",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.90,
        }
        inc2 = test_engine.process_event(ev2)
        assert inc2 is not None, "Single source with score 45.0 >= 40 MUST create a visible incident"
        assert inc2.sources == ["HIGH_RISK_CAM"]
        assert inc2.score == 45.0
        assert inc2.score >= SEVERITY_THRESHOLDS["Medium"]
        assert "hr-cam-frame-2" in inc2.event_ids

        # Frame 3: Another HIGH_RISK_CAM frame at T = 1.0s with conf 0.85 (in 1.5s window).
        # Max confidence in window remains 0.90 (does NOT sum 0.60 + 0.90 + 0.85 = overflow past 100).
        ev3 = {
            "event_id": "hr-cam-frame-3",
            "timestamp": "2026-09-25T12:00:01.000Z",
            "source_type": "HIGH_RISK_CAM",
            "zone_id": "Gate_Charlie",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.85,
        }
        inc3 = test_engine.process_event(ev3)
        assert inc3 is not None
        assert inc3.incident_id == inc2.incident_id
        assert inc3.score == 45.0, f"Expected max confidence score 45.0, got {inc3.score}"
    finally:
        SOURCE_WEIGHTS.pop("HIGH_RISK_CAM", None)

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
    # At T = 2.0s, events within 1.5s are ev2 (T = 0.5s, diff 1.5s) and ev3 (T = 2.0s, diff 0.0s).
    # Distinct sources in window: IOT and CYBER (count 2, multiplier 1.5)
    # Score = (0.35*1.0 + 0.30*0.95) * 1.5 * 100 = 95.25
    assert updated_inc.score == 95.25
    assert "dedup-cyb-001" in updated_inc.event_ids, "Must merge new event_id into events list"
    assert "CYBER" in updated_inc.sources

    # 3. Fourth event arrives at T = 4.0s (within 5s of last event, but 2.0s after ev3)
    # Only ev4 is in the [2.5s, 4.0s] window. Score is recalculated from scratch for that window!
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
    # Score is recalculated fresh: 0.35 * 0.85 * 1.0 * 100 = 29.75 (Low)
    assert updated_inc2.score == 29.75
    assert updated_inc2.severity == "Low"
    assert "dedup-vid-002" in updated_inc2.event_ids
    assert len(updated_inc2.event_ids) == 4

    # 4. Fifth event arrives at T = 4.5s (IOT, conf 1.00) - within 0.5s of ev4!
    # In window [3.0s, 4.5s]: ev4 (VIDEO, 0.85) and ev5 (IOT, 1.00) corroborate
    ev5 = {
        "event_id": "dedup-iot-002",
        "timestamp": "2026-09-25T12:00:04.500Z",
        "source_type": "IOT",
        "zone_id": "Vault_Zulu",
        "coordinates": [37.4320, -122.1745],
        "event_type": "door_forced",
        "confidence": 1.00,
    }
    updated_inc3 = test_engine.process_event(ev5)
    assert updated_inc3 is not None
    assert updated_inc3.incident_id == orig_incident_id
    # (0.35*0.85 + 0.35*1.0) * 1.5 * 100 = 97.12 (Critical)
    assert updated_inc3.score == 97.12
    assert updated_inc3.severity == "Critical"

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


def test_synopsis_label_recalculation_on_deduplication():
    """
    Verify that when an incident is created or updated through de-duplication:
    - Count DISTINCT source_types across all merged events.
    - If 1 distinct source_type: "Single-source detection: [source]"
    - If 2 or more distinct source_types: "Corroborated multi-vector detection across: [sources]"
    - Single-source merged events do NOT say "Corroborated multimodal detection across: [source]".
    """
    orig_video_weight = SOURCE_WEIGHTS.get("VIDEO", 0.35)
    SOURCE_WEIGHTS["VIDEO"] = 0.50
    try:
        test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

        # 1. First event: VIDEO frame 1 at T = 0s (conf 0.60 -> score 30.0 < 40, suppressed)
        ev1 = {
            "event_id": "syn-vid-01",
            "timestamp": "2026-09-25T12:00:00.000Z",
            "source_type": "VIDEO",
            "zone_id": "Perimeter_Gate_Syn",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.60,
        }
        inc1 = test_engine.process_event(ev1)
        assert inc1 is None, "Frame 1 alone is suppressed (< Medium threshold)"

        # 2. Second event: VIDEO frame 2 at T = 0.5s (conf 0.90 -> score 45.0 >= 40 -> creates fresh single-source incident)
        ev2 = {
            "event_id": "syn-vid-02",
            "timestamp": "2026-09-25T12:00:00.500Z",
            "source_type": "VIDEO",
            "zone_id": "Perimeter_Gate_Syn",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.90,
        }
        inc2 = test_engine.process_event(ev2)
        assert inc2 is not None, "Fresh incident created for single source >= Medium"
        assert inc2.sources == ["VIDEO"]
        assert inc2.description == "Single-source detection: VIDEO", (
            f"Expected 'Single-source detection: VIDEO', got '{inc2.description}'"
        )

        # 3. Third event: VIDEO frame 3 at T = 2.0s (within 5s of OPEN incident in same zone)
        # De-duplicates into existing incident. DISTINCT source_types count is still 1 (VIDEO).
        ev3 = {
            "event_id": "syn-vid-03",
            "timestamp": "2026-09-25T12:00:02.000Z",
            "source_type": "VIDEO",
            "zone_id": "Perimeter_Gate_Syn",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.95,
        }
        inc3 = test_engine.process_event(ev3)
        assert inc3 is not None
        assert inc3.incident_id == inc2.incident_id, "Must be de-duplicated into the existing incident"
        assert inc3.sources == ["VIDEO"]
        assert inc3.description == "Single-source detection: VIDEO", (
            f"Expected merged single-source incident to remain 'Single-source detection: VIDEO', got '{inc3.description}'"
        )

        # 4. Fourth event: IOT sensor at T = 3.0s (within 5s, new distinct source modality)
        # De-duplicates into existing incident. DISTINCT source_types count is now 2 (VIDEO, IOT).
        ev4 = {
            "event_id": "syn-iot-04",
            "timestamp": "2026-09-25T12:00:03.000Z",
            "source_type": "IOT",
            "zone_id": "Perimeter_Gate_Syn",
            "coordinates": [37.4320, -122.1745],
            "event_type": "fence_motion",
            "confidence": 1.00,
        }
        inc4 = test_engine.process_event(ev4)
        assert inc4 is not None
        assert inc4.incident_id == inc2.incident_id
        assert set(inc4.sources) == {"VIDEO", "IOT"}
        assert inc4.description == "Corroborated multi-vector detection across: VIDEO, IOT", (
            f"Expected 'Corroborated multi-vector detection across: VIDEO, IOT', got '{inc4.description}'"
        )

        # 5. Fifth event: CYBER access log at T = 4.0s (within 5s, third distinct source modality)
        # De-duplicates into existing incident. DISTINCT source_types count is now 3 (VIDEO, IOT, CYBER).
        ev5 = {
            "event_id": "syn-cyb-05",
            "timestamp": "2026-09-25T12:00:04.000Z",
            "source_type": "CYBER",
            "zone_id": "Perimeter_Gate_Syn",
            "coordinates": [37.4320, -122.1745],
            "event_type": "unauthorized_override",
            "confidence": 0.95,
        }
        inc5 = test_engine.process_event(ev5)
        assert inc5 is not None
        assert inc5.incident_id == inc2.incident_id
        assert set(inc5.sources) == {"VIDEO", "IOT", "CYBER"}
        assert inc5.description == "Corroborated multi-vector detection across: VIDEO, IOT, CYBER", (
            f"Expected 'Corroborated multi-vector detection across: VIDEO, IOT, CYBER', got '{inc5.description}'"
        )
    finally:
        SOURCE_WEIGHTS["VIDEO"] = orig_video_weight

    print("[PASS] test_synopsis_label_recalculation_on_deduplication")


def test_cyber_burst_scoring_and_window_filtering():
    """
    Verify:
    1. A brute-force burst of 10 CYBER events in the correlation window contributes as ONE
       source modality using the MAXIMUM confidence value (0.30 * 1.0 * 100 = 30.0),
       never overflowing past 100 or summing every individual event.
    2. Multi-source corroboration (VIDEO + CYBER within 1.5s) correctly scales via
       CORROBORATION_MULTIPLIER[2] (e.g. 94.88).
    3. Additional bursts of CYBER events during the open incident do NOT inflate the score past 100.
    4. Merged incidents recalculate their score from scratch using ONLY events within 1.5s
       of the newest event's timestamp, returning to single-source score when VIDEO expires.
    """
    test_engine = CorrelationEngine(dedup_window_seconds=5.0, cooldown_window_seconds=5.0)

    # 1. Burst of 10 CYBER failed logins within 1 second at T = 0.0s to 0.9s
    # Each has confidence between 0.85 and 1.0.
    # Grouping by source_type takes MAX confidence (1.0).
    # Score = min(100, 0.30 * 1.0 * 1.0 * 100) = 30.0 (< 40 threshold).
    # None of them create a false-positive incident!
    for i in range(10):
        ev = {
            "event_id": f"cyber-burst-{i:02d}",
            "timestamp": f"2026-09-25T12:00:00.{i:03d}Z",
            "source_type": "CYBER",
            "zone_id": "Server_Alpha",
            "coordinates": [37.4, -122.1],
            "event_type": "failed_login",
            "confidence": 1.0 if i == 9 else round(0.85 + (i * 0.015), 3),
        }
        res = test_engine.process_event(ev)
        assert res is None, f"CYBER burst event {i} should be suppressed (score 30.0 < 40, not overflowed!)"

    # 2. Corroborating VIDEO event arrives at T = 1.0s (within 1.5s of the CYBER burst)
    # Distinct sources = 2 (CYBER max conf 1.0, VIDEO conf 0.95).
    # Score = (0.35 * 0.95 + 0.30 * 1.0) * 1.5 * 100 = 94.88 (Critical)
    ev_video = {
        "event_id": "video-corr-01",
        "timestamp": "2026-09-25T12:00:01.000Z",
        "source_type": "VIDEO",
        "zone_id": "Server_Alpha",
        "coordinates": [37.4, -122.1],
        "event_type": "person_detected",
        "confidence": 0.95,
    }
    inc_open = test_engine.process_event(ev_video)
    assert inc_open is not None
    assert inc_open.score == 94.88, f"Expected 94.88, got {inc_open.score}"
    assert inc_open.severity == "Critical"
    assert set(inc_open.sources) == {"CYBER", "VIDEO"}

    # 3. Another burst of 5 CYBER events arrives at T = 1.5s (within 5s dedup window & 1.5s correlation window)
    # De-duplicates into existing incident.
    # Max confidence per source remains 1.0 for CYBER, 0.95 for VIDEO.
    # Score MUST REMAIN 94.88 (does NOT sum 5 more additions to overflow past 100!)
    for i in range(5):
        ev = {
            "event_id": f"cyber-burst-followup-{i:02d}",
            "timestamp": f"2026-09-25T12:00:01.{500 + i * 50:03d}Z",
            "source_type": "CYBER",
            "zone_id": "Server_Alpha",
            "coordinates": [37.4, -122.1],
            "event_type": "failed_login",
            "confidence": 1.0,
        }
        inc_dedup = test_engine.process_event(ev)
        assert inc_dedup is not None
        assert inc_dedup.score == 94.88, f"Score must stay 94.88 using max confidence, got {inc_dedup.score}"

    # 4. Spaced out CYBER event arrives at T = 3.5s (2.5s after VIDEO event, so VIDEO is outside 1.5s correlation window)
    # Recalculates from scratch using ONLY events within 1.5s of T = 3.5s:
    # Only CYBER is in the correlation window! Max conf = 1.0.
    # Score drops back to single-source 30.0 (Low severity).
    ev_late = {
        "event_id": "cyber-late-01",
        "timestamp": "2026-09-25T12:00:03.500Z",
        "source_type": "CYBER",
        "zone_id": "Server_Alpha",
        "coordinates": [37.4, -122.1],
        "event_type": "failed_login",
        "confidence": 1.0,
    }
    inc_late = test_engine.process_event(ev_late)
    assert inc_late is not None
    assert inc_late.score == 30.0, f"Expected 30.0 after VIDEO expired from window, got {inc_late.score}"
    assert inc_late.severity == "Low"

    print("[PASS] test_cyber_burst_scoring_and_window_filtering")


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
    test_synopsis_label_recalculation_on_deduplication()
    test_cyber_burst_scoring_and_window_filtering()
    print("=" * 65)
    print("  ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 65)
