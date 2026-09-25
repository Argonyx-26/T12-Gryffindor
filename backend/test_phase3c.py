"""
Gryfffindor Sentinel — Phase 3C Test Suite (Persistent Intelligence & Production Backend)

20 deterministic tests verifying:
1. Database Connection Check
2. Event Creation & Validation
3. Event Persistence to Database
4. Event Retrieval from Database
5. Incident Persistence & Synthesis
6. Incident Update & Status Persistence
7. Incident Lifecycle Transitions (open -> dispatched -> ACKNOWLEDGED -> RESOLVED -> false_positive)
8. Incident-Event Relationship (Junction Table incident_events)
9. Duplicate Event Idempotency & Conflict Handling
10. Restart Recovery (Full backend state restoration from DB)
11. Historical Event Querying & Pagination
12. Historical Incident Filtering
13. Behavioral Baseline Persistence & Reload
14. Redis Active Incident Caching
15. Redis Connection Failure In-Memory Fallback
16. Database Connectivity Health Status
17. WebSocket Compatibility & Alert Emitting
18. Trace ID End-to-End Persistence
19. Latency Metrics Compatibility (GET /metrics)
20. Configurable Data Retention Cleanup (POST /admin/cleanup)
"""

import os
import sys
import time
import json
import uuid
from datetime import datetime, timezone, timedelta

# Add parent workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from backend.config import settings
from backend.database import init_db, db_session, check_db_connection
from backend.db_models import EventModel, IncidentModel, IncidentEventModel, BehavioralBaselineModel, AuditLogModel
from backend.models import Event, Incident
from backend.redis_client import SentinelRedisClient, REDIS_CLIENT
from backend.temporal_engine import BehavioralBaselineEngine
from backend.main import app, EVENTS_DB, INCIDENTS_DB, load_state_from_db


def run_tests():
    print("==================================================")
    print(" RUNNING PHASE 3C PRODUCTION BACKEND TEST SUITE   ")
    print("==================================================")

    passed = 0
    failed = 0

    def assert_test(condition: bool, test_name: str, detail: str = ""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✅ [PASS] Test {passed + failed:02d}: {test_name}")
        else:
            failed += 1
            print(f"  ❌ [FAIL] Test {passed + failed:02d}: {test_name} — {detail}")

    # Reset state
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    init_db()
    client = TestClient(app)

    # 1. Database Connection Check
    db_connected = check_db_connection()
    assert_test(db_connected, "Database Connection Check", f"Connected: {db_connected}")

    # 2. Event Creation & Validation
    test_evt_1 = Event(
        event_id="p3c-evt-001",
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_type="VIDEO",
        zone_id="Server_Room",
        coordinates=[12.9, 77.5],
        event_type="person_detected",
        confidence=0.95,
        raw_meta={"camera_id": "CAM-01", "trace_id": "trc-p3c-001"},
    )
    assert_test(test_evt_1.event_id == "p3c-evt-001", "Event Creation & Validation", f"ID: {test_evt_1.event_id}")

    # 3. Event Persistence to Database
    resp = client.post("/ingest", json=test_evt_1.model_dump())
    assert_test(resp.status_code == 201, "Event Ingestion & DB Persistence Endpoint", f"Status: {resp.status_code}")
    with db_session() as db:
        db_evt = db.query(EventModel).filter_by(event_id="p3c-evt-001").first()
        assert_test(db_evt is not None and db_evt.trace_id == "trc-p3c-001", "Event Database Record Verification", f"Record: {db_evt}")

    # 4. Event Retrieval from Database
    get_evt_resp = client.get("/events?zone_id=Server_Room")
    assert_test(get_evt_resp.status_code == 200 and len(get_evt_resp.json()) >= 1, "Event Retrieval from DB", f"Items: {len(get_evt_resp.json())}")

    # 5. Incident Persistence & Synthesis
    test_evt_2 = Event(
        event_id="p3c-evt-002",
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_type="IOT",
        zone_id="Server_Room",
        coordinates=[12.9, 77.5],
        event_type="door_open",
        confidence=0.98,
        raw_meta={"off_shift": True},
    )
    resp2 = client.post("/ingest", json=test_evt_2.model_dump())
    inc_data = resp2.json().get("triggered_incident")
    assert_test(inc_data is not None and inc_data["score"] >= 60.0, "Incident Synthesis & Corroboration", f"Inc: {inc_data['incident_id'] if inc_data else None}")
    
    inc_id = inc_data["incident_id"] if inc_data else ""
    with db_session() as db:
        db_inc = db.query(IncidentModel).filter_by(incident_id=inc_id).first()
        assert_test(db_inc is not None and db_inc.status == "dispatched", "Incident Database Persistence", f"DB Status: {db_inc.status if db_inc else None}")

    # 6. Incident Update & Status Persistence
    patch_resp = client.patch(f"/incidents/{inc_id}/status?new_status=dispatched")
    assert_test(patch_resp.status_code == 200, "Incident Status Update API", f"Patch status: {patch_resp.status_code}")

    # 7. Incident Lifecycle Transitions
    ack_resp = client.patch(f"/incidents/{inc_id}/acknowledge")
    res_resp = client.patch(f"/incidents/{inc_id}/resolve")
    assert_test(
        ack_resp.status_code == 200 and res_resp.status_code == 200 and res_resp.json()["status"] == "RESOLVED",
        "Incident Lifecycle Transitions (ACK -> RESOLVED)",
        f"Final status: {res_resp.json().get('status') if res_resp.status_code == 200 else None}",
    )

    # 8. Incident-Event Relationship Junction Table
    with db_session() as db:
        ie_records = db.query(IncidentEventModel).filter_by(incident_id=inc_id).all()
        assert_test(len(ie_records) >= 1, "Incident-Event Junction Table Relationship", f"Junction records: {len(ie_records)}")

    # 9. Duplicate Event Idempotency & Conflict Handling
    dup_resp = client.post("/ingest", json=test_evt_1.model_dump())
    assert_test(dup_resp.status_code == 409, "Duplicate Event Conflict Handling (409)", f"Dup Status: {dup_resp.status_code}")

    # 10. Restart Recovery Simulation
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    load_state_from_db()
    assert_test(len(EVENTS_DB) >= 2 and inc_id in INCIDENTS_DB, "Restart Recovery (State Reload from DB)", f"Reloaded events: {len(EVENTS_DB)}, incs: {len(INCIDENTS_DB)}")

    # 11. Historical Event Querying & Pagination
    page_resp = client.get("/events?page=1&limit=1")
    page_data = page_resp.json()
    assert_test("items" in page_data and page_data["limit"] == 1 and len(page_data["items"]) == 1, "Historical Event Querying & Pagination", f"Page keys: {list(page_data.keys()) if isinstance(page_data, dict) else None}")

    # 12. Historical Incident Filtering
    filt_resp = client.get(f"/incidents?severity=Critical&status=RESOLVED")
    assert_test(filt_resp.status_code == 200, "Historical Incident Filtering", f"Filt count: {len(filt_resp.json())}")

    # 13. Behavioral Baseline Persistence & Reload
    with db_session() as db:
        BehavioralBaselineEngine.save_baseline_to_db("Server_Room", "VIDEO", "person_detected", 14, 2.5, db)
    BehavioralBaselineEngine._baselines_cache.clear()
    with db_session() as db:
        BehavioralBaselineEngine.load_baselines_from_db(db)
    cached_val = BehavioralBaselineEngine._baselines_cache.get("Server_Room:VIDEO:person_detected:14")
    assert_test(cached_val == 2.5, "Behavioral Baseline Persistence & Reload", f"Cached val: {cached_val}")

    # 14. Redis Active Incident Caching
    r_client = SentinelRedisClient()
    r_client.set_active_incident("inc-test-redis", {"incident_id": "inc-test-redis", "score": 90.0})
    active_map = r_client.get_active_incidents()
    assert_test("inc-test-redis" in active_map, "Redis Active Incident Caching", f"Active keys: {list(active_map.keys())}")
    r_client.remove_active_incident("inc-test-redis")

    # 15. Redis Connection Failure Degraded Fallback
    r_offline = SentinelRedisClient("redis://127.0.0.1:59999/0")
    assert_test(not r_offline.is_connected, "Redis Connection Failure Detection", f"Is connected: {r_offline.is_connected}")
    r_offline.set_active_incident("inc-degraded-1", {"status": "open"})
    fallback_map = r_offline.get_active_incidents()
    assert_test("inc-degraded-1" in fallback_map, "Redis In-Memory Degraded Fallback", f"Fallback map: {fallback_map}")

    # 16. Database & Redis Health Status Endpoint
    health_resp = client.get("/health")
    assert_test(health_resp.status_code == 200 and "database" in health_resp.json(), "GET /health System Status Endpoint", f"Health: {health_resp.json()}")

    # 17. WebSocket Alert Broadcast Compatibility
    try:
        import asyncio
        from backend.main import manager
        asyncio.run(manager.broadcast({"test": "ws_alert"}))
        assert_test(True, "WebSocket Alert Broadcast Compatibility", "Broadcast executed successfully")
    except Exception as e:
        assert_test(False, "WebSocket Alert Broadcast Compatibility", f"Broadcast failed: {e}")

    # 18. Trace ID End-to-End Persistence
    with db_session() as db:
        evt_trc = db.query(EventModel).filter_by(trace_id="trc-p3c-001").first()
        assert_test(evt_trc is not None and evt_trc.event_id == "p3c-evt-001", "Trace ID End-to-End Persistence in DB", f"Trace Evt: {evt_trc}")

    # 19. Latency Metrics Compatibility (GET /metrics)
    metrics_resp = client.get("/metrics")
    m_json = metrics_resp.json()
    assert_test("latency" in m_json and "pipeline_breakdown_ms" in m_json["latency"], "Metrics Compatibility GET /metrics", f"Metrics latency keys: {list(m_json.get('latency', {}).keys())}")

    # 20. Configurable Data Retention Cleanup (POST /admin/cleanup)
    cleanup_resp = client.post("/admin/cleanup")
    assert_test(cleanup_resp.status_code == 200 and "deleted_events_count" in cleanup_resp.json(), "Configurable Data Retention Cleanup API", f"Cleanup: {cleanup_resp.json()}")

    print("==================================================")
    print(f" TOTAL TESTS: {passed + failed} | PASSED: {passed} | FAILED: {failed}")
    print("==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
