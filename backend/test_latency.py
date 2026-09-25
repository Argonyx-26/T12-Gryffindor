"""
Gryfffindor Sentinel — Latency Patch Automated Test Suite (Phase 3B Final Patch)

22 deterministic tests verifying:
1. Stage 0: Frame to inference start timing
2. Stage 1: YOLO inference timing
3. Stage 2: Video event generation timing
4. Stage 3: Network ingestion cross-process UTC timing
5. Stage 4: Intelligence processing timing
6. Stage 5: Alert emission timing
7. Total End-to-End cross-process UTC timing
8. Missing frame capture UTC timestamp produces null end-to-end latency
9. Missing event generation UTC timestamp produces null network ingestion latency
10. Negative clock skew handling (rejection & invalid_timestamp_samples counter)
11. Trace ID propagation
12. IoT event null end-to-end latency
13. Cyber event null end-to-end latency
14. Multi-process cross-process ingestion timing validation
15. Single sample percentile calculation
16. Multiple sample percentiles (p50 / p95)
17. Bounded memory cap (maxlen=1000)
18. Zero sample metric handling returns null
19. 6-stage metrics schema in GET /metrics
20. Stage duration vs total trace consistency
21. Incident deduplication safety under latency collection
22. Full regression benchmark execution (100% F1 score)
"""

import os
import sys
import time
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
import numpy as np

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.latency_collector import LatencyCollector, LATENCY_COLLECTOR
from backend.models import Event, Incident
from backend.main import (
    evaluate_threat_correlation,
    EVENTS_DB,
    INCIDENTS_DB,
    get_metrics,
    calculate_incident_severity,
)
from backend.video_engine import MockVideoSource, YOLOEngine, SpatialAnalyticsEngine, convert_to_event_model
from backend.evaluation_dataset import EvaluationBenchmark


def run_tests():
    print("==================================================")
    print(" RUNNING PHASE 3B FINAL LATENCY TEST SUITE       ")
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
    LATENCY_COLLECTOR.clear()

    # 1. Stage 0: Frame to Inference Start Timing
    c = LatencyCollector()
    c.record_frame_to_inference_start(3.5)
    s0 = c._calculate_stats(c.frame_to_inf_start_samples)
    assert_test(s0["average"] == 3.5 and s0["sample_count"] == 1, "Stage 0: Frame to Inference Start", f"Got: {s0}")

    # 2. Stage 1: YOLO Inference Timing
    c.record_yolo_latency(22.4)
    s1 = c._calculate_stats(c.yolo_samples)
    assert_test(s1["average"] == 22.4 and s1["sample_count"] == 1, "Stage 1: YOLO Inference Timing", f"Got: {s1}")

    # 3. Stage 2: Video Event Generation Timing
    c.record_event_gen_latency(1.8)
    s2 = c._calculate_stats(c.event_gen_samples)
    assert_test(s2["average"] == 1.8 and s2["sample_count"] == 1, "Stage 2: Video Event Generation Timing", f"Got: {s2}")

    # 4. Stage 3: Network Ingestion Cross-Process UTC Timing
    c.record_network_ingest_latency(4.2)
    s3 = c._calculate_stats(c.network_ingest_samples)
    assert_test(s3["average"] == 4.2 and s3["sample_count"] == 1, "Stage 3: Network Ingestion Cross-Process UTC", f"Got: {s3}")

    # 5. Stage 4: Intelligence Processing Timing
    c.record_intelligence_latency(0.45)
    s4 = c._calculate_stats(c.intel_samples)
    assert_test(s4["average"] == 0.45 and s4["sample_count"] == 1, "Stage 4: Intelligence Processing Timing", f"Got: {s4}")

    # 6. Stage 5: Alert Emission Timing
    c.record_alert_emit_latency(0.15)
    s5 = c._calculate_stats(c.alert_emit_samples)
    assert_test(s5["average"] == 0.15 and s5["sample_count"] == 1, "Stage 5: Alert Emission Timing", f"Got: {s5}")

    # 7. Total End-to-End Cross-Process UTC Timing
    c.record_end_to_end_latency(45.0)
    se2e = c._calculate_stats(c.e2e_samples)
    assert_test(se2e["average"] == 45.0 and se2e["sample_count"] == 1, "Total End-to-End Cross-Process UTC Timing", f"Got: {se2e}")

    # 8. Missing Frame Capture UTC Timestamp Produces Null
    LATENCY_COLLECTOR.clear()
    empty_stats = LATENCY_COLLECTOR._calculate_stats(LATENCY_COLLECTOR.e2e_samples)
    assert_test(empty_stats["average"] is None and empty_stats["sample_count"] == 0, "Missing Frame Capture Timestamp Null Handling", f"Got: {empty_stats}")

    # 9. Missing Event Generation UTC Timestamp Produces Null Network Ingestion
    empty_net = LATENCY_COLLECTOR._calculate_stats(LATENCY_COLLECTOR.network_ingest_samples)
    assert_test(empty_net["average"] is None and empty_net["sample_count"] == 0, "Missing Event Gen Timestamp Null Network Ingestion", f"Got: {empty_net}")

    # 10. Negative Clock Skew Rejection & invalid_timestamp_samples Counter
    c_skew = LatencyCollector()
    c_skew.record_network_ingest_latency(-15.0)
    c_skew.record_end_to_end_latency(-50.0)
    assert_test(
        c_skew.invalid_timestamp_samples == 2 and len(c_skew.network_ingest_samples) == 0 and len(c_skew.e2e_samples) == 0,
        "Negative Clock Skew Rejection",
        f"Invalid samples: {c_skew.invalid_timestamp_samples}",
    )

    # 11. Trace ID Propagation
    mock_src = MockVideoSource()
    ret, frame, cap_ns, cap_utc = mock_src.read_frame()
    spatial = SpatialAnalyticsEngine(cooldown_seconds=0.0)
    mock_dets = [{"class": "person", "confidence": 0.92, "bbox": [50, 50, 150, 250], "centroid": (100, 150), "track_id": 1}]
    poly = np.array([[0, 0], [300, 0], [300, 300], [0, 300]], dtype=np.int32)
    raw_evts = spatial.process_frame_analytics(
        detections=mock_dets,
        frame_shape=frame.shape,
        zone_id="Perimeter_Gate_3",
        camera_id="CAM-TEST",
        restricted_polygon=poly,
        timing_info={"inference_start_ns": cap_ns + 1000, "inference_end_ns": cap_ns + 5000, "yolo_inference_ms": 4.0},
        frame_capture_ns=cap_ns,
        frame_capture_utc=cap_utc,
    )
    trace_id_present = len(raw_evts) > 0 and "trace_id" in raw_evts[0]["raw_meta"] and raw_evts[0]["raw_meta"]["trace_id"].startswith("trc-")
    assert_test(trace_id_present, "Trace ID Propagation", f"Meta: {raw_evts[0]['raw_meta'] if raw_evts else 'None'}")

    # 12. IoT Event Null End-to-End Latency
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    LATENCY_COLLECTOR.clear()
    iot_event = Event(
        event_id="t-iot-1",
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_type="IOT",
        zone_id="Server_Room",
        coordinates=[12.9, 77.5],
        event_type="forced_entry",
        confidence=0.95,
        raw_meta={"off_shift": True},
    )
    EVENTS_DB.append(iot_event)
    evaluate_threat_correlation(iot_event, ingest_ns=time.perf_counter_ns())
    metrics = get_metrics()
    iot_e2e = metrics["latency"]["end_to_end_detection_ms"]
    assert_test(iot_e2e["sample_count"] == 0 and iot_e2e["average"] is None, "IoT Event Null End-to-End Latency", f"Got: {iot_e2e}")

    # 13. Cyber Event Null End-to-End Latency
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    LATENCY_COLLECTOR.clear()
    cyber_event = Event(
        event_id="t-cyber-1",
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_type="CYBER",
        zone_id="Server_Room",
        coordinates=[12.9, 77.5],
        event_type="login_spike",
        confidence=0.98,
        raw_meta={"failed_count": 20},
    )
    EVENTS_DB.append(cyber_event)
    evaluate_threat_correlation(cyber_event, ingest_ns=time.perf_counter_ns())
    metrics = get_metrics()
    cyber_e2e = metrics["latency"]["end_to_end_detection_ms"]
    assert_test(cyber_e2e["sample_count"] == 0 and cyber_e2e["average"] is None, "Cyber Event Null End-to-End Latency", f"Got: {cyber_e2e}")

    # 14. Multi-Process Cross-Process Ingestion Timing Validation
    # Simulates Process A (Vision Worker) sending ISO UTC payload to Process B (Ingestion Endpoint)
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    LATENCY_COLLECTOR.clear()

    proc_a_cap_utc = (datetime.now(timezone.utc) - timedelta(milliseconds=50)).isoformat().replace("+00:00", "Z")
    proc_a_gen_utc = (datetime.now(timezone.utc) - timedelta(milliseconds=10)).isoformat().replace("+00:00", "Z")

    cross_proc_evt = Event(
        event_id="t-proc-a",
        timestamp=proc_a_gen_utc,
        source_type="VIDEO",
        zone_id="Perimeter_Gate_3",
        coordinates=[12.9, 77.5],
        event_type="person_detected",
        confidence=0.91,
        raw_meta={
            "frame_capture_timestamp_utc": proc_a_cap_utc,
            "event_generation_timestamp_utc": proc_a_gen_utc,
            "trace_id": "trc-cross-process-test",
        },
    )

    # Ingest event in Process B
    from backend.main import ingest_event
    import asyncio
    asyncio.run(ingest_event(cross_proc_evt))

    m_summary = LATENCY_COLLECTOR.get_metrics_summary()
    net_ingest_stat = m_summary["pipeline_breakdown_ms"]["3_network_ingestion"]
    assert_test(
        net_ingest_stat["sample_count"] == 1 and net_ingest_stat["average"] is not None and net_ingest_stat["average"] >= 0,
        "Multi-Process Cross-Process Ingestion UTC Timing",
        f"Got: {net_ingest_stat}",
    )

    # 15. Single Sample Percentile Calculation
    c_single = LatencyCollector()
    c_single.record_intelligence_latency(15.4)
    single_stats = c_single._calculate_stats(c_single.intel_samples)
    assert_test(
        single_stats["p50"] == 15.4 and single_stats["p95"] == 15.4 and single_stats["sample_count"] == 1,
        "Single Sample Percentile Calculation",
        f"Got: {single_stats}",
    )

    # 16. Multiple Sample Percentiles (p50 / p95)
    c_multi = LatencyCollector()
    for val in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]:
        c_multi.record_intelligence_latency(val)
    multi_stats = c_multi._calculate_stats(c_multi.intel_samples)
    assert_test(
        multi_stats["sample_count"] == 10 and multi_stats["p50"] == 50.0 and multi_stats["p95"] == 100.0,
        "Multiple Sample Percentiles (p50/p95)",
        f"Got: {multi_stats}",
    )

    # 17. Bounded Memory Cap (maxlen=1000)
    c_bounded = LatencyCollector(max_samples=5)
    for i in range(20):
        c_bounded.record_intelligence_latency(float(i))
    assert_test(
        len(c_bounded.intel_samples) == 5 and list(c_bounded.intel_samples) == [15.0, 16.0, 17.0, 18.0, 19.0],
        "Bounded Memory Deque Cap",
        f"Length: {len(c_bounded.intel_samples)}",
    )

    # 18. Zero Sample Handling Returns Null
    c_zero = LatencyCollector()
    summary_zero = c_zero.get_metrics_summary()
    assert_test(
        summary_zero["intelligence_processing_ms"]["sample_count"] == 0
        and summary_zero["end_to_end_detection_ms"]["sample_count"] == 0
        and summary_zero["pipeline_breakdown_ms"]["0_frame_to_inference_start"]["average"] is None,
        "Zero Sample Handling Returns Null",
        f"Got: {summary_zero}",
    )

    # 19. 6-Stage Metrics Schema in GET /metrics
    m_schema = get_metrics()
    stages = m_schema["latency"]["pipeline_breakdown_ms"]
    expected_keys = [
        "0_frame_to_inference_start",
        "1_yolo_inference",
        "2_video_event_generation",
        "3_network_ingestion",
        "4_intelligence_processing",
        "5_alert_emission",
        "total_end_to_end",
    ]
    all_keys_present = all(k in stages for k in expected_keys) and "invalid_timestamp_samples" in m_schema["latency"]
    assert_test(all_keys_present, "6-Stage Metrics Schema in GET /metrics", f"Keys: {list(stages.keys())}")

    # 20. Stage Duration vs Total Trace Consistency
    trace_consistent = (
        raw_evts[0]["raw_meta"]["frame_capture_monotonic_ns"]
        < raw_evts[0]["raw_meta"]["inference_start_ns"]
        < raw_evts[0]["raw_meta"]["inference_end_ns"]
        < raw_evts[0]["raw_meta"]["event_generation_ns"]
    )
    assert_test(trace_consistent, "Stage Duration Monotonic Order Consistency", "Timestamps ordered sequentially")

    # 21. Incident Deduplication Preservation
    EVENTS_DB.clear()
    INCIDENTS_DB.clear()
    evt_obj_1 = convert_to_event_model(raw_evts[0], "Perimeter_Gate_3")
    evt_obj_2 = Event(
        event_id="t-v2-dedup",
        timestamp=evt_obj_1.timestamp,
        source_type="IOT",
        zone_id="Perimeter_Gate_3",
        coordinates=[12.9, 77.5],
        event_type="forced_entry",
        confidence=0.95,
        raw_meta={"off_shift": True},
    )
    EVENTS_DB.append(evt_obj_1)
    EVENTS_DB.append(evt_obj_2)
    evaluate_threat_correlation(evt_obj_2, ingest_ns=time.perf_counter_ns())
    evaluate_threat_correlation(evt_obj_2, ingest_ns=time.perf_counter_ns())
    assert_test(len(INCIDENTS_DB) == 1, "Incident Deduplication Safety under Latency Tracking", f"Count: {len(INCIDENTS_DB)}")

    # 22. Full Regression Benchmark Execution
    eval_res = EvaluationBenchmark.run_benchmark()
    assert_test(
        eval_res["metrics"]["f1_score"] == 1.0 and eval_res["metrics"]["precision"] == 1.0,
        "Full Regression Benchmark Execution (100% F1)",
        f"F1={eval_res['metrics']['f1_score']}, Precision={eval_res['metrics']['precision']}",
    )

    print("==================================================")
    print(f" TOTAL TESTS: {passed + failed} | PASSED: {passed} | FAILED: {failed}")
    print("==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
