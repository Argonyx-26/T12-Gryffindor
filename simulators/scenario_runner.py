"""
simulators/scenario_runner.py
One command to drive the entire scripted demo, per the pitch script:
  Act 1: Baseline        - normal ambient traffic, near-zero alerts
  Act 2: Suppressed Noise - single-vector events that should be filtered
  Act 3: Multi-Vector Breach - CCTV + sensor + cyber corroborate at once

Also doubles as the demo-day safety net: `--replay events.jsonl` replays a
pre-recorded event log straight to /ingest if live components die.

Usage:
    python scenario_runner.py                 # full scripted demo
    python scenario_runner.py --act 3          # just the breach act
    python scenario_runner.py --mock-cctv      # inject fake person_detected
                                                 events (use before YOLO is wired up)
    python scenario_runner.py --replay events.jsonl   # offline fallback replay
    python scenario_runner.py --record events.jsonl   # log every event emitted
                                                          this run, for later replay
"""
import argparse
import json
import random
import time
import uuid

import requests

from common import HUB_URL, ZONES, init_producer, make_event, post_event, enable_recording, close_recording, now_utc_iso
from sensor_sim import emit_door_open, emit_motion
from syslog_sim import emit_login, emit_login_spike

_record_fh = None


def _maybe_record(evt: dict):
    if _record_fh:
        _record_fh.write(json.dumps(evt) + "\n")
        _record_fh.flush()


def _post(evt: dict):
    _maybe_record(evt)
    return post_event(evt)


def emit_cctv_person(zone_id: str, confidence: float = 0.9, tripwire: bool = True):
    """Mock CCTV event matching what vision_worker.py will eventually emit
    for real — lets the pipeline be demoed/tested before YOLO is wired up."""
    evt = make_event(
        source="cctv",
        zone_id=zone_id,
        event_type="person_detected",
        confidence=confidence,
        payload={
            "bbox": [120, 80, 260, 400],
            "frame_b64": None,  # real vision_worker fills this with a JPEG b64 crop
            "tripwire_crossed": tripwire,
        },
    )
    ok = _post(evt)
    print(f"[scenario] mock person_detected zone={zone_id} -> {'OK' if ok else 'FAIL'}")
    return evt


def act1_baseline(duration_s: int = 20):
    print("\n=== ACT 1: BASELINE ===")
    zones = list(ZONES.keys())
    end = time.time() + duration_s
    while time.time() < end:
        zone = random.choice(zones)
        roll = random.random()
        if roll < 0.4:
            evt = make_event("sensor", zone, "motion", round(random.uniform(0.6, 0.85), 2))
            _post(evt)
        elif roll < 0.7:
            evt = make_event("syslog", zone, "login_success", 1.0, {"user": "jdoe"})
            _post(evt)
        else:
            evt = make_event("sensor", zone, "door_open", round(random.uniform(0.8, 0.9), 2),
                              {"off_shift": False})
            _post(evt)
        print(f"[act1] {evt['type']} @ {zone}")
        time.sleep(2)
    print("=== ACT 1 done: expect ~0 alerts, Low/none severity ===")


def act2_suppressed_noise(mock_cctv: bool = False):
    print("\n=== ACT 2: SUPPRESSED NOISE ===")
    print("-> single stray CCTV detection (shadow/cat), low confidence")
    if mock_cctv:
        emit_cctv_person("Parking_Lot", confidence=0.42, tripwire=False)
    time.sleep(1.5)

    print("-> single in-shift door open (expected, not a breach)")
    emit_door_open("Perimeter_Gate_3", off_shift=False, confidence=0.9)
    time.sleep(1.5)

    print("-> single failed login (no corroboration)")
    emit_login("Server_Room", success=False)
    time.sleep(1.5)
    print("=== ACT 2 done: all three should be suppressed (single-source) ===")


def act3_multi_vector_breach(zone_id: str = "Perimeter_Gate_3", mock_cctv: bool = True):
    print(f"\n=== ACT 3: MULTI-VECTOR BREACH @ {zone_id} ===")
    print("-> person crosses tripwire")
    if mock_cctv:
        emit_cctv_person(zone_id, confidence=0.93, tripwire=True)
    time.sleep(0.1)

    print("-> door contact opens off-shift")
    emit_door_open(zone_id, off_shift=True, confidence=0.98)
    time.sleep(0.1)

    print("-> login spike hits the same zone")
    emit_login_spike(zone_id, burst=12)

    print("=== ACT 3 done: expect one incident, score climbing ~45 -> ~90+, Critical ===")


def run_replay(path: str, speed: float = 1.0):
    """Fallback mode: replays a pre-recorded event log verbatim to /ingest.
    Preserves relative timing between events (scaled by `speed`)."""
    print(f"[replay] loading {path}")
    with open(path, "r") as f:
        events = [json.loads(line) for line in f if line.strip()]
    print(f"[replay] {len(events)} events loaded, hub={HUB_URL}")

    prev_ts = None
    for evt in events:
        if prev_ts is not None:
            # best-effort gap reconstruction from ts_utc; falls back to 0.3s
            gap = 0.3
            time.sleep(gap / speed)
        prev_ts = evt.get("ts_utc") or evt.get("timestamp")
        # give replayed events a fresh event_id and timestamp so backend correlation windows still work
        evt["event_id"] = str(uuid.uuid4())
        evt["timestamp"] = now_utc_iso()
        success = post_event(evt)
        print(f"[replay] {evt.get('type') or evt.get('event_type')} @ {evt.get('zone_id')} -> {'OK' if success else 'FAIL'}")
    print("[replay] done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--act", type=int, choices=[1, 2, 3], help="run only this act")
    parser.add_argument("--zone", default="Perimeter_Gate_3", help="breach zone for act 3")
    parser.add_argument("--mock-cctv", action="store_true",
                         help="inject fake person_detected events (use before vision_worker is ready)")
    parser.add_argument("--replay", metavar="FILE", help="offline fallback: replay a recorded event log")
    parser.add_argument("--record", metavar="FILE", help="record every event emitted this run to FILE")
    args = parser.parse_args()

    if args.replay:
        run_replay(args.replay)
        raise SystemExit(0)

    init_producer("scenario_runner")

    if args.record:
        enable_recording(args.record)

    try:
        if args.act == 1:
            act1_baseline()
        elif args.act == 2:
            act2_suppressed_noise(mock_cctv=args.mock_cctv)
        elif args.act == 3:
            act3_multi_vector_breach(zone_id=args.zone, mock_cctv=args.mock_cctv)
        else:
            act1_baseline(duration_s=15)
            act2_suppressed_noise(mock_cctv=args.mock_cctv)
            time.sleep(2)
            act3_multi_vector_breach(zone_id=args.zone, mock_cctv=args.mock_cctv)
    finally:
        if args.record:
            close_recording()
            print(f"[scenario] recorded events saved to {args.record}")
