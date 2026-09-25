"""
simulators/sensor_sim.py
Mocks IoT door-contact / motion sensors. Emits `door_open` and `motion`
events per the unified schema. Runs standalone (random ambient noise) or
is driven by scenario_runner.py for the scripted 3-act demo.

Standalone usage:
    python sensor_sim.py                 # ambient noise loop, random zones
    python sensor_sim.py --zone Server_Room --type door_open --off-shift
"""
import argparse
import random
import time
from datetime import datetime, timezone

from common import ZONES, init_producer, make_event, post_event


def is_off_shift(zone_id: str, when: datetime = None) -> bool:
    when = when or datetime.now(timezone.utc)
    start, end = ZONES[zone_id]["shift_hours"]
    return not (start <= when.hour < end)


def emit_door_open(zone_id: str, off_shift: bool = None, confidence: float = 0.97):
    off = is_off_shift(zone_id) if off_shift is None else off_shift
    evt = make_event(
        source="sensor",
        zone_id=zone_id,
        event_type="door_open",
        confidence=confidence,
        payload={"off_shift": off, "contact_id": f"{zone_id}_DC1"},
    )
    ok = post_event(evt)
    print(f"[sensor_sim] door_open zone={zone_id} off_shift={off} -> {'OK' if ok else 'FAIL'}")
    return evt


def emit_motion(zone_id: str, confidence: float = 0.85):
    evt = make_event(
        source="sensor",
        zone_id=zone_id,
        event_type="motion",
        confidence=confidence,
        payload={"sensor_id": f"{zone_id}_PIR1"},
    )
    ok = post_event(evt)
    print(f"[sensor_sim] motion zone={zone_id} -> {'OK' if ok else 'FAIL'}")
    return evt


def ambient_loop(interval_s: float = 4.0):
    """Background noise: occasional in-shift door/motion events that should
    get suppressed by the backend as single-source, non-anomalous activity."""
    init_producer("sensor_sim")
    zones = list(ZONES.keys())
    print("[sensor_sim] ambient loop started (Ctrl+C to stop)")
    try:
        while True:
            zone = random.choice(zones)
            if random.random() < 0.5:
                emit_door_open(zone, off_shift=False, confidence=round(random.uniform(0.8, 0.95), 2))
            else:
                emit_motion(zone, confidence=round(random.uniform(0.6, 0.9), 2))
            time.sleep(interval_s + random.uniform(-1, 1))
    except KeyboardInterrupt:
        print("[sensor_sim] stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zone", choices=list(ZONES.keys()))
    parser.add_argument("--type", choices=["door_open", "motion"])
    parser.add_argument("--off-shift", action="store_true")
    parser.add_argument("--interval", type=float, default=4.0)
    args = parser.parse_args()

    if args.zone and args.type:
        init_producer("sensor_sim")
        if args.type == "door_open":
            emit_door_open(args.zone, off_shift=args.off_shift)
        else:
            emit_motion(args.zone)
    else:
        ambient_loop(args.interval)
