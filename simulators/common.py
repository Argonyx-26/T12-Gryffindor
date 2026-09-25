"""
simulators/common.py
Shared config + event-posting helper for sensor_sim.py, syslog_sim.py,
and scenario_runner.py. Keeps every producer emitting the exact unified
event schema the backend expects.
"""
import json
import os
import sys
import uuid
import requests

SHARED_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

try:
    from shared.clock import now_utc_iso, sync_clock
except ImportError:
    from clock import now_utc_iso, sync_clock  # noqa: E402

HUB_URL = os.getenv("HUB_URL", "http://127.0.0.1:8000")
INGEST_URL = f"{HUB_URL}/ingest"

# Zone catalog — updated from data/zones.json to ensure full alignment with backend scoring
ZONES = {
    "Server_Room": {"lat": 37.4282, "lng": -122.1688, "weight": 1.5, "shift_hours": (9, 18)},
    "Perimeter_Gate_3": {"lat": 37.4320, "lng": -122.1745, "weight": 1.3, "shift_hours": (9, 18)},
    "Parking_Lot": {"lat": 37.4255, "lng": -122.1620, "weight": 0.8, "shift_hours": (0, 24)},
    "Parking_Lot_B": {"lat": 37.4255, "lng": -122.1620, "weight": 0.8, "shift_hours": (0, 24)},
}

SOURCE_MAPPING = {
    "cctv": "VIDEO",
    "sensor": "IOT",
    "syslog": "CYBER",
    "VIDEO": "VIDEO",
    "IOT": "IOT",
    "CYBER": "CYBER",
}


def make_event(source: str, zone_id: str, event_type: str, confidence: float, payload: dict | None = None) -> dict:
    """
    Creates an event dictionary adapted to match the backend Pydantic model (`Event`),
    mapping fields to timestamp, source_type, coordinates, event_type, and raw_meta.
    """
    source_type = SOURCE_MAPPING.get(source, "IOT")
    zone_info = ZONES.get(zone_id, {"lat": 0.0, "lng": 0.0})
    coords = [zone_info["lat"], zone_info["lng"]]
    ts = now_utc_iso()
    meta = payload or {}

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "ts_utc": ts,
        "source": source,
        "source_type": source_type,
        "zone_id": zone_id,
        "coordinates": coords,
        "event_type": event_type,
        "type": event_type,
        "confidence": round(confidence, 3),
        "raw_meta": meta,
        "payload": meta,
    }


_record_fh = None


def enable_recording(path: str):
    global _record_fh
    _record_fh = open(path, "w")


def close_recording():
    global _record_fh
    if _record_fh:
        _record_fh.close()
        _record_fh = None


def post_event(event: dict, retries: int = 2, timeout: float = 2.0) -> bool:
    """POSTs a single event to /ingest. Returns True on success. Never raises —
    a dead/unreachable hub must not crash a simulator mid-demo."""
    if _record_fh:
        _record_fh.write(json.dumps(event) + "\n")
        _record_fh.flush()

    for attempt in range(retries + 1):
        try:
            resp = requests.post(INGEST_URL, json=event, timeout=timeout)
            if resp.status_code < 300:
                res_data = resp.json()
                if res_data.get("triggered_incident"):
                    print(f"[common] INCIDENT TRIGGERED: {res_data['triggered_incident']['incident_id']} score={res_data['triggered_incident']['score']} sources={res_data['triggered_incident']['sources']}")
                return True
            print(f"[common] /ingest returned {resp.status_code}: {resp.text[:200]}")
        except requests.RequestException as exc:
            print(f"[common] post attempt {attempt+1} failed: {exc}")
    return False


def init_producer(name: str):
    """Standard startup for every producer script: sync clock, print status."""
    print(f"[{name}] hub = {HUB_URL}")
    sync_clock(HUB_URL)
