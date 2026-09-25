"""
shared/clock.py
Clock-sync helper for every producer laptop (sensor_sim, syslog_sim, vision_worker).
Keeps event timestamps aligned to the hub's clock so the ±1.5s correlation
window in the backend stays valid even with real, physically separate laptops.
"""
import time
import os
from datetime import datetime, timezone

import requests

_offset = 0.0
_synced = False


def sync_clock(hub: str = None, rounds: int = 5) -> float:
    """Runs a small NTP-style handshake against GET {hub}/time and stores
    the offset between this machine's clock and the hub's clock. Call this
    once at process startup, before emitting any events."""
    global _offset, _synced
    hub = hub or os.getenv("HUB_URL", "http://localhost:8000")
    best = None
    for _ in range(rounds):
        try:
            t0 = time.time()
            resp = requests.get(f"{hub}/time", timeout=2)
            resp.raise_for_status()
            server_epoch = resp.json()["epoch"]
            t1 = time.time()
            rtt = t1 - t0
            off = server_epoch - (t0 + rtt / 2)
            if best is None or rtt < best[0]:
                best = (rtt, off)
        except requests.RequestException as exc:
            print(f"[clock] sync attempt failed: {exc}")
    if best is not None:
        _offset = best[1]
        _synced = True
        print(f"[clock] synced. offset={_offset*1000:.1f} ms, rtt={best[0]*1000:.1f} ms")
    else:
        print("[clock] WARNING: could not reach hub /time — running unsynced (offset=0)")
    return _offset


def is_synced() -> bool:
    return _synced


def now_utc_iso() -> str:
    """Returns an ISO-8601 UTC timestamp adjusted by the measured offset,
    in the exact format the unified event schema expects."""
    dt = datetime.fromtimestamp(time.time() + _offset, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
