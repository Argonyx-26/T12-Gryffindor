"""
simulators/syslog_sim.py
Mocks a syslog auth stream. Emits `login_failed` / `login_success` events
for ambient traffic, and can fire a scripted `login_spike` burst (brute-force
surge) for the multi-vector breach act. A lightweight rolling Z-score
detector (mirrors ai/cyber_anomaly.py) decides when raw failed-login volume
is itself anomalous, independent of the scripted spike.

Standalone usage:
    python syslog_sim.py                          # ambient loop
    python syslog_sim.py --spike Server_Room       # fire one brute-force burst
"""
import argparse
import random
import time
from collections import deque, defaultdict

from common import ZONES, init_producer, make_event, post_event

IPS = ["10.2.4.{}".format(i) for i in range(2, 40)]
USERS = ["svc_backup", "admin", "jdoe", "root", "svc_monitor", "guest"]

# Rolling window of failed-login counts per zone, for local anomaly scoring.
_window = defaultdict(lambda: deque(maxlen=30))


def _zscore(zone_id: str, value: int) -> float:
    hist = list(_window[zone_id])
    if len(hist) < 5:
        return 0.0
    mean = sum(hist) / len(hist)
    var = sum((x - mean) ** 2 for x in hist) / len(hist)
    std = var ** 0.5
    return 0.0 if std == 0 else (value - mean) / std


def emit_login(zone_id: str, success: bool, user: str = None, src_ip: str = None):
    evt = make_event(
        source="syslog",
        zone_id=zone_id,
        event_type="login_success" if success else "login_failed",
        confidence=1.0,
        payload={"user": user or random.choice(USERS), "src_ip": src_ip or random.choice(IPS)},
    )
    ok = post_event(evt)
    print(f"[syslog_sim] {evt['type']} zone={zone_id} -> {'OK' if ok else 'FAIL'}")
    return evt


def emit_login_spike(zone_id: str, burst: int = 12, confidence: float = 0.9):
    """Fires `burst` rapid login_failed events from a small set of IPs (brute
    force pattern), then emits a single login_spike anomaly event summarizing
    it — this is the event the backend's cyber vector actually scores on."""
    attacker_ips = random.sample(IPS, k=min(3, len(IPS)))
    z = _zscore(zone_id, burst)
    evt = make_event(
        source="syslog",
        zone_id=zone_id,
        event_type="login_spike",
        confidence=min(0.99, confidence + min(0.09, max(0, z) * 0.01)),
        payload={"failed_count": burst, "window_s": 10, "src_ips": attacker_ips, "zscore": round(z, 2)},
    )
    ok = post_event(evt)
    print(f"[syslog_sim] login_spike zone={zone_id} zscore={z:.2f} -> {'OK' if ok else 'FAIL'}")
    _window[zone_id].append(burst)

    for _ in range(burst):
        emit_login(zone_id, success=False, user="admin", src_ip=random.choice(attacker_ips))
        time.sleep(0.01)

    return evt


def ambient_loop(interval_s: float = 5.0):
    init_producer("syslog_sim")
    zones = list(ZONES.keys())
    print("[syslog_sim] ambient loop started (Ctrl+C to stop)")
    try:
        while True:
            zone = random.choice(zones)
            success = random.random() < 0.85
            emit_login(zone, success=success)
            _window[zone].append(0 if success else 1)
            time.sleep(interval_s + random.uniform(-1.5, 1.5))
    except KeyboardInterrupt:
        print("[syslog_sim] stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--spike", choices=list(ZONES.keys()))
    parser.add_argument("--burst", type=int, default=12)
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()

    if args.spike:
        init_producer("syslog_sim")
        emit_login_spike(args.spike, burst=args.burst)
    else:
        ambient_loop(args.interval)
