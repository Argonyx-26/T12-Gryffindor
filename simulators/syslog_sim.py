"""
Syslog Cyber Simulator (syslog_sim.py)
--------------------------------------
Simulates computer system login attempts for the Intelligent Threat Detection System.
Generates cyber telemetry data such as successful logins, failed logins, and login spikes.
"""

import uuid
from datetime import datetime, timezone
import random
import time
import sys
import json

# Sample pool of usernames for fake event generation
SAMPLE_USERNAMES = ["admin", "root", "jdoe", "sysadmin", "dev_user", "operator", "sec_analyst"]


def get_utc_timestamp() -> str:
    """Generates ISO-8601 UTC timestamp string with millisecond precision and Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_fake_ip() -> str:
    """Generates a random fake IP address in the local subnet format."""
    return f"192.168.1.{random.randint(10, 250)}"


def generate_event(event_type: str = None, username: str = None, ip_address: str = None) -> dict:
    """
    Generates a single Cyber login event matching the required schema and prints it.
    
    Args:
        event_type (str, optional): 'login_success', 'login_failed', or 'login_spike'.
        username (str, optional): Fake username. Randomly selected if None.
        ip_address (str, optional): Fake IP address. Randomly generated if None.
        
    Returns:
        dict: The generated event dictionary.
    """
    if not event_type:
        # Under normal conditions: mostly success (~80%), rare failures (~20%)
        event_type = random.choices(["login_success", "login_failed"], weights=[80, 20])[0]

    if not username:
        username = random.choice(SAMPLE_USERNAMES)

    if not ip_address:
        ip_address = generate_fake_ip()

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": get_utc_timestamp(),
        "source_type": "CYBER",
        "zone_id": "Server_Room",
        "coordinates": [12.9720, 77.5950],
        "event_type": event_type,
        "confidence": 1.0,
        "raw_meta": {
            "username": username,
            "ip_address": ip_address
        }
    }

    # Print each event to the console as it's generated
    print(f"[CYBER SYSLOG] Event Generated:\n{json.dumps(event, indent=2)}\n")
    return event


def run_normal_mode(duration: float = None):
    """
    Simulates normal daily system operations.
    Generates occasional login_success and rare login_failed events every 5-15 seconds.
    
    Args:
        duration (float, optional): Maximum seconds to run. If None, runs indefinitely.
    """
    print("--- Starting Syslog Cyber Simulator in NORMAL mode ---")
    start_time = time.time()

    try:
        while True:
            # Check if duration limit is reached (when called by scenario_runner)
            if duration and (time.time() - start_time) >= duration:
                print("--- Syslog Cyber Simulator NORMAL mode duration complete ---")
                break

            sleep_time = random.uniform(5, 15)
            if duration:
                remaining = duration - (time.time() - start_time)
                if remaining <= 0:
                    break
                if sleep_time > remaining:
                    time.sleep(remaining)
                    break

            time.sleep(sleep_time)
            generate_event()

    except KeyboardInterrupt:
        print("\n--- Stopped Syslog Cyber Simulator ---")


def run_breach_mode() -> list:
    """
    Simulates a brute-force cyber attack.
    Rapidly generates 10 'login_failed' events within 2 seconds, then one 'login_spike' event.
    
    Returns:
        list: List of generated breach event dictionaries.
    """
    print("--- Triggering Syslog Cyber BREACH mode (Brute-Force Attack Simulation) ---")
    attacker_ip = "192.168.1.199"
    target_user = "admin"
    events = []

    # Rapidly generate 10 login_failed attempts over ~1.5 seconds (0.15s interval)
    for _ in range(10):
        evt = generate_event(event_type="login_failed", username=target_user, ip_address=attacker_ip)
        events.append(evt)
        time.sleep(0.15)

    # Follow up with one login_spike event
    spike_evt = generate_event(event_type="login_spike", username=target_user, ip_address=attacker_ip)
    events.append(spike_evt)

    return events


if __name__ == "__main__":
    # Choose mode from terminal: python syslog_sim.py normal OR python syslog_sim.py breach
    mode = "normal"
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()

    if mode == "breach":
        run_breach_mode()
    else:
        run_normal_mode()
