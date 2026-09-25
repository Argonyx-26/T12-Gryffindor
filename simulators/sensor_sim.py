"""
IoT Sensor Simulator (sensor_sim.py)
-----------------------------------
Simulates physical IoT door sensor events for the Intelligent Threat Detection System.
Generates telemetry data such as door opens, door closes, and motion detections.
"""

import uuid
from datetime import datetime, timezone
import random
import time
import sys
import json
import os
import requests

# FastAPI hub configuration
HUB_URL = os.getenv("HUB_URL", "http://localhost:8000")
INGEST_URL = f"{HUB_URL.rstrip('/')}/ingest"


def send_event_to_hub(event: dict):
    """
    Sends the generated event as a POST request to the FastAPI server.
    Logs status code and response message or friendly error if server unreachable.
    """
    try:
        response = requests.post(INGEST_URL, json=event, timeout=5)
        print(f"[SERVER RESPONSE] Status Code: {response.status_code} | Message: {response.text}\n")
    except requests.RequestException as e:
        print(f"[SERVER ERROR] Could not reach FastAPI server at {INGEST_URL}: {e}\n")


def get_utc_timestamp() -> str:
    """Generates ISO-8601 UTC timestamp string with millisecond precision and Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_event(event_type: str = None) -> dict:
    """
    Generates a single IoT door sensor event matching the required schema, prints it, and sends it to the server.
    
    Args:
        event_type (str, optional): Type of event ('door_open', 'door_close', 'motion_detected').
                                    If None, a random type is selected.
    
    Returns:
        dict: The generated event dictionary.
    """
    if not event_type:
        event_type = random.choice(["door_open", "door_close", "motion_detected"])

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": get_utc_timestamp(),
        "source_type": "IOT",
        "zone_id": "Perimeter_Gate_3",
        "coordinates": [12.9716, 77.5946],
        "event_type": event_type,
        "confidence": 1.0,
        "raw_meta": {}
    }

    # Print each event to the console as it's generated
    print(f"[IOT SENSOR] Event Generated:\n{json.dumps(event, indent=2)}")

    # Send event to FastAPI server
    send_event_to_hub(event)

    return event


def run_normal_mode(duration: float = None):
    """
    Simulates normal daily activity.
    Generates occasional random events every 5-15 seconds.
    
    Args:
        duration (float, optional): Maximum seconds to run. If None, runs indefinitely.
    """
    print("--- Starting IoT Sensor Simulator in NORMAL mode ---")
    start_time = time.time()
    
    try:
        while True:
            # Check if duration limit is reached (when called by scenario_runner)
            if duration and (time.time() - start_time) >= duration:
                print("--- IoT Sensor Simulator NORMAL mode duration complete ---")
                break
                
            sleep_time = random.uniform(5, 15)
            # If a duration limit is set, adjust sleep time to not exceed duration
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
        print("\n--- Stopped IoT Sensor Simulator ---")


def run_breach_mode() -> dict:
    """
    Simulates a security breach event.
    Generates one clear 'door_open' event immediately.
    
    Returns:
        dict: The breach event dictionary.
    """
    print("--- Triggering IoT Sensor BREACH mode ---")
    event = generate_event(event_type="door_open")
    return event


if __name__ == "__main__":
    # Choose mode from terminal: python sensor_sim.py normal OR python sensor_sim.py breach
    mode = "normal"
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()

    if mode == "breach":
        run_breach_mode()
    else:
        run_normal_mode()
