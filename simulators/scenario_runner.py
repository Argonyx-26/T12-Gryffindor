"""
Scenario Runner (scenario_runner.py)
------------------------------------
Orchestrates a 3-part live demonstration for the Intelligent Threat Detection & Situational Awareness System.

Phases executed:
- Part 1: "Baseline" - Runs normal activity mode for both IoT and Cyber simulators for 15 seconds.
- Part 2: "Suppressed Noise" - Triggers a single isolated IoT door open event to demonstrate event filtering.
- Part 3: "Multi-Vector Breach" - Triggers near-simultaneous physical perimeter breach and cyber brute-force attack.
"""

import os
import requests
import time
import threading

# Import the simulator modules (supports running from repo root or simulators directory)
try:
    import sensor_sim
    import syslog_sim
except ImportError:
    from simulators import sensor_sim
    from simulators import syslog_sim

# FastAPI hub configuration from environment variable with localhost fallback
HUB_URL = os.getenv("HUB_URL", "http://localhost:8000")
INGEST_URL = f"{HUB_URL.rstrip('/')}/ingest"


def main():
    print("======================================================================")
    print("  INTELLIGENT THREAT DETECTION & SITUATIONAL AWARENESS DEMO RUNNER")
    print(f"  Target HUB_URL: {INGEST_URL}")
    print("======================================================================\n")

    # ==================================================================
    # PART 1: BASELINE - Normal Activity (15 seconds)
    # ==================================================================
    print("=== BASELINE: Normal Activity ===")
    print("Running normal background activity on both IoT and Cyber simulators for 15 seconds...\n")

    # Launch normal mode for both simulators in separate background threads
    # so they execute simultaneously for 15 seconds.
    sensor_thread = threading.Thread(
        target=sensor_sim.run_normal_mode, 
        kwargs={"duration": 15}, 
        name="IoT-Baseline-Thread"
    )
    syslog_thread = threading.Thread(
        target=syslog_sim.run_normal_mode, 
        kwargs={"duration": 15}, 
        name="Cyber-Baseline-Thread"
    )

    sensor_thread.start()
    syslog_thread.start()

    # Wait for both threads to complete their 15-second run before moving on
    sensor_thread.join()
    syslog_thread.join()

    print("\n>>> Part 1 Complete. Pausing 3 seconds before Part 2...\n")
    time.sleep(3)

    # ==================================================================
    # PART 2: SUPPRESSED NOISE - Single Sensor Trigger
    # ==================================================================
    print("=== SUPPRESSED NOISE: Single Sensor Trigger ===")
    print("Triggering just ONE single door_open event (simulating isolated low-risk activity)...\n")

    # Call generate_event directly to produce exactly one single door_open event
    sensor_sim.generate_event(event_type="door_open")

    print("Waiting 5 seconds to observe system output/filtering...\n")
    time.sleep(5)

    print(">>> Part 2 Complete. Pausing 2 seconds before Part 3...\n")
    time.sleep(2)

    # ==================================================================
    # PART 3: MULTI-VECTOR BREACH - Simultaneous Multi-Vector Attack
    # ==================================================================
    print("=== MULTI-VECTOR BREACH ===")
    print("Triggering BREACH mode on BOTH simulators at nearly the exact same time!\n")

    # Launch breach modes in parallel threads to execute within 0.1s of each other
    t_sensor_breach = threading.Thread(target=sensor_sim.run_breach_mode, name="IoT-Breach-Thread")
    t_syslog_breach = threading.Thread(target=syslog_sim.run_breach_mode, name="Cyber-Breach-Thread")

    t_sensor_breach.start()
    time.sleep(0.1)  # Tiny sub-second delay to fire almost simultaneously
    t_syslog_breach.start()

    # Wait for breach actions to finish
    t_sensor_breach.join()
    t_syslog_breach.join()

    print("\n======================================================================")
    print(" DEMO SCENARIO FINISHED ")
    print("======================================================================")


if __name__ == "__main__":
    main()
