"""
Local Demo Runner (simulators/local_demo.py)
---------------------------------------------
Offline local mock mode runner for Intelligent Threat Detection & Situational Awareness System.
Spawns the local FastAPI backend server, waits for readiness, executes demo scenario phases,
and outputs a final summary report of events, incidents, and noise suppression rate.
"""

import argparse
import atexit
import os
import sys
import subprocess
import time
import threading
import requests

# Hard-code HUB_URL for self-contained offline local demo
os.environ["HUB_URL"] = "http://localhost:8000"
HUB_URL = "http://localhost:8000"
INGEST_URL = f"{HUB_URL}/ingest"

# Import simulator modules
import sensor_sim
import syslog_sim


def start_backend_server() -> subprocess.Popen:
    """
    Launches the FastAPI backend server as a background process and waits
    until http://localhost:8000/ is ready.
    """
    print("======================================================================")
    print("  [LOCAL DEMO] Starting FastAPI Backend Server...")
    print("======================================================================")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    backend_script = os.path.join(project_root, "backend", "main.py")

    env = os.environ.copy()
    env["PYTHONPATH"] = project_root

    # Launch backend server process using module path so backend package imports resolve cleanly
    proc = subprocess.Popen(
        [sys.executable, "-m", "backend.main"],
        cwd=project_root,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Register process cleanup on script exit
    def cleanup():
        if proc.poll() is None:
            print("\n  [LOCAL DEMO] Stopping background FastAPI backend server...")
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    atexit.register(cleanup)

    print("  [LOCAL DEMO] Waiting for backend server to become ready at http://localhost:8000/ ...")
    start_time = time.time()
    server_ready = False

    while time.time() - start_time < 15:
        try:
            r = requests.get("http://localhost:8000/", timeout=1)
            if r.status_code == 200:
                server_ready = True
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)

    if server_ready:
        print("  [LOCAL DEMO] Backend server is ONLINE and ready!\n")
    else:
        print("  [WARNING] Backend server readiness check timed out. Proceeding with demo...\n")

    return proc


def print_phase_header(phase_name: str):
    """Prints a prominent section header for live demo phases."""
    border = "=" * 50
    print(f"\n{border}")
    print(f"  {phase_name}")
    print(f"{border}\n")


def run_phase_1_baseline():
    """Runs Phase 1: Baseline - Normal background activity for 15 seconds."""
    print_phase_header("PHASE 1: BASELINE - Normal Activity")
    print("Running normal background activity on IoT and Cyber simulators for 15 seconds...\n")

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

    sensor_thread.join()
    syslog_thread.join()

    print("\n>>> Phase 1 Complete. Pausing 3 seconds before Phase 2...\n")
    time.sleep(3)


def run_phase_2_suppressed_noise():
    """Runs Phase 2: Suppressed Noise - Single isolated sensor trigger."""
    print_phase_header("PHASE 2: SUPPRESSED NOISE - Single Sensor Trigger")
    print("Triggering just ONE single door_open event (isolated low-risk activity)...\n")

    sensor_sim.generate_event(event_type="door_open")

    print("\nWaiting 5 seconds to observe system output/filtering...\n")
    time.sleep(5)

    print(">>> Phase 2 Complete. Pausing 2 seconds before Phase 3...\n")
    time.sleep(2)


def run_phase_3_breach():
    """Runs Phase 3: Multi-Vector Breach - Simultaneous physical & cyber attack."""
    print_phase_header("PHASE 3: MULTI-VECTOR BREACH - Simultaneous Multi-Vector Attack")
    print("Triggering BREACH mode on BOTH simulators at nearly the exact same time!\n")

    t_sensor = threading.Thread(target=sensor_sim.run_breach_mode, name="IoT-Breach-Thread")
    t_syslog = threading.Thread(target=syslog_sim.run_breach_mode, name="Cyber-Breach-Thread")

    t_sensor.start()
    time.sleep(0.1)
    t_syslog.start()

    t_sensor.join()
    t_syslog.join()

    print("\n>>> Phase 3 Complete.\n")


def print_summary_report():
    """Fetches metrics from backend server and displays noise suppression summary."""
    print("\n======================================================================")
    print("                   LOCAL DEMO SUMMARY REPORT")
    print("======================================================================\n")

    total_events = 0
    total_incidents = 0

    try:
        r = requests.get("http://localhost:8000/", timeout=3)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("stats", {})
            total_events = stats.get("ingested_events", 0)
            total_incidents = stats.get("active_incidents", 0)
    except Exception as e:
        print(f"Warning: Could not fetch metrics summary from server: {e}")

    # Fallback checks if / did not populate numbers
    if total_events == 0:
        try:
            ev_res = requests.get("http://localhost:8000/events", timeout=3)
            if ev_res.status_code == 200:
                total_events = len(ev_res.json())
        except Exception:
            pass

    if total_incidents == 0:
        try:
            inc_res = requests.get("http://localhost:8000/incidents", timeout=3)
            if inc_res.status_code == 200:
                total_incidents = len(inc_res.json())
        except Exception:
            pass

    suppressed_count = max(0, total_events - total_incidents)
    suppression_pct = (suppressed_count / total_events * 100.0) if total_events > 0 else 0.0

    print(f"  Total Telemetry Events Ingested : {total_events}")
    print(f"  Total Incidents Created         : {total_incidents}")
    print(f"  Noise Suppression Rate          : {suppression_pct:.1f}% ({suppressed_count} event(s) suppressed as non-incident noise)")
    print("\n======================================================================")
    print("                     OFFLINE LOCAL DEMO COMPLETED")
    print("======================================================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="Local Mock Mode Demo Runner - Runs entire pipeline on one machine."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run all 3 demo phases automatically with realistic pauses (default mode)."
    )
    parser.add_argument(
        "--breach-only",
        action="store_true",
        help="Skip straight to Phase 3: Multi-Vector Breach for fast re-testing."
    )

    args = parser.parse_args()
    breach_only = args.breach_only

    backend_proc = start_backend_server()

    try:
        if breach_only:
            run_phase_3_breach()
        else:
            run_phase_1_baseline()
            run_phase_2_suppressed_noise()
            run_phase_3_breach()

        print_summary_report()
    except KeyboardInterrupt:
        print("\n[LOCAL DEMO] Demonstration interrupted by user.")


if __name__ == "__main__":
    main()
