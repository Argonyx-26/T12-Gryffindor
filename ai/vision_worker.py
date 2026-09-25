"""
Intelligent Threat Detection & Situational Awareness System
Vision Worker Module

This script monitors a video feed (local video file in a continuous loop),
detects persons using YOLOv8 Nano at a throttled inference rate (~5 FPS),
checks if any detected person enters a predefined rectangular "tripwire zone",
and triggers structured intrusion alerts with a 2-second cooldown.
"""

from typing import Optional
import os
import sys
import time
import uuid
import json
import argparse
import threading
from datetime import datetime, timezone
import requests
import cv2
import numpy as np
from ultralytics import YOLO


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

# Central Ingestion Hub URL (configurable via HUB_URL environment variable)
HUB_URL = os.getenv("HUB_URL", "http://localhost:8000")
INGEST_URL = f"{HUB_URL.rstrip('/')}/ingest"

# Default path to the input video file
DEFAULT_VIDEO_PATH = os.path.join("data", "sample.mp4")

# YOLO model name (Nano is lightweight and fast)
MODEL_NAME = "yolov8n.pt"

# Performance Settings: Reduced inference resolution from 640 to 320 for 2-3x faster CPU throughput
INFERENCE_IMG_SIZE = 320

# Target inference rate in frames per second (processes YOLO ~5 times per second)
TARGET_INFERENCE_FPS = 5

# Alert cooldown in seconds (avoids spamming alert events)
ALERT_COOLDOWN_SECONDS = 2.0

# Zone Metadata for Alert Schema
ZONE_ID = "Perimeter_Gate_3"
GEO_COORDINATES = [12.9716, 77.5946]  # [Latitude, Longitude]


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_iso_timestamp() -> str:
    """
    Returns current UTC timestamp in ISO-8601 format with millisecond precision
    e.g., '2026-09-24T10:15:03.412Z'
    """
    now = datetime.now(timezone.utc)
    # Format with microseconds and trim to milliseconds, appending 'Z' for UTC
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def create_tripwire_zone(frame_width: int, frame_height: int) -> np.ndarray:
    """
    Defines a 4-point polygon representing the rectangular tripwire/restricted zone.
    Here we scale the coordinates relative to the video frame dimensions so that
    it adapts cleanly to any video resolution (e.g. 720p, 1080p, 480p).
    
    Points define a polygon in clockwise order:
    [top-left, top-right, bottom-right, bottom-left]
    """
    x1 = int(frame_width * 0.35)   # 35% from left
    y1 = int(frame_height * 0.25)  # 25% from top
    x2 = int(frame_width * 0.85)   # 85% from left
    y2 = int(frame_height * 0.80)  # 80% from top

    polygon = np.array([
        [x1, y1],  # Top-left
        [x2, y1],  # Top-right
        [x2, y2],  # Bottom-right
        [x1, y2]   # Bottom-left
    ], dtype=np.int32)

    return polygon


def check_point_in_zone(point: tuple, zone_polygon: np.ndarray) -> bool:
    """
    Checks if a (x, y) point falls inside the tripwire zone polygon.
    cv2.pointPolygonTest returns:
      +1 if the point is inside the contour
       0 if the point is on the contour edge
      -1 if the point is outside the contour
    """
    result = cv2.pointPolygonTest(zone_polygon, point, measureDist=False)
    return result >= 0


def generate_intrusion_event(confidence: float, bbox: list, timing_meta: Optional[dict] = None) -> dict:
    """
    Builds the standardized event dictionary according to the required schema.
    """
    raw_meta = {
        "bbox": [int(b) for b in bbox]
    }
    if timing_meta:
        raw_meta.update(timing_meta)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": get_iso_timestamp(),
        "source_type": "VIDEO",
        "zone_id": ZONE_ID,
        "coordinates": GEO_COORDINATES,
        "event_type": "person_detected",
        "confidence": round(float(confidence), 4),
        "raw_meta": raw_meta,
    }


def send_event_to_hub(event: dict) -> None:
    """
    Sends an intrusion event dictionary as an HTTP POST request to {HUB_URL}/ingest
    using the Python 'requests' library in a background daemon thread.
    
    Wrapped in try/except and dispatched asynchronously so network round-trips
    never block or reduce the video processing frame rate.
    """
    def _worker():
        try:
            response = requests.post(INGEST_URL, json=event, timeout=3.0)
            print(f"📡 [HUB RESPONSE] Status {response.status_code}: {response.text.strip()}", flush=True)
        except requests.exceptions.RequestException as exc:
            print(f"⚠️ [HUB ERROR] Failed to send event to Hub at {INGEST_URL}: {exc}", flush=True)
        except Exception as exc:
            print(f"⚠️ [HUB UNEXPECTED ERROR] Could not deliver alert to Hub: {exc}", flush=True)

    threading.Thread(target=_worker, daemon=True).start()


# ==============================================================================
# MAIN VISION PIPELINE
# ==============================================================================

def main():
    print("=" * 70)
    print(" Intelligent Threat Detection & Situational Awareness System ")
    print(" Vision Worker Initializing...")
    print("=" * 70)

    # Parse command line options (defaulting to data/sample.mp4)
    parser = argparse.ArgumentParser(
        description="Intelligent Threat Detection & Situational Awareness System - Vision Worker"
    )
    parser.add_argument(
        "--video", "-v",
        default=DEFAULT_VIDEO_PATH,
        help=f"Path to video file or webcam index (default: '{DEFAULT_VIDEO_PATH}')"
    )
    parser.add_argument(
        "--max-frames",
        type=int,
        default=None,
        help="Optional maximum number of frames to process before exiting (useful for testing)"
    )
    parser.add_argument(
        "--frame-skip", "-n",
        type=int,
        default=None,
        help="Process YOLO detection every Nth frame (default: auto-calculated for ~5 FPS)"
    )
    args = parser.parse_args()
    video_source = args.video

    # Check if the video source is an integer index (e.g. for webcam: '0')
    if isinstance(video_source, str) and video_source.isdigit():
        video_source = int(video_source)
        is_webcam = True
    else:
        is_webcam = False
        # 1. Verify Video Source Exists if it's a file
        if not os.path.exists(video_source):
            print(f"\n[WARNING] Video file not found at: '{video_source}'")
            print(f"Please place your sample video at '{DEFAULT_VIDEO_PATH}' or specify another file via:")
            print("   python ai/vision_worker.py --video <path_to_video.mp4>")
            print("Creating 'data/' folder if it does not already exist...")
            os.makedirs("data", exist_ok=True)
            print("Exiting. Place your video and re-run the script.")
            return

    # 2. Ingestion Endpoint Configuration
    print(f"\n[INFO] Central Ingestion Hub: {INGEST_URL}")

    # 3. Load YOLOv8 Nano Model
    print(f"[INFO] Loading YOLO model: {MODEL_NAME}...")
    # This automatically downloads the weights 'yolov8n.pt' on first run
    model = YOLO(MODEL_NAME)
    print("[INFO] Model loaded successfully.")

    # 3. Open Video Stream
    source_label = f"Webcam #{video_source}" if is_webcam else f"File '{video_source}'"
    print(f"[INFO] Opening video stream from: {source_label}")
    cap = cv2.VideoCapture(video_source)

    if not cap.isOpened():
        print(f"[ERROR] Could not open video source: {source_label}.")
        return

    # Retrieve video properties
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    video_fps = cap.get(cv2.CAP_PROP_FPS)

    # If the video FPS cannot be read properly, default to 30 FPS
    if video_fps <= 0 or np.isnan(video_fps):
        video_fps = 30.0

    print(f"[INFO] Resolution: {frame_width}x{frame_height}, Native FPS: {video_fps:.2f}")

    # Calculate frame skip factor N to achieve ~TARGET_INFERENCE_FPS (5 FPS)
    # Allows explicit override via --frame-skip / -n (default: auto-calculated for ~5 FPS)
    if args.frame_skip is not None and args.frame_skip > 0:
        frame_interval = args.frame_skip
    else:
        frame_interval = max(1, int(round(video_fps / TARGET_INFERENCE_FPS)))

    print(f"[INFO] Performance config: imgsz={INFERENCE_IMG_SIZE}, Frame-skip N={frame_interval} (Target: ~{TARGET_INFERENCE_FPS} FPS)")

    # Frame playback delay to maintain original video playback speed
    playback_delay_ms = max(1, int(1000.0 / video_fps))

    # Define the 4-point rectangular tripwire polygon
    tripwire_zone = create_tripwire_zone(frame_width, frame_height)

    # State variables
    frame_count = 0
    last_alert_time = 0.0
    latest_detections = []  # Stores (bbox, confidence, center_point, is_inside)

    # FPS Monitoring variables (logged to console every 5 seconds)
    fps_start_time = time.time()
    inference_count = 0
    total_frames_in_interval = 0
    current_inference_fps = float(TARGET_INFERENCE_FPS)

    print("\n[INFO] Starting video loop. Press 'q' in the video window to quit.")
    print("-" * 70)

    try:
        while True:
            frame_start_time = time.time()
            t_cap_utc = get_iso_timestamp()
            t_cap_ns = time.perf_counter_ns()

            # Step 1: Read a frame from the video
            ret, frame = cap.read()

            # If the video reached the end, automatically loop back to frame 0
            if not ret or frame is None:
                if is_webcam:
                    print("[INFO] Webcam stream ended.")
                    break

                # Loop back to the start of the video file
                cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                ret, frame = cap.read()
                if not ret or frame is None:
                    # If looping via seek fails, re-open the capture object
                    cap.release()
                    cap = cv2.VideoCapture(video_source)
                    continue

            frame_count += 1
            total_frames_in_interval += 1

            # Stop if max_frames limit is set and reached (for testing/automation)
            if args.max_frames and frame_count > args.max_frames:
                print(f"\n[INFO] Reached requested limit of {args.max_frames} frames. Exiting.")
                break

            # Step 2: Run YOLOv8 Nano at throttled ~5 FPS rate
            # Only run inference every `frame_interval` frames
            if frame_count % frame_interval == 0:
                inference_count += 1
                latest_detections = []

                # Run inference at reduced image size (320) for 2-3x faster CPU execution:
                t_inf_start_ns = time.perf_counter_ns()
                results = model(frame, imgsz=INFERENCE_IMG_SIZE, classes=[0], verbose=False)
                t_inf_end_ns = time.perf_counter_ns()

                # Process detection results
                for r in results:
                    boxes = r.boxes
                    for box in boxes:
                        # Extract bounding box coordinates [x1, y1, x2, y2]
                        x1, y1, x2, y2 = box.xyxy[0].cpu().numpy()
                        conf = float(box.conf[0].cpu().numpy())

                        # Compute center point of the bounding box
                        cx = int((x1 + x2) / 2)
                        cy = int((y1 + y2) / 2)

                        # Step 4: Check if center point falls inside tripwire polygon
                        is_inside = check_point_in_zone((cx, cy), tripwire_zone)

                        latest_detections.append({
                            "bbox": [x1, y1, x2, y2],
                            "conf": conf,
                            "center": (cx, cy),
                            "is_inside": is_inside
                        })

                        # Step 5 & 6: Trigger intrusion event if inside zone (with 2s cooldown)
                        if is_inside:
                            current_time = time.time()
                            if current_time - last_alert_time >= ALERT_COOLDOWN_SECONDS:
                                last_alert_time = current_time

                                t_evt_gen_ns = time.perf_counter_ns()
                                t_evt_gen_utc = get_iso_timestamp()
                                timing_meta = {
                                    "frame_capture_timestamp_utc": t_cap_utc,
                                    "event_generation_timestamp_utc": t_evt_gen_utc,
                                    "frame_capture_monotonic_ns": t_cap_ns,
                                    "inference_start_ns": t_inf_start_ns,
                                    "inference_end_ns": t_inf_end_ns,
                                    "yolo_inference_ms": round((t_inf_end_ns - t_inf_start_ns) / 1e6, 2),
                                    "event_generation_ns": t_evt_gen_ns,
                                    "trace_id": f"trc-{uuid.uuid4().hex[:8]}",
                                }

                                # Construct the standardized intrusion event dictionary
                                alert_event = generate_intrusion_event(conf, [x1, y1, x2, y2], timing_meta=timing_meta)

                                # Print the alert dictionary cleanly formatted to console
                                print("\n🚨 [INTRUSION ALERT TRIGGERED] 🚨")
                                print(json.dumps(alert_event, indent=2))

                                # Send event as HTTP POST request to {HUB_URL}/ingest
                                send_event_to_hub(alert_event)
                                print("-" * 70)

            # Step 3: Visual Annotations

            # 3A. Draw the Tripwire Zone
            # Determine if any person is currently inside the zone to highlight it
            any_intrusion = any(d["is_inside"] for d in latest_detections)
            zone_color = (0, 0, 255) if any_intrusion else (0, 255, 0)  # Red if breached, Green if secure

            # Draw semi-transparent overlay over the restricted zone
            overlay = frame.copy()
            cv2.fillPoly(overlay, [tripwire_zone], zone_color)
            cv2.addWeighted(overlay, 0.20, frame, 0.80, 0, frame)

            # Draw the boundary polygon line
            cv2.polylines(frame, [tripwire_zone], isClosed=True, color=zone_color, thickness=2)

            # Zone label
            zone_label = f"RESTRICTED ZONE: {ZONE_ID} {'[BREACHED]' if any_intrusion else '[SECURE]'}"
            cv2.putText(
                frame,
                zone_label,
                (tripwire_zone[0][0], max(25, tripwire_zone[0][1] - 10)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                zone_color,
                2,
                cv2.LINE_AA
            )

            # 3B. Draw Bounding Boxes and Center Points for each detected person
            for det in latest_detections:
                x1, y1, x2, y2 = [int(v) for v in det["bbox"]]
                cx, cy = det["center"]
                is_inside = det["is_inside"]
                conf = det["conf"]

                # Red for intruders, Yellow/Cyan for outside persons
                box_color = (0, 0, 255) if is_inside else (0, 255, 255)

                # Draw bounding box
                cv2.rectangle(frame, (x1, y1), (x2, y2), box_color, 2)

                # Draw center point dot
                dot_color = (0, 0, 255) if is_inside else (0, 255, 0)
                cv2.circle(frame, (cx, cy), radius=5, color=dot_color, thickness=-1)

                # Label tag above bounding box
                status_text = "INTRUDER" if is_inside else "Person"
                label = f"{status_text} ({conf * 100:.1f}%)"
                (w, h), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)

                # Background banner for label readability
                cv2.rectangle(frame, (x1, max(0, y1 - 22)), (x1 + w + 6, y1), box_color, -1)
                cv2.putText(
                    frame,
                    label,
                    (x1 + 3, max(15, y1 - 6)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    (0, 0, 0),
                    1,
                    cv2.LINE_AA
                )

            # 3C. Display System HUD Status (Top-Left Corner)
            cv2.putText(
                frame,
                f"Threat Detection System | Inference: {current_inference_fps:.1f} FPS (Target: ~{TARGET_INFERENCE_FPS})",
                (15, 30),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.65,
                (255, 255, 255),
                2,
                cv2.LINE_AA
            )
            cv2.putText(
                frame,
                "Press 'q' to exit",
                (15, 60),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (200, 200, 200),
                1,
                cv2.LINE_AA
            )

            # Step 3D: Periodic FPS Logging (Console output every 5 seconds)
            current_time = time.time()
            elapsed_fps_time = current_time - fps_start_time
            if elapsed_fps_time >= 5.0:
                actual_inference_fps = inference_count / elapsed_fps_time
                actual_video_fps = total_frames_in_interval / elapsed_fps_time
                print(
                    f"⏱️ [FPS MONITOR] Achieving {actual_inference_fps:.2f} FPS Inference "
                    f"(Target: ~{TARGET_INFERENCE_FPS} FPS) | Video Playback: {actual_video_fps:.2f} FPS",
                    flush=True
                )
                current_inference_fps = actual_inference_fps
                fps_start_time = current_time
                inference_count = 0
                total_frames_in_interval = 0

            # Step 3E: Show the live video window
            cv2.imshow("Intelligent Threat Detection & Situational Awareness", frame)

            # Play at normal video frame rate (compensate for elapsed processing time to keep playback smooth)
            frame_elapsed_ms = (time.time() - frame_start_time) * 1000.0
            actual_delay_ms = max(1, int(playback_delay_ms - frame_elapsed_ms))

            # Break loop immediately if the user presses 'q'
            key = cv2.waitKey(actual_delay_ms) & 0xFF
            if key == ord('q'):
                print("\n[INFO] 'q' pressed. Stopping vision worker.")
                break

    except KeyboardInterrupt:
        print("\n[INFO] KeyboardInterrupt received. Stopping...")
    finally:
        # Cleanup OpenCV resources
        cap.release()
        cv2.destroyAllWindows()
        print("[INFO] Video capture released and windows closed. Goodbye!")


if __name__ == "__main__":
    main()
