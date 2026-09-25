"""
Intelligent Threat Detection & Situational Awareness System
Vision Worker Module

This script monitors a video feed (local video file in a continuous loop),
detects persons using YOLOv8 Nano at a throttled inference rate (~5 FPS),
checks if any detected person enters a predefined rectangular "tripwire zone",
and triggers structured intrusion alerts with a 2-second cooldown.
"""

import os
import sys
import time
import uuid
import json
import argparse
from datetime import datetime, timezone
import cv2
import numpy as np
from ultralytics import YOLO


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

# Default path to the input video file
DEFAULT_VIDEO_PATH = os.path.join("data", "sample.mp4")

# YOLO model name (Nano is lightweight and fast)
MODEL_NAME = "yolov8n.pt"

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


def generate_intrusion_event(confidence: float, bbox: list) -> dict:
    """
    Builds the standardized event dictionary according to the required schema.
    """
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": get_iso_timestamp(),
        "source_type": "VIDEO",
        "zone_id": ZONE_ID,
        "coordinates": GEO_COORDINATES,
        "event_type": "person_detected",
        "confidence": round(float(confidence), 4),
        "raw_meta": {
            "bbox": [int(b) for b in bbox]
        }
    }


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

    # 2. Load YOLOv8 Nano Model
    print(f"\n[INFO] Loading YOLO model: {MODEL_NAME}...")
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

    # Calculate frame skip factor to achieve ~TARGET_INFERENCE_FPS (5 FPS)
    # Example: If video is 30 FPS, 30 / 5 = run YOLO every 6 frames
    frame_interval = max(1, int(round(video_fps / TARGET_INFERENCE_FPS)))
    print(f"[INFO] YOLO inference will run every {frame_interval} frame(s) to hit ~{TARGET_INFERENCE_FPS} FPS.")

    # Frame playback delay to maintain original video playback speed
    playback_delay_ms = max(1, int(1000.0 / video_fps))

    # Define the 4-point rectangular tripwire polygon
    tripwire_zone = create_tripwire_zone(frame_width, frame_height)

    # State variables
    frame_count = 0
    last_alert_time = 0.0
    latest_detections = []  # Stores (bbox, confidence, center_point, is_inside)

    print("\n[INFO] Starting video loop. Press 'q' in the video window to quit.")
    print("-" * 70)

    try:
        while True:
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

            # Step 2: Run YOLOv8 Nano at throttled ~5 FPS rate
            # Only run inference every `frame_interval` frames
            if frame_count % frame_interval == 0:
                latest_detections = []

                # Run inference:
                # - classes=[0]: Only detect class 0 ('person' in COCO dataset)
                # - verbose=False: Suppress default per-frame YOLO printouts
                results = model(frame, classes=[0], verbose=False)

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

                                # Construct the standardized intrusion event dictionary
                                alert_event = generate_intrusion_event(conf, [x1, y1, x2, y2])

                                # Print the alert dictionary cleanly formatted to console
                                print("\n🚨 [INTRUSION ALERT TRIGGERED] 🚨")
                                print(json.dumps(alert_event, indent=2))
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
                f"Threat Detection System | Feed: {TARGET_INFERENCE_FPS} FPS Inference",
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

            # Step 3D: Show the live video window
            cv2.imshow("Intelligent Threat Detection & Situational Awareness", frame)

            # Play at normal video frame rate (wait for playback_delay_ms)
            # Break loop immediately if the user presses 'q'
            key = cv2.waitKey(playback_delay_ms) & 0xFF
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
