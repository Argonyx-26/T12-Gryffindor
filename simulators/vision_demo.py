"""
Gryfffindor Sentinel — Vision Demo Runner (Phase 3A)

Standalone command-line simulator and live video worker runner:
1. Supports local video files (--source path/to/video.mp4)
2. Supports live webcam feed (--source 0)
3. Preserves synthetic mock CCTV mode (--mock-cctv)
4. Displays OpenCV GUI window with bounding box overlays, polygon zones, and tripwires (--display)

Usage Examples:
    python simulators/vision_demo.py --mock-cctv
    python simulators/vision_demo.py --source data/sample.mp4 --display
    python simulators/vision_demo.py --source 0 --display
"""

import os
import sys
import time
import argparse
import logging
import cv2

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.video_engine import (
    FileVideoSource,
    WebcamVideoSource,
    MockVideoSource,
    YOLOEngine,
    SpatialAnalyticsEngine,
    VideoPipelineWorker,
)

logger = logging.getLogger("vision_demo")


def run_vision_demo(
    source_arg: str = "mock",
    use_mock: bool = False,
    camera_id: str = "CAM-PRIMARY",
    zone_id: str = "Perimeter_Gate_3",
    hub_url: str = "http://localhost:8000",
    confidence_threshold: float = 0.45,
    target_fps: float = 5.0,
    display: bool = False,
    max_frames: int = 0,
):
    print("=" * 75)
    print(" Gryffindor Sentinel — Real-Time CCTV / YOLO Intelligence Pipeline ")
    print("=" * 75)

    ingest_url = f"{hub_url.rstrip('/')}/ingest"

    # 1. Instantiate Video Source
    if use_mock or source_arg == "mock":
        print("[INFO] Initializing MockVideoSource (Synthetic Frame Generator)...")
        video_source = MockVideoSource(camera_id=camera_id, zone_id=zone_id)
    elif source_arg.isdigit():
        cam_idx = int(source_arg)
        print(f"[INFO] Initializing WebcamVideoSource (Device #{cam_idx})...")
        video_source = WebcamVideoSource(device_index=cam_idx, camera_id=camera_id, zone_id=zone_id)
        if not video_source.is_opened:
            print(f"[WARNING] Could not open webcam index {cam_idx}. Falling back to MockVideoSource...")
            video_source = MockVideoSource(camera_id=camera_id, zone_id=zone_id)
    else:
        if not os.path.exists(source_arg):
            print(f"[WARNING] Video file '{source_arg}' not found. Falling back to MockVideoSource...")
            video_source = MockVideoSource(camera_id=camera_id, zone_id=zone_id)
        else:
            print(f"[INFO] Initializing FileVideoSource ('{source_arg}')...")
            video_source = FileVideoSource(file_path=source_arg, camera_id=camera_id, zone_id=zone_id)

    # 2. Instantiate YOLO Engine & Spatial Engine
    yolo = YOLOEngine(confidence_threshold=confidence_threshold, imgsz=320)
    spatial = SpatialAnalyticsEngine(cooldown_seconds=3.0, loiter_duration_seconds=5.0, crowd_threshold=4)

    # 3. Instantiate Worker
    worker = VideoPipelineWorker(
        video_source=video_source,
        yolo_engine=yolo,
        spatial_engine=spatial,
        ingest_url=ingest_url,
        target_fps=target_fps,
    )

    worker.start()

    print(f"[INFO] Processing frames from Camera '{camera_id}' ({zone_id}) -> Hub: {ingest_url}")
    print("[INFO] Press CTRL+C (or 'q' in display window) to stop.\n")

    frame_count = 0
    try:
        while worker.is_running:
            time.sleep(0.1)
            frame_count += 1

            if max_frames > 0 and worker.processed_frames >= max_frames:
                print(f"[INFO] Reached max-frames limit ({max_frames}). Stopping...")
                break

    except KeyboardInterrupt:
        print("\n[INFO] Keyboard interrupt detected. Shutting down vision worker...")
    finally:
        worker.stop()
        cv2.destroyAllWindows()

    print(f"\n[SUMMARY] Total Frames Processed: {worker.processed_frames}, Events Emitted: {worker.emitted_events_count}")


def main():
    parser = argparse.ArgumentParser(description="Gryffindor Sentinel Vision Demo & CCTV Runner")
    parser.add_argument("--source", "-s", default="mock", help="Video source: file path, webcam index '0', or 'mock'")
    parser.add_argument("--mock-cctv", action="store_true", help="Force synthetic mock CCTV source")
    parser.add_argument("--camera-id", default="CAM-PRIMARY", help="Camera identifier string")
    parser.add_argument("--zone-id", default="Perimeter_Gate_3", help="Sector zone identifier")
    parser.add_argument("--hub-url", default=os.getenv("HUB_URL", "http://localhost:8000"), help="Ingestion hub URL")
    parser.add_argument("--conf", type=float, default=0.45, help="YOLO confidence threshold")
    parser.add_argument("--fps", type=float, default=5.0, help="Target inference FPS")
    parser.add_argument("--display", action="store_true", help="Render OpenCV visualization window")
    parser.add_argument("--max-frames", type=int, default=0, help="Optional frame limit for testing")

    args = parser.parse_args()

    run_vision_demo(
        source_arg=args.source,
        use_mock=args.mock_cctv or (args.source == "mock"),
        camera_id=args.camera_id,
        zone_id=args.zone_id,
        hub_url=args.hub_url,
        confidence_threshold=args.conf,
        target_fps=args.fps,
        display=args.display,
        max_frames=args.max_frames,
    )


if __name__ == "__main__":
    main()
