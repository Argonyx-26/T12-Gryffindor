"""
Gryfffindor Sentinel — Video Engine Module (Phase 3A)

Provides real-time CCTV / computer vision capabilities:
1. Reusable VideoSource abstraction (FileVideoSource, WebcamVideoSource, MockVideoSource)
2. YOLOEngine loader (loads YOLOv8 model once, auto-detects CUDA GPU / CPU fallback)
3. SpatialAnalyticsEngine (Polygon Restricted Zones, Virtual Line Tripwires, Loitering Duration, Crowd Counting)
4. Anti-Flooding Debouncer & Temporal Cooldown Manager
5. VideoPipelineWorker for threaded non-blocking frame processing
"""

import os
import sys
import time
import uuid
import math
import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

import cv2
import numpy as np

# Configure module logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("video_engine")

# Try importing ultralytics / torch safely
try:
    from ultralytics import YOLO
    import torch
    ULTRALYTICS_AVAILABLE = True
except ImportError:
    ULTRALYTICS_AVAILABLE = False
    logger.warning("ultralytics or torch not available. YOLO engine will run in mock detection fallback mode.")

# Import unified Event model from backend
from backend.models import Event
from backend.latency_collector import LATENCY_COLLECTOR

DEFAULT_INGEST_URL = "http://localhost:8000/ingest"
ZONES_GEO_COORDS = {
    "Perimeter_Gate_3": [12.9716, 77.5946],
    "Server_Room": [12.9720, 77.5950],
    "Parking_Lot_B": [12.9710, 77.5940],
}

# ==============================================================================
# 1. VIDEO SOURCE ABSTRACTIONS
# ==============================================================================

class BaseVideoSource(ABC):
    """Abstract base class for all video sources."""

    def __init__(self, camera_id: str = "CAM-PRIMARY", zone_id: str = "Perimeter_Gate_3"):
        self.camera_id = camera_id
        self.zone_id = zone_id
        self.is_opened = False

    @abstractmethod
    def read_frame(self) -> Tuple[bool, Optional[np.ndarray], Optional[int]]:
        """Reads the next video frame. Returns (success_bool, frame_ndarray, capture_monotonic_ns)."""
        pass

    @abstractmethod
    def release(self) -> None:
        """Releases underlying video resources."""
        pass


class FileVideoSource(BaseVideoSource):
    """Video source reading from a local MP4/AVI video file in continuous loop."""

    def __init__(self, file_path: str, camera_id: str = "CAM-FILE", zone_id: str = "Perimeter_Gate_3", loop: bool = True):
        super().__init__(camera_id, zone_id)
        self.file_path = file_path
        self.loop = loop
        self.cap = cv2.VideoCapture(file_path)
        self.is_opened = self.cap.isOpened()
        if not self.is_opened:
            logger.error(f"Failed to open video file source: '{file_path}'")

    def read_frame(self) -> Tuple[bool, Optional[np.ndarray], Optional[int], Optional[str]]:
        if not self.is_opened or not self.cap:
            return False, None, None, None

        capture_ns = time.perf_counter_ns()
        capture_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ret, frame = self.cap.read()
        if not ret and self.loop:
            # Loop video back to beginning on EOF
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            capture_ns = time.perf_counter_ns()
            capture_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            ret, frame = self.cap.read()

        return ret, frame, capture_ns, capture_utc

    def release(self) -> None:
        if self.cap:
            self.cap.release()
            self.is_opened = False


class WebcamVideoSource(BaseVideoSource):
    """Video source reading from a local webcam or USB camera index."""

    def __init__(self, device_index: int = 0, camera_id: str = "CAM-WEBCAM", zone_id: str = "Perimeter_Gate_3"):
        super().__init__(camera_id, zone_id)
        self.device_index = device_index
        self.cap = cv2.VideoCapture(device_index)
        self.is_opened = self.cap.isOpened()
        if not self.is_opened:
            logger.error(f"Failed to open webcam index: {device_index}")

    def read_frame(self) -> Tuple[bool, Optional[np.ndarray], Optional[int], Optional[str]]:
        if not self.is_opened or not self.cap:
            return False, None, None, None
        capture_ns = time.perf_counter_ns()
        capture_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ret, frame = self.cap.read()
        return ret, frame, capture_ns, capture_utc

    def release(self) -> None:
        if self.cap:
            self.cap.release()
            self.is_opened = False


class MockVideoSource(BaseVideoSource):
    """Hardware-independent synthetic frame generator for unit testing and fallback."""

    def __init__(self, camera_id: str = "CAM-MOCK", zone_id: str = "Perimeter_Gate_3", width: int = 640, height: int = 480):
        super().__init__(camera_id, zone_id)
        self.width = width
        self.height = height
        self.is_opened = True
        self._step = 0

    def read_frame(self) -> Tuple[bool, Optional[np.ndarray], Optional[int], Optional[str]]:
        capture_ns = time.perf_counter_ns()
        capture_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._step += 1
        # Create dark background frame
        frame = np.zeros((self.height, self.width, 3), dtype=np.uint8) + 30
        # Draw a simulated moving person rectangle
        x = (self._step * 10) % (self.width - 100) + 50
        y = (self._step * 5) % (self.height - 150) + 50
        cv2.rectangle(frame, (x, y), (x + 60, y + 120), (0, 255, 0), 2)
        cv2.putText(frame, "SIMULATED PERSON", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 255, 0), 1)
        return True, frame, capture_ns, capture_utc

    def release(self) -> None:
        self.is_opened = False


# ==============================================================================
# 2. YOLO DETECTION ENGINE (SINGLE-LOAD, CUDA GPU / CPU FALLBACK)
# ==============================================================================

class YOLOEngine:
    """
    YOLOv8 Object Detection Engine.
    Loads PyTorch/Ultralytics weights once at startup.
    Detects CUDA GPU availability and falls back gracefully to CPU.
    """

    def __init__(self, model_name: str = "yolov8n.pt", confidence_threshold: float = 0.45, imgsz: int = 320):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.imgsz = imgsz
        self.model = None
        self.device = "cpu"
        self._init_model()

    def _init_model(self) -> None:
        if not ULTRALYTICS_AVAILABLE:
            logger.warning("YOLOEngine running in mock detection mode (ultralytics not installed).")
            return

        try:
            # Check GPU availability
            if torch.cuda.is_available():
                self.device = "cuda:0"
                logger.info(f"🚀 CUDA GPU Acceleration Detected! Device: {torch.cuda.get_device_name(0)}")
            else:
                self.device = "cpu"
                logger.info("ℹ️ CUDA GPU not detected. Falling back to CPU for YOLO inference.")

            logger.info(f"[YOLOEngine] Loading model weights '{self.model_name}' on {self.device}...")
            self.model = YOLO(self.model_name)
            logger.info(f"[YOLOEngine] Model '{self.model_name}' loaded successfully!")
        except Exception as err:
            logger.error(f"[YOLOEngine] Error initializing YOLO model: {err}. Falling back to CPU mock detector.")
            self.model = None

    def detect(self, frame: np.ndarray) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Runs object detection on a single OpenCV BGR frame.
        Returns (detections_list, timing_info_dict).
        """
        if frame is None:
            return [], {}

        t_start_ns = time.perf_counter_ns()

        if self.model is None or not ULTRALYTICS_AVAILABLE:
            t_end_ns = time.perf_counter_ns()
            yolo_ms = (t_end_ns - t_start_ns) / 1e6
            LATENCY_COLLECTOR.record_yolo_latency(yolo_ms)

            # Return synthetic mock detection for testing / fallback
            h, w = frame.shape[:2]
            cx, cy = int(w * 0.5), int(h * 0.5)
            dets = [{
                "class": "person",
                "confidence": 0.92,
                "bbox": [cx - 30, cy - 60, cx + 30, cy + 60],
                "centroid": (cx, cy),
                "track_id": 101,
            }]
            timing = {
                "inference_start_ns": t_start_ns,
                "inference_end_ns": t_end_ns,
                "yolo_inference_ms": yolo_ms,
            }
            return dets, timing

        try:
            results = self.model.predict(
                source=frame,
                conf=self.confidence_threshold,
                imgsz=self.imgsz,
                device=self.device,
                verbose=False
            )
            t_end_ns = time.perf_counter_ns()
            yolo_ms = (t_end_ns - t_start_ns) / 1e6
            LATENCY_COLLECTOR.record_yolo_latency(yolo_ms)

            detections = []
            if results and len(results) > 0:
                res = results[0]
                boxes = res.boxes
                if boxes is not None:
                    for i in range(len(boxes)):
                        box = boxes[i]
                        cls_id = int(box.cls[0].item())
                        cls_name = self.model.names.get(cls_id, f"cls_{cls_id}")
                        conf = float(box.conf[0].item())
                        xyxy = [int(v) for v in box.xyxy[0].tolist()]

                        x1, y1, x2, y2 = xyxy
                        cx = int((x1 + x2) / 2)
                        cy = int((y1 + y2) / 2)
                        track_id = int(box.id[0].item()) if box.id is not None else (i + 1)

                        detections.append({
                            "class": cls_name,
                            "confidence": round(conf, 4),
                            "bbox": xyxy,
                            "centroid": (cx, cy),
                            "track_id": track_id,
                        })

            timing = {
                "inference_start_ns": t_start_ns,
                "inference_end_ns": t_end_ns,
                "yolo_inference_ms": yolo_ms,
            }
            return detections, timing
        except Exception as err:
            t_end_ns = time.perf_counter_ns()
            logger.error(f"[YOLOEngine] Inference exception: {err}")
            return [], {"inference_start_ns": t_start_ns, "inference_end_ns": t_end_ns, "yolo_inference_ms": 0.0}


# ==============================================================================
# 3. SPATIAL ANALYTICS & ANTI-FLOODING DEBOUNCER
# ==============================================================================

def check_line_intersection(p1: Tuple[int, int], p2: Tuple[int, int], q1: Tuple[int, int], q2: Tuple[int, int]) -> bool:
    """
    Checks if line segment p1-p2 intersects line segment q1-q2.
    Used for virtual tripwire line crossing analytics.
    """
    def ccw(A, B, C):
        return (C[1] - A[1]) * (B[0] - A[0]) > (B[1] - A[1]) * (C[0] - A[0])

    return ccw(p1, q1, q2) != ccw(p2, q1, q2) and ccw(p1, p2, q1) != ccw(p1, p2, q2)


class SpatialAnalyticsEngine:
    """
    Executes spatial geometry & behavior rules on frame detections:
    1. Polygonal Restricted Zones (person enters polygon)
    2. Virtual Line Tripwires (person centroid crosses line segment)
    3. Loitering Detection (person stays inside zone > loiter_duration_sec)
    4. Crowd Detection (person count inside zone > crowd_threshold)
    5. Debouncing / Cooldown Manager (prevents event flooding)
    """

    def __init__(self, cooldown_seconds: float = 3.0, loiter_duration_seconds: float = 5.0, crowd_threshold: int = 4):
        self.cooldown_seconds = cooldown_seconds
        self.loiter_duration_seconds = loiter_duration_seconds
        self.crowd_threshold = crowd_threshold

        # Cooldown tracker: {event_key: timestamp_last_emitted}
        self.last_event_times: Dict[str, float] = {}

        # Centroid history for tripwires: {track_id: (prev_cx, prev_cy)}
        self.prev_centroids: Dict[int, Tuple[int, int]] = {}

        # Loitering entry times: {track_id: timestamp_entered}
        self.loiter_entries: Dict[int, float] = {}

    def is_cooldown_active(self, event_key: str, custom_cooldown: Optional[float] = None) -> bool:
        """Returns True if event_key is currently in cooldown period."""
        cd = custom_cooldown if custom_cooldown is not None else self.cooldown_seconds
        last_t = self.last_event_times.get(event_key, 0.0)
        return (time.time() - last_t) < cd

    def mark_event_emitted(self, event_key: str) -> None:
        """Updates last emitted timestamp for event_key."""
        self.last_event_times[event_key] = time.time()

    def process_frame_analytics(
        self,
        detections: List[Dict[str, Any]],
        frame_shape: Tuple[int, int],
        zone_id: str,
        camera_id: str,
        restricted_polygon: Optional[np.ndarray] = None,
        tripwire_line: Optional[Tuple[Tuple[int, int], Tuple[int, int]]] = None,
        timing_info: Optional[Dict[str, Any]] = None,
        frame_capture_ns: Optional[int] = None,
        frame_capture_utc: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluates spatial rules on frame detections.
        Returns a list of standardized raw event payload dicts ready for conversion to Event objects.
        """
        now = time.time()
        generated_events = []
        h, w = frame_shape[:2]

        def _build_meta(base_meta: Dict[str, Any]) -> Dict[str, Any]:
            meta = dict(base_meta)
            meta["camera_id"] = camera_id
            now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            meta["frame_capture_timestamp_utc"] = frame_capture_utc or now_utc
            meta["event_generation_timestamp_utc"] = now_utc

            if frame_capture_ns:
                meta["frame_capture_monotonic_ns"] = frame_capture_ns
            if timing_info:
                inf_start_ns = timing_info.get("inference_start_ns")
                inf_end_ns = timing_info.get("inference_end_ns")
                meta["inference_start_ns"] = inf_start_ns
                meta["inference_end_ns"] = inf_end_ns
                meta["yolo_inference_ms"] = timing_info.get("yolo_inference_ms")

                # Same-process Stage 0: Frame Capture -> YOLO Start
                if frame_capture_ns and inf_start_ns:
                    s0_ms = (inf_start_ns - frame_capture_ns) / 1e6
                    LATENCY_COLLECTOR.record_frame_to_inference_start(s0_ms)

            evt_gen_ns = time.perf_counter_ns()
            meta["event_generation_ns"] = evt_gen_ns
            meta["trace_id"] = f"trc-{uuid.uuid4().hex[:8]}"

            # Same-process Stage 2: VIDEO Event Generation (Event Gen - Inference End)
            if timing_info and timing_info.get("inference_end_ns"):
                s2_ms = (evt_gen_ns - timing_info["inference_end_ns"]) / 1e6
                LATENCY_COLLECTOR.record_event_gen_latency(s2_ms)

            return meta

        # Default restricted polygon if none provided (30% to 70% frame bounds)
        if restricted_polygon is None:
            restricted_polygon = np.array([
                [int(w * 0.25), int(h * 0.20)],
                [int(w * 0.75), int(h * 0.20)],
                [int(w * 0.75), int(h * 0.80)],
                [int(w * 0.25), int(h * 0.80)],
            ], dtype=np.int32)

        # Default tripwire line if none provided (horizontal line across middle 80%)
        if tripwire_line is None:
            tripwire_line = ((int(w * 0.1), int(h * 0.5)), (int(w * 0.9), int(h * 0.5)))

        persons_in_zone = 0
        current_track_ids = set()

        for det in detections:
            cls_name = det.get("class", "person")
            conf = det.get("confidence", 0.0)
            cx, cy = det.get("centroid", (0, 0))
            track_id = det.get("track_id", 0)
            current_track_ids.add(track_id)

            if cls_name != "person":
                # Handle vehicle detection
                if cls_name in ["car", "truck", "bus", "motorcycle"]:
                    vk = f"vehicle_{zone_id}_{track_id}"
                    if not self.is_cooldown_active(vk, custom_cooldown=5.0):
                        self.mark_event_emitted(vk)
                        generated_events.append({
                            "event_type": "vehicle_detected",
                            "confidence": conf,
                            "raw_meta": _build_meta({"vehicle_type": cls_name, "bbox": det["bbox"], "track_id": track_id}),
                        })
                continue

            # 1. Base person_detected check with anti-flooding cooldown
            pk = f"person_{zone_id}_{track_id}"
            if not self.is_cooldown_active(pk, custom_cooldown=4.0):
                self.mark_event_emitted(pk)
                generated_events.append({
                    "event_type": "person_detected",
                    "confidence": conf,
                    "raw_meta": _build_meta({"bbox": det["bbox"], "track_id": track_id}),
                })

            # 2. Polygon Restricted Zone Check
            is_inside = cv2.pointPolygonTest(restricted_polygon, (cx, cy), measureDist=False) >= 0
            if is_inside:
                persons_in_zone += 1
                rk = f"restricted_zone_{zone_id}_{track_id}"
                if not self.is_cooldown_active(rk, custom_cooldown=6.0):
                    self.mark_event_emitted(rk)
                    generated_events.append({
                        "event_type": "restricted_zone_entry",
                        "confidence": conf,
                        "raw_meta": _build_meta({
                            "restricted_zone": True,
                            "bbox": det["bbox"],
                            "track_id": track_id,
                            "centroid": [cx, cy],
                        }),
                    })

                # 3. Loitering Duration Check
                if track_id not in self.loiter_entries:
                    self.loiter_entries[track_id] = now
                else:
                    duration = now - self.loiter_entries[track_id]
                    if duration >= self.loiter_duration_seconds:
                        lk = f"loiter_{zone_id}_{track_id}"
                        if not self.is_cooldown_active(lk, custom_cooldown=10.0):
                            self.mark_event_emitted(lk)
                            generated_events.append({
                                "event_type": "loitering_detected",
                                "confidence": conf,
                                "raw_meta": _build_meta({
                                    "loiter_duration_sec": round(duration, 1),
                                    "bbox": det["bbox"],
                                    "track_id": track_id,
                                }),
                            })
            else:
                # Left zone -> clear loiter timer
                self.loiter_entries.pop(track_id, None)

            # 4. Virtual Line Tripwire Crossing Check
            prev_point = self.prev_centroids.get(track_id)
            if prev_point is not None:
                if check_line_intersection(prev_point, (cx, cy), tripwire_line[0], tripwire_line[1]):
                    tk = f"tripwire_{zone_id}_{track_id}"
                    if not self.is_cooldown_active(tk, custom_cooldown=5.0):
                        self.mark_event_emitted(tk)
                        generated_events.append({
                            "event_type": "tripwire_crossed",
                            "confidence": conf,
                            "raw_meta": _build_meta({
                                "tripwire_id": f"LINE-{zone_id}-01",
                                "previous_pos": list(prev_point),
                                "current_pos": [cx, cy],
                                "bbox": det["bbox"],
                                "track_id": track_id,
                            }),
                        })

            # Update centroid history
            self.prev_centroids[track_id] = (cx, cy)

        # 5. Crowd Density Count Check
        if persons_in_zone >= self.crowd_threshold:
            ck = f"crowd_{zone_id}"
            if not self.is_cooldown_active(ck, custom_cooldown=8.0):
                self.mark_event_emitted(ck)
                generated_events.append({
                    "event_type": "crowd_detected",
                    "confidence": 0.95,
                    "raw_meta": _build_meta({
                        "person_count": persons_in_zone,
                        "threshold": self.crowd_threshold,
                    }),
                })

        # Clean up stale tracks no longer present
        stale_tracks = set(self.prev_centroids.keys()) - current_track_ids
        for st in stale_tracks:
            self.prev_centroids.pop(st, None)
            self.loiter_entries.pop(st, None)

        return generated_events


# ==============================================================================
# 4. EVENT CONVERTER & WORKER PIPELINE
# ==============================================================================

def convert_to_event_model(raw_event: Dict[str, Any], zone_id: str) -> Event:
    """Converts a raw analytics event payload into a standardized backend Event model."""
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    geo_coords = ZONES_GEO_COORDS.get(zone_id, [12.9716, 77.5946])

    return Event(
        event_id=f"evt-v-{uuid.uuid4().hex[:8]}",
        timestamp=now_iso,
        source_type="VIDEO",
        zone_id=zone_id,
        coordinates=geo_coords,
        event_type=raw_event["event_type"],
        confidence=raw_event["confidence"],
        raw_meta=raw_event["raw_meta"],
    )


class VideoPipelineWorker:
    """
    Background threaded worker processing frames from a VideoSource,
    running YOLO detection and Spatial Analytics, and delivering generated
    VIDEO Events to the backend ingestion endpoint.
    """

    def __init__(
        self,
        video_source: BaseVideoSource,
        yolo_engine: YOLOEngine,
        spatial_engine: SpatialAnalyticsEngine,
        ingest_url: str = DEFAULT_INGEST_URL,
        target_fps: float = 5.0,
    ):
        self.source = video_source
        self.yolo = yolo_engine
        self.spatial = spatial_engine
        self.ingest_url = ingest_url
        self.target_fps = target_fps

        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.processed_frames = 0
        self.emitted_events_count = 0

    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info(f"[VideoPipelineWorker] Background worker started for Camera '{self.source.camera_id}' ({self.source.zone_id})")

    def stop(self) -> None:
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        self.source.release()
        logger.info(f"[VideoPipelineWorker] Worker stopped. Processed {self.processed_frames} frames, emitted {self.emitted_events_count} events.")

    def _run_loop(self) -> None:
        interval = 1.0 / max(1.0, self.target_fps)

        while self.is_running and self.source.is_opened:
            start_t = time.time()
            frame_res = self.source.read_frame()
            if len(frame_res) == 4:
                ret, frame, capture_ns, capture_utc = frame_res
            else:
                ret, frame, capture_ns = frame_res
                capture_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            if not ret or frame is None:
                time.sleep(0.05)
                continue

            self.processed_frames += 1

            # 1. Run YOLO inference
            detections, timing_info = self.yolo.detect(frame)

            # 2. Run Spatial Analytics
            raw_events = self.spatial.process_frame_analytics(
                detections=detections,
                frame_shape=frame.shape,
                zone_id=self.source.zone_id,
                camera_id=self.source.camera_id,
                timing_info=timing_info,
                frame_capture_ns=capture_ns,
                frame_capture_utc=capture_utc,
            )

            # 3. Convert & dispatch events
            for raw_evt in raw_events:
                event_obj = convert_to_event_model(raw_evt, self.source.zone_id)
                self.emitted_events_count += 1
                self._dispatch_event(event_obj)

            # Throttle loop to target FPS
            elapsed = time.time() - start_t
            sleep_t = max(0.0, interval - elapsed)
            time.sleep(sleep_t)
            time.sleep(sleep_t)

    def _dispatch_event(self, event_obj: Event) -> None:
        """Sends Event object to backend ingestion hub."""
        import requests
        def _post():
            try:
                payload = event_obj.model_dump()
                resp = requests.post(self.ingest_url, json=payload, timeout=2.0)
                logger.info(f"📡 [VIDEO EVENT SENT] {event_obj.event_type} @ {event_obj.zone_id} -> Status {resp.status_code}")
            except Exception as err:
                logger.warning(f"⚠️ [VIDEO EVENT DELIVERY ERROR] Could not post to {self.ingest_url}: {err}")

        threading.Thread(target=_post, daemon=True).start()
