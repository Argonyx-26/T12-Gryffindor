"""
Gryfffindor Sentinel — Bounded Latency Collector Module (Phase 3B Final Patch)

Tracks 6 granular pipeline stages + total end-to-end detection latency:
0. Frame Capture -> YOLO Start (frame_to_inference_start_ms)
1. YOLO Inference (yolo_inference_ms)
2. VIDEO Event Generation (video_event_generation_ms)
3. Network / Ingestion (network_ingestion_ms - cross-process UTC)
4. Intelligence Processing (intelligence_processing_ms)
5. Alert Emission (alert_emission_ms)

Also maintains invalid_timestamp_samples counter for clock skew rejection.
"""

import math
from collections import deque
from typing import Dict, Any, List, Optional


class LatencyCollector:
    """
    Lightweight, thread-safe memory-bounded collector for latency metrics.
    Uses collections.deque with maxlen=1000 to prevent unbounded memory growth.
    """

    def __init__(self, max_samples: int = 1000):
        self.frame_to_inf_start_samples: deque = deque(maxlen=max_samples)
        self.yolo_samples: deque = deque(maxlen=max_samples)
        self.event_gen_samples: deque = deque(maxlen=max_samples)
        self.network_ingest_samples: deque = deque(maxlen=max_samples)
        self.intel_samples: deque = deque(maxlen=max_samples)
        self.alert_emit_samples: deque = deque(maxlen=max_samples)
        self.e2e_samples: deque = deque(maxlen=max_samples)
        self.invalid_timestamp_samples: int = 0

    def clear(self):
        """Resets all collected metrics samples and counters."""
        self.frame_to_inf_start_samples.clear()
        self.yolo_samples.clear()
        self.event_gen_samples.clear()
        self.network_ingest_samples.clear()
        self.intel_samples.clear()
        self.alert_emit_samples.clear()
        self.e2e_samples.clear()
        self.invalid_timestamp_samples = 0

    def record_frame_to_inference_start(self, latency_ms: Optional[float]):
        """Records Stage 0: Frame capture to YOLO start duration."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.frame_to_inf_start_samples.append(float(latency_ms))

    def record_yolo_latency(self, latency_ms: Optional[float]):
        """Records Stage 1: YOLO neural network inference duration."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.yolo_samples.append(float(latency_ms))

    def record_event_gen_latency(self, latency_ms: Optional[float]):
        """Records Stage 2: VIDEO event spatial analytics generation duration."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.event_gen_samples.append(float(latency_ms))

    def record_network_ingest_latency(self, latency_ms: Optional[float]):
        """Records Stage 3: Network transmission & ingestion arrival duration (Cross-process UTC)."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.network_ingest_samples.append(float(latency_ms))

    def record_intelligence_latency(self, latency_ms: Optional[float]):
        """Records Stage 4: Backend intelligence evaluation duration."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.intel_samples.append(float(latency_ms))

    def record_alert_emit_latency(self, latency_ms: Optional[float]):
        """Records Stage 5: Alert broadcast & emission duration."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.alert_emit_samples.append(float(latency_ms))

    def record_end_to_end_latency(self, latency_ms: Optional[float]):
        """Records Total End-to-End: Camera frame capture to alert emission duration (Cross-process UTC)."""
        if latency_ms is None:
            return
        if latency_ms < 0:
            self.invalid_timestamp_samples += 1
            return
        self.e2e_samples.append(float(latency_ms))

    @staticmethod
    def _calculate_stats(samples: deque) -> Dict[str, Any]:
        """
        Computes average, p50, p95, min, max, and sample_count.
        Returns None for metrics if sample_count == 0 to avoid false 0 ms reporting.
        """
        count = len(samples)
        if count == 0:
            return {
                "average": None,
                "p50": None,
                "p95": None,
                "min": None,
                "max": None,
                "sample_count": 0,
            }

        s_list = sorted(list(samples))
        if count == 1:
            val = round(s_list[0], 2)
            return {
                "average": val,
                "p50": val,
                "p95": val,
                "min": val,
                "max": val,
                "sample_count": 1,
            }

        avg = round(sum(s_list) / count, 2)
        idx_p50 = int(round(0.50 * (count - 1)))
        idx_p95 = int(round(0.95 * (count - 1)))

        return {
            "average": avg,
            "p50": round(s_list[idx_p50], 2),
            "p95": round(s_list[idx_p95], 2),
            "min": round(s_list[0], 2),
            "max": round(s_list[-1], 2),
            "sample_count": count,
        }

    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Returns structured dictionary containing 6-stage metric categories for GET /metrics.
        """
        return {
            "intelligence_processing_ms": self._calculate_stats(self.intel_samples),
            "end_to_end_detection_ms": self._calculate_stats(self.e2e_samples),
            "yolo_inference_ms": self._calculate_stats(self.yolo_samples),
            "invalid_timestamp_samples": self.invalid_timestamp_samples,
            "pipeline_breakdown_ms": {
                "0_frame_to_inference_start": self._calculate_stats(self.frame_to_inf_start_samples),
                "1_yolo_inference": self._calculate_stats(self.yolo_samples),
                "2_video_event_generation": self._calculate_stats(self.event_gen_samples),
                "3_network_ingestion": self._calculate_stats(self.network_ingest_samples),
                "4_intelligence_processing": self._calculate_stats(self.intel_samples),
                "5_alert_emission": self._calculate_stats(self.alert_emit_samples),
                "total_end_to_end": self._calculate_stats(self.e2e_samples),
            },
        }


# Global Singleton Collector Instance
LATENCY_COLLECTOR = LatencyCollector(max_samples=1000)
