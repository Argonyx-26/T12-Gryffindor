# SYSTEM LIMITATIONS & FUTURE ROADMAP — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  

---

## 1. Identified System Limitations

### 1. Benchmark Scope vs. Real-World Deployment
The reported 100% F1-score and 70% noise suppression rate were achieved on our **10-scenario controlled evaluation dataset** (`backend/evaluation_dataset.py`). Real-world operational environments introduce unpredictability (e.g., extreme weather, camera lens dirt, network outages, complex multi-person camouflage) that will produce non-zero false positives and false negatives.

### 2. CCTV Hardware & Processing Constraints
- Running YOLOv8 on standard CPU hardware limits processing speeds to ~15-20 FPS for 1080p feeds.
- Processing multiple high-resolution (4K 60FPS) video feeds simultaneously requires dedicated NVIDIA CUDA GPU acceleration (TensorRT optimization).

### 3. Network Clock Synchronization (NTP)
- Granular cross-process network latency measurement relies on synchronized UTC timestamps between distributed nodes (camera worker, IoT sensors, backend server).
- Clock skew exceeding 1.5 seconds across nodes can cause correlation window misses unless clock synchronization protocols (NTP/PTP) are maintained.

### 4. Behavioral Baseline Warm-Up Period
- The behavioral intelligence engine requires an initial warm-up period (e.g., 50-100 ambient events per zone) to calculate meaningful statistical moving baselines ($\mu$ and $\sigma$).
- During cold starts, the system falls back to default static risk profiles.

### 5. Static Correlation Window Boundary
- The current correlation window is fixed at **±1.5 seconds**.
- While effective for high-frequency access control and login spikes, slow stealthy intrusions occurring over minutes or hours require longer macro-correlation windows.

---

## 2. Future System Roadmap & Planned Enhancements

1. **Dynamic AI-Driven Correlation Windows**: Adaptive sliding windows that scale based on zone risk level and historical activity patterns.
2. **TensorRT GPU Acceleration**: Optimizing YOLO vision workers with TensorRT for multi-camera 4K 60FPS real-time processing.
3. **Multi-Node Distributed Redis Cluster**: Horizontal scaling across multi-region edge nodes.
4. **Adversarial Input Hardening**: Adding vision model robustness against physical camouflage and adversarial attack patterns.
