# JUDGE Q&A DEFENSE GUIDE — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**OBJECTIVE**: Technical, Concise, and Defendable Answers for Mentor & Judge Examinations  

---

### A. What problem are you solving?
Conventional security monitoring systems operate in silos. CCTV operators miss events due to fatigue, IoT door alarms trigger false alarms, and Cyber security teams are disconnected from physical security. Gryffindor Sentinel fuses VIDEO, IoT, and Cyber events in real-time to detect complex multi-vector physical/cyber threats while suppressing false alarms.

### B. Why is this different from a normal CCTV system?
A standard CCTV system only sees visual pixels and relies on human eyes. Gryffindor Sentinel correlates computer vision detections with physical access control sensors and cyber network authentication logs, scoring threats contextually and explaining *why* an incident triggered.

### C. Why use multiple sources?
Single modalities are vulnerable to blind spots or noise (e.g., shadows on camera, maintenance workers opening doors). Combining VIDEO (0.35 weight), IoT (0.35 weight), and CYBER (0.30 weight) ensures threats are corroborated across physical and digital domains.

### D. Why YOLO?
We use YOLOv8 because it provides state-of-the-art real-time object detection speed (30+ FPS on GPU) with lightweight CPU execution capability. It allows custom polygon restricted zones, tripwires, loitering detection, and bounding-box spatial analysis.

### E. Why PostgreSQL?
PostgreSQL provides ACID-compliant, authoritative relational persistence for events, synthesized incidents, junction mappings (`incident_events`), behavioral baselines, and operator audit trails, ensuring complete restart recovery.

### F. Why Redis?
Redis provides sub-millisecond in-memory caching for active incidents and low-latency Pub/Sub fan-out to push real-time alert updates across WebSocket broadcaster instances.

### G. What happens if Redis goes down?
Our custom `SentinelRedisClient` catches connection failures and automatically falls back to an in-memory dictionary cache. System ingestion, scoring, and WebSocket streaming continue operating without interruption.

### H. What happens if the database goes down?
The database layer logs the outage via `check_db_connection()` and gracefully falls back to an isolated SQLite file (`gryffindor.db`), or returns clean HTTP error responses without corrupting existing memory state.

### I. How do you detect false positives?
We suppress false positives by filtering single-source low-risk events (< 40 score), requiring corroboration for score scaling, applying temporal decay, checking behavioral zone baselines, and deduplicating recurring events.

### J. How do you reduce false negatives?
We apply off-shift (1.3x) and restricted-zone (1.4x) risk scaling, track rapid event bursts, preserve historical events in PostgreSQL, and combine redundant physical and cyber modalities so blinded cameras don't hide door breaches.

### K. How does correlation work?
The correlation engine inspects incoming events and groups those sharing the same `zone_id` whose timestamps fall within a sliding **±1.5-second correlation window**.

### L. Why ±1.5 seconds?
Empirical testing demonstrated that 1.5 seconds captures physical door sensor triggers, camera bounding box entries, and concurrent cyber login spikes without falsely grouping unrelated background traffic from minutes prior.

### M. How is the score calculated?
Base risk per event type is weighted by modality (`VIDEO=0.35`, `IOT=0.35`, `CYBER=0.30`), multiplied by corroboration scaling (`1.0x` for 1 source, `1.5x` for 2, `2.2x` for 3), contextual multipliers (off-shift `1.3x`, restricted zone `1.4x`), and capped between 0 and 100.

### N. Why do multiple sources increase confidence?
Independent event detection from separate physical sensors and cyber servers makes coincidence exponentially improbable, justifying the `1.5x` (2 sources) and `2.2x` (3 sources) corroboration multipliers.

### O. What is temporal intelligence?
Temporal intelligence evaluates time-dependent patterns: exponential recency decay ($e^{-\lambda \cdot \Delta t}$), event burst frequencies, and chronological event sequence progression.

### P. What is behavioral intelligence?
Behavioral intelligence builds statistical moving baselines (mean $\mu$ and standard deviation $\sigma$) of normal event frequency per zone to detect statistical anomalies without hardcoding arbitrary static thresholds.

### Q. How do you detect abnormal behavior?
We compute Z-scores ($Z = \frac{x - \mu}{\sigma}$) of current event activity against historical zone baselines. Z-scores above 2.0 apply an anomaly multiplier to the threat score.

### R. How is latency measured?
We instrument a 6-stage pipeline using Python's `time.perf_counter_ns()` for same-process execution and UTC ISO-8601 deltas for cross-process/network boundaries.

### S. How do you know the latency measurement is correct?
We test same-process monotonic timing alongside cross-process UTC timing, rejecting invalid negative deltas caused by clock skew and verifying metrics with `backend/test_latency.py`.

### T. What is trace_id?
A unique distributed tracing string (`trc-...`) injected at event creation and passed end-to-end through FastAPI ingestion, PostgreSQL records, incident synthesis, and WebSocket alert payloads.

### U. How do you prevent duplicate incidents?
When events ingest into a zone with an existing active incident within the correlation window, the engine updates the existing incident's score, sources, and timeline rather than creating duplicate alert cards.

### V. What happens when the same event is replayed?
Ingesting an exact duplicate `event_id` returns HTTP 409 Conflict (Idempotency). Scenario replays generate fresh UUIDs to test pipeline processing cleanly.

### W. How scalable is the system?
In our load tests, the FastAPI backend handled up to 100 events/sec synchronously with sub-50ms ingestion latencies and minimal CPU (<5%) and memory (108MB) footprint.

### X. What are the current limitations?
Fixed ±1.5s correlation window, synthetic benchmark evaluation boundaries, CPU frame rate limitations for 4K video, reliance on clock synchronization, and baseline warm-up requirements.

### Y. What would you improve next?
1. Dynamic AI-driven correlation windows based on zone traffic.
2. TensorRT GPU acceleration for 4K 60FPS video feeds.
3. Multi-node distributed Redis cluster support.

### Z. What happens if one modality fails?
The system operates seamlessly on the remaining active modalities. A failure of VIDEO does not stop IoT and CYBER events from correlating and generating alerts.

### AA. Is the 100% F1 score realistic?
**No, 100% F1 is not a real-world operational guarantee.** The 100% F1 score was measured specifically on our **10-scenario controlled evaluation benchmark** to verify algorithmic correctness. Real-world deployments encounter noisy sensors, occlusion, and unpredictable human behavior that lower operational accuracy.
