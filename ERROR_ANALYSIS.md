# ERROR ANALYSIS — FALSE POSITIVE & FALSE NEGATIVE MANAGEMENT

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  

---

## 1. Overview & Core Definitions

In operational threat detection systems:
- **False Positive (FP)**: An alert generated for a situation that is actually benign (e.g., an authorized employee returning after hours triggering a critical breach alert).
- **False Negative (FN)**: A genuine threat that passes undetected by the system (e.g., an intruder evading camera detection and opening an unauthorized door without an alert).

> [!WARNING]
> While our system achieved a 100% F1-score on our 100-event controlled evaluation benchmark, **real-world performance can differ from the controlled benchmark** due to environmental noise, sensor degradation, and unpredictable human behavior.

---

## 2. False Positive Reduction Mechanisms

Gryffindor Sentinel implements seven defense layers specifically engineered to suppress false positives:

1. **Multi-Source Corroboration**: Single-source events carry lower multipliers (`1.0x`). Corroborated events across 2 or 3 modalities apply `1.5x` and `2.2x` multipliers, preventing isolated noise from escalating.
2. **Single-Source Low-Risk Suppression**: Any single-source event with a calculated score below `Medium` (< 40) is automatically suppressed at the ingestion boundary.
3. **Temporal Recency Decay**: Events decay exponentially ($e^{-\lambda \cdot \Delta t}$), ensuring stale activity cannot falsely combine with new events.
4. **Behavioral Zone Baselines**: Normal ambient traffic establishes moving statistical averages ($\mu$ and $\sigma$). Events within normal bounds receive lower anomaly scores.
5. **Correlation Window Boundary**: Events occurring outside the sliding **±1.5-second correlation window** are not grouped into multi-source incidents.
6. **Confidence Thresholding**: YOLO camera detections below specified confidence floors (e.g. `< 0.40`) are discarded before event creation.
7. **Incident Deduplication**: Subsequent events in the same zone update existing active incidents rather than spawning multiple duplicate alert cards.

---

## 3. False Negative Protection Mechanisms

To minimize the risk of missing genuine security threats:

1. **Multimodal Redundancy**: If a physical camera is blinded or obscured, IoT door sensors and Cyber login logs continue feeding the correlation engine.
2. **Off-Shift & Restricted Zone Multipliers**: High-risk spatial/temporal contexts automatically apply risk scaling (`1.3x` off-shift, `1.4x` restricted zone) to ensure single critical events are not overlooked.
3. **Burst Detection & Sequence Anomalies**: Rapid bursts of low-level cyber failures or out-of-sequence physical accesses trigger anomaly boosts even if individual events appear weak.
4. **Authoritative State Persistence**: Event history is preserved in PostgreSQL, enabling retroactive correlation analysis if delayed evidence arrives.
