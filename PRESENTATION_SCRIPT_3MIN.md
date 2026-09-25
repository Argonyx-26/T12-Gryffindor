# 3-MINUTE PRESENTATION SCRIPT — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**TARGET DURATION**: 3 Minutes (180 Seconds)  

---

### [0:00–0:20] THE PROBLEM
> "Hi everyone! In modern facility security, systems operate in silos. Cameras watch rooms, IoT door sensors log entries, and IT teams monitor cyber logins. But attackers don't respect these boundaries—they exploit them. Security operators are overwhelmed by false alarms, while coordinated multi-vector physical and cyber breaches slip right through the cracks."

---

### [0:20–0:45] THE SOLUTION
> "We built **Gryffindor Sentinel**—an intelligent, multimodal threat detection and situational awareness system. It ingests computer vision detections from CCTV, physical IoT access events, and cyber syslog feeds, correlating them in real-time to detect true security breaches while automatically filtering out background noise."

---

### [0:45–1:20] THE ARCHITECTURE
> "Under the hood, our system runs YOLOv8 for real-time video analytics—detecting restricted zone entries and tripwires. Events flow into a fast FastAPI backend, where our engine groups events happening within a 1.5-second window in the same zone. We persist all state to PostgreSQL and use Redis for sub-millisecond caching and real-time WebSocket alert broadcasting to our tactical dashboard."

---

### [1:20–1:50] INTELLIGENCE & CORRELATION
> "What makes Sentinel smart is context. We combine camera weight at 35%, IoT at 35%, and Cyber at 30%. When multiple sources trigger together, our corroboration engine applies a 2.2x multiplier, scaling the score to Critical. Plus, our temporal and behavioral intelligence engine builds zone activity baselines to spot abnormal spikes automatically."

---

### [1:50–2:20] LIVE DEMO
> "Let’s look at the live dashboard. In Act 1, ambient motion occurs, but score stays low—no false alarm. In Act 2, an isolated failed login happens, and Sentinel suppresses it. But now in Act 3, watch what happens when a tripwire camera detection, an off-shift door breach, and a cyber brute-force login spike hit the Server Room simultaneously... Boom! Instant Critical incident INC-8821 with a 100/100 threat score, full XAI explanation, and response recommendations!"

---

### [2:20–2:40] RESULTS
> "In our tested environment, total end-to-end detection latency was under 100 milliseconds—far below our 1.8-second project target. On our 10-scenario controlled evaluation dataset, Sentinel achieved a 100% F1-score with a 70% noise suppression rate while consuming just 108 MB of RAM."

---

### [2:40–3:00] LIMITATIONS & FUTURE WORK
> "While our controlled benchmark results are outstanding, real-world deployments face camera occlusions and sensor degradation. Next, we plan to implement dynamic correlation windows and TensorRT GPU acceleration. Thank you, and we're ready for your questions!"
