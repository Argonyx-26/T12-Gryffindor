# 5-MINUTE PRESENTATION SCRIPT — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**TARGET DURATION**: 5 Minutes (300 Seconds)  

---

### [0:00–0:45] PROBLEM & MOTIVATION
> "Good morning judges and mentors! Today, physical security teams look at camera walls, IoT access teams monitor door keycards, and IT departments monitor server syslog feeds. But real-world security threats don't happen in isolation. An intruder might breach a physical gate, swipe a stolen badge, and launch a cyber brute-force login at the server console all within a few seconds. Separate tools produce mountains of false alarms, causing alarm fatigue. We built **Gryffindor Sentinel** to solve this by fusing VIDEO, IoT, and CYBER streams into a single intelligent situational awareness engine."

---

### [0:45–1:45] SYSTEM ARCHITECTURE & MODALITIES
> "Gryffindor Sentinel connects three event modalities:
> 1. **VIDEO**: Driven by YOLOv8, our computer vision worker processes real-time camera feeds to detect persons, restricted zone entries, tripwire crossings, loitering, and crowds.
> 2. **IOT**: Captures physical access events like door sensor states and keycard swipes.
> 3. **CYBER**: Ingests authentication logs and network syslog events.
> 
> All events stream into a high-performance FastAPI backend. The engine correlates events occurring within a sliding ±1.5-second window in the same zone. To ensure reliability, state is saved to PostgreSQL, while Redis handles sub-millisecond active incident caching and WebSocket Pub/Sub broadcasting."

---

### [1:45–2:45] INTELLIGENCE, SCORING & EXPLAINABILITY
> "How does Sentinel evaluate threat risk?
> First, each modality is weighted: Video at 35%, IoT at 35%, and Cyber at 30%.
> Second, our **Behavioral & Temporal Intelligence Engine** applies exponential recency decay and tracks statistical zone activity baselines. If activity spikes abnormally above moving averages, an anomaly multiplier triggers.
> Third, when events coincide across multiple sources, our corroboration engine applies a multiplier—1.5x for 2 sources and 2.2x for 3 sources.
> Finally, our Explainable AI module generates human-readable narratives, listing specific contributing factors, score breakdowns, interactive timelines, and actionable security recommendations for operators."

---

### [2:45–3:45] LIVE DEMO & THREE-ACT SCENARIO
> "Let’s walk through our live 3-Act demonstration:
> - **Act 1: Normal Baseline**. Ambient motion and routine keycard swipes occur. As you can see on the dashboard, threat scores remain low, demonstrating that Sentinel doesn't alarm on routine traffic.
> - **Act 2: Isolated Noise**. We inject a low-confidence camera detection and a single failed login. Our single-source low-risk filter automatically suppresses escalation, keeping the dashboard clean.
> - **Act 3: Correlated Breach**. Now, we trigger a tripwire camera detection, an off-shift door open, and a cyber login spike simultaneously in the Server Room. Watch the dashboard—an instant Critical alert triggers with a 100/100 score, full XAI evidence, and recommended response steps!"

---

### [3:45–4:30] VERIFIED METRICS & LATENCY PERFORMANCE
> "Let's review our performance data:
> - **Latency**: Our 6-stage pipeline instrumentation measured an average end-to-end detection latency under 100 milliseconds in our tested environment—well below our official 1.8-second target.
> - **Benchmark Accuracy**: On our 10-scenario controlled evaluation dataset, Sentinel achieved a 100% F1-score with a 70% noise suppression rate.
> - **Resource Efficiency**: The engine consumes only 108 MB of RAM and under 5% CPU, making it deployable on edge servers."

---

### [4:30–5:00] LIMITATIONS & FUTURE ROADMAP
> "We want to be transparent about limitations: 100% F1 represents our controlled benchmark, while real-world operational environments present camera occlusions and network jitter. Moving forward, we plan to implement dynamic correlation windows and TensorRT GPU acceleration for 4K video feeds. Thank you for your time!"
