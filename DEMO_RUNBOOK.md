# LIVE DEMO RUNBOOK — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**OBJECTIVE**: Step-by-Step Operator & Presenter Guide for Live Mentor & Judge Demonstrations  

---

## 1. System Launch & Startup Sequence

Run the commands in separate terminal windows from the repository root (`c:\Users\PRAGNA PAYAL SAHU\OneDrive\Desktop\Argonyx_Gryfffindor\Team-2`):

```powershell
# Terminal 1: Launch Production FastAPI Backend Server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Launch Tactical React Dashboard (Frontend)
cd frontend
npm run dev

# Terminal 3: Launch Vision Worker (Optional - Real Webcam / Video file)
python ai/vision_worker.py --source 0 --show-video

# Terminal 4: Demo Scenario Runner (For Automated 3-Act Demo)
python simulators/scenario_runner.py --mock-cctv
```

---

## 2. Three-Act Demonstration Flow

### ACT 1 — NORMAL BASELINE (Ambient Operational Traffic)

**Action**: Presenter initiates Act 1 or launches scenario runner. Ambient motion, authorized keycard swipes, and routine logins occur.

**System Behavior**:
- Raw events appear in live stream.
- Threat score remains low (< 40).
- No alerts dispatched to dashboard.
- Temporal engine updates ambient activity baselines.

**Presenter Explanation to Judges**:
> *"Notice how ambient events are ingested in real time. The system establishes normal operational baselines per zone. Crucially, the system does NOT treat every routine event as a security incident."*

---

### ACT 2 — ISOLATED NOISE (False-Positive Protection)

**Action**: Ingest isolated weak signals (e.g., stray CCTV detection with `confidence=0.42`, in-shift door opening, single failed login).

**System Behavior**:
- Single-source low-risk events are evaluated.
- Threat score evaluated at < 40 (Low Severity).
- Single-source Low severity filter suppresses escalation.
- Incident count on dashboard remains **0**.

**Presenter Explanation to Judges**:
> *"Here we inject isolated noise—a low-confidence motion detection and a single failed login attempt. A conventional system might flood operators with false alarms. Gryffindor Sentinel suppresses isolated low-risk noise to protect operator bandwidth."*

---

### ACT 3 — CORRELATED THREAT (Multi-Vector Breach)

**Action**: Trigger multi-source events in `Server_Room` within the ±1.5-second correlation window:
1. `VIDEO`: Restricted zone tripwire intrusion (`confidence=0.95`).
2. `IOT`: Off-shift physical door breach (`confidence=0.98`).
3. `CYBER`: Authentication brute-force login spike (`confidence=0.90`).

**Observed System Output**:
- **Corroborated Critical Incident Created**: `INC-XXXXX`
- **Calculated Threat Score**: **100.0 / 100** (Critical)
- **Sources Corroborated**: `['CYBER', 'IOT', 'VIDEO']` (2.2× Corroboration Multiplier)
- **Dashboard Action**: Instantly pops up alert card via WebSocket stream with Explainable AI narrative, contributing factors, timeline, and response recommendations.

**Presenter Explanation to Judges**:
> *"When VIDEO, IoT, and CYBER events coincide within our 1.5-second window in the Server Room, multi-source correlation activates. The corroboration multiplier scales the score to 100, creating a Critical incident with full XAI explanations and recommended responses."*

---

## 3. Demo Failure Recovery Procedures

| Issue / Failure | Symptom | Exact Recovery Command | Explanation to Judges |
|-----------------|---------|------------------------|-----------------------|
| **Backend Crashed** | Dashboard shows "Disconnected" | `python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000` | *"Restarting service; persistent state will reload automatically from PostgreSQL."* |
| **Frontend WS Lost** | Dashboard alerts stop updating | Hard refresh page (`Ctrl + Shift + R`) or check `VITE_WS_URL`. | *"Re-connecting browser WebSocket client."* |
| **Redis Service Offline** | Red warning in backend log | No action needed. System auto-falls back to in-memory mode. | *"Redis is offline; system seamlessly degrades to active in-memory caching."* |
| **PostgreSQL DB Offline** | Database warning log | System falls back to SQLite (`gryffindor.db`). | *"Database auto-fallback active; state safety preserved."* |
| **Physical Camera Fails** | Camera window closes or drops | `python simulators/scenario_runner.py --mock-cctv` | *"Switching to high-fidelity mock CCTV stream."* |
| **Event Replay Conflict** | HTTP 409 returned | Use scenario runner which generates fresh UUIDs per replay. | *"Idempotency prevented duplicate event ingestion; generating fresh event ID."* |
