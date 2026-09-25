# TECHNICAL ARCHITECTURE & DATA FLOW — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**SYSTEM**: Multimodal Threat Detection & Situational Awareness Backend  

---

## 1. End-to-End System Data Flow Diagram

```
 ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
 │   CAMERA / VISION    │   │     IoT SENSORS      │   │    SYSLOG / CYBER    │
 │ (YOLOv8 Detection)   │   │ (Access/Door Sensors)│   │ (Auth/Network Logs)  │
 └──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘
            │ VIDEO Event              │ IOT Event                │ CYBER Event
            └──────────────────────────┼──────────────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │    FastAPI Ingestion Boundary    │
                     │  (/ingest + Schema Validation)    │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │     Temporal Engine (Recency)     │
                     │  & Behavioral Intelligence Engine │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Multi-Source Correlation Engine   │
                     │ (±1.5-Second Sliding Window)      │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Context-Aware Threat Scoring Core │
                     │ (Weights, Corroboration, XAI)     │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │   Incident Lifecycle Manager      │
                     │  (Synthesis, Timeline, Deduplication) │
                     └─────────┬───────────────────────┬─┘
                               │                       │
                               ▼                       ▼
                     ┌──────────────────┐    ┌──────────────────┐
                     │   PostgreSQL DB  │    │ Redis Pub/Sub &  │
                     │ (Authoritative)  │    │ Active State Cache│
                     └──────────────────┘    └─────────┬────────┘
                                                       │
                                                       ▼
                                             ┌──────────────────┐
                                             │ WebSocket Stream │
                                             │  (/ws/alerts)    │
                                             └─────────┬────────┘
                                                       │
                                                       ▼
                                             ┌──────────────────┐
                                             │ React Dashboard  │
                                             └──────────────────┘
```

---

## 2. Component Breakdown & Responsibilities

1. **YOLO Vision Engine (`ai/vision_worker.py`)**: Real-time object detection (persons, vehicles) with polygon restricted zones, tripwires, loitering detection, and crowd counting. Emits structured VIDEO JSON events.
2. **FastAPI Ingestion Boundary (`backend/main.py`)**: Accepts POST `/ingest` HTTP requests, validates JSON schema, checks duplicate event IDs (409 Conflict), attaches ingestion timestamps (`ingest_ns`), and propagates distributed trace IDs (`trc-...`).
3. **Temporal & Behavioral Intelligence Engine (`backend/temporal_engine.py`)**:
   - Calculates exponential time-decay for event recency.
   - Maintains statistical moving baselines per zone ($\mu$ and $\sigma$) to compute Z-score anomaly multipliers.
   - Detects rapid event bursts and sequence anomalies.
4. **Multi-Source Correlation Engine (`backend/main.py`)**: Groups incoming events occurring within a sliding **±1.5-second correlation window** in the same physical zone.
5. **Context-Aware Threat Scoring Core (`backend/scoring_engine.py`)**:
   - Applies modality weights: `VIDEO=0.35`, `IOT=0.35`, `CYBER=0.30`.
   - Applies corroboration multipliers: `1 source = 1.0x`, `2 sources = 1.5x`, `3 sources = 2.2x`.
   - Evaluates contextual factors: off-shift hours (1.3x), restricted zone (1.4x), repeated events (1.1x per repeat, max 1.5x).
   - Generates Explainable AI (XAI) narratives and recommended response actions.
6. **Incident Lifecycle Manager (`backend/main.py`)**: Synthesizes correlated events into unified incidents (`INC-XXXXX`), manages statuses (`DETECTED`, `CORRELATED`, `SCORED`, `dispatched`, `open`), and updates chronological timelines.
7. **PostgreSQL Relational Database (`backend/database.py` & `backend/db_models.py`)**: Authoritative persistent store for events, incidents, junction records (`incident_events`), behavioral baselines, and audit logs.
8. **Redis Cache & Pub/Sub (`backend/redis_client.py`)**: Low-latency active incident cache and real-time Pub/Sub fan-out layer for WebSockets.
9. **WebSocket Stream & React Dashboard (`frontend/`)**: Real-time visual monitoring dashboard with live metrics, interactive maps, incident detail modals, and sound alerts.

---

## 3. Key Design Justifications & Architectural Rationale

### Why Multimodal Input is Useful
Single-modality security systems suffer high false alarm rates (e.g., a CCTV camera triggered by shadows, or an IoT door sensor triggered by maintenance). Combining VIDEO, IoT, and CYBER modalities ensures that genuine multi-vector physical/digital breaches are corroborated before dispatching emergency teams.

### Why Correlation is Required
Attacks often manifest across separate systems simultaneously (e.g., a cyber brute-force login attempt paired with an unauthorized physical door badge swipe and camera detection). Correlation connects these isolated signals into a unified threat picture.

### Why Temporal & Behavioral Intelligence is Required
A door opening at 2:00 PM on a Tuesday is routine; the same door opening at 2:00 AM on a Sunday during a cyber login burst is highly anomalous. Temporal decay and zone-based statistical baselines allow the system to evaluate context rather than static rule thresholds.

### Why Persistence is Required
System restarts or power outages must not lose active security state, audit trails, or historical baselines. PostgreSQL ensures that state is fully recovered upon backend reboot.

### Why Redis is Used
Redis provides sub-millisecond lookups for active incidents and enables seamless horizontal Pub/Sub scaling across multiple WebSocket broadcaster nodes.

### What Happens if Redis Fails
`SentinelRedisClient` detects connection failure and gracefully switches to an in-memory dictionary cache. The backend continues operating without interruption.

### What Happens if PostgreSQL Fails
If PostgreSQL becomes unreachable, the database layer falls back to SQLite (`gryffindor.db`) if configured, or returns clean HTTP service error responses without corrupting state.

### How Duplicate Events are Handled
Each event carries a unique `event_id`. Re-submitting an existing ID returns HTTP 409 Conflict. Replaying demo scenarios uses fresh UUIDs.

### How `trace_id` is Propagated
Every camera frame or ingestion payload includes a `trace_id` (`trc-...`). This ID is preserved through FastAPI ingestion, saved to PostgreSQL `events` and `incidents` records, included in WebSocket messages, and returned in REST query endpoints.
