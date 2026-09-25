# Gryffindor Sentinel — Intelligent Threat Detection & Situational Awareness System

[![Phase 3C Production Backend](https://img.shields.io/badge/Phase-3C_Persistent_Backend-blue)](https://github.com/Team-Gryffindor/Sentinel)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)](https://redis.io)

**Gryffindor Sentinel** is an enterprise-grade multi-modal threat detection and situational awareness system designed for high-security physical and cyber perimeters. It fuses real-time CCTV/YOLO vision analytics, IoT physical access sensors, and cyber syslog authentication events into unified, explainable threat alerts.

---

## 🏗️ Architecture & Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          MULTI-MODAL SOURCES                             │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐ │
│  │ Vision Worker /    │  │  IoT Door & Access │  │   Cyber Syslog     │ │
│  │ YOLO Analytics     │  │     Sensors        │  │   Auth Monitors    │ │
│  └─────────┬──────────┘  └─────────┬──────────┘  └─────────┬──────────┘ │
└────────────┼───────────────────────┼───────────────────────┼────────────┘
             │ HTTP POST /ingest     │ HTTP POST /ingest     │ HTTP POST /ingest
             ▼                       ▼                       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI FUSION BACKEND                            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ 1. Schema Validation & Duplicate De-duplication                    │  │
│  │ 2. PostgreSQL Ingestion Persistence (events table)                 │  │
│  │ 3. Spatial & Temporal Correlation Engine (±1.5s Window)            │  │
│  │ 4. Contextual Threat Scoring (Weights + Corroboration Multiplier)  │  │
│  │ 5. Behavioral Anomaly Detection & Burst Rate Analysis             │  │
│  │ 6. Explainable AI (XAI) Factor Extraction & Recommendations        │  │
│  └──────────────────────────────────┬─────────────────────────────────┘  │
└─────────────────────────────────────┼────────────────────────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
┌──────────────────────────────┐              ┌──────────────────────────────┐
│       POSTGRESQL (DB)        │              │       REDIS (CACHE/PUBSUB)   │
├──────────────────────────────┤              ├──────────────────────────────┤
│ - events                     │              │ - active incidents cache     │
│ - incidents                  │              │ - Pub/Sub alert fan-out      │
│ - incident_events (junction) │              │ - Degraded mode if offline   │
│ - behavioral_baselines       │              └──────────────┬───────────────┘
│ - audit_logs                 │                             │
└──────────────────────────────┘                             ▼
                                              ┌──────────────────────────────┐
                                              │      WebSocket Fan-out       │
                                              │         /ws/alerts           │
                                              └──────────────┬───────────────┘
                                                             │
                                                             ▼
                                              ┌──────────────────────────────┐
                                              │    Tactical Dashboard        │
                                              └──────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python**: 3.11+
- **Docker Compose** (Optional for PostgreSQL & Redis)

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Configuration variables:
```env
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/gryffindor
REDIS_URL=redis://localhost:6379/0
EVENT_RETENTION_DAYS=30
INCIDENT_RETENTION_DAYS=90
HUB_URL=http://localhost:8000
ALLOW_SQLITE_FALLBACK=true
```

### 3. Run Database & Redis (Docker)
```bash
docker-compose up -d
```

### 4. Database Migrations (Alembic)
```bash
alembic upgrade head
```

### 5. Launch FastAPI Backend
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

---

## ⚡ 6-Stage Pipeline Latency Model

| Stage | Name | Description | Instrumentation |
|-------|------|-------------|-----------------|
| **Stage 0** | `frame_to_inference_start` | Frame Capture to Neural Network Input | `perf_counter_ns` |
| **Stage 1** | `yolo_inference` | YOLO Bounding Box & Class Inference | `perf_counter_ns` |
| **Stage 2** | `video_event_generation` | Spatial Analytics & Event Synthesis | `perf_counter_ns` |
| **Stage 3** | `network_ingestion` | Transmission Boundary to Backend Arrival | Cross-Process UTC ISO-8601 |
| **Stage 4** | `intelligence_processing` | Spatial/Temporal Correlation & Scoring | `perf_counter_ns` |
| **Stage 5** | `alert_emission` | Alert Serialization & WebSocket Broadcast | `perf_counter_ns` |

---

## 🧪 Verification & Test Suite

Run the full automated verification suite:

```bash
# Phase 3C Persistent Backend Suite (20 tests)
python backend/test_phase3c.py

# Threat Scoring Core Tests
python backend/test_scoring.py

# Multi-Modal Fusion Tests
python backend/test_phase2.py

# Vision Pipeline Tests
python backend/test_phase3a.py

# Behavioral & Temporal Analytics Tests
python backend/test_phase3b.py

# 6-Stage Latency Suite (22 tests)
python backend/test_latency.py

# Three-Act Demo Scenario
python simulators/scenario_runner.py --mock-cctv

# Evaluation Dataset Benchmark
python backend/evaluation_dataset.py
```

---

## 📊 Core API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | System, PostgreSQL, and Redis status |
| `POST` | `/ingest` | Multi-modal event ingestion |
| `GET` | `/events` | Paginated event history & filtering |
| `GET` | `/incidents` | Paginated threat alerts & filtering |
| `PATCH` | `/incidents/{id}/status` | Status updates (acknowledged/resolved) |
| `POST` | `/admin/cleanup` | Retention policy cleanup |
| `GET` | `/metrics` | 6-stage latency & system metrics |
| `WS` | `/ws/alerts` | Live WebSocket alert broadcast |
