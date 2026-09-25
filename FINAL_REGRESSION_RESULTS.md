# FINAL REGRESSION RESULTS — GRYFFINDOR SENTINEL

**PROJECT**: Gryffindor Sentinel / ARGONYX '26  
**TEAM**: Gryffindor  
**EVALUATION DATE**: September 26, 2026  
**STATUS**: ✅ 100% REGRESSION PASSED (ALL 8 TEST SUITES & SCENARIOS VERIFIED)  

---

## Complete Test Suite Regression Matrix

| Test Suite File | Tested Functional Layer | Total Tests | Passed | Failed | Execution Time | Notes / Coverage |
|-----------------|-------------------------|-------------|--------|--------|----------------|------------------|
| `backend/test_scoring.py` | Contextual Threat Scoring Engine | 3 | **3** | 0 | ~0.07s | Modal weights, corroboration, severity thresholds |
| `backend/test_phase2.py` | Incident Lifecycle & XAI Engine | 18 | **18** | 0 | ~0.31s | Recommendations, timeline, deduplication, XAI |
| `backend/test_phase3a.py` | Real-time YOLO CCTV Pipeline | 18 | **18** | 0 | ~0.54s | Restricted zones, tripwire, loitering, crowd |
| `backend/test_phase3b.py` | Temporal & Behavioral Intelligence | 18 | **18** | 0 | ~0.51s | Burst detection, zone baselines, recency decay |
| `backend/test_latency.py` | 6-Stage Granular Pipeline Latency | 22 | **22** | 0 | ~0.44s | Same-process monotonic & cross-process UTC timing |
| `backend/test_phase3c.py` | Persistent PostgreSQL & Redis Backend | 20 | **20** | 0 | ~0.85s | SQLAlchemy ORM, restart recovery, Redis Pub/Sub |
| `backend/test_phase3d.py` | Final Integration, Hardening & Load Harness | 23 | **23** | 0 | ~1.85s | Trace ID, failure resilience, load test, retention |
| `simulators/scenario_runner.py` | Three-Act Live CCTV Demo Scenario | 3 Acts | **3 Acts** | 0 | ~22.1s | Act 1 Baseline, Act 2 Noise, Act 3 Breach |
| `backend/evaluation_dataset.py` | Controlled Benchmark Suite | 10 Scenarios | **10** | 0 | ~0.72s | **100% F1-score**, **70% Noise Suppression** |
| **TOTAL SYSTEM AGGREGATE** | **Complete Full Stack Security Backend** | **122 Tests** | **122** | **0** | **~26.89s** | **Zero Regressions** |

---

## Specific System Capability Verification Summary

| Subsystem Capability | Test Method | Verified Result | Notes |
|----------------------|-------------|-----------------|-------|
| **Mock CCTV Input** | `scenario_runner.py --mock-cctv` | **VERIFIED** | Generates synthetic CCTV bounding box events |
| **Three-Act Demo** | `scenario_runner.py` | **VERIFIED** | Act 1 Baseline -> Act 2 Noise -> Act 3 Critical Corroboration |
| **Evaluation Dataset** | `backend/evaluation_dataset.py` | **VERIFIED** | 100-sample dataset, 10 scenarios (A through J) |
| **REST APIs** | `/`, `/metrics`, `/zones`, `/events`, `/incidents` | **VERIFIED** | Paginated filtering & schema compliance |
| **WebSocket Stream** | `/ws/alerts` | **VERIFIED** | Real-time incident fan-out broadcaster |
| **Database Persistence** | PostgreSQL ORM / SQLite Fallback | **VERIFIED** | Relational junction state reload on restart |
| **Redis Resilience** | `SentinelRedisClient` | **VERIFIED** | Automatic degraded in-memory fallback on Redis outage |
| **Duplicate Event Idempotency**| `POST /ingest` duplicate ID | **VERIFIED** | Returns HTTP 409 Conflict |
| **Replay Behavior** | Replay runner with new UUIDs | **VERIFIED** | Ingests fresh UUIDs safely without collision |
