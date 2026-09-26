# Gryffindor Sentinel — Integrated System Documentation

## 1. Executive Summary

**Gryffindor Sentinel** has achieved full-stack integration, uniting the multi-modal threat correlation engine (CCTV/YOLO Vision, IoT Sensors, Cyber System Logs) with a live React tactical command center featuring an interactive **Leaflet Tactical Geospatial Map**.

The system dynamically ingests physical and logical events, determines deterministic primary geospatial locations for synthesized incidents, streams live alerts over WebSockets, and provides bi-directional map-dashboard synchronization.

---

## 2. Integrated System Architecture

```
[ CCTV Camera / YOLOv8 ]  ──►  HTTP POST /ingest ──┐
[ IoT Sensor Network   ]  ──►  HTTP POST /ingest ──┼─► [ FastAPI Correlation Hub ]
[ Cyber Syslog Stream  ]  ──►  HTTP POST /ingest ──┘           │
                                                                 ├──► [ Location Engine ]
                                                                 ├──► [ Scoring Engine ]
                                                                 ├──► [ PostgreSQL / Redis ]
                                                                 │
                                                               WebSocket Stream (/ws/alerts)
                                                                 │
                                                                 ▼
                                                  [ React Tactical Dashboard ]
                                                    ├── Live Alert Feed
                                                    ├── Evidence Drawer (XAI)
                                                    └── Leaflet Tactical Map (Bi-directional)
```

---

## 3. Location Engine & Deterministic Resolution

Location resolution is managed centrally by `backend/location_config.py`.

### Location Resolution Hierarchy
1. **Event Location (`get_event_location`)**:
   - **Physical Events (VIDEO / IOT)**: Resolves coordinates via camera/sensor lookup in catalog or zone centroid. Marked as `location_type = "physical"`.
   - **Logical Events (CYBER)**: Resolves host/system node to zone centroid. Marked as `location_type = "logical"`.

2. **Incident Primary Location (`get_incident_primary_location`)**:
   - Evaluates all correlated events contributing to an incident.
   - Selects the highest confidence physical event as the primary pinpoint.
   - Aggregate lists of contributing cameras (`contributing_cameras`), IoT sensors (`contributing_iot`), and cyber nodes (`contributing_cyber`).

---

## 4. API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/locations` | GET | Returns full catalog of site bounds, zone geometries, cameras, sensors, and cyber nodes. |
| `/ingest` / `/events` | POST | Multi-modal event ingestion endpoint. Enriches events with location metadata. |
| `/metrics` | GET | Comprehensive system health, suppression rates, and 6-stage latency breakdown. |
| `/incidents` | GET | Retrieves list of synthesized multi-vector incidents with location metadata. |
| `/ws/alerts` | WS | Real-time bi-directional alert broadcast bus. |

---

## 5. Map-Dashboard Bi-directional Synchronization

1. **Map Pin -> Dashboard Evidence Drawer**:
   - Clicking an incident pin on the Leaflet map triggers `onSelectIncident(incident)`.
   - Automatically opens the `EvidenceDrawer` displaying score breakdown, XAI explanations, contributing factors, recommendations, and interactive timeline.

2. **Dashboard Feed -> Map Auto-Center**:
   - Selecting an alert card in the `LiveAlertFeed` or `EvidenceDrawer` triggers `map.flyTo([lat, lng], 17)`.
   - The tactical map smoothly animates to the primary incident location and pops up detailed incident telemetry.

---

## 6. Regression & Verification Suite

The system has passed 150/150 automated regression and integration tests:

| Suite | Tests | Result |
| :--- | :---: | :---: |
| `test_scoring.py` | 3 | PASS |
| `test_phase2.py` | 18 | PASS |
| `test_phase3a.py` | 18 | PASS |
| `test_phase3b.py` | 18 | PASS |
| `test_latency.py` | 22 | PASS |
| `test_phase3c.py` | 22 | PASS |
| `test_phase3d.py` | 43 | PASS |
| `test_integrated_system.py` | 6 | PASS |
| **TOTAL** | **150** | **100% PASS** |
