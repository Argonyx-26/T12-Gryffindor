/**
 * mockAlerts.js
 * 
 * Sample mock data representing real-time security alerts in the Gryffindor Sentinel system.
 * Used for offline testing, UI validation, and demonstration modes.
 */

export const INITIAL_ALERTS = [
  {
    incident_id: "INC-9E3FFC19",
    zone_id: "Perimeter_Gate_3",
    score: 100,
    severity: "Critical",
    timestamp: "05:22:17 UTC",
    status: "dispatched",
    sources: ["CYBER", "IOT", "VIDEO"],
    camera_id: "CAM-GATE-03-EXT",
    description: "Corroborated multi-vector detection across: CYBER, IOT, VIDEO",
    events: [
      {
        event_id: "evt-vid-9e3f-01",
        timestamp: "2026-09-26T05:22:15.102Z",
        source_type: "VIDEO",
        zone_id: "Perimeter_Gate_3",
        event_type: "person_detected",
        confidence: 0.96,
        raw_meta: {
          camera_id: "CAM-GATE-03-EXT",
          bbox: [120, 45, 340, 510]
        }
      },
      {
        event_id: "evt-iot-9e3f-02",
        timestamp: "2026-09-26T05:22:16.220Z",
        source_type: "IOT",
        zone_id: "Perimeter_Gate_3",
        event_type: "door_open",
        confidence: 1.0,
        raw_meta: {
          sensor_id: "iot-reed-03",
          tamper_detected: true
        }
      },
      {
        event_id: "evt-cyb-9e3f-03",
        timestamp: "2026-09-26T05:22:17.004Z",
        source_type: "CYBER",
        zone_id: "Perimeter_Gate_3",
        event_type: "brute_force_auth",
        confidence: 0.99,
        raw_meta: {
          service: "ssh",
          attempts: 24,
          ip: "192.168.1.188"
        }
      }
    ],
    correlated_events: [
      "05:22:15 UTC - Optical tripwire breached by human profile (CAM-GATE-03-EXT)",
      "05:22:16 UTC - High magnetic tension alert on Perimeter Gate 3 latch",
      "05:22:17 UTC - Rapid cyber SSH authentication burst from unauthorized internal IP"
    ]
  },
  {
    incident_id: "INC-FB524C03",
    zone_id: "Perimeter_Gate_3",
    score: 100,
    severity: "Critical",
    timestamp: "05:22:02 UTC",
    status: "dispatched",
    sources: ["IOT", "VIDEO"],
    camera_id: "CAM-PERIMETER-04",
    description: "Corroborated multi-vector detection across: IOT, VIDEO",
    events: [
      {
        event_id: "evt-vid-fb52-01",
        timestamp: "2026-09-26T05:22:01.442Z",
        source_type: "VIDEO",
        zone_id: "Perimeter_Gate_3",
        event_type: "person_detected",
        confidence: 0.94,
        raw_meta: {
          camera_id: "CAM-PERIMETER-04",
          bbox: [180, 60, 360, 480]
        }
      },
      {
        event_id: "evt-iot-fb52-02",
        timestamp: "2026-09-26T05:22:02.100Z",
        source_type: "IOT",
        zone_id: "Perimeter_Gate_3",
        event_type: "motion_detected",
        confidence: 0.98,
        raw_meta: {
          sensor_id: "pir-gate-03"
        }
      }
    ],
    correlated_events: [
      "05:22:01 UTC - Optical surveillance detected unauthorized intruder (BBox: [180, 60, 360, 480])",
      "05:22:02 UTC - Motion sensor verified secondary physical vibration at barrier"
    ]
  },
  {
    incident_id: "INC-91A575A2",
    zone_id: "Server_Room",
    score: 85,
    severity: "High",
    timestamp: "05:22:13 UTC",
    status: "open",
    sources: ["CYBER", "IOT"],
    camera_id: "CAM-SRV-201",
    description: "Corroborated multi-vector detection across: CYBER, IOT",
    events: [
      {
        event_id: "evt-cyb-91a5-01",
        timestamp: "2026-09-26T05:22:10.050Z",
        source_type: "CYBER",
        zone_id: "Server_Room",
        event_type: "login_failed_multiple",
        confidence: 0.92,
        raw_meta: {
          account: "root",
          count: 7
        }
      },
      {
        event_id: "evt-iot-91a5-02",
        timestamp: "2026-09-26T05:22:13.120Z",
        source_type: "IOT",
        zone_id: "Server_Room",
        event_type: "door_open",
        confidence: 1.0,
        raw_meta: {
          badge_scanned: false
        }
      }
    ],
    correlated_events: [
      "05:22:10 UTC - Consecutive failed privileged credentials on Server Vault gateway",
      "05:22:13 UTC - Server Room physical portal unsealed without badge clearance"
    ]
  }
];
