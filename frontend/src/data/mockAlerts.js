/**
 * mockAlerts.js
 * 
 * Sample mock data representing real-time security alerts in the Gryffindor system.
 * In a production system, this data would stream in via WebSockets or SSE (Server-Sent Events).
 * 
 * Each alert includes:
 * - incident_id: Unique tracking code for the security incident
 * - zone_id: Specific facility sector or perimeter location
 * - score: Calculated threat probability / severity score (0 to 100)
 * - severity: Categorized priority level ("Critical", "High", "Medium", "Low")
 * - timestamp: ISO / Tactical time string when the trigger was logged
 * - description: Tactical summary of the detected incident
 * - camera_id: Identifier for the corresponding PTZ or fixed surveillance camera
 * - correlated_events: Array of auxiliary sensor hits and access log triggers
 */

export const INITIAL_ALERTS = [
  {
    incident_id: "INC-9042",
    zone_id: "Sector 4 - Perimeter North Fence",
    score: 94,
    severity: "Critical",
    timestamp: "12:08:42 UTC",
    description: "Perimeter intrusion tripwire breached with cutting acoustic signature detected.",
    camera_id: "CAM-PTZ-04B",
    correlated_events: [
      "12:08:14 UTC - Perimeter infrared fence barrier 04-B tripwire broken",
      "12:08:29 UTC - Acoustic sensor detected high-frequency metal shears frequency",
      "12:08:38 UTC - Thermal sensor flagged bi-pedal heat signature (approx. 78 kg)"
    ]
  },
  {
    incident_id: "INC-9043",
    zone_id: "Sector 2 - Server Vault Alpha",
    score: 82,
    severity: "High",
    timestamp: "12:09:15 UTC",
    description: "Biometric authentication repeated failures followed by forced door latch pressure.",
    camera_id: "CAM-INT-201",
    correlated_events: [
      "12:08:50 UTC - 3 consecutive biometric fingerprint scan rejections on Door V-2",
      "12:09:02 UTC - Proximity sensor triggered inside airlock vestibule without clearance badge",
      "12:09:11 UTC - Electronic strike plate latch under high magnetic tamper tension"
    ]
  },
  {
    incident_id: "INC-9044",
    zone_id: "Sector 7 - Hangar Loading Bay B",
    score: 65,
    severity: "Medium",
    timestamp: "12:09:58 UTC",
    description: "Unscheduled cargo transport vehicle parked in restricted loading corridor.",
    camera_id: "CAM-EXT-704",
    correlated_events: [
      "12:09:20 UTC - Automated license plate scanner flagged unlisted commercial plate (XZ-889)",
      "12:09:44 UTC - Vehicle stationary beyond 180s threshold in red loading zone"
    ]
  },
  {
    incident_id: "INC-9045",
    zone_id: "Sector 1 - Admin Lobby & Atrium",
    score: 38,
    severity: "Low",
    timestamp: "12:11:02 UTC",
    description: "Turnstile badge tailgating anomaly detected during employee shift change.",
    camera_id: "CAM-LOB-102",
    correlated_events: [
      "12:10:45 UTC - Optical turnstile passage detected 2 distinct bodies on 1 NFC tap",
      "12:10:52 UTC - Visitor registration desk alert: No secondary guest pass matched"
    ]
  }
];
