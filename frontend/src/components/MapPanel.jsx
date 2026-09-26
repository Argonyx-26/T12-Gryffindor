import React, { useState, useEffect, useMemo } from 'react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import { Map as MapIcon, Compass, ShieldAlert, CheckCircle2, RotateCcw } from 'lucide-react';

/**
 * Controller component that handles programmatic pan/zoom (flyTo)
 * when a user clicks an alert card in the Live Alert Feed.
 */
function MapController({ selectedAlert, zonesMap, defaultCenter }) {
  const map = useMap();

  useEffect(() => {
    if (!selectedAlert) return;

    const zone = zonesMap[selectedAlert.zone_id];
    const lat = Array.isArray(selectedAlert.coordinates) && selectedAlert.coordinates.length >= 2
      ? Number(selectedAlert.coordinates[0])
      : (zone ? Number(zone.latitude) : null);

    const lng = Array.isArray(selectedAlert.coordinates) && selectedAlert.coordinates.length >= 2
      ? Number(selectedAlert.coordinates[1])
      : (zone ? Number(zone.longitude) : null);

    if (lat != null && lng != null && !isNaN(lat) && !isNaN(lng)) {
      map.flyTo([lat, lng], 18, {
        duration: 1.2,
        easeLinearity: 0.25,
      });
    }
  }, [selectedAlert, zonesMap, map]);

  return null;
}

/**
 * Reset view helper button inside the map controls
 */
function MapResetButton({ defaultCenter, defaultZoom }) {
  const map = useMap();
  return (
    <button
      type="button"
      onClick={() => map.flyTo(defaultCenter, defaultZoom, { duration: 1 })}
      title="Reset View to Campus Center"
      className="bg-slate-950/90 hover:bg-slate-800 text-slate-300 hover:text-white p-2 rounded border border-slate-700 shadow-lg cursor-pointer transition-colors"
    >
      <RotateCcw className="w-4 h-4" />
    </button>
  );
}

// -----------------------------------------------------------------------------
// Leaflet Custom Markers using L.divIcon
// -----------------------------------------------------------------------------

// 1. Camera Marker (📷 emoji icon)
const createCameraIcon = () =>
  L.divIcon({
    className: 'custom-leaflet-marker',
    html: `
      <div style="
        display: flex;
        align-items: center;
        justify-content: center;
        width: 30px;
        height: 30px;
        background: rgba(15, 23, 42, 0.95);
        border: 2px solid #38bdf8;
        border-radius: 8px;
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.55);
        font-size: 15px;
        cursor: pointer;
        user-select: none;
      ">
        📷
      </div>
    `,
    iconSize: [30, 30],
    iconAnchor: [15, 15],
    popupAnchor: [0, -18],
  });

// 2. IoT Sensor Marker (small blue circle)
const createIotIcon = () =>
  L.divIcon({
    className: 'custom-leaflet-marker',
    html: `
      <div style="
        display: flex;
        align-items: center;
        justify-content: center;
        width: 22px;
        height: 22px;
        background: rgba(15, 23, 42, 0.95);
        border: 2px solid #3b82f6;
        border-radius: 50%;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.6);
        cursor: pointer;
        user-select: none;
      ">
        <div style="
          width: 8px;
          height: 8px;
          background: #3b82f6;
          border-radius: 50%;
        "></div>
      </div>
    `,
    iconSize: [22, 22],
    iconAnchor: [11, 11],
    popupAnchor: [0, -14],
  });

// 3. Cyber Node Marker (⚡ emoji icon)
const createCyberIcon = () =>
  L.divIcon({
    className: 'custom-leaflet-marker',
    html: `
      <div style="
        display: flex;
        align-items: center;
        justify-content: center;
        width: 30px;
        height: 30px;
        background: rgba(15, 23, 42, 0.95);
        border: 2px solid #c084fc;
        border-radius: 8px;
        box-shadow: 0 0 10px rgba(192, 132, 252, 0.55);
        font-size: 15px;
        cursor: pointer;
        user-select: none;
      ">
        ⚡
      </div>
    `,
    iconSize: [30, 30],
    iconAnchor: [15, 15],
    popupAnchor: [0, -18],
  });

// 4. Incident Marker (Pulsing, colored by severity: red=Critical, orange=High, yellow=Medium, green=Low)
const createIncidentIcon = (incident, isSelected) => {
  const isResolved = incident.status === 'false_positive' || incident.status === 'resolved';
  const sev = incident.severity || 'Medium';

  const color =
    sev === 'Critical' ? '#ef4444' :
    sev === 'High' ? '#f97316' :
    sev === 'Medium' ? '#eab308' :
    '#22c55e';

  const pulseStyle = !isResolved ? `
    <div style="
      position: absolute;
      inset: -8px;
      border-radius: 50%;
      background: ${color};
      opacity: 0.45;
      animation: leaflet-pulse 1.6s cubic-bezier(0, 0, 0.2, 1) infinite;
      pointer-events: none;
    "></div>
  ` : '';

  const reticleStyle = isSelected ? `
    <div style="
      position: absolute;
      inset: -12px;
      border-radius: 50%;
      border: 2px dashed #06b6d4;
      animation: leaflet-spin 8s linear infinite;
      pointer-events: none;
    "></div>
  ` : '';

  return L.divIcon({
    className: 'custom-leaflet-marker',
    html: `
      <div style="
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        background: #020617;
        border: 2.5px solid ${color};
        border-radius: 50%;
        box-shadow: ${isResolved ? 'none' : `0 0 18px ${color}`};
        opacity: ${isResolved ? 0.35 : 1};
        filter: ${isResolved ? 'grayscale(1)' : 'none'};
        cursor: pointer;
        user-select: none;
      ">
        ${pulseStyle}
        ${reticleStyle}
        <span style="font-size: 16px; line-height: 1; z-index: 2;">${isResolved ? '✓' : '⚠️'}</span>
        <span style="
          position: absolute;
          top: -6px;
          right: -6px;
          background: ${color};
          color: ${sev === 'Critical' ? '#ffffff' : '#020617'};
          font-family: monospace;
          font-size: 9px;
          font-weight: 800;
          padding: 1px 4px;
          border-radius: 9999px;
          border: 1px solid rgba(0,0,0,0.4);
          z-index: 3;
        ">${incident.score ?? ''}</span>
      </div>
    `,
    iconSize: [36, 36],
    iconAnchor: [18, 18],
    popupAnchor: [0, -22],
  });
};

/**
 * Main MapPanel Component
 */
export default function MapPanel({
  alerts = [],
  selectedAlert = null,
  onSelectAlert = () => {},
  apiUrl = 'http://localhost:8000',
}) {
  const [zones, setZones] = useState([]);
  const [nodes, setNodes] = useState([]);

  // Fetch real locations/zones from backend GET /locations (fallback: GET /zones)
  useEffect(() => {
    let isSubscribed = true;

    async function loadData() {
      const baseUrl = (apiUrl || 'http://localhost:8000').replace(/\/+$/, '');
      let loadedZones = [];
      let loadedNodes = [];

      // Attempt 1: GET /locations
      try {
        const locRes = await fetch(`${baseUrl}/locations`);
        if (locRes.ok) {
          const locData = await locRes.json();
          if (Array.isArray(locData) && locData.length > 0) {
            loadedNodes = locData.map((loc) => {
              const typeStr = String(loc.type || loc.source_type || '').toLowerCase();
              let type = 'iot';
              if (typeStr.includes('cam') || typeStr.includes('video') || String(loc.id).toLowerCase().includes('cam')) {
                type = 'camera';
              } else if (typeStr.includes('cyber') || typeStr.includes('net') || String(loc.id).toLowerCase().includes('cyber')) {
                type = 'cyber';
              }
              const lat = Number(loc.latitude ?? loc.lat ?? (Array.isArray(loc.coordinates) ? loc.coordinates[0] : 0));
              const lng = Number(loc.longitude ?? loc.lng ?? (Array.isArray(loc.coordinates) ? loc.coordinates[1] : 0));
              return {
                id: loc.id || `NODE-${Math.random().toString(36).slice(2, 6)}`,
                name: loc.name || `${type.toUpperCase()} Node`,
                type,
                lat,
                lng,
                zone_id: loc.zone_id || loc.zone,
              };
            });
          }
        }
      } catch {
        // Fallback to /zones
      }

      // Attempt 2: GET /zones
      try {
        const zoneRes = await fetch(`${baseUrl}/zones`);
        if (zoneRes.ok) {
          const zoneData = await zoneRes.json();
          if (Array.isArray(zoneData) && zoneData.length > 0) {
            loadedZones = zoneData;
          }
        }
      } catch (err) {
        console.warn('[MapPanel] Failed to fetch /zones:', err);
      }

      // Default Stanford campus zones fallback if offline or backend empty
      if (loadedZones.length === 0) {
        loadedZones = [
          { id: 'Server_Room', name: 'Central Server & Data Facility', latitude: 37.4282, longitude: -122.1688, zone_weight: 1.5 },
          { id: 'Perimeter_Gate_3', name: 'North Campus Perimeter Gate 3', latitude: 37.4320, longitude: -122.1745, zone_weight: 1.3 },
          { id: 'Parking_Lot', name: 'East Campus Visitor Parking Lot', latitude: 37.4255, longitude: -122.1620, zone_weight: 0.8 },
        ];
      }

      // If /locations did not supply nodes, build real infrastructure nodes from zones
      if (loadedNodes.length === 0) {
        loadedNodes = loadedZones.flatMap((z) => {
          const lat = Number(z.latitude);
          const lng = Number(z.longitude);
          const zId = z.id;

          if (zId === 'Perimeter_Gate_3') {
            return [
              { id: 'CAM-GATE-03', name: 'CCTV PTZ Gate 3', type: 'camera', lat, lng, zone_id: zId },
              { id: 'IOT-GATE-03', name: 'IoT Magnetic Gate Sensor', type: 'iot', lat: lat + 0.0003, lng: lng + 0.0004, zone_id: zId },
              { id: 'CYBER-GATE-03', name: 'Gate Access Badge Node', type: 'cyber', lat: lat - 0.0003, lng: lng + 0.0004, zone_id: zId },
            ];
          } else if (zId === 'Server_Room') {
            return [
              { id: 'CYBER-SRV-01', name: 'Server Auth Gateway & Firewall', type: 'cyber', lat, lng, zone_id: zId },
              { id: 'IOT-SRV-01', name: 'Vault PIR / Door Sensor', type: 'iot', lat: lat + 0.0003, lng: lng - 0.0004, zone_id: zId },
              { id: 'CAM-SRV-01', name: 'CCTV Dome (Data Vault)', type: 'camera', lat: lat - 0.0003, lng: lng - 0.0004, zone_id: zId },
            ];
          } else if (zId === 'Parking_Lot') {
            return [
              { id: 'CAM-PARK-01', name: 'Panoramic CCTV East Lot', type: 'camera', lat, lng, zone_id: zId },
              { id: 'IOT-PARK-01', name: 'Barrier Induction Loop', type: 'iot', lat: lat - 0.0003, lng: lng + 0.0004, zone_id: zId },
              { id: 'CYBER-PARK-01', name: 'Exterior Mesh Wi-Fi AP', type: 'cyber', lat: lat + 0.0003, lng: lng - 0.0004, zone_id: zId },
            ];
          }

          return [
            { id: `CAM-${zId}`, name: `${z.name || zId} Camera`, type: 'camera', lat, lng, zone_id: zId },
            { id: `IOT-${zId}`, name: `${z.name || zId} IoT Sensor`, type: 'iot', lat: lat + 0.0003, lng: lng + 0.0003, zone_id: zId },
            { id: `CYBER-${zId}`, name: `${z.name || zId} Cyber Node`, type: 'cyber', lat: lat - 0.0003, lng: lng - 0.0003, zone_id: zId },
          ];
        });
      }

      if (isSubscribed) {
        setZones(loadedZones);
        setNodes(loadedNodes);
      }
    }

    loadData();
    return () => {
      isSubscribed = false;
    };
  }, [apiUrl]);

  // Lookup map for fast zone coordinates retrieval
  const zonesMap = useMemo(() => {
    const map = {};
    zones.forEach((z) => {
      map[z.id] = z;
    });
    return map;
  }, [zones]);

  // Requirement 3: Center on average of all zone coordinates (default zoom 17)
  const defaultCenter = useMemo(() => {
    if (zones.length === 0) return [37.4286, -122.1684];
    const avgLat = zones.reduce((sum, z) => sum + Number(z.latitude), 0) / zones.length;
    const avgLng = zones.reduce((sum, z) => sum + Number(z.longitude), 0) / zones.length;
    return [avgLat, avgLng];
  }, [zones]);

  // Prepared incident markers from WebSocket alerts
  const incidentMarkers = useMemo(() => {
    return alerts.map((incident, idx) => {
      const zone = zonesMap[incident.zone_id];
      const lat = Array.isArray(incident.coordinates) && incident.coordinates.length >= 2
        ? Number(incident.coordinates[0])
        : (zone ? Number(zone.latitude) : 37.428);

      const lng = Array.isArray(incident.coordinates) && incident.coordinates.length >= 2
        ? Number(incident.coordinates[1])
        : (zone ? Number(zone.longitude) : -122.168);

      const isResolved = incident.status === 'false_positive' || incident.status === 'resolved';

      // Slight radial scatter if multiple incidents coincide at the exact same location
      const angle = (idx * 1.25) % (Math.PI * 2);
      const scatterOffset = idx > 0 ? 0.00025 : 0;

      return {
        ...incident,
        lat: lat + Math.cos(angle) * scatterOffset,
        lng: lng + Math.sin(angle) * scatterOffset,
        isResolved,
        zoneName: zone ? zone.name : incident.zone_id,
      };
    });
  }, [alerts, zonesMap]);

  const activeAlertsCount = incidentMarkers.filter(m => !m.isResolved).length;

  return (
    <section className="bg-slate-950/90 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-2xl h-full min-h-[580px] relative">
      {/* Embedded CSS for custom Leaflet marker animations & offline fallback background */}
      <style>{`
        @keyframes leaflet-pulse {
          0% { transform: scale(0.95); opacity: 0.8; }
          70% { transform: scale(1.6); opacity: 0; }
          100% { transform: scale(0.95); opacity: 0; }
        }
        @keyframes leaflet-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .leaflet-container {
          background-color: #020617 !important;
          font-family: inherit;
        }
        .custom-leaflet-marker {
          background: transparent;
          border: none;
        }
        .leaflet-popup-content-wrapper {
          background: #020617 !important;
          color: #f1f5f9 !important;
          border: 1px solid #334155;
          border-radius: 8px;
          box-shadow: 0 10px 25px rgba(0,0,0,0.6);
        }
        .leaflet-popup-tip {
          background: #020617 !important;
        }
      `}</style>

      {/* Map Header Bar */}
      <div className="bg-slate-900/90 px-4 py-3 border-b border-slate-800 flex items-center justify-between z-10">
        <div className="flex items-center gap-2.5">
          <MapIcon className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
            TACTICAL SITUATIONAL MAP
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 hidden sm:inline-block">
            LEAFLET + OSM
          </span>
        </div>

        {/* Live Status and Grid Readout */}
        <div className="flex items-center gap-3 font-mono text-xs text-slate-400">
          <div className="hidden md:flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 text-[11px]">
            <Compass className="w-3.5 h-3.5 text-cyan-400" />
            <span>GRID: {defaultCenter[0].toFixed(4)}°N {Math.abs(defaultCenter[1]).toFixed(4)}°W</span>
          </div>

          <div className="flex items-center gap-1.5 text-red-400 font-mono text-[11px] bg-red-950/40 border border-red-500/30 px-2 py-1 rounded">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span>{activeAlertsCount} ACTIVE {activeAlertsCount === 1 ? 'THREAT' : 'THREATS'}</span>
          </div>
        </div>
      </div>

      {/* Main Leaflet Map Canvas */}
      <div className="relative flex-1 w-full bg-slate-950 tactical-grid-bg overflow-hidden">
        {zones.length > 0 && (
          <MapContainer
            center={defaultCenter}
            zoom={17}
            scrollWheelZoom={true}
            style={{ height: '100%', width: '100%', minHeight: '520px', background: '#020617' }}
          >
            {/* OpenStreetMap Standard Tiles (No API key needed) */}
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              maxZoom={19}
            />

            {/* FlyTo Controller: Smoothly pans map when alert card is clicked */}
            <MapController
              selectedAlert={selectedAlert}
              zonesMap={zonesMap}
              defaultCenter={defaultCenter}
            />

            {/* 1. Infrastructure Nodes: Cameras (📷), IoT Sensors (●), Cyber Nodes (⚡) */}
            {nodes.map((node) => {
              const icon =
                node.type === 'camera' ? createCameraIcon() :
                node.type === 'cyber' ? createCyberIcon() :
                createIotIcon();

              return (
                <Marker
                  key={`node-${node.id}`}
                  position={[node.lat, node.lng]}
                  icon={icon}
                  eventHandlers={{
                    click: () => {
                      // If an incident exists in this node's zone, open its Evidence Drawer
                      const matchingIncident = alerts.find(a => a.zone_id === node.zone_id);
                      if (matchingIncident) {
                        onSelectAlert(matchingIncident);
                      }
                    },
                  }}
                >
                  <Popup>
                    <div className="font-mono text-xs text-slate-200">
                      <div className="font-bold text-cyan-400 flex items-center gap-1">
                        <span>{node.type === 'camera' ? '📷' : node.type === 'cyber' ? '⚡' : '●'}</span>
                        <span>{node.name}</span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1">ID: {node.id}</div>
                      <div className="text-[10px] text-slate-400">Zone: {node.zone_id}</div>
                      <div className="text-[9px] text-slate-500 mt-1">
                        {node.lat.toFixed(5)}°N, {node.lng.toFixed(5)}°W
                      </div>
                    </div>
                  </Popup>
                </Marker>
              );
            })}

            {/* 2. Live WebSocket Incident Threat Markers (Pulsing, Colored by Severity) */}
            {incidentMarkers.map((incident) => {
              const isSelected = selectedAlert?.incident_id === incident.incident_id;
              const icon = createIncidentIcon(incident, isSelected);

              return (
                <Marker
                  key={`incident-${incident.incident_id}`}
                  position={[incident.lat, incident.lng]}
                  icon={icon}
                  eventHandlers={{
                    // Requirement 7: Clicking marker opens incident's Evidence Drawer
                    click: () => {
                      onSelectAlert(incident);
                    },
                  }}
                >
                  <Popup>
                    <div className="font-mono text-xs text-left min-w-[160px]">
                      <div className="flex items-center justify-between gap-2 border-b border-slate-700 pb-1">
                        <span className="font-bold text-slate-100">{incident.incident_id}</span>
                        <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                          incident.severity === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500/50' :
                          incident.severity === 'High' ? 'bg-orange-950 text-orange-400 border border-orange-500/50' :
                          incident.severity === 'Medium' ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/50' :
                          'bg-emerald-950 text-emerald-400 border border-emerald-500/50'
                        }`}>
                          {incident.severity}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-300 mt-1">
                        {incident.zoneName || incident.zone_id}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        Threat Score: <span className="font-bold text-red-400">{incident.score}/100</span>
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Status: <span className="uppercase text-cyan-300">{incident.status}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => onSelectAlert(incident)}
                        className="mt-2 w-full bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 px-2 py-1 rounded text-[10px] font-bold tracking-wider cursor-pointer"
                      >
                        OPEN EVIDENCE DRAWER
                      </button>
                    </div>
                  </Popup>
                </Marker>
              );
            })}
          </MapContainer>
        )}

        {/* Floating Reset View Control */}
        <div className="absolute top-4 right-4 z-[400] flex flex-col gap-2">
          {zones.length > 0 && (
            <div className="bg-slate-950/90 rounded border border-slate-800 p-1 shadow-lg">
              <button
                type="button"
                onClick={() => {
                  const matching = alerts[0];
                  if (matching) onSelectAlert(matching);
                }}
                title="Focus Most Recent Threat"
                className="bg-slate-900 hover:bg-slate-800 text-red-400 hover:text-red-300 p-1.5 rounded flex items-center justify-center cursor-pointer transition-colors"
              >
                <ShieldAlert className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Tactical Legend Box */}
        <div className="absolute bottom-4 left-4 z-[400] bg-slate-950/90 border border-slate-800 px-3 py-2 rounded-lg font-mono text-[10px] text-slate-300 shadow-xl flex flex-col gap-1.5 backdrop-blur-sm pointer-events-auto">
          <div className="flex items-center justify-between text-[9px] text-slate-500 border-b border-slate-800/80 pb-1">
            <span className="tracking-wider uppercase">MAP TELEMETRY</span>
            <span className="text-cyan-400 font-semibold">LEAFLET OSM</span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-[10px]">
            <span className="flex items-center gap-1 text-slate-300">
              <span className="text-sm leading-none">📷</span> Cameras
            </span>
            <span className="flex items-center gap-1 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> IoT Sensors
            </span>
            <span className="flex items-center gap-1 text-slate-300">
              <span className="text-purple-400 text-sm leading-none">⚡</span> Cyber Nodes
            </span>
          </div>

          <div className="flex items-center gap-2 pt-1 border-t border-slate-800/80 text-[9px]">
            <span className="text-slate-500">SEVERITY:</span>
            <span className="text-red-400 font-bold">● Crit</span>
            <span className="text-orange-400 font-bold">● High</span>
            <span className="text-yellow-400 font-bold">● Med</span>
            <span className="text-emerald-400 font-bold">● Low</span>
          </div>
        </div>

        {/* Offline / Tile Fallback Hint */}
        <div className="absolute bottom-4 right-4 z-[400] hidden sm:flex items-center gap-2 bg-slate-950/85 border border-slate-800 px-2.5 py-1 rounded font-mono text-[10px] text-slate-400 backdrop-blur-sm pointer-events-none">
          <span>Click marker to open Evidence Drawer</span>
          <span className="text-slate-700">|</span>
          <span>Feed card pans to incident</span>
        </div>
      </div>
    </section>
  );
}
