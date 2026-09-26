import React, { useEffect, useRef, useState } from 'react';
import { Map, Navigation, Layers, Compass, Maximize2, Radio, Filter, Eye, ShieldAlert, Video, Cpu, Server } from 'lucide-react';

/**
 * Tactical Coordinates Catalog for Demo Campus Site
 */
const DEFAULT_CENTER = [37.4282, -122.1688];
const DEFAULT_ZOOM = 16;

const ZONES_GEOMETRY = {
  "Server_Room": {
    name: "Central Server Facility",
    polygon: [
      [37.4286, -122.1692],
      [37.4286, -122.1684],
      [37.4278, -122.1684],
      [37.4278, -122.1692]
    ]
  },
  "Perimeter_Gate_3": {
    name: "North Perimeter Gate 3",
    polygon: [
      [37.4325, -122.1750],
      [37.4325, -122.1740],
      [37.4315, -122.1740],
      [37.4315, -122.1750]
    ]
  },
  "Parking_Lot": {
    name: "East Visitor Parking",
    polygon: [
      [37.4260, -122.1625],
      [37.4260, -122.1615],
      [37.4250, -122.1615],
      [37.4250, -122.1625]
    ]
  },
  "Parking_Lot_B": {
    name: "West Parking Lot B",
    polygon: [
      [37.4255, -122.1635],
      [37.4255, -122.1625],
      [37.4245, -122.1625],
      [37.4245, -122.1635]
    ]
  }
};

const FIXED_ASSETS = [
  { id: 'CAM-01', name: 'CCTV Gate 3', type: 'camera', lat: 37.4320, lng: -122.1745, zone: 'Perimeter_Gate_3' },
  { id: 'CAM-02', name: 'CCTV East Parking', type: 'camera', lat: 37.4255, lng: -122.1620, zone: 'Parking_Lot' },
  { id: 'CAM-03', name: 'CCTV Server Vault', type: 'camera', lat: 37.4282, lng: -122.1688, zone: 'Server_Room' },
  { id: 'IOT-01', name: 'Server Door Sensor', type: 'iot', lat: 37.4282, lng: -122.1688, zone: 'Server_Room' },
  { id: 'IOT-02', name: 'Gate 3 IR Sensor', type: 'iot', lat: 37.4320, lng: -122.1745, zone: 'Perimeter_Gate_3' },
  { id: 'CYBER-01', name: 'Auth Server Node', type: 'cyber', lat: 37.4282, lng: -122.1688, zone: 'Server_Room', location_type: 'logical' }
];

export default function MapPanel({
  activeIncidents = [],
  selectedIncident = null,
  onSelectIncident = null,
  isConnected = true
}) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const layerGroupRef = useRef(null);
  const polygonGroupRef = useRef(null);

  const [filterModality, setFilterModality] = useState({ VIDEO: true, IOT: true, CYBER: true });
  const [filterSeverity, setFilterSeverity] = useState({ Critical: true, High: true, Medium: true, Low: true });
  const [showLegend, setShowLegend] = useState(true);
  const [leafletLoaded, setLeafletLoaded] = useState(false);

  // Dynamically load Leaflet if not present on window
  useEffect(() => {
    if (window.L) {
      setLeafletLoaded(true);
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    script.integrity = 'sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=';
    script.crossOrigin = '';
    script.onload = () => setLeafletLoaded(true);
    document.head.appendChild(script);
  }, []);

  // Initialize Map Instance ONCE
  useEffect(() => {
    if (!leafletLoaded || !mapContainerRef.current || mapInstanceRef.current) return;

    const L = window.L;
    const map = L.map(mapContainerRef.current, {
      center: DEFAULT_CENTER,
      zoom: DEFAULT_ZOOM,
      zoomControl: false,
      attributionControl: false
    });

    // Offline Tactical Map (no external tile server or API keys required)
    L.control.zoom({ position: 'topright' }).addTo(map);

    polygonGroupRef.current = L.layerGroup().addTo(map);
    layerGroupRef.current = L.layerGroup().addTo(map);

    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, [leafletLoaded]);

  // Sync Layers & Markers whenever incidents, filters, or map instance updates
  useEffect(() => {
    if (!mapInstanceRef.current || !leafletLoaded) return;
    const L = window.L;
    const map = mapInstanceRef.current;
    const layerGroup = layerGroupRef.current;
    const polygonGroup = polygonGroupRef.current;

    layerGroup.clearLayers();
    polygonGroup.clearLayers();

    // 1. Render Zone Polygons with Dynamic Threat Colors
    Object.entries(ZONES_GEOMETRY).forEach(([zoneId, zoneData]) => {
      const zoneIncidents = activeIncidents.filter(inc => {
        const incZone = inc.zone_id || (inc.location && inc.location.primary_location && inc.location.primary_location.zone_id);
        return incZone === zoneId && inc.status !== 'false_positive';
      });

      let strokeColor = '#06b6d4';
      let fillColor = '#06b6d4';
      let fillOpacity = 0.12;

      if (zoneIncidents.some(i => i.severity === 'Critical')) {
        strokeColor = '#ef4444';
        fillColor = '#ef4444';
        fillOpacity = 0.45;
      } else if (zoneIncidents.some(i => i.severity === 'High')) {
        strokeColor = '#f97316';
        fillColor = '#f97316';
        fillOpacity = 0.35;
      } else if (zoneIncidents.some(i => i.severity === 'Medium')) {
        strokeColor = '#eab308';
        fillColor = '#eab308';
        fillOpacity = 0.25;
      }

      const polygon = L.polygon(zoneData.polygon, {
        color: strokeColor,
        weight: 2,
        fillColor: fillColor,
        fillOpacity: fillOpacity,
        dashArray: zoneIncidents.length > 0 ? '6, 6' : null
      });

      polygon.bindTooltip(`<b>${zoneData.name}</b><br/>Status: ${zoneIncidents.length > 0 ? `${zoneIncidents.length} Active Incident(s)` : 'Clear'}`, {
        className: 'custom-leaflet-tooltip',
        sticky: true
      });

      polygonGroup.addLayer(polygon);
    });

    // 2. Render Fixed Infrastructure Assets (Cameras, IoT Sensors, Cyber Nodes)
    FIXED_ASSETS.forEach(asset => {
      const srcType = asset.type === 'camera' ? 'VIDEO' : asset.type === 'iot' ? 'IOT' : 'CYBER';
      if (!filterModality[srcType]) return;

      const iconHtml = asset.type === 'camera'
        ? `<div class="w-7 h-7 rounded-full bg-slate-900 border-2 border-cyan-400 flex items-center justify-center text-cyan-400 text-xs shadow-lg font-mono">📷</div>`
        : asset.type === 'iot'
        ? `<div class="w-6 h-6 rounded-full bg-slate-900 border-2 border-emerald-400 flex items-center justify-center text-emerald-400 text-xs shadow-lg font-mono">●</div>`
        : `<div class="w-6 h-6 rounded-full bg-slate-900 border-2 border-purple-400 flex items-center justify-center text-purple-400 text-xs shadow-lg font-mono">⚡</div>`;

      const customIcon = L.divIcon({
        html: iconHtml,
        className: 'custom-asset-pin',
        iconSize: [28, 28],
        iconAnchor: [14, 14]
      });

      const marker = L.marker([asset.lat, asset.lng], { icon: customIcon });
      marker.bindPopup(`
        <div style="font-family: monospace; font-size: 11px; color: #f1f5f9; background: #0f172a; padding: 8px; border-radius: 6px;">
          <strong style="color: #38bdf8;">${asset.name} (${asset.id})</strong><br/>
          Zone: ${asset.zone}<br/>
          Modality: ${srcType}<br/>
          Status: Operational
        </div>
      `, { className: 'custom-leaflet-popup' });

      layerGroup.addLayer(marker);
    });

    // 3. Render Active Incidents
    activeIncidents.forEach(inc => {
      if (inc.status === 'false_positive') return;
      if (!filterSeverity[inc.severity]) return;

      // Extract coordinates
      let lat = DEFAULT_CENTER[0];
      let lng = DEFAULT_CENTER[1];
      let locType = 'physical';

      if (inc.location && inc.location.primary_location) {
        lat = inc.location.primary_location.latitude || lat;
        lng = inc.location.primary_location.longitude || lng;
        locType = inc.location.primary_location.location_type || locType;
      } else if (inc.coordinates && inc.coordinates.length >= 2) {
        lat = inc.coordinates[0];
        lng = inc.coordinates[1];
      }

      const isSelected = selectedIncident && selectedIncident.incident_id === inc.incident_id;
      const isCritical = inc.severity === 'Critical';
      const colorHex = isCritical ? '#ef4444' : inc.severity === 'High' ? '#f97316' : inc.severity === 'Medium' ? '#eab308' : '#3b82f6';

      const pinHtml = `
        <div class="relative flex items-center justify-center">
          <div class="absolute w-9 h-9 rounded-full animate-ping opacity-75" style="background-color: ${colorHex};"></div>
          <div class="w-8 h-8 rounded-full bg-slate-950 border-2 flex items-center justify-center text-xs font-mono font-bold shadow-2xl ${
            isSelected ? 'ring-4 ring-cyan-400 scale-125' : ''
          }" style="border-color: ${colorHex}; color: ${colorHex};">
            🚨
          </div>
        </div>
      `;

      const incIcon = L.divIcon({
        html: pinHtml,
        className: 'custom-incident-pin',
        iconSize: [36, 36],
        iconAnchor: [18, 18]
      });

      const marker = L.marker([lat, lng], { icon: incIcon });
      
      const sourcesText = (inc.sources || []).join(' + ') || 'MULTI-VECTOR';
      const popupContent = `
        <div style="font-family: monospace; font-size: 11px; color: #f1f5f9; background: #020617; padding: 10px; border-radius: 8px; border: 1px solid #334155; min-width: 180px;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 4px; margin-bottom: 6px;">
            <strong style="color: ${colorHex};">${inc.incident_id}</strong>
            <span style="background: ${colorHex}22; color: ${colorHex}; padding: 2px 6px; border-radius: 4px; font-size: 10px;">${inc.severity}</span>
          </div>
          <div><strong>SCORE:</strong> ${inc.score.toFixed(1)} / 100</div>
          <div><strong>ZONE:</strong> ${inc.zone_id || 'Campus'}</div>
          <div><strong>SOURCES:</strong> ${sourcesText}</div>
          <div><strong>LOCATION:</strong> ${locType === 'logical' ? 'Logical Node' : `${lat.toFixed(4)}, ${lng.toFixed(4)}`}</div>
          <div style="margin-top: 8px; text-align: center;">
            <span style="color: #38bdf8; text-decoration: underline; cursor: pointer;">Click to view Evidence & Timeline</span>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, { className: 'custom-leaflet-popup' });

      marker.on('click', () => {
        if (onSelectIncident) {
          onSelectIncident(inc);
        }
      });

      layerGroup.addLayer(marker);
    });

  }, [activeIncidents, selectedIncident, filterModality, filterSeverity, leafletLoaded]);

  // Center Map on Selected Incident when explicitly changed from dashboard
  useEffect(() => {
    if (!selectedIncident || !mapInstanceRef.current) return;
    let lat = DEFAULT_CENTER[0];
    let lng = DEFAULT_CENTER[1];

    if (selectedIncident.location && selectedIncident.location.primary_location) {
      lat = selectedIncident.location.primary_location.latitude || lat;
      lng = selectedIncident.location.primary_location.longitude || lng;
    } else if (selectedIncident.coordinates && selectedIncident.coordinates.length >= 2) {
      lat = selectedIncident.coordinates[0];
      lng = selectedIncident.coordinates[1];
    }

    mapInstanceRef.current.flyTo([lat, lng], 17, { duration: 1.2 });
  }, [selectedIncident]);

  return (
    <section className="bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-2xl h-full min-h-[580px] relative">
      {/* Map Header Bar */}
      <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-800 flex items-center justify-between z-10">
        <div className="flex items-center gap-2.5">
          <Map className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
            SITUATIONAL GEOSPATIAL MAP
          </h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 hidden sm:inline-block">
            LEAFLET TACTICAL ENGINE
          </span>
        </div>

        {/* Coordinates & Sync Indicators */}
        <div className="flex items-center gap-3 font-mono text-xs text-slate-400">
          <div className="hidden md:flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
            <Compass className="w-3.5 h-3.5 text-slate-500" />
            <span>GRID: 37°25'41"N 122°10'07"W</span>
          </div>

          <div className="flex items-center gap-1.5 text-emerald-400">
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
            <span className="text-[11px] hidden sm:inline">{isConnected ? 'GPS SYNC' : 'OFFLINE'}</span>
          </div>
        </div>
      </div>

      {/* Main Leaflet Map Canvas */}
      <div className="relative flex-1 w-full h-full min-h-[500px]">
        <div
          ref={mapContainerRef}
          className="absolute inset-0 w-full h-full z-0 bg-slate-950"
          style={{
            backgroundImage: 'radial-gradient(#334155 1.5px, transparent 1.5px)',
            backgroundSize: '24px 24px',
            backgroundColor: '#020617'
          }}
        />

        {/* Map Legend Overlay */}
        {showLegend && (
          <div className="absolute bottom-4 right-4 z-10 bg-slate-950/90 border border-slate-800 p-3 rounded-lg font-mono text-[11px] text-slate-300 backdrop-blur shadow-2xl flex flex-col gap-2">
            <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-1 text-[10px] font-bold">
              <span>MAP LEGEND</span>
              <button onClick={() => setShowLegend(false)} className="text-slate-500 hover:text-white">✕</button>
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
              <div className="flex items-center gap-1.5">📷 <span className="text-slate-400">Camera</span></div>
              <div className="flex items-center gap-1.5">● <span className="text-slate-400">IoT Sensor</span></div>
              <div className="flex items-center gap-1.5">⚡ <span className="text-slate-400">Cyber Node</span></div>
              <div className="flex items-center gap-1.5">🚨 <span className="text-slate-400">Incident</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-red-500 inline-block" /> <span className="text-red-400">Critical</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded bg-orange-500 inline-block" /> <span className="text-orange-400">High</span></div>
            </div>
          </div>
        )}

        {!showLegend && (
          <button
            onClick={() => setShowLegend(true)}
            className="absolute bottom-4 right-4 z-10 bg-slate-950/90 border border-slate-800 px-3 py-1.5 rounded text-xs font-mono text-cyan-400 hover:text-white shadow"
          >
            LEGEND
          </button>
        )}

        {/* Scale & Campus Status Bar */}
        <div className="absolute bottom-4 left-4 z-10 bg-slate-950/80 px-3 py-1.5 rounded border border-slate-800 font-mono text-[10px] text-slate-400 flex items-center gap-3">
          <span>STANFORD CAMPUS PERIMETER</span>
          <span className="w-12 h-0.5 bg-cyan-500 block rounded" />
          <span>500m</span>
        </div>
      </div>
    </section>
  );
}
