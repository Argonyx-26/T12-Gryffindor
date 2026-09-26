import React, { useState, useEffect } from 'react';
import { Camera, ListFilter, ShieldAlert, X, Radio, ChevronRight, Eye, Crosshair } from 'lucide-react';

/**
 * EvidenceDrawer Component
 * 
 * Purpose:
 * Renders below the Live Alert Feed. When an alert card is clicked or VIEW EVIDENCE
 * is selected from the Active Response Panel, this drawer displays the selected
 * incident's full forensic dossier:
 * 1. Alert summary details (Incident ID, Zone, Severity, Threat Score, Timestamp, Status)
 * 2. Surveillance Optical Feed:
 *    - Renders raw_meta.frame_b64 directly as an <img> tag if available.
 *    - Displays bbox coordinates (e.g. "BBox: [120, 45, 340, 510]") and camera_id if bbox exists.
 *    - Displays a neutral message "No video source correlated for this incident" if no VIDEO source exists.
 * 3. Correlated Events & Sensor Telemetry list.
 * 
 * Props:
 * - selectedAlert: The active alert object, or null if none is selected
 * - onClose: Function to dismiss or collapse the drawer
 * - apiUrl: Base URL of the backend API (defaults to http://localhost:8000)
 */
export default function EvidenceDrawer({ selectedAlert, onClose, apiUrl = 'http://localhost:8000' }) {
  // Local state to store fetched full contributing event objects when not embedded on the incident
  const [fetchedEvents, setFetchedEvents] = useState([]);
  const [isLoadingEvents, setIsLoadingEvents] = useState(false);

  // Fetch full contributing event objects from backend if not already embedded
  useEffect(() => {
    if (!selectedAlert || !selectedAlert.incident_id) {
      setFetchedEvents([]);
      return;
    }

    // If the incident object already contains full contributing event objects, use them directly
    if (Array.isArray(selectedAlert.events) && selectedAlert.events.length > 0) {
      setFetchedEvents([]);
      return;
    }

    let isCancelled = false;
    setIsLoadingEvents(true);

    const fetchIncidentEvents = async () => {
      try {
        const base = apiUrl.replace(/\/+$/, '');
        // 1. Try dedicated incident events endpoint: GET /incidents/{incident_id}/events
        const res = await fetch(`${base}/incidents/${encodeURIComponent(selectedAlert.incident_id)}/events`);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0 && !isCancelled) {
            setFetchedEvents(data);
            setIsLoadingEvents(false);
            return;
          }
        }

        // 2. Fallback: GET /events?zone_id={zone_id}
        if (selectedAlert.zone_id) {
          const resZone = await fetch(`${base}/events?zone_id=${encodeURIComponent(selectedAlert.zone_id)}&limit=25`);
          if (resZone.ok) {
            const dataZone = await resZone.json();
            if (Array.isArray(dataZone) && !isCancelled) {
              setFetchedEvents(dataZone);
              setIsLoadingEvents(false);
              return;
            }
          }
        }
      } catch (err) {
        console.warn('[EvidenceDrawer] Error fetching contributing events:', err);
      } finally {
        if (!isCancelled) {
          setIsLoadingEvents(false);
        }
      }
    };

    fetchIncidentEvents();

    return () => {
      isCancelled = true;
    };
  }, [selectedAlert?.incident_id, selectedAlert?.zone_id, apiUrl]);

  // If no alert has been clicked yet or drawer is closed, display an empty-state hint
  if (!selectedAlert) {
    return (
      <div 
        id="evidence-drawer" 
        className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-6 text-center text-slate-500 font-mono text-xs shadow-lg transition-all duration-300"
      >
        <div className="flex flex-col items-center justify-center gap-2.5">
          <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-500">
            <Eye className="w-5 h-5 text-slate-400" />
          </div>
          <p className="font-semibold text-slate-300 uppercase tracking-wider text-xs">
            Forensic Dossier Standby
          </p>
          <p className="text-slate-500 text-[11px] max-w-xs leading-relaxed font-sans">
            Forensic evidence, surveillance snapshots, and multi-sensor correlations will load here automatically when an alert is selected.
          </p>
        </div>
      </div>
    );
  }

  const { incident_id, zone_id, score, severity, timestamp, description, camera_id, correlated_events } = selectedAlert;

  // Contributing events: embedded events take priority, then fetched events
  const contributingEvents = (Array.isArray(selectedAlert.events) && selectedAlert.events.length > 0)
    ? selectedAlert.events
    : fetchedEvents;

  // Sources list from alert
  const sourcesList = Array.isArray(selectedAlert.sources)
    ? selectedAlert.sources
    : (selectedAlert.source_type ? [selectedAlert.source_type] : []);

  // Filter for VIDEO-source events
  const videoEvents = contributingEvents.filter(
    (ev) => String(ev.source_type || '').toUpperCase() === 'VIDEO'
  );

  // Check if VIDEO source is part of this incident
  const hasVideoSource =
    sourcesList.some((s) => String(s).toUpperCase() === 'VIDEO') ||
    String(selectedAlert.source_type || '').toUpperCase() === 'VIDEO' ||
    videoEvents.length > 0 ||
    Boolean(selectedAlert.raw_meta?.frame_b64) ||
    Boolean(selectedAlert.raw_meta?.bbox) ||
    Boolean(selectedAlert.raw_meta?.frame);

  // Preferred video event: one with frame_b64 or bbox, otherwise first video event
  const primaryVideoEvent = videoEvents.find(
    (ev) => ev.raw_meta?.frame_b64 || ev.raw_meta?.bbox || ev.bbox
  ) || videoEvents[0] || null;

  // Extract raw_meta from video event (fallback to selectedAlert.raw_meta)
  const rawMeta = primaryVideoEvent?.raw_meta || selectedAlert.raw_meta || {};

  // Check for raw_meta.frame_b64
  const rawFrameB64 =
    rawMeta.frame_b64 ||
    primaryVideoEvent?.frame_b64 ||
    selectedAlert.raw_meta?.frame_b64 ||
    selectedAlert.frame_b64 ||
    rawMeta.frame ||
    rawMeta.image ||
    null;

  const frameB64 = typeof rawFrameB64 === 'string' && rawFrameB64.trim().length > 0
    ? (rawFrameB64.startsWith('data:') ? rawFrameB64 : `data:image/jpeg;base64,${rawFrameB64}`)
    : null;

  // Check for raw_meta.bbox
  const rawBbox =
    rawMeta.bbox ??
    rawMeta.bounding_box ??
    primaryVideoEvent?.bbox ??
    selectedAlert.raw_meta?.bbox ??
    selectedAlert.bbox ??
    null;

  const formattedBbox = Array.isArray(rawBbox)
    ? `[${rawBbox.join(', ')}]`
    : (rawBbox && typeof rawBbox === 'object' ? JSON.stringify(rawBbox) : (rawBbox ? String(rawBbox) : null));

  // Camera ID identification
  const resolvedCameraId =
    rawMeta.camera_id ||
    primaryVideoEvent?.camera_id ||
    selectedAlert.camera_id ||
    (selectedAlert.zone_id ? `CAM-${String(selectedAlert.zone_id).replace(/\s+/g, '-').slice(0, 12).toUpperCase()}` : 'CAM-PRIMARY');

  // Dynamic description logic
  const getDisplayDescription = () => {
    let desc = description;
    if (sourcesList.length === 0 && typeof desc === 'string') {
      const match = desc.match(/(?:detection across:\s*)(.+)$/i);
      if (match) {
        const extracted = match[1].split(',').map((s) => s.trim()).filter(Boolean);
        if (extracted.length === 1) return `Single-source detection: ${extracted[0]}`;
        if (extracted.length >= 2) return `Corroborated multi-vector detection across: ${extracted.join(', ')}`;
      }
    }

    if (sourcesList.length === 1) {
      return `Single-source detection: ${sourcesList[0]}`;
    }
    if (sourcesList.length >= 2) {
      return `Corroborated multi-vector detection across: ${sourcesList.join(', ')}`;
    }
    if (desc && (desc.startsWith('Corroborated multimodal detection across:') || desc.startsWith('Corroborated multi-vector detection across:'))) {
      return 'Multi-vector physical/cyber anomaly detected by Gryffindor Sentinel.';
    }
    return desc || 'Multi-vector physical/cyber anomaly detected by Gryffindor Sentinel.';
  };

  const displayDescription = getDisplayDescription();

  // Severity color indicator helper
  const getBadgeColor = (sev) => {
    switch (sev) {
      case 'Critical':
        return 'text-white bg-red-600 border-red-400 font-extrabold shadow-[0_0_12px_rgba(239,68,68,0.6)] animate-pulse';
      case 'High':
        return 'text-slate-950 bg-amber-500 border-amber-300 font-extrabold shadow-sm';
      case 'Medium':
        return 'text-slate-950 bg-yellow-400 border-yellow-200 font-extrabold shadow-sm';
      case 'Low':
      default:
        return 'text-slate-950 bg-emerald-500 border-emerald-300 font-extrabold shadow-sm';
    }
  };

  return (
    <div 
      id="evidence-drawer" 
      className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-2xl transition-all duration-300 animate-in fade-in slide-in-from-top-4"
    >
      {/* Drawer Header with Title and Close Button */}
      <div className="bg-slate-900/90 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-xs font-bold tracking-wider text-slate-200 uppercase font-mono">
            EVIDENCE DRAWER <span className="text-slate-500">//</span> {incident_id}
          </h3>
          {selectedAlert.status && (
            <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
              selectedAlert.status === 'dispatched'
                ? 'bg-cyan-950 text-cyan-300 border-cyan-500/40'
                : selectedAlert.status === 'false_positive'
                ? 'bg-slate-800 text-slate-400 border-slate-700'
                : 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30'
            }`}>
              {selectedAlert.status}
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={onClose}
          title="Close drawer"
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Incident Summary Card Details */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
          <div>
            <span className="text-[10px] text-slate-500 block">SECTOR ZONE</span>
            <span className="font-semibold text-slate-200 truncate block">{zone_id}</span>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 block">SEVERITY LEVEL</span>
            <span className={`inline-block px-2 py-0.5 mt-0.5 rounded text-[11px] font-bold border ${getBadgeColor(severity)}`}>
              {severity}
            </span>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 block">THREAT SCORE</span>
            <span className="font-bold text-red-400 text-sm">{score}/100</span>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 block">TRIGGER TIME</span>
            <span className="text-slate-300 font-semibold">{timestamp}</span>
          </div>
        </div>

        {displayDescription && (
          <div className="text-xs bg-slate-900/40 p-2.5 rounded border border-slate-800/60 text-slate-300 font-mono">
            <span className="text-slate-500 mr-2">[SYNOPSIS]</span>
            {displayDescription}
          </div>
        )}

        {/* Surveillance Optical Feed Section */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <Camera className="w-3.5 h-3.5 text-slate-400" />
              SURVEILLANCE OPTICAL FEED
            </span>
            <span className="text-[10px] text-slate-500 font-mono">
              TARGET: {hasVideoSource ? resolvedCameraId : 'N/A (NON-OPTICAL)'}
            </span>
          </div>

          {/* Tactical Snapshot / Optical Feed Display */}
          <div className="relative w-full h-52 bg-slate-900/90 rounded-lg border border-slate-800 flex flex-col items-center justify-center p-4 overflow-hidden group">
            {/* Tactical Grid Background */}
            <div className="absolute inset-0 tactical-grid-bg opacity-30 pointer-events-none" />

            {/* Corner Bracket Accents */}
            <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-slate-700 pointer-events-none z-20" />
            <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-slate-700 pointer-events-none z-20" />
            <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-slate-700 pointer-events-none z-20" />
            <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-slate-700 pointer-events-none z-20" />

            {/* Live Indicator Badge: REC LIVE for video source, NON-OPTICAL otherwise */}
            {hasVideoSource ? (
              <div className="absolute top-3 right-3 flex items-center gap-1.5 bg-red-950/80 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-mono text-red-400 z-20 shadow">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping inline-block" />
                REC LIVE
              </div>
            ) : (
              <div className="absolute top-3 right-3 flex items-center gap-1.5 bg-slate-900/90 border border-slate-700 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 z-20 shadow">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-500 inline-block" />
                NON-OPTICAL
              </div>
            )}

            {(() => {
              // 1. If raw_meta.frame_b64 exists and is not null, render directly as <img> tag
              if (hasVideoSource && frameB64) {
                return (
                  <div className="relative w-full h-full flex items-center justify-center overflow-hidden">
                    <img
                      src={frameB64}
                      alt={`Surveillance frame for ${incident_id}`}
                      className="w-full h-full object-cover rounded filter contrast-110"
                    />
                    {formattedBbox && (
                      <div className="absolute bottom-2 left-2 bg-slate-950/85 border border-cyan-500/40 px-2.5 py-1 rounded text-[10px] font-mono text-cyan-300 shadow flex items-center gap-1.5">
                        <Crosshair className="w-3 h-3 text-cyan-400" />
                        <span>BBox: {formattedBbox}</span>
                        <span className="text-slate-500">|</span>
                        <span className="text-slate-400">{resolvedCameraId}</span>
                      </div>
                    )}
                  </div>
                );
              }

              // 2. Otherwise, if raw_meta.bbox exists, display bounding box coordinates as text and camera_id
              if (hasVideoSource && formattedBbox) {
                return (
                  <div className="relative z-10 flex flex-col items-center text-center space-y-2.5 max-w-sm">
                    <div className="w-10 h-10 rounded-full bg-cyan-950/70 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]">
                      <Crosshair className="w-5 h-5 text-cyan-400 animate-pulse" />
                    </div>
                    <div className="bg-slate-950/90 border border-cyan-500/30 px-4 py-2.5 rounded-lg font-mono shadow-lg space-y-1">
                      <span className="text-[10px] text-cyan-400 block tracking-wider uppercase font-semibold">
                        OPTICAL BOUNDING BOX
                      </span>
                      <span className="text-xs text-slate-100 font-bold tracking-widest block font-mono">
                        BBox: {formattedBbox}
                      </span>
                      <span className="text-[11px] text-slate-400 block font-mono">
                        Camera ID: <span className="text-cyan-300 font-semibold">{resolvedCameraId}</span>
                      </span>
                    </div>
                    <p className="text-[11px] font-mono text-slate-400">
                      Vision target detected: <span className="text-slate-200">{primaryVideoEvent?.event_type || selectedAlert.event_type || 'person_detected'}</span>
                      {primaryVideoEvent?.confidence !== undefined && (
                        <span className="text-cyan-400 ml-1.5 font-semibold">({Math.round(primaryVideoEvent.confidence * 100)}% conf)</span>
                      )}
                    </p>
                  </div>
                );
              }

              // 3. If VIDEO source is present but neither frame nor bbox is specified
              if (hasVideoSource) {
                return (
                  <div className="relative z-10 flex flex-col items-center text-center space-y-2 max-w-sm">
                    <div className="w-10 h-10 rounded-full bg-cyan-950/70 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                      <Crosshair className="w-5 h-5 text-cyan-400 animate-spin" style={{ animationDuration: '8s' }} />
                    </div>
                    <p className="text-xs font-semibold font-mono text-slate-200 tracking-wider uppercase">
                      Optical Video Channel Active
                    </p>
                    <p className="text-[11px] font-mono text-slate-400">
                      Camera ID: <span className="text-cyan-300 font-semibold">{resolvedCameraId}</span> (awaiting optical frame capture)
                    </p>
                  </div>
                );
              }

              // 4. If no VIDEO source in this incident at all: neutral message
              return (
                <div className="relative z-10 flex flex-col items-center text-center space-y-2 max-w-sm">
                  <div className="w-11 h-11 rounded-full bg-slate-900 border border-slate-700/80 flex items-center justify-center text-slate-500">
                    <Camera className="w-5 h-5 text-slate-500 opacity-60" />
                  </div>
                  <p className="text-xs font-semibold font-mono text-slate-300 tracking-wider uppercase">
                    No video source correlated for this incident
                  </p>
                  <p className="text-[11px] font-mono text-slate-500 leading-relaxed">
                    Synthesized from non-optical telemetry ({sourcesList.length > 0 ? sourcesList.join(', ') : 'IOT / CYBER'})
                  </p>
                </div>
              );
            })()}
          </div>
        </div>

        {/* Correlated Events & Sensor Telemetry List */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <ListFilter className="w-3.5 h-3.5 text-slate-500" />
              Correlated Events & Sensor Telemetry
            </span>
            {isLoadingEvents && (
              <span className="text-[10px] text-cyan-400 animate-pulse">Syncing events...</span>
            )}
          </div>

          <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800/80 space-y-2 font-mono text-xs">
            {contributingEvents.length > 0 ? (
              contributingEvents.map((evt, idx) => (
                <div key={evt.event_id || idx} className="flex items-start gap-2 text-slate-300">
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
                  <div className="flex-1 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      evt.source_type === 'VIDEO' ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40' :
                      evt.source_type === 'IOT' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40' :
                      'bg-purple-950/80 text-purple-300 border-purple-500/40'
                    }`}>
                      {evt.source_type}
                    </span>
                    <span className="font-semibold text-slate-200">
                      {evt.event_type}
                    </span>
                    {evt.confidence !== undefined && (
                      <span className="text-[11px] text-slate-400">
                        ({Math.round(evt.confidence * 100)}% conf)
                      </span>
                    )}
                    {evt.raw_meta?.bbox && (
                      <span className="text-[10px] text-cyan-400">
                        BBox: [{Array.isArray(evt.raw_meta.bbox) ? evt.raw_meta.bbox.join(', ') : evt.raw_meta.bbox}]
                      </span>
                    )}
                    <span className="text-[10px] text-slate-500 ml-auto">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : ''}
                    </span>
                  </div>
                </div>
              ))
            ) : correlated_events && correlated_events.length > 0 ? (
              correlated_events.map((evt, idx) => (
                <div key={idx} className="flex items-start gap-2 text-slate-300">
                  <ChevronRight className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{evt}</span>
                </div>
              ))
            ) : (
              <p className="text-slate-500 italic">No additional correlated events logged.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
