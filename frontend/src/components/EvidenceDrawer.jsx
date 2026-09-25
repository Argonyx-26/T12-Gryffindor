import React from 'react';
import { Camera, ListFilter, ShieldAlert, X, Radio, ChevronRight, Eye, Crosshair } from 'lucide-react';

/**
 * EvidenceDrawer Component
 * 
 * Purpose:
 * Renders below the Live Alert Feed. When an alert card is clicked, this drawer
 * displays the selected incident's full dossier:
 * 1. Alert summary details (Incident ID, Zone, Severity, Score, Timestamp)
 * 2. Gray placeholder box: "Camera snapshot will go here"
 * 3. List of 2-3 correlated events as text lines
 * 
 * Props:
 * - selectedAlert: The active alert object, or null if none is selected
 * - onClose: Function to dismiss or collapse the drawer
 */
export default function EvidenceDrawer({ selectedAlert, onClose }) {
  // If no alert has been clicked yet, display an empty-state hint
  if (!selectedAlert) {
    return (
      <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-6 text-center text-slate-500 font-mono text-xs shadow-lg transition-all duration-300">
        <div className="flex flex-col items-center justify-center gap-2">
          <Eye className="w-8 h-8 text-slate-700 animate-pulse" />
          <p className="font-semibold text-slate-400 uppercase tracking-wider">
            Evidence Drawer Standby
          </p>
          <p className="text-slate-500 text-[11px] max-w-xs">
            Click on any alert card in the feed above to expand forensic evidence, camera snapshot, and correlated events.
          </p>
        </div>
      </div>
    );
  }

  const { incident_id, zone_id, score, severity, timestamp, description, camera_id, correlated_events } = selectedAlert;

  // Severity color indicator helper
  const getBadgeColor = (sev) => {
    switch (sev) {
      case 'Critical':
        return 'text-red-400 bg-red-950/80 border-red-500/50';
      case 'High':
        return 'text-amber-400 bg-amber-950/80 border-amber-500/50';
      case 'Medium':
        return 'text-yellow-400 bg-yellow-950/80 border-yellow-500/50';
      case 'Low':
      default:
        return 'text-emerald-400 bg-emerald-950/80 border-emerald-500/50';
    }
  };

  return (
    <div className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-2xl transition-all duration-300 animate-in fade-in slide-in-from-top-4">
      {/* Drawer Header with Title and Close Button */}
      <div className="bg-slate-900/90 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-xs font-bold tracking-wider text-slate-200 uppercase font-mono">
            EVIDENCE DRAWER <span className="text-slate-500">//</span> {incident_id}
          </h3>
        </div>

        <button
          type="button"
          onClick={onClose}
          title="Close drawer"
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors"
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

        {description && (
          <div className="text-xs bg-slate-900/40 p-2.5 rounded border border-slate-800/60 text-slate-300 font-mono">
            <span className="text-slate-500 mr-2">[SYNOPSIS]</span>
            {description}
          </div>
        )}

        {/* Gray Placeholder Box: Camera Snapshot */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <Camera className="w-3.5 h-3.5 text-slate-400" />
              SURVEILLANCE OPTICAL FEED
            </span>
            <span className="text-[10px] text-slate-500 font-mono">
              TARGET: {camera_id || 'CAM-PRIMARY'}
            </span>
          </div>

          {/* Placeholder Gray Box with Tactical Reticle Overlay */}
          <div className="relative w-full h-48 bg-slate-900/90 rounded-lg border border-slate-800 flex flex-col items-center justify-center p-4 overflow-hidden group">
            {/* Tactical Grid Background */}
            <div className="absolute inset-0 tactical-grid-bg opacity-30" />

            {/* Corner Bracket Accents */}
            <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-slate-700" />
            <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-slate-700" />
            <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-slate-700" />
            <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-slate-700" />

            {/* Simulated crosshair & REC badge */}
            <div className="absolute top-3 right-3 flex items-center gap-1.5 bg-red-950/80 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-mono text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping inline-block" />
              REC LIVE
            </div>

            {/* Main Required Placeholder Label */}
            <div className="relative z-10 flex flex-col items-center text-center space-y-2">
              <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
                <Crosshair className="w-6 h-6 text-slate-400 animate-spin" style={{ animationDuration: '12s' }} />
              </div>
              <p className="text-sm font-semibold font-mono text-slate-300 tracking-wider">
                Camera snapshot will go here
              </p>
              <p className="text-[11px] font-mono text-slate-500">
                Awaiting frame capture buffer from RTSP feed
              </p>
            </div>
          </div>
        </div>

        {/* Correlated Events List (2-3 simple text lines) */}
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 uppercase tracking-wider">
            <ListFilter className="w-3.5 h-3.5 text-slate-500" />
            <span>Correlated Events & Sensor Telemetry</span>
          </div>

          <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800/80 space-y-2 font-mono text-xs">
            {correlated_events && correlated_events.length > 0 ? (
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
