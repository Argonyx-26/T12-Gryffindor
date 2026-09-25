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
    <div className="bg-slate-950/90 border border-slate-800 rounded-xl overflow-hidden shadow-2xl transition-all duration-300 animate-in fade-in slide-in-from-top-4">
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

        {/* Phase 2: Explainable AI & Score Breakdown */}
        {selectedAlert.explanation && (
          <div className="bg-slate-900/80 p-3.5 rounded-lg border border-slate-800 space-y-2 font-mono text-xs">
            <div className="flex items-center gap-1.5 text-cyan-400 font-bold uppercase tracking-wider text-[11px]">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>EXPLAINABLE AI THREAT ANALYSIS</span>
            </div>
            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {selectedAlert.explanation}
            </p>
            {selectedAlert.contributing_factors && selectedAlert.contributing_factors.length > 0 && (
              <div className="mt-2 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase block font-mono">CONTRIBUTING RISK FACTORS:</span>
                <ul className="list-disc list-inside text-amber-300/90 text-xs space-y-0.5 font-sans">
                  {selectedAlert.contributing_factors.map((factor, fIdx) => (
                    <li key={fIdx}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}
            {selectedAlert.score_breakdown && (
              <div className="mt-3 pt-2 border-t border-slate-800 flex items-center gap-2 flex-wrap text-[10px] font-mono">
                <span className="text-slate-500">MODALITY BREAKDOWN:</span>
                {Object.entries(selectedAlert.score_breakdown.modality_contributions || {}).map(([mod, val]) => (
                  <span key={mod} className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-slate-300">
                    {mod}: <strong className="text-red-400">{val}</strong>
                  </span>
                ))}
                {selectedAlert.score_breakdown.corroboration_multiplier && (
                  <span className="bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30 text-cyan-300">
                    MULT: <strong>{selectedAlert.score_breakdown.corroboration_multiplier}x</strong>
                  </span>
                )}
                {selectedAlert.score_breakdown.zone_weight && (
                  <span className="bg-amber-950/60 px-2 py-0.5 rounded border border-amber-500/30 text-amber-300">
                    ZONE: <strong>{selectedAlert.score_breakdown.zone_weight}</strong>
                  </span>
                )}
              </div>
            )}
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
          <div className="relative w-full h-44 bg-slate-900/90 rounded-lg border border-slate-800 flex flex-col items-center justify-center p-4 overflow-hidden group">
            <div className="absolute inset-0 tactical-grid-bg opacity-30" />
            <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-slate-700" />
            <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-slate-700" />
            <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-slate-700" />
            <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-slate-700" />

            <div className="absolute top-3 right-3 flex items-center gap-1.5 bg-red-950/80 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-mono text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping inline-block" />
              REC LIVE
            </div>

            <div className="relative z-10 flex flex-col items-center text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
                <Crosshair className="w-5 h-5 text-slate-400 animate-spin" style={{ animationDuration: '12s' }} />
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

        {/* Phase 2: Response Recommendations */}
        {selectedAlert.recommendations && selectedAlert.recommendations.length > 0 && (
          <div className="space-y-1.5 font-mono text-xs">
            <div className="flex items-center gap-1.5 text-slate-400 uppercase tracking-wider">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span>TACTICAL RESPONSE RECOMMENDATIONS</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 space-y-1 font-sans text-xs">
              {selectedAlert.recommendations.map((rec, rIdx) => (
                <div key={rIdx} className="flex items-start gap-2 text-slate-300">
                  <span className="text-amber-400 font-mono font-bold">•</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Phase 2: Chronological Timeline Log */}
        {selectedAlert.timeline && selectedAlert.timeline.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 uppercase tracking-wider">
              <ListFilter className="w-3.5 h-3.5 text-slate-500" />
              <span>INCIDENT EVENT CHRONOLOGY</span>
            </div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800 space-y-2 font-mono text-xs max-h-48 overflow-y-auto">
              {selectedAlert.timeline.map((item, tIdx) => (
                <div key={tIdx} className="flex items-start gap-2 text-slate-300 border-b border-slate-800/40 pb-1.5 last:border-0 last:pb-0">
                  <span className="text-[10px] text-slate-500 shrink-0 font-mono">{item.timestamp?.split('T')[1]?.slice(0, 8) || '00:00:00'}</span>
                  <span className="text-cyan-400 font-bold shrink-0 font-mono">[{item.source}]</span>
                  <span className="text-slate-300 font-sans">{item.description}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Correlated Events List Fallback */}
        {(!selectedAlert.timeline || selectedAlert.timeline.length === 0) && correlated_events && correlated_events.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 uppercase tracking-wider">
              <ListFilter className="w-3.5 h-3.5 text-slate-500" />
              <span>Correlated Events & Sensor Telemetry</span>
            </div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800/80 space-y-2 font-mono text-xs">
              {correlated_events.map((evt, idx) => (
                <div key={idx} className="flex items-start gap-2 text-slate-300">
                  <ChevronRight className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{evt}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
