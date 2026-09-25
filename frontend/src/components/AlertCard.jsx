import React, { useState } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Siren, XOctagon, Clock, MapPin, Check, ShieldCheck } from 'lucide-react';

/**
 * AlertCard Component
 * 
 * Represents an individual threat detection incident card within the Live Alert Feed.
 * 
 * Props:
 * - alert: The incident data object (incident_id, zone_id, score, severity, timestamp, status)
 * - isSelected: Boolean indicating whether this card is currently selected for evidence inspection
 * - onSelect: Callback function invoked when the card is clicked
 * - onUpdateStatus: Callback function to update the incident status in local state immediately
 */
export default function AlertCard({ alert, isSelected, onSelect, onUpdateStatus }) {
  const { incident_id, zone_id, score, severity, timestamp, status } = alert;

  // Base API URL from environment variable or default to localhost:8000
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  // Local loading states for button network requests
  const [isDispatching, setIsDispatching] = useState(false);
  const [isMarkingFP, setIsMarkingFP] = useState(false);

  /**
   * Helper function to return styling classes and icons tailored to the severity level.
   */
  const getSeverityStyle = (level) => {
    switch (level) {
      case 'Critical':
        return {
          badge: 'bg-red-950/80 text-red-400 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
          dot: 'bg-red-500 animate-ping',
          icon: <AlertCircle className="w-3.5 h-3.5 text-red-400" />,
          scoreColor: 'text-red-500',
          accentBorder: 'border-l-red-500',
        };
      case 'High':
        return {
          badge: 'bg-amber-950/80 text-amber-400 border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.2)]',
          dot: 'bg-amber-500',
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />,
          scoreColor: 'text-amber-400',
          accentBorder: 'border-l-amber-500',
        };
      case 'Medium':
        return {
          badge: 'bg-yellow-950/80 text-yellow-300 border-yellow-500/50',
          dot: 'bg-yellow-400',
          icon: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />,
          scoreColor: 'text-yellow-400',
          accentBorder: 'border-l-yellow-500',
        };
      case 'Low':
      default:
        return {
          badge: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/50',
          dot: 'bg-emerald-400',
          icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />,
          scoreColor: 'text-emerald-400',
          accentBorder: 'border-l-emerald-500',
        };
    }
  };

  const style = getSeverityStyle(severity);

  /**
   * Action handler: Dispatches tactical response units
   * 1. Updates alert status in UI immediately for responsiveness
   * 2. Sends POST request to {VITE_API_URL}/incidents/{incident_id}/dispatch
   */
  const handleDispatch = async (e) => {
    e.stopPropagation();
    console.log(`[TACTICAL COMMAND] Dispatch initiated for Incident: ${incident_id} (${zone_id})`);

    // 1. Immediately update UI state
    if (onUpdateStatus) {
      onUpdateStatus(incident_id, 'dispatched', { dispatch_ts: new Date().toISOString() });
    }

    // 2. Send POST request to backend API
    setIsDispatching(true);
    try {
      const url = `${apiUrl}/incidents/${encodeURIComponent(incident_id)}/dispatch`;
      console.log(`[API POST] Dispatch request sending to: ${url}`);
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        console.warn(`[API] Dispatch returned status ${response.status} for ${incident_id}`);
      } else {
        const result = await response.json();
        console.log(`[API] Dispatch response received:`, result);
      }
    } catch (err) {
      console.error(`[API ERROR] Failed to connect to ${apiUrl}/incidents/${incident_id}/dispatch:`, err);
    } finally {
      setIsDispatching(false);
    }
  };

  /**
   * Action handler: Marks incident as false positive
   * 1. Updates alert status in UI immediately for responsiveness
   * 2. Sends POST to {VITE_API_URL}/incidents/{incident_id}/feedback with body {"verdict": "false_positive"}
   */
  const handleFalsePositive = async (e) => {
    e.stopPropagation();
    console.log(`[TACTICAL COMMAND] Marking as False Positive: ${incident_id} (${zone_id})`);

    // 1. Immediately update UI state
    if (onUpdateStatus) {
      onUpdateStatus(incident_id, 'false_positive');
    }

    // 2. Send POST request with feedback body
    setIsMarkingFP(true);
    try {
      const url = `${apiUrl}/incidents/${encodeURIComponent(incident_id)}/feedback`;
      console.log(`[API POST] Feedback sending to: ${url}`);
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict: 'false_positive' }),
      });

      if (!response.ok) {
        console.warn(`[API] Feedback returned status ${response.status} for ${incident_id}`);
      } else {
        const result = await response.json();
        console.log(`[API] Feedback confirmed:`, result);
      }
    } catch (err) {
      console.error(`[API ERROR] Failed to connect to ${apiUrl}/incidents/${incident_id}/feedback:`, err);
    } finally {
      setIsMarkingFP(false);
    }
  };

  const isDispatched = status === 'dispatched';
  const isFalsePositive = status === 'false_positive';

  return (
    <div
      onClick={() => onSelect(alert)}
      className={`group relative p-4 rounded-lg cursor-pointer transition-all duration-200 border-l-4 ${style.accentBorder} ${
        isFalsePositive ? 'opacity-60 bg-slate-950/40' : ''
      } ${
        isSelected
          ? 'bg-slate-900/90 border-slate-700 ring-2 ring-red-500/60 shadow-[0_0_20px_rgba(239,68,68,0.15)]'
          : 'bg-slate-900/60 hover:bg-slate-900/90 border-t border-r border-b border-slate-800 hover:border-slate-700'
      }`}
    >
      {/* Top Header of Card: Incident ID & Severity Badge */}
      <div className="flex items-center justify-between gap-2 mb-2.5">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs font-semibold text-slate-400 uppercase tracking-wider bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
            {incident_id}
          </span>
          <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>{timestamp}</span>
          </div>
          {isDispatched && (
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/40 flex items-center gap-1">
              <Check className="w-2.5 h-2.5" />
              DISPATCHED
            </span>
          )}
          {isFalsePositive && (
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
              FALSE POSITIVE
            </span>
          )}
        </div>

        {/* Severity Badge */}
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold font-mono tracking-wide border shrink-0 ${style.badge}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
          {style.icon}
          {severity.toUpperCase()}
        </span>
      </div>

      {/* Main Body: Zone Name & Large Threat Score */}
      <div className="flex items-start justify-between gap-4 my-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1 font-mono uppercase tracking-wider">
            <MapPin className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <span>Target Zone</span>
          </div>
          <h3 className="text-base font-semibold text-slate-100 group-hover:text-red-400 transition-colors truncate">
            {zone_id}
          </h3>
          {alert.description && (
            <p className="text-xs text-slate-400 mt-1 line-clamp-1 font-sans">
              {alert.description}
            </p>
          )}
        </div>

        {/* Big Threat Score */}
        <div className="text-right shrink-0">
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest leading-none">
            THREAT SCORE
          </div>
          <div className={`text-3xl font-extrabold font-mono tracking-tight ${style.scoreColor}`}>
            {score}
            <span className="text-xs text-slate-600 font-normal ml-0.5">/100</span>
          </div>
        </div>
      </div>

      {/* Action Buttons: Dispatch & Mark False Positive */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center gap-2 justify-end flex-wrap">
        {/* False Positive Button */}
        <button
          type="button"
          onClick={handleFalsePositive}
          disabled={isMarkingFP || isFalsePositive}
          title="Mark alert as false positive (POST /incidents/{id}/feedback)"
          className={`px-2.5 py-1.5 rounded text-xs font-mono uppercase tracking-wider border transition-colors flex items-center gap-1.5 active:scale-95 ${
            isFalsePositive
              ? 'bg-slate-900 text-slate-500 border-slate-800 cursor-not-allowed'
              : 'bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border-slate-800 hover:border-slate-700'
          }`}
        >
          <XOctagon className="w-3.5 h-3.5 text-slate-400" />
          <span>{isFalsePositive ? 'Marked FP' : isMarkingFP ? 'Sending...' : 'False Positive'}</span>
        </button>

        {/* Red Dispatch Button */}
        <button
          type="button"
          onClick={handleDispatch}
          disabled={isDispatching || isDispatched}
          title="Dispatch tactical unit (POST /incidents/{id}/dispatch)"
          className={`px-3 py-1.5 rounded text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 active:scale-95 ${
            isDispatched
              ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-500/40 shadow-sm cursor-not-allowed'
              : 'bg-red-600 hover:bg-red-500 text-white shadow-md shadow-red-950/50 hover:shadow-red-600/30'
          }`}
        >
          {isDispatched ? (
            <>
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Dispatched</span>
            </>
          ) : (
            <>
              <Siren className={`w-3.5 h-3.5 ${isDispatching ? 'animate-spin' : ''}`} />
              <span>{isDispatching ? 'Dispatching...' : 'Dispatch'}</span>
            </>
          )}
        </button>
      </div>

      {/* Selected Indicator Pill */}
      {isSelected && (
        <div className="absolute -right-1 top-1/2 -translate-y-1/2 bg-red-500 w-1.5 h-8 rounded-l-full shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
      )}
    </div>
  );
}
