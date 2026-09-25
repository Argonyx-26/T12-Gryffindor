import React from 'react';
import { AlertCircle, AlertTriangle, Info, CheckCircle2, Siren, XOctagon, Clock, MapPin } from 'lucide-react';

/**
 * AlertCard Component
 * 
 * Represents an individual threat detection incident card within the Live Alert Feed.
 * 
 * Props:
 * - alert: The incident data object (incident_id, zone_id, score, severity, timestamp)
 * - isSelected: Boolean indicating whether this card is currently selected for evidence inspection
 * - onSelect: Callback function invoked when the card is clicked
 */
export default function AlertCard({ alert, isSelected, onSelect }) {
  const { incident_id, zone_id, score, severity, timestamp } = alert;

  /**
   * Helper function to return styling classes and icons tailored to the severity level.
   * - Critical: Red/Crimson
   * - High: Amber/Orange
   * - Medium: Yellow
   * - Low: Green/Emerald
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
   * Logs to console as specified in requirements.
   */
  const handleDispatch = (e) => {
    // stopPropagation prevents the parent card's onClick from triggering
    e.stopPropagation();
    console.log(`[TACTICAL COMMAND] Dispatch initiated for Incident: ${incident_id} (${zone_id})`);
    alertUserAction(`Dispatched emergency tactical response team to ${zone_id}`);
  };

  /**
   * Action handler: Marks incident as false positive
   * Logs to console as specified in requirements.
   */
  const handleFalsePositive = (e) => {
    e.stopPropagation();
    console.log(`[TACTICAL COMMAND] Marked as False Positive: ${incident_id} (${zone_id})`);
    alertUserAction(`Incident ${incident_id} marked as False Positive. Telemetry flagged.`);
  };

  // Quick feedback helper for demonstration
  const alertUserAction = (msg) => {
    console.info(`Action Logged: ${msg}`);
  };

  return (
    <div
      onClick={() => onSelect(alert)}
      className={`group relative p-4 rounded-lg cursor-pointer transition-all duration-200 border-l-4 ${style.accentBorder} ${
        isSelected
          ? 'bg-slate-900/90 border-slate-700 ring-2 ring-red-500/60 shadow-[0_0_20px_rgba(239,68,68,0.15)]'
          : 'bg-slate-900/60 hover:bg-slate-900/90 border-t border-r border-b border-slate-800 hover:border-slate-700'
      }`}
    >
      {/* Top Header of Card: Incident ID & Severity Badge */}
      <div className="flex items-center justify-between gap-2 mb-2.5">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold text-slate-400 uppercase tracking-wider bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
            {incident_id}
          </span>
          <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>{timestamp}</span>
          </div>
        </div>

        {/* Severity Badge */}
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold font-mono tracking-wide border ${style.badge}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
          {style.icon}
          {severity.toUpperCase()}
        </span>
      </div>

      {/* Main Body: Zone Name & Large Threat Score */}
      <div className="flex items-start justify-between gap-4 my-2">
        <div className="flex-1">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1 font-mono uppercase tracking-wider">
            <MapPin className="w-3.5 h-3.5 text-slate-500" />
            <span>Target Zone</span>
          </div>
          <h3 className="text-base font-semibold text-slate-100 group-hover:text-red-400 transition-colors">
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
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center gap-2 justify-end">
        {/* False Positive Button */}
        <button
          type="button"
          onClick={handleFalsePositive}
          title="Mark alert as false positive"
          className="px-2.5 py-1.5 rounded text-xs font-mono uppercase tracking-wider bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 transition-colors flex items-center gap-1.5 active:scale-95"
        >
          <XOctagon className="w-3.5 h-3.5 text-slate-400" />
          <span>False Positive</span>
        </button>

        {/* Red Dispatch Button */}
        <button
          type="button"
          onClick={handleDispatch}
          title="Dispatch tactical security unit"
          className="px-3 py-1.5 rounded text-xs font-mono font-bold uppercase tracking-wider bg-red-600 hover:bg-red-500 text-white shadow-md shadow-red-950/50 hover:shadow-red-600/30 transition-all flex items-center gap-1.5 active:scale-95"
        >
          <Siren className="w-3.5 h-3.5" />
          <span>Dispatch</span>
        </button>
      </div>

      {/* Selected Indicator Pill */}
      {isSelected && (
        <div className="absolute -right-1 top-1/2 -translate-y-1/2 bg-red-500 w-1.5 h-8 rounded-l-full shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
      )}
    </div>
  );
}
