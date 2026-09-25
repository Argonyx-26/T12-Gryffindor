import React from 'react';
import AlertCard from './AlertCard';
import { Flame, Bell, Filter } from 'lucide-react';

/**
 * LiveAlertFeed Component
 * 
 * Purpose:
 * Renders the tactical feed of incoming threat detection events.
 * 
 * Props:
 * - alerts: Array of alert objects
 * - selectedAlertId: Currently inspected incident_id (for highlighting)
 * - onSelectAlert: Function to handle selecting an alert to display in Evidence Drawer
 */
export default function LiveAlertFeed({ alerts, selectedAlertId, onSelectAlert }) {
  return (
    <section className="bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-xl">
      {/* Panel Tactical Header */}
      <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Flame className="w-4 h-4 text-red-500 animate-pulse" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 animate-ping" />
          </div>
          <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
            LIVE ALERT FEED
          </h2>
          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-full bg-red-950/80 text-red-400 border border-red-500/30">
            {alerts.length} ACTIVE
          </span>
        </div>

        {/* Tactical status badge */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400 hidden sm:inline-block">
            STREAM: ACTIVE
          </span>
          <div className="w-2 h-2 rounded-full bg-emerald-500" />
        </div>
      </div>

      {/* Feed List Container */}
      <div className="p-3.5 space-y-3 overflow-y-auto max-h-[520px]">
        {alerts.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
            No active threat alerts in queue.
          </div>
        ) : (
          alerts.map((alert) => (
            <AlertCard
              key={alert.incident_id}
              alert={alert}
              isSelected={selectedAlertId === alert.incident_id}
              onSelect={onSelectAlert}
            />
          ))
        )}
      </div>

      {/* Panel Footer / Quick Tip */}
      <div className="bg-slate-900/40 px-4 py-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 flex items-center justify-between">
        <span>TIP: Click any card to inspect Evidence Drawer</span>
        <span className="text-slate-400 font-mono">SENSORS: 4/4 SYNC</span>
      </div>
    </section>
  );
}
