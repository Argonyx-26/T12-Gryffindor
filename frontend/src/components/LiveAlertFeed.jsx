import React from 'react';
import AlertCard from './AlertCard';
import { Flame, RefreshCw, Radio, Wifi, WifiOff, ShieldCheck, Trash2 } from 'lucide-react';

/**
 * LiveAlertFeed Component
 * 
 * Purpose:
 * Renders the tactical feed of incoming threat detection events received from the WebSocket.
 * 
 * Props:
 * - alerts: Array of live alert objects (most recent first)
 * - selectedAlertId: Currently inspected incident_id (for card border highlight)
 * - onSelectAlert: Function to handle selecting an alert to display in Evidence Drawer
 * - onUpdateStatus: Function to update an incident status locally (Dispatch / False Positive)
 * - onClearAlerts: Function to purge/dismiss active alerts and reset feed to nominal
 * - connectionStatus: 'connected' | 'reconnecting' | 'disconnected'
 * - isConnected: Boolean indicating live WebSocket connection
 */
export default function LiveAlertFeed({
  alerts,
  selectedAlertId,
  onSelectAlert,
  onUpdateStatus,
  onClearAlerts,
  onLoadDemoAlerts,
  connectionStatus = 'reconnecting',
  isConnected = false,
}) {
  return (
    <section className="bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-xl">
      {/* Panel Tactical Header */}
      <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Flame className="w-4 h-4 text-red-500 animate-pulse" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 animate-ping" />
          </div>
          <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
            LIVE ALERT FEED
          </h2>
          <span className={`text-xs font-mono font-semibold px-2 py-0.5 rounded-full border ${
            alerts.length === 0
              ? 'bg-emerald-950/70 text-emerald-400 border-emerald-500/40'
              : 'bg-red-950/80 text-red-400 border-red-500/30'
          }`}>
            {alerts.length === 0 ? '0 ACTIVE // NOMINAL' : `${alerts.length} ACTIVE`}
          </span>
        </div>

        {/* Action Controls & Live Status Indicator */}
        <div className="flex items-center gap-2">
          {/* Quick Clear Feed Action */}
          {alerts.length > 0 && onClearAlerts && (
            <button
              type="button"
              onClick={onClearAlerts}
              title="Clear active feed and reset dashboard to nominal standby"
              className="px-2.5 py-1 rounded bg-slate-900/90 hover:bg-red-950/80 text-slate-400 hover:text-red-400 border border-slate-800 hover:border-red-500/40 text-xs font-mono flex items-center gap-1.5 transition-all active:scale-95 shadow-sm"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Feed</span>
            </button>
          )}

          {isConnected ? (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 font-mono text-xs shadow-[0_0_10px_rgba(16,185,129,0.2)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              <span className="font-bold tracking-wider">Live</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/80 border border-amber-500/40 text-amber-400 font-mono text-xs animate-pulse shadow-[0_0_10px_rgba(245,158,11,0.2)]">
              <RefreshCw className="w-3 h-3 animate-spin" />
              <span className="font-semibold tracking-wider capitalize">{connectionStatus}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Feed List Container */}
      <div className="p-3.5 space-y-3 overflow-y-auto max-h-[520px]">
        {alerts.length === 0 ? (
          <div className="p-8 text-center border border-emerald-500/20 bg-emerald-950/10 rounded-xl space-y-4 my-2 transition-all duration-300">
            <div className="relative mx-auto w-14 h-14 flex items-center justify-center rounded-full bg-emerald-950/60 border border-emerald-500/40 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
              <ShieldCheck className="w-7 h-7 text-emerald-400" />
              <span className="absolute -top-0.5 -right-0.5 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
              </span>
            </div>
            <div className="space-y-1.5">
              <p className="font-mono font-bold text-emerald-300 text-sm tracking-wider uppercase">
                No active threats — systems nominal
              </p>
              <p className="text-slate-400 text-xs font-sans max-w-sm mx-auto leading-relaxed">
                Perimeter sensors, CCTV optical feeds, and AI correlation are actively armed. Incoming threats will appear here in real time.
              </p>
            </div>
            <div className="pt-2 flex flex-col items-center gap-3">
              {onLoadDemoAlerts && (
                <button
                  type="button"
                  onClick={onLoadDemoAlerts}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-300 font-mono text-xs font-semibold cursor-pointer shadow hover:scale-105 active:scale-95 transition-all flex items-center gap-1.5"
                >
                  <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                  <span>Load Demo Threat Feed</span>
                </button>
              )}
              <div className="flex items-center justify-center gap-4 text-[11px] font-mono text-slate-500 border-t border-slate-800/60 pt-2 w-full">
                <span className="flex items-center gap-1.5 text-emerald-400/80">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  SENSORS ARMED
                </span>
                <span>•</span>
                <span className="flex items-center gap-1.5 text-cyan-400/80">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  AI ENGINE ACTIVE
                </span>
              </div>
            </div>
          </div>
        ) : (
          alerts.map((alert) => (
            <AlertCard
              key={alert.incident_id}
              alert={alert}
              isSelected={selectedAlertId === alert.incident_id}
              onSelect={onSelectAlert}
              onUpdateStatus={onUpdateStatus}
            />
          ))
        )}
      </div>

      {/* Panel Footer / Status Ticker */}
      <div className="bg-slate-900/40 px-4 py-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 flex items-center justify-between">
        <span>TIP: Click any card to inspect Evidence Drawer</span>
        <span className="text-slate-400 font-mono flex items-center gap-1.5">
          {isConnected ? (
            <>
              <Wifi className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400 font-bold">LIVE</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3 h-3 text-amber-400 animate-pulse" />
              <span className="text-amber-400 font-bold animate-pulse">RECONNECTING</span>
            </>
          )}
        </span>
      </div>
    </section>
  );
}
