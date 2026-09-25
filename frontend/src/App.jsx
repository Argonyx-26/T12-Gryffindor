import React, { useState } from 'react';
import Header from './components/Header';
import LiveAlertFeed from './components/LiveAlertFeed';
import EvidenceDrawer from './components/EvidenceDrawer';
import MapPanel from './components/MapPanel';
import { INITIAL_ALERTS } from './data/mockAlerts';
import { Shield, AlertTriangle, Cpu, HardDrive } from 'lucide-react';

/**
 * App Component - Root Dashboard for Gryffindor Sentinel
 * 
 * Architecture Overview:
 * 1. Global State:
 *    - `alerts`: List of active threat events (initialized with mockAlerts)
 *    - `selectedAlert`: Currently inspected alert object. When an alert card is clicked,
 *      this state updates, which slides/expands the EvidenceDrawer below the alert feed.
 * 
 * 2. Visual Layout:
 *    - Header: Top navigation bar with tactical title, live ticking clock, and defense stats.
 *    - Main Body (Two columns on desktop, stacked on mobile):
 *      - Left Column (Live Alert Feed & Evidence Drawer directly below it).
 *      - Right Column (Geospatial Tactical Map placeholder).
 *    - Status Bar: Bottom telemetry footer showing system health.
 */
export default function App() {
  // Store alerts array in state so new alerts can easily be appended or filtered
  const [alerts, setAlerts] = useState(INITIAL_ALERTS);

  // Track which alert is currently clicked/selected for the Evidence Drawer.
  // Pre-select the first alert (Critical) so the user immediately sees the rich details.
  const [selectedAlert, setSelectedAlert] = useState(INITIAL_ALERTS[0]);

  // Handler when user clicks an alert card in the feed
  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
  };

  // Handler to close or collapse the evidence drawer
  const handleCloseDrawer = () => {
    setSelectedAlert(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-red-600 selection:text-white">
      
      {/* 1. Tactical Header with Live Clock */}
      <Header />

      {/* 2. Main Dashboard Content Grid */}
      <main className="flex-1 max-w-[1920px] w-full mx-auto p-4 md:p-6 flex flex-col gap-6">
        
        {/* Top Operational Status Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className="p-2 rounded bg-red-950/60 border border-red-500/30 text-red-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">ACTIVE INCIDENTS</span>
              <span className="text-sm font-bold font-mono text-slate-200">{alerts.length} THREATS</span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className="p-2 rounded bg-amber-950/60 border border-amber-500/30 text-amber-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">DEFENSE POSTURE</span>
              <span className="text-sm font-bold font-mono text-amber-400">LEVEL 2 ELEVATED</span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className="p-2 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">AI THREAT ENGINE</span>
              <span className="text-sm font-bold font-mono text-cyan-400">INFERENCE: 18ms</span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className="p-2 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
              <HardDrive className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">DATABASE REPLICATION</span>
              <span className="text-sm font-bold font-mono text-emerald-400">SYNCHRONIZED</span>
            </div>
          </div>
        </div>

        {/* Tactical Panels Layout: Left (Feed + Evidence Drawer) | Right (Map Panel) */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column: Live Alert Feed + Evidence Drawer (5 cols on lg, 5 on xl) */}
          <div className="lg:col-span-5 flex flex-col gap-5">
            {/* Live Alert Feed */}
            <LiveAlertFeed
              alerts={alerts}
              selectedAlertId={selectedAlert ? selectedAlert.incident_id : null}
              onSelectAlert={handleSelectAlert}
            />

            {/* Evidence Drawer (renders below the alert feed) */}
            <EvidenceDrawer
              selectedAlert={selectedAlert}
              onClose={handleCloseDrawer}
            />
          </div>

          {/* Right Column: Situational Map Panel (7 cols on lg, 7 on xl) */}
          <div className="lg:col-span-7 h-full">
            <MapPanel />
          </div>

        </div>

      </main>

      {/* 3. Bottom Tactical Status Ticker */}
      <footer className="bg-slate-950 border-t border-slate-900 px-4 py-2 text-[11px] font-mono text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="text-slate-400">GRYFFINDOR KERNEL v2.4</span>
          <span className="text-slate-700">|</span>
          <span className="text-emerald-400">ALL SUBSYSTEMS NOMINAL</span>
        </div>
        <div className="text-slate-600">
          SECURE PROTOCOL CLASSIFIED // INTERNAL COMMAND AUTHORIZED
        </div>
      </footer>

    </div>
  );
}
