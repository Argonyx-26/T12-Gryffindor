import React, { useState, useMemo } from 'react';
import Header from './components/Header';
import LiveAlertFeed from './components/LiveAlertFeed';
import EvidenceDrawer from './components/EvidenceDrawer';
import MapPanel from './components/MapPanel';
import ActiveResponsePanel from './components/ActiveResponsePanel';
import { useAlertSocket } from './hooks/useAlertSocket';
import { Shield, AlertTriangle, Cpu, Radio } from 'lucide-react';

/**
 * App Component - Root Dashboard for Gryffindor
 * 
 * Architecture Overview:
 * 1. Live Data Source:
 *    - Connects to the backend WebSocket stream via `useAlertSocket` hook.
 *    - Automatically handles JSON parsing, prepending new alerts (most recent first),
 *      and auto-reconnecting every 3 seconds if disconnected.
 * 
 * 2. Visual Layout:
 *    - Header: Top navigation bar with tactical title, live ticking clock, and WS status.
 *    - Status Bar: Real-time telemetry indicators reflecting live threat count.
 *    - Main Body:
 *      - Left Column (Live Alert Feed & Evidence Drawer directly below it).
 *      - Right Column (Geospatial Tactical Map placeholder).
 *    - Footer: Bottom telemetry ticker showing system protocol status.
 */
export default function App() {
  // Connect to the real-time WebSocket alert stream
  const { alerts, clearAlerts, isConnected, connectionStatus, updateAlertStatus, wsUrl, apiUrl, loadMockAlerts } = useAlertSocket();

  // Track the ID of the currently selected incident card for inspection in Evidence Drawer
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  // Track whether the Evidence Drawer is open or collapsed
  const [isDrawerOpen, setIsDrawerOpen] = useState(true);

  // Derive the active alert object from the live list.
  // If user selected an ID, find it in the current alerts list (ensuring updated status is reflected).
  // If none explicitly selected, automatically select the most recent alert (index 0).
  const activeAlert = useMemo(() => {
    if (alerts.length === 0) return null;
    if (selectedAlertId) {
      const match = alerts.find((a) => a.incident_id === selectedAlertId);
      if (match) return match;
    }
    // Default to the first (most recent) incoming alert
    return alerts[0] || null;
  }, [alerts, selectedAlertId]);

  // Handler when user clicks an alert card in the feed, map marker, or "VIEW EVIDENCE" on Active Response Panel
  const handleSelectAlert = (alert) => {
    if (!alert) return;
    setSelectedAlertId(alert.incident_id);
    setIsDrawerOpen(true);
    // Smoothly scroll down to the Evidence Drawer
    setTimeout(() => {
      const el = document.getElementById('evidence-drawer');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }, 50);
  };

  // Handler to close or collapse the evidence drawer
  const handleCloseDrawer = () => {
    setIsDrawerOpen(false);
  };

  // Compute threat posture dynamically from live alerts (excluding false positives and resolved)
  const activeAlerts = alerts.filter(a => {
    const s = String(a.status || '').toLowerCase();
    return s !== 'false_positive' && s !== 'resolved' && s !== 'closed';
  });
  const criticalCount = activeAlerts.filter(a => String(a.severity || '').toLowerCase() === 'critical' || Number(a.score) >= 85).length;
  const highCount = activeAlerts.filter(a => String(a.severity || '').toLowerCase() === 'high' || (Number(a.score) >= 70 && Number(a.score) < 85)).length;
  const threatPosture = criticalCount > 0
    ? 'DEFCON 1 // CRITICAL'
    : highCount > 0
    ? 'DEFCON 2 // ELEVATED'
    : activeAlerts.length > 0
    ? 'DEFCON 3 // WATCH'
    : 'DEFCON 4 // NOMINAL';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-red-600 selection:text-white">
      
      {/* 1. Tactical Header with Live Clock & WebSocket Indicator */}
      <Header isConnected={isConnected} threatPosture={threatPosture} apiUrl={apiUrl} wsUrl={wsUrl} />

      {/* 2. Main Dashboard Content Grid */}
      <main className="flex-1 max-w-[1920px] w-full mx-auto p-4 md:p-6 flex flex-col gap-6">
        
        {/* Full-Width Active Emergency Response Panel (Appears only on active Critical/High alerts) */}
        <ActiveResponsePanel
          alerts={alerts}
          onSelectAlert={handleSelectAlert}
          onUpdateStatus={updateAlertStatus}
          apiUrl={apiUrl}
        />

        {/* Top Operational Status Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className={`p-2 rounded border ${
              activeAlerts.length > 0
                ? 'bg-red-950/60 border-red-500/30 text-red-400'
                : 'bg-emerald-950/60 border-emerald-500/30 text-emerald-400'
            }`}>
              {activeAlerts.length > 0 ? <AlertTriangle className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">ACTIVE INCIDENTS</span>
              <span className={`text-sm font-bold font-mono ${
                activeAlerts.length > 0 ? 'text-slate-200' : 'text-emerald-400'
              }`}>
                {activeAlerts.length === 0 ? '0 THREATS // NOMINAL' : `${activeAlerts.length} ${activeAlerts.length === 1 ? 'THREAT' : 'THREATS'}`}
              </span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className={`p-2 rounded border ${
              criticalCount > 0
                ? 'bg-red-950/60 border-red-500/40 text-red-400'
                : highCount > 0
                ? 'bg-amber-950/60 border-amber-500/30 text-amber-400'
                : 'bg-emerald-950/60 border-emerald-500/30 text-emerald-400'
            }`}>
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">DEFENSE POSTURE</span>
              <span className={`text-sm font-bold font-mono ${
                criticalCount > 0
                  ? 'text-red-400'
                  : highCount > 0
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}>
                {threatPosture}
              </span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className="p-2 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">AI CORRELATION ENGINE</span>
              <span className="text-sm font-bold font-mono text-cyan-400">FUSION ACTIVE</span>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg flex items-center gap-3">
            <div className={`p-2 rounded border ${
              isConnected
                ? 'bg-emerald-950/60 border-emerald-500/30 text-emerald-400'
                : 'bg-amber-950/60 border-amber-500/30 text-amber-400 animate-pulse'
            }`}>
              <Radio className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] text-slate-500 font-mono block">LIVE BACKEND SYNC</span>
              <span className={`text-sm font-bold font-mono ${
                isConnected ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {isConnected ? 'LIVE' : 'RECONNECTING (3s)'}
              </span>
            </div>
          </div>
        </div>

        {/* Tactical Panels Layout: Left (Live Feed + Evidence Drawer) | Right (Map Panel) */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column: Live Alert Feed + Evidence Drawer (5 cols on lg) */}
          <div className="lg:col-span-5 flex flex-col gap-5">
            {/* Live Alert Feed Connected to useAlertSocket */}
            <LiveAlertFeed
              alerts={alerts}
              selectedAlertId={isDrawerOpen && activeAlert ? activeAlert.incident_id : null}
              onSelectAlert={handleSelectAlert}
              onUpdateStatus={updateAlertStatus}
              onClearAlerts={clearAlerts}
              onLoadDemoAlerts={loadMockAlerts}
              connectionStatus={connectionStatus}
              isConnected={isConnected}
            />

            {/* Evidence Drawer (renders below the alert feed) */}
            <EvidenceDrawer
              selectedAlert={isDrawerOpen ? activeAlert : null}
              onClose={handleCloseDrawer}
              apiUrl={apiUrl}
            />
          </div>

          {/* Right Column: Situational Map Panel (7 cols on lg) */}
          <div className="lg:col-span-7 h-full">
            <MapPanel
              alerts={alerts}
              selectedAlert={activeAlert}
              onSelectAlert={handleSelectAlert}
              apiUrl={apiUrl}
            />
          </div>

        </div>

      </main>

      {/* 3. Bottom Tactical Status Ticker */}
      <footer className="bg-slate-950 border-t border-slate-900 px-4 py-2 text-[11px] font-mono text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-slate-400">GRYFFINDOR KERNEL v2.4</span>
          <span className="text-slate-700">|</span>
          <span className="text-slate-400">CONFIG:</span>
          <span className="text-cyan-400">API: {apiUrl}</span>
          <span className="text-slate-700">|</span>
          <span className="text-cyan-400">WS: {wsUrl}</span>
        </div>
        <div className="text-slate-600">
          SECURE PROTOCOL CLASSIFIED // INTERNAL COMMAND AUTHORIZED
        </div>
      </footer>

    </div>
  );
}
