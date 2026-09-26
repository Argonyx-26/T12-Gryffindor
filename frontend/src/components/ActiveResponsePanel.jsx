import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { 
  Siren, 
  Send, 
  BellRing, 
  Eye, 
  CheckCircle2, 
  ChevronRight, 
  Radio 
} from 'lucide-react';

/**
 * ActiveResponsePanel Component
 * 
 * Full-width emergency banner that renders at the top of the dashboard ONLY
 * when there is at least one active Critical or High severity incident (open or dispatched).
 * 
 * Features:
 * 1. Bold, high-contrast alarm style (red pulsing for Critical, orange for High).
 * 2. Large text: "INTRUSION DETECTED — [ZONE NAME]" with corroborated sources list.
 * 3. Audible sound via Web Audio API synth played ONCE when a new Critical/High alert arrives.
 * 4. Three quick-action buttons:
 *    - DISPATCH SECURITY (calls /incidents/{id}/dispatch)
 *    - NOTIFY ALL ZONES (visual broadcast confirmation)
 *    - VIEW EVIDENCE (opens incident in Evidence Drawer)
 * 5. Counter for multiple active threats (e.g. "+2 more active").
 * 6. Smooth enter / exit animations.
 */
export default function ActiveResponsePanel({
  alerts = [],
  onSelectAlert = () => {},
  onUpdateStatus = () => {},
  apiUrl = 'http://localhost:8000',
}) {
  const [isDispatching, setIsDispatching] = useState(false);
  const [isNotified, setIsNotified] = useState(false);

  // 1. Filter only active Critical or High severity incidents
  // Shows for status "open" OR "dispatched", and only hides when status becomes "false_positive" or fully resolved
  const activeUrgentIncidents = useMemo(() => {
    if (!Array.isArray(alerts)) return [];
    return alerts.filter((a) => {
      if (!a) return false;
      const sev = String(a.severity || '').trim().toLowerCase();
      const score = Number(a.score) || 0;
      const isUrgent = sev === 'critical' || sev === 'high' || score >= 70;

      const status = String(a.status || 'open').trim().toLowerCase();
      const isResolved = status === 'false_positive' || status === 'resolved' || status === 'closed';
      const isOpenOrDispatched = status === 'open' || status === 'dispatched' || status === 'true_positive';

      return isUrgent && isOpenOrDispatched && !isResolved;
    });
  }, [alerts]);

  // 2. Select the most prominent incident (Critical first, then highest score)
  const primaryIncident = useMemo(() => {
    if (!activeUrgentIncidents || activeUrgentIncidents.length === 0) return null;
    return [...activeUrgentIncidents].sort((a, b) => {
      const aIsCrit = String(a.severity || '').toLowerCase() === 'critical' || Number(a.score) >= 85;
      const bIsCrit = String(b.severity || '').toLowerCase() === 'critical' || Number(b.score) >= 85;
      if (aIsCrit && !bIsCrit) return -1;
      if (bIsCrit && !aIsCrit) return 1;
      return (Number(b.score) || 0) - (Number(a.score) || 0);
    })[0] || null;
  }, [activeUrgentIncidents]);

  // 3. Audio Alert (Web Audio API synth - played ONCE per new incident ID)
  const playAlertSound = useCallback(() => {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const now = ctx.currentTime;

      // Create dual-tone warble siren
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      // First siren chirp
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(580, now + 0.16);
      // Second siren chirp
      osc.frequency.setValueAtTime(920, now + 0.20);
      osc.frequency.exponentialRampToValueAtTime(620, now + 0.38);

      gain.gain.setValueAtTime(0.18, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.40);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + 0.40);
    } catch {
      // Audio playback blocked or unavailable in silent environment
    }
  }, []);

  const seenIncidentIdsRef = useRef(new Set());

  useEffect(() => {
    if (!activeUrgentIncidents || activeUrgentIncidents.length === 0) return;
    const unnotified = activeUrgentIncidents.filter(
      (inc) => !seenIncidentIdsRef.current.has(inc.incident_id)
    );

    if (unnotified.length > 0) {
      playAlertSound();
      unnotified.forEach((inc) => seenIncidentIdsRef.current.add(inc.incident_id));
    }
  }, [activeUrgentIncidents, playAlertSound]);

  // If no active Critical/High incidents, completely hide the panel
  if (activeUrgentIncidents.length === 0 || !primaryIncident) {
    return null;
  }

  const additionalCount = activeUrgentIncidents.length - 1;
  const isCritical = String(primaryIncident.severity || '').toLowerCase() === 'critical' || Number(primaryIncident.score) >= 85;


  // Format zone name and corroborated sources text
  const zoneName = primaryIncident.zone_id
    ? primaryIncident.zone_id.replace(/_/g, ' ').toUpperCase()
    : 'RESTRICTED SECTOR';

  const sourcesList = Array.isArray(primaryIncident.sources)
    ? primaryIncident.sources.map(s => String(s).toUpperCase())
    : (primaryIncident.source_type ? [String(primaryIncident.source_type).toUpperCase()] : []);

  const sourcesText = sourcesList.length >= 2
    ? `${sourcesList.join(' + ')} CONFIRMED`
    : sourcesList.length === 1
    ? `${sourcesList[0]} SENSOR CONFIRMED`
    : 'MULTIMODAL ANOMALY CONFIRMED';

  // Action: Dispatch Security Units
  const handleDispatch = async () => {
    if (!primaryIncident) return;
    setIsDispatching(true);
    
    // Update local state immediately for instant feedback
    if (onUpdateStatus) {
      onUpdateStatus(primaryIncident.incident_id, 'dispatched', {
        dispatch_ts: new Date().toISOString(),
      });
    }

    try {
      const baseUrl = (apiUrl || 'http://localhost:8000').replace(/\/+$/, '');
      const url = `${baseUrl}/incidents/${encodeURIComponent(primaryIncident.incident_id)}/dispatch`;
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err) {
      console.error('[ActiveResponsePanel] Dispatch error:', err);
    } finally {
      setIsDispatching(false);
    }
  };

  // Action: Broadcast Alert Notification to All Zones
  const handleNotifyAll = () => {
    setIsNotified(true);
    setTimeout(() => {
      setIsNotified(false);
    }, 4500);
  };

  // Action: View Incident Evidence Dossier
  const handleViewEvidence = () => {
    if (onSelectAlert && primaryIncident) {
      onSelectAlert(primaryIncident);
    }
    const drawerEl = document.getElementById('evidence-drawer');
    if (drawerEl) {
      drawerEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  };

  const isDispatched = String(primaryIncident.status || '').toLowerCase() === 'dispatched';

  return (
    <div
      role="alert"
      className={`w-full rounded-xl p-4 md:p-5 border-2 shadow-2xl transition-all duration-300 animate-in fade-in slide-in-from-top-4 relative overflow-hidden ${
        isCritical
          ? 'bg-gradient-to-r from-red-950/95 via-red-900/85 to-slate-950/95 border-red-500 shadow-[0_0_35px_rgba(239,68,68,0.45)]'
          : 'bg-gradient-to-r from-orange-950/95 via-amber-950/85 to-slate-950/95 border-orange-500 shadow-[0_0_35px_rgba(249,115,22,0.45)]'
      }`}
    >
      {/* Background Animated Strobe Stripe */}
      <div 
        className="absolute inset-0 opacity-15 pointer-events-none"
        style={{
          backgroundImage: 'repeating-linear-gradient(45deg, rgba(255,255,255,0.1), rgba(255,255,255,0.1) 15px, transparent 15px, transparent 30px)'
        }}
      />

      <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left Side: Alarm Icon & Large Banner Title */}
        <div className="flex items-start md:items-center gap-3.5">
          <div className={`p-3 rounded-lg flex items-center justify-center shrink-0 border ${
            isCritical
              ? 'bg-red-600 text-white border-red-400 animate-pulse shadow-[0_0_18px_rgba(239,68,68,0.8)]'
              : 'bg-orange-500 text-slate-950 border-orange-300 animate-pulse shadow-[0_0_18px_rgba(249,115,22,0.8)]'
          }`}>
            <Siren className="w-7 h-7" />
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-black uppercase tracking-wider ${
                isCritical ? 'bg-red-600 text-white' : 'bg-orange-500 text-slate-950'
              }`}>
                {primaryIncident.severity} ALERT // SCORE {primaryIncident.score}
              </span>

              <span className="text-xs font-mono text-slate-300 bg-slate-950/80 px-2 py-0.5 rounded border border-slate-700">
                INCIDENT ID: {primaryIncident.incident_id}
              </span>

              {additionalCount > 0 && (
                <span className="text-xs font-mono font-bold bg-amber-400 text-slate-950 px-2 py-0.5 rounded-full animate-bounce">
                  +{additionalCount} MORE ACTIVE
                </span>
              )}

              {isDispatched && (
                <span className="text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/50 px-2 py-0.5 rounded flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  RESPONSE TEAM EN ROUTE
                </span>
              )}
            </div>

            <h2 className="text-lg md:text-2xl font-black font-mono tracking-tight text-white uppercase flex items-center gap-2">
              <span>INTRUSION DETECTED — {zoneName}</span>
            </h2>

            <p className="text-xs md:text-sm font-mono tracking-wider font-semibold text-slate-200 flex items-center gap-2">
              <Radio className={`w-3.5 h-3.5 ${isCritical ? 'text-red-400' : 'text-orange-400'} animate-pulse`} />
              <span className={isCritical ? 'text-red-300' : 'text-orange-300'}>
                {sourcesText}
              </span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-300 text-xs font-normal">
                {primaryIncident.timestamp || 'TRIGGERED JUST NOW'}
              </span>
            </p>
          </div>
        </div>

        {/* Right Side: Quick Action Buttons */}
        <div className="flex items-center gap-2.5 flex-wrap sm:flex-nowrap">
          {/* Action 1: DISPATCH SECURITY */}
          <button
            type="button"
            onClick={handleDispatch}
            disabled={isDispatching}
            className={`px-4 py-2.5 rounded-lg font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 shadow-lg transition-all cursor-pointer ${
              isDispatched
                ? 'bg-slate-900 border border-cyan-500/50 text-cyan-300 hover:bg-slate-800'
                : isCritical
                ? 'bg-red-600 hover:bg-red-500 text-white border border-red-400 shadow-[0_0_20px_rgba(239,68,68,0.6)] hover:scale-105 active:scale-95'
                : 'bg-orange-500 hover:bg-orange-400 text-slate-950 border border-orange-300 shadow-[0_0_20px_rgba(249,115,22,0.6)] hover:scale-105 active:scale-95'
            }`}
          >
            {isDispatched ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                <span>DISPATCHED</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span>{isDispatching ? 'DISPATCHING...' : 'DISPATCH SECURITY'}</span>
              </>
            )}
          </button>

          {/* Action 2: NOTIFY ALL ZONES */}
          <button
            type="button"
            onClick={handleNotifyAll}
            className={`px-4 py-2.5 rounded-lg font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 border shadow transition-all cursor-pointer ${
              isNotified
                ? 'bg-emerald-950 text-emerald-300 border-emerald-500/60'
                : 'bg-slate-900/90 hover:bg-slate-800 text-slate-200 border-slate-700 hover:border-slate-500'
            }`}
          >
            {isNotified ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>ZONES ALERTED ✓</span>
              </>
            ) : (
              <>
                <BellRing className="w-4 h-4 text-amber-400" />
                <span>NOTIFY ALL ZONES</span>
              </>
            )}
          </button>

          {/* Action 3: VIEW EVIDENCE */}
          <button
            type="button"
            onClick={handleViewEvidence}
            className="px-4 py-2.5 rounded-lg font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 bg-slate-900/90 hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 shadow transition-all cursor-pointer hover:scale-105 active:scale-95"
          >
            <Eye className="w-4 h-4" />
            <span>VIEW EVIDENCE</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
