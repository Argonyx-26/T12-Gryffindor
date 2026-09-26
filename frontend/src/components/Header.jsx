import React, { useState, useEffect } from 'react';
import { ShieldAlert, Clock, Radio, Activity, Terminal } from 'lucide-react';

/**
 * Header Component
 * 
 * Purpose:
 * Renders the top tactical command banner for "GRYFFINDOR".
 * Includes:
 * 1. Title with tactical iconography
 * 2. Live digital clock that ticks every second via a React useEffect timer
 * 3. System status telemetry indicators (DEFCON level, encryption status, active feed)
 */
export default function Header({ 
  isConnected = false, 
  threatPosture = 'DEFCON 4 // NOMINAL',
  apiUrl = '',
  wsUrl = '',
}) {
  // Store the current time in React state so the UI automatically re-renders every second
  const [currentTime, setCurrentTime] = useState(new Date());

  // Set up an interval timer when the component mounts to update the time every second
  useEffect(() => {
    const timerId = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    // Clean up the timer when the component unmounts to prevent memory leaks
    return () => clearInterval(timerId);
  }, []);

  // Format the time as HH:MM:SS with leading zeros
  const formattedTime = currentTime.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  // Format the date as standard military format: DD-MMM-YYYY
  const formattedDate = currentTime.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).toUpperCase();

  const [evalData, setEvalData] = useState(null);
  const [showEvalModal, setShowEvalModal] = useState(false);

  const fetchEvalData = async () => {
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiUrl}/evaluation`);
      if (res.ok) {
        const json = await res.json();
        setEvalData(json.evaluation);
      }
    } catch (err) {
      console.error('Failed to fetch evaluation metrics:', err);
    }
  };

  const handleOpenEval = () => {
    fetchEvalData();
    setShowEvalModal(true);
  };

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur-md px-4 py-3 sticky top-0 z-40">
      <div className="max-w-[1920px] mx-auto flex flex-col md:flex-row md:items-center justify-between gap-3">
        
        {/* Left Side: System Title & Tactical Logo */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded bg-red-950/60 border border-red-500/40 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.25)]">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
            <span className="absolute -top-1 -left-1 w-1.5 h-1.5 border-t border-l border-red-500" />
            <span className="absolute -top-1 -right-1 w-1.5 h-1.5 border-t border-r border-red-500" />
            <span className="absolute -bottom-1 -left-1 w-1.5 h-1.5 border-b border-l border-red-500" />
            <span className="absolute -bottom-1 -right-1 w-1.5 h-1.5 border-b border-r border-red-500" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg md:text-xl font-bold tracking-wider text-slate-100 uppercase font-mono">
                GRYFFINDOR
              </h1>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono border border-slate-700 hidden sm:inline-block">
                v2.0-EXPLAINABLE
              </span>
            </div>
            <p className="text-xs text-slate-400 tracking-widest font-mono flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-red-400" />
              <span>CONTEXT-AWARE THREAT ENGINE</span>
              <span className="text-slate-600">|</span>
              {isConnected ? (
                <span className="text-emerald-400 flex items-center gap-1.5 font-mono font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />
                  LIVE
                </span>
              ) : (
                <span className="text-amber-400 flex items-center gap-1.5 font-mono font-semibold animate-pulse">
                  <span className="w-2 h-2 rounded-full bg-amber-500 inline-block animate-ping" />
                  RECONNECTING
                </span>
              )}
            </p>
            {/* Target Endpoints Config Debug Label */}
            <div className="text-[10px] font-mono text-slate-400 flex items-center gap-2 mt-0.5">
              <span>API: <span className="text-cyan-400 font-semibold">{apiUrl || 'http://localhost:8000'}</span></span>
              <span className="text-slate-600">|</span>
              <span>WS: <span className="text-cyan-400 font-semibold">{wsUrl || 'ws://localhost:8000/ws/alerts'}</span></span>
            </div>
          </div>
        </div>

        {/* Center / Right: Evaluation Button & Live Clock */}
        <div className="flex items-center gap-3 sm:gap-6 flex-wrap">
          
          {/* Evaluation Metrics Button */}
          <button
            type="button"
            onClick={handleOpenEval}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-950 hover:bg-slate-800 border border-cyan-500/40 text-cyan-300 font-mono text-xs transition-colors shadow-sm"
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>SYSTEM EVALUATION</span>
          </button>

          {/* Tactical DEFCON / Threat Status indicator */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded bg-slate-950/70 border border-slate-800">
            <Radio className={`w-3.5 h-3.5 animate-pulse ${
              threatPosture.includes('CRITICAL') ? 'text-red-400' :
              threatPosture.includes('ELEVATED') ? 'text-amber-400' :
              'text-emerald-400'
            }`} />
            <div className="text-left font-mono">
              <span className="text-[10px] text-slate-500 block leading-none">THREAT POSTURE</span>
              <span className={`text-xs font-bold leading-none ${
                threatPosture.includes('CRITICAL') ? 'text-red-400' :
                threatPosture.includes('ELEVATED') ? 'text-amber-400' :
                'text-emerald-400'
              }`}>
                {threatPosture}
              </span>
            </div>
          </div>

          {/* Live Clock Component */}
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded bg-slate-950 border border-slate-800 shadow-inner">
            <Clock className="w-4 h-4 text-red-400" />
            <div className="font-mono text-right">
              <div className="text-sm md:text-base font-bold text-slate-100 tracking-wider">
                {formattedTime}
              </div>
              <div className="text-[10px] text-slate-400 tracking-wider">
                {formattedDate} LOCAL
              </div>
            </div>
          </div>

        </div>

      </div>

      {/* Evaluation Metrics Modal */}
      {showEvalModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4 font-mono shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                <Activity className="w-5 h-5 text-cyan-400" />
                <span>SYSTEM EVALUATION & PERFORMANCE METRICS</span>
              </div>
              <button
                onClick={() => setShowEvalModal(false)}
                className="text-slate-400 hover:text-white font-bold"
              >
                ✕
              </button>
            </div>

            {evalData ? (
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">PRECISION</span>
                  <span className="text-emerald-400 font-bold text-lg">{(evalData.precision * 100).toFixed(1)}%</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">RECALL</span>
                  <span className="text-emerald-400 font-bold text-lg">{(evalData.recall * 100).toFixed(1)}%</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">F1 SCORE</span>
                  <span className="text-cyan-400 font-bold text-lg">{evalData.f1_score.toFixed(3)}</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">NOISE SUPPRESSION</span>
                  <span className="text-amber-400 font-bold text-lg">{evalData.suppression_rate_pct}%</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">LATENCY (P50)</span>
                  <span className="text-slate-200 font-bold text-sm">{evalData.p50_latency_ms} ms</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">LATENCY (P95)</span>
                  <span className="text-slate-200 font-bold text-sm">{evalData.p95_latency_ms} ms</span>
                </div>
                <div className="col-span-2 bg-slate-950 p-3 rounded border border-slate-800 flex justify-between text-[11px] text-slate-400">
                  <span>EVENTS: <strong className="text-slate-200">{evalData.total_events_processed}</strong></span>
                  <span>INCIDENTS: <strong className="text-red-400">{evalData.total_incidents_synthesized}</strong></span>
                  <span>CONFUSION: <strong className="text-cyan-300">TP:{evalData.true_positives} FP:{evalData.false_positives}</strong></span>
                </div>
              </div>
            ) : (
              <p className="text-slate-400 text-xs italic">Loading evaluation metrics...</p>
            )}

            <div className="pt-2 text-right">
              <button
                onClick={() => setShowEvalModal(false)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
