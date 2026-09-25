import React, { useState, useEffect } from 'react';
import { ShieldAlert, Clock, Radio, Activity, Terminal } from 'lucide-react';

/**
 * Header Component
 * 
 * Purpose:
 * Renders the top tactical command banner for "GRYFFINDOR SENTINEL".
 * Includes:
 * 1. Title with tactical iconography
 * 2. Live digital clock that ticks every second via a React useEffect timer
 * 3. System status telemetry indicators (DEFCON level, encryption status, active feed)
 */
export default function Header({ isConnected = false, threatPosture = 'DEFCON 4 // NOMINAL' }) {
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

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur-md px-4 py-3 sticky top-0 z-40">
      <div className="max-w-[1920px] mx-auto flex flex-col md:flex-row md:items-center justify-between gap-3">
        
        {/* Left Side: System Title & Tactical Logo */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded bg-red-950/60 border border-red-500/40 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.25)]">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
            {/* Corner tactical accents */}
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
                v2.4-TACTICAL
              </span>
            </div>
            <p className="text-xs text-slate-400 tracking-widest font-mono flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-red-400" />
              <span>TACTICAL COMMAND CENTER</span>
              <span className="text-slate-600">|</span>
              {isConnected ? (
                <span className="text-emerald-400 flex items-center gap-1.5 font-mono font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />
                  Live
                </span>
              ) : (
                <span className="text-amber-400 flex items-center gap-1.5 font-mono font-semibold animate-pulse">
                  <span className="w-2 h-2 rounded-full bg-amber-500 inline-block animate-ping" />
                  Reconnecting...
                </span>
              )}
            </p>
          </div>
        </div>

        {/* Center / Right: Live Clock & Threat Posture Telemetry */}
        <div className="flex items-center gap-3 sm:gap-6 flex-wrap">
          
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

          {/* Secure Network Feed */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded bg-slate-950/70 border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <div className="text-left font-mono">
              <span className="text-[10px] text-slate-500 block leading-none">SITUATION BUS</span>
              <span className="text-xs font-semibold text-cyan-300 leading-none">TLS 1.3 SECURE</span>
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
    </header>
  );
}
