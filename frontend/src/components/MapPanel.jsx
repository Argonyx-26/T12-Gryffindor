import React from 'react';
import { Map, Navigation, Layers, Compass, Maximize2, Radio } from 'lucide-react';

/**
 * MapPanel Component
 * 
 * Purpose:
 * Renders the Situational Geospatial Map panel on the right side of the dashboard.
 * In this initial version, it renders a tactical placeholder box with the text
 * "Map will go here", designed to be swapped out seamlessly for the real Leaflet map.
 */
export default function MapPanel() {
  return (
    <section className="bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-2xl h-full min-h-[580px]">
      {/* Map Header Bar */}
      <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Map className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
            TACTICAL SITUATIONAL MAP
          </h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 hidden sm:inline-block">
            LEAFLET LAYER READY
          </span>
        </div>

        {/* Coordinates Readout */}
        <div className="flex items-center gap-3 font-mono text-xs text-slate-400">
          <div className="hidden md:flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
            <Compass className="w-3.5 h-3.5 text-slate-500" />
            <span>GRID: 37°46'29.7"N 122°25'09.8"W</span>
          </div>

          <div className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[11px] hidden sm:inline">GPS SYNC</span>
          </div>
        </div>
      </div>

      {/* Main Map Canvas Area: Placeholder Gray Box */}
      <div className="relative flex-1 p-4 flex flex-col">
        {/* Placeholder Gray Box with Tactical Radar / Military Command styling */}
        <div className="relative flex-1 w-full bg-slate-900/70 border border-slate-800 rounded-lg flex flex-col items-center justify-center p-8 overflow-hidden group">
          
          {/* Tactical Background Grid Pattern */}
          <div className="absolute inset-0 tactical-grid-bg opacity-30 pointer-events-none" />

          {/* Concentric Radar Rings Overlay */}
          <div className="absolute w-[420px] h-[420px] rounded-full border border-slate-800/80 pointer-events-none" />
          <div className="absolute w-[280px] h-[280px] rounded-full border border-slate-800/60 pointer-events-none" />
          <div className="absolute w-[140px] h-[140px] rounded-full border border-slate-800/40 pointer-events-none" />

          {/* Animated Radar Sweep Line */}
          <div className="absolute w-[360px] h-[360px] rounded-full pointer-events-none flex items-center justify-center animate-radar">
            <div className="w-1/2 h-0.5 bg-gradient-to-r from-transparent to-red-500/40 origin-right translate-x-[-50%]" />
          </div>

          {/* Corner Tactical Brackets */}
          <div className="absolute top-4 left-4 w-5 h-5 border-t-2 border-l-2 border-slate-700" />
          <div className="absolute top-4 right-4 w-5 h-5 border-t-2 border-r-2 border-slate-700" />
          <div className="absolute bottom-4 left-4 w-5 h-5 border-b-2 border-l-2 border-slate-700" />
          <div className="absolute bottom-4 right-4 w-5 h-5 border-b-2 border-r-2 border-slate-700" />

          {/* Map Controls Mockup (Top Right of Map) */}
          <div className="absolute top-6 right-6 flex flex-col gap-1.5 z-10">
            <div className="bg-slate-950/90 border border-slate-800 p-2 rounded text-slate-400 hover:text-white cursor-pointer shadow">
              <Layers className="w-4 h-4" />
            </div>
            <div className="bg-slate-950/90 border border-slate-800 p-2 rounded text-slate-400 hover:text-white cursor-pointer shadow">
              <Navigation className="w-4 h-4" />
            </div>
            <div className="bg-slate-950/90 border border-slate-800 p-2 rounded text-slate-400 hover:text-white cursor-pointer shadow">
              <Maximize2 className="w-4 h-4" />
            </div>
          </div>

          {/* Central Placeholder Notice */}
          <div className="relative z-10 flex flex-col items-center text-center space-y-3 bg-slate-950/90 border border-slate-800 p-6 rounded-xl shadow-2xl max-w-sm">
            <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
              <Map className="w-6 h-6" />
            </div>

            <div>
              {/* Exact user-requested text */}
              <h3 className="text-lg font-bold font-mono text-slate-200 tracking-wider">
                Map will go here
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Leaflet interactive geospatial engine & sector pins placeholder
              </p>
            </div>

            <div className="w-full pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span>ZONES: 4 CONFIGURED</span>
              <span className="text-red-400 flex items-center gap-1">
                <Radio className="w-3 h-3 animate-pulse" />
                GEO-FENCE ACTIVE
              </span>
            </div>
          </div>

          {/* Scale Indicator Bar at Bottom Left */}
          <div className="absolute bottom-6 left-6 z-10 bg-slate-950/80 px-3 py-1.5 rounded border border-slate-800 font-mono text-[10px] text-slate-400 flex items-center gap-3">
            <span>SCALE: 1:50,000</span>
            <span className="w-12 h-1 bg-slate-600 block rounded" />
            <span>500m</span>
          </div>

        </div>
      </div>
    </section>
  );
}
