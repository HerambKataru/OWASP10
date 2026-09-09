import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Trash2, Pause, Play, ShieldAlert, Cpu, Activity, Filter } from 'lucide-react';

export default function LiveTerminal({ activeScanId }) {
  const [logs, setLogs] = useState([
    {
      timestamp: new Date().toLocaleTimeString(),
      level: 'INFO',
      component: 'CORE',
      message: 'SentinelX Core Engine ready. Standing by for telemetry...'
    }
  ]);
  const [isPaused, setIsPaused] = useState(false);
  const [progress, setProgress] = useState({
    percentage: 0,
    step: 'Idle / Ready',
    activeComponent: 'CORE'
  });
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const bottomRef = useRef(null);

  useEffect(() => {
    const getWsUrl = () => {
      if (import.meta.env.VITE_WS_BASE_URL) return `${import.meta.env.VITE_WS_BASE_URL}/ws/logs`;
      if (import.meta.env.VITE_API_BASE_URL) {
        const base = import.meta.env.VITE_API_BASE_URL.replace(/^http/, 'ws');
        return `${base}/ws/logs`;
      }
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.hostname === 'localhost' ? 'localhost:8000' : window.location.host;
      return `${protocol}//${host}/ws/logs`;
    };

    const ws = new WebSocket(getWsUrl());

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'log') {
          if (!activeScanId || !data.scan_id || data.scan_id === activeScanId) {
            setLogs((prev) => [...prev.slice(-500), data]);
          }
        } else if (data.type === 'progress') {
          if (!activeScanId || !data.scan_id || data.scan_id === activeScanId) {
            setProgress({
              percentage: data.percentage || 0,
              step: data.step || 'Running assessment...',
              activeComponent: data.component || 'SCANNER'
            });
          }
        }
      } catch (err) {
        console.error('WS log parse error:', err);
      }
    };

    ws.onerror = () => {
      console.log('WS reconnecting or waiting for backend...');
    };

    return () => {
      ws.close();
    };
  }, [activeScanId]);

  useEffect(() => {
    if (!isPaused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isPaused]);

  const getLevelColor = (level) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-950/80 border-red-700 shadow-[0_0_8px_rgba(255,0,85,0.4)]';
      case 'ALERT':
      case 'WARN':
        return 'text-amber-400 bg-amber-950/80 border-amber-700';
      case 'SUCCESS':
        return 'text-emerald-400 bg-emerald-950/80 border-emerald-700';
      default:
        return 'text-cyan-400 bg-cyan-950/80 border-cyan-800';
    }
  };

  const filteredLogs = logs.filter(log => {
    if (selectedFilter === 'ALL') return true;
    return log.component?.toUpperCase() === selectedFilter;
  });

  const availableComponents = ['ALL', 'CORE', 'RECON', 'SQLI', 'XSS', 'IDOR', 'AUTH', 'HEADERS', 'EXPOSURE', 'AI'];

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#070A11] flex flex-col h-[360px] shadow-2xl overflow-hidden font-mono">
      {/* Live Stage Progress Bar Header */}
      <div className="bg-[#0B0F19] px-4 py-2.5 border-b border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
            <span className="font-bold text-slate-200">LIVE VAPT TELEMETRY STREAM</span>
            <span className="text-[10px] text-slate-500">•</span>
            <span className="text-cyan-400 font-semibold truncate max-w-xs">{progress.step}</span>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="text-xs font-bold text-slate-200">{progress.percentage}%</span>
            <div className="flex items-center gap-1.5 text-slate-400">
              <button
                onClick={() => setIsPaused(!isPaused)}
                className="hover:text-slate-200 p-1 transition"
                title={isPaused ? 'Resume auto-scroll' : 'Pause auto-scroll'}
              >
                {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-400" /> : <Pause className="w-3.5 h-3.5" />}
              </button>
              <button
                onClick={() => setLogs([])}
                className="hover:text-red-400 p-1 transition"
                title="Clear logs"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Visual Progress Track */}
        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-emerald-400 to-cyan-400 transition-all duration-300 shadow-[0_0_10px_rgba(0,240,255,0.5)]"
            style={{ width: `${progress.percentage}%` }}
          />
        </div>

        {/* Module Filter Chips */}
        <div className="flex items-center gap-1.5 pt-1 overflow-x-auto terminal-scroll">
          <Filter className="w-3 h-3 text-slate-500 shrink-0 mr-1" />
          {availableComponents.map(comp => (
            <button
              key={comp}
              onClick={() => setSelectedFilter(comp)}
              className={`px-2 py-0.5 rounded text-[9px] font-bold transition shrink-0 ${
                selectedFilter === comp
                  ? 'bg-cyan-500 text-slate-950 shadow-[0_0_8px_rgba(0,240,255,0.4)]'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              {comp}
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Feed */}
      <div className="flex-1 p-3.5 overflow-y-auto space-y-1 text-[11px] leading-relaxed terminal-scroll bg-[#050811]">
        {filteredLogs.map((log, index) => (
          <div key={index} className="flex items-start gap-2.5 hover:bg-slate-900/40 px-1 py-0.5 rounded transition">
            <span className="text-slate-500 shrink-0 select-none text-[10px]">[{log.timestamp}]</span>
            <span className={`px-1.5 py-0.2 rounded border text-[9px] font-bold shrink-0 ${getLevelColor(log.level)}`}>
              {log.component || 'ENGINE'}
            </span>
            <span className="text-slate-200 break-all font-mono">{log.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
