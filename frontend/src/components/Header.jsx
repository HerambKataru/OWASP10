import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Target, Play, ShieldAlert, Cpu, LogOut, User, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Header({ currentScan, scans = [], onSelectScan }) {
  const navigate = useNavigate();
  const { currentUser, logout } = useAuth();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="h-16 bg-[#0B0F19]/90 backdrop-blur border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20 font-sans">
      {/* Left: Active Target Indicator & Scan Switcher */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-700/60">
          <Target className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono text-slate-400">Target:</span>
          <span className="text-xs font-mono font-semibold text-slate-200 truncate max-w-[220px]">
            {currentScan ? currentScan.target : 'No active target selected'}
          </span>
        </div>

        {/* Scan Selector Dropdown */}
        {scans.length > 0 && (
          <select
            value={currentScan ? currentScan.id : ''}
            onChange={(e) => {
              const selected = scans.find(s => s.id === parseInt(e.target.value));
              if (selected && onSelectScan) onSelectScan(selected);
            }}
            className="bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                #{s.id} — {s.target.slice(0, 30)} ({s.status.toUpperCase()})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Right: User Profile & Quick Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate('/new-scan')}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition-all shadow-[0_0_12px_rgba(0,240,255,0.25)]"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Launch Scan</span>
        </button>

        {/* User Profile Pill */}
        {currentUser && (
          <div className="flex items-center gap-2 pl-3 border-l border-slate-800">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 font-mono text-xs font-bold">
              {currentUser.displayName ? currentUser.displayName[0].toUpperCase() : 'A'}
            </div>
            <div className="hidden lg:block text-left">
              <div className="text-xs font-mono font-bold text-slate-200 leading-tight truncate max-w-[130px]">
                {currentUser.displayName || currentUser.email?.split('@')[0]}
              </div>
              <div className="text-[10px] font-mono text-slate-500 leading-tight">
                {currentUser.role || 'Security Analyst'}
              </div>
            </div>

            <button
              onClick={handleLogout}
              className="p-1.5 hover:bg-red-950/60 text-slate-400 hover:text-red-400 rounded-lg transition"
              title="Sign Out of Workstation"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
