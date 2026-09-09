import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  PlusCircle,
  Radar,
  Network,
  Database,
  Code2,
  Lock,
  KeyRound,
  UploadCloud,
  Sliders,
  EyeOff,
  FileCode,
  ShieldAlert,
  Bug,
  FileSpreadsheet,
  Settings,
  Shield,
  LogOut,
  UserCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/new-scan', label: 'New Scan', icon: PlusCircle, highlight: true },
  { path: '/recon', label: 'Reconnaissance', icon: Radar },
  { path: '/http-analyzer', label: 'HTTP Analyzer', icon: Network },
  { type: 'header', label: 'OWASP TOP 10 SCANNERS' },
  { path: '/scanners/sqli', label: 'SQL Injection', icon: Database },
  { path: '/scanners/xss', label: 'Cross-Site Scripting', icon: Code2 },
  { path: '/scanners/idor', label: 'Broken Access Control', icon: Lock },
  { path: '/scanners/auth', label: 'Authentication', icon: KeyRound },
  { path: '/scanners/upload', label: 'File Upload', icon: UploadCloud },
  { path: '/scanners/headers', label: 'Misconfiguration', icon: Sliders },
  { path: '/scanners/exposure', label: 'Sensitive Data Exposure', icon: EyeOff },
  { type: 'header', label: 'INTELLIGENCE & ANALYSIS' },
  { path: '/static-analysis', label: 'Static Code Analysis', icon: FileCode },
  { path: '/threat-intel', label: 'Threat Intelligence', icon: ShieldAlert },
  { path: '/cve-intelligence', label: 'CVE Intelligence', icon: Bug },
  { path: '/reports', label: 'Reports', icon: FileSpreadsheet },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const { currentUser, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <aside className="w-64 bg-[#0B0F19] border-r border-slate-800/80 flex flex-col h-screen sticky top-0 select-none z-30">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-5 border-b border-slate-800/80 gap-3 bg-[#080C14]">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 glow-cyan">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-extrabold text-lg tracking-wider text-white">SENTINEL</span>
            <span className="font-extrabold text-lg text-cyan-400">X</span>
          </div>
          <div className="text-[10px] text-slate-400 font-mono tracking-tight">OWASP VAPT SUITE</div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1 terminal-scroll">
        {NAV_ITEMS.map((item, idx) => {
          if (item.type === 'header') {
            return (
              <div key={idx} className="pt-4 pb-1.5 px-3 text-[10px] font-bold text-slate-400 font-mono tracking-wider">
                {item.label}
              </div>
            );
          }

          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold shadow-[0_0_12px_rgba(0,240,255,0.15)]'
                    : item.highlight
                    ? 'text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span className="truncate">{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Authenticated User Status Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-[#080C14] text-[11px] font-mono text-slate-400 space-y-2">
        {currentUser && (
          <div className="flex items-center justify-between bg-slate-900/60 p-2 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 min-w-0">
              <UserCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <div className="truncate">
                <span className="text-slate-200 text-xs font-bold block truncate">
                  {currentUser.displayName || currentUser.email?.split('@')[0]}
                </span>
                <span className="text-[9px] text-slate-500 block">Firebase Authenticated</span>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="p-1 hover:text-red-400 text-slate-500 transition"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        <div className="flex items-center justify-between text-[10px]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Engine Online</span>
          </div>
          <span className="text-slate-500">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}
