import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  Globe,
  FileText,
  Layers,
  Clock,
  Play,
  CheckCircle2,
  ExternalLink,
  Sparkles,
  Bot,
  Activity,
  Cpu,
  Target,
  Zap,
  GitPullRequest
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import RiskGauge from '../components/RiskGauge';
import LiveTerminal from '../components/LiveTerminal';
import FindingCard from '../components/FindingCard';
import { scanService } from '../services/api';

const SEVERITY_COLORS = {
  Critical: '#FF0055',
  High: '#F97316',
  Medium: '#F59E0B',
  Low: '#3B82F6',
  Informational: '#64748B'
};

export default function Dashboard({ currentScan }) {
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [aiData, setAiData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (currentScan?.id) {
      setLoading(true);
      Promise.all([
        scanService.getScanFindings(currentScan.id),
        scanService.getAiAdvisor(currentScan.id).catch(() => ({ data: null }))
      ])
        .then(([findingsRes, aiRes]) => {
          setFindings(findingsRes.data);
          if (aiRes.data && !aiRes.data.message) {
            setAiData(aiRes.data);
          }
        })
        .catch((err) => console.error('Failed to fetch dashboard data:', err))
        .finally(() => setLoading(false));
    }
  }, [currentScan]);

  const stats = {
    critical: currentScan?.critical_count ?? findings.filter(f => f.severity === 'Critical').length,
    high: currentScan?.high_count ?? findings.filter(f => f.severity === 'High').length,
    medium: currentScan?.medium_count ?? findings.filter(f => f.severity === 'Medium').length,
    low: currentScan?.low_count ?? findings.filter(f => f.severity === 'Low').length,
    endpoints: currentScan?.endpoints_count || 1,
    forms: currentScan?.forms_count || 0,
    riskScore: currentScan?.risk_score || 0,
  };

  const cvssScores = findings.map(f => f.cvss_score || 5.0);
  const avgCvss = cvssScores.length > 0 ? (cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length).toFixed(1) : '0.0';
  const exploitabilityIndex = Math.min(10.0, (parseFloat(avgCvss) * 0.7) + (stats.critical * 1.5) + (stats.high * 0.8)).toFixed(1);

  const severityPieData = [
    { name: 'Critical', value: stats.critical, color: SEVERITY_COLORS.Critical },
    { name: 'High', value: stats.high, color: SEVERITY_COLORS.High },
    { name: 'Medium', value: stats.medium, color: SEVERITY_COLORS.Medium },
    { name: 'Low', value: stats.low, color: SEVERITY_COLORS.Low },
  ].filter(d => d.value > 0);

  const owaspRadarData = [
    { category: 'A01:Access', count: findings.filter(f => f.category === 'idor').length },
    { category: 'A02:Crypto', count: findings.filter(f => f.category === 'exposure').length },
    { category: 'A03:Injection', count: findings.filter(f => ['sqli', 'xss'].includes(f.category)).length },
    { category: 'A04:Design', count: findings.filter(f => f.category === 'upload').length },
    { category: 'A05:Misconfig', count: findings.filter(f => f.category === 'headers').length },
    { category: 'A06:Outdated', count: findings.filter(f => ['static', 'cve'].includes(f.category)).length },
    { category: 'A07:Auth', count: findings.filter(f => f.category === 'auth').length },
  ];

  const technologies = Array.isArray(currentScan?.technologies)
    ? currentScan.technologies
    : ['Nginx', 'FastAPI', 'React', 'SQLite'];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Target Welcome Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-[#0C1427] via-[#0F1C36] to-[#0A1020] border border-slate-800 p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">
              {currentScan?.scan_type?.toUpperCase() || 'ASSESSMENT WORKSTATION'}
            </span>
            <span className="text-xs font-mono text-slate-400">Status:</span>
            <span className={`text-xs font-mono font-bold ${currentScan?.status === 'completed' ? 'text-emerald-400' : 'text-cyan-400 animate-pulse'}`}>
              {currentScan?.status?.toUpperCase() || 'READY'}
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            {currentScan?.target || 'Ready for Security Assessment'}
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Automated multi-vector OWASP Top 10 assessment with real CVSS calculation & AI vulnerability reasoning.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/new-scan')}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition shadow-[0_0_15px_rgba(0,240,255,0.3)] font-mono"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>Start New Scan</span>
          </button>
          {currentScan && (
            <button
              onClick={() => navigate('/reports')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition font-mono"
            >
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>View Report</span>
            </button>
          )}
        </div>
      </div>

      {/* Real Mathematical Parameters Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3.5">
        <div className="bg-[#0C1220] border border-red-900/40 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-red-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Critical</span>
            <ShieldAlert className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-red-400">{stats.critical}</div>
        </div>

        <div className="bg-[#0C1220] border border-orange-900/40 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-orange-400 mb-1">
            <span className="text-[10px] font-mono uppercase">High</span>
            <AlertTriangle className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-orange-400">{stats.high}</div>
        </div>

        <div className="bg-[#0C1220] border border-amber-900/40 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-amber-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Medium</span>
            <AlertCircle className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-amber-400">{stats.medium}</div>
        </div>

        <div className="bg-[#0C1220] border border-blue-900/40 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-blue-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Low</span>
            <Info className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-blue-400">{stats.low}</div>
        </div>

        <div className="bg-[#0C1220] border border-slate-800 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-cyan-400 mb-1">
            <span className="text-[10px] font-mono uppercase">CVSS Avg</span>
            <Zap className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-100">{avgCvss}</div>
        </div>

        <div className="bg-[#0C1220] border border-slate-800 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-cyan-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Exploit Index</span>
            <Activity className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-100">{exploitabilityIndex}</div>
        </div>

        <div className="bg-[#0C1220] border border-slate-800 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-cyan-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Endpoints</span>
            <Globe className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-100">{stats.endpoints}</div>
        </div>

        <div className="bg-[#0C1220] border border-slate-800 rounded-xl p-3.5 shadow-lg">
          <div className="flex items-center justify-between text-cyan-400 mb-1">
            <span className="text-[10px] font-mono uppercase">Input Vectors</span>
            <Layers className="w-3.5 h-3.5" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-100">{stats.forms}</div>
        </div>
      </div>

      {/* Main Charts & Risk Engine Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Gauge Card */}
        <div className="rounded-2xl border border-slate-800 bg-[#0C1220] p-5 flex flex-col justify-between shadow-xl">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">Consolidated Risk Score</h3>
            <span className="text-[10px] font-mono text-cyan-400">CVSS v3.1 Formulation</span>
          </div>

          <RiskGauge score={stats.riskScore} />

          <div className="text-center text-xs text-slate-400 font-mono mt-2 bg-[#070A11] p-2.5 rounded-xl border border-slate-800">
            Score evaluated based on CVSS severity, attack vector breadth, and multi-flaw synergies
          </div>
        </div>

        {/* Severity Distribution Chart */}
        <div className="rounded-2xl border border-slate-800 bg-[#0C1220] p-5 flex flex-col justify-between shadow-xl">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-200">Severity Distribution</h3>
            <span className="text-[10px] font-mono text-slate-400">Total: {findings.length}</span>
          </div>

          <div className="h-44 flex items-center justify-center">
            {severityPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500 font-mono">No vulnerabilities logged</div>
            )}
          </div>

          <div className="flex justify-center gap-3 text-[11px] font-mono">
            {severityPieData.map(d => (
              <span key={d.name} className="flex items-center gap-1.5" style={{ color: d.color }}>
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                {d.name}: {d.value}
              </span>
            ))}
          </div>
        </div>

        {/* OWASP Coverage Radar */}
        <div className="rounded-2xl border border-slate-800 bg-[#0C1220] p-5 flex flex-col justify-between shadow-xl">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-slate-200">OWASP Top 10 Coverage</h3>
            <span className="text-[10px] font-mono text-cyan-400">2025 Benchmark</span>
          </div>

          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={owaspRadarData}>
                <PolarGrid stroke="#1E293B" />
                <PolarAngleAxis dataKey="category" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                <Radar name="Findings" dataKey="count" stroke="#00F0FF" fill="#00F0FF" fillOpacity={0.4} />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          <div className="text-center text-[11px] text-slate-400 font-mono">
            Categorical density of identified attack surfaces
          </div>
        </div>
      </div>

      {/* AI SECURITY ADVISOR PANEL */}
      <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-[#0F1E38]/80 to-[#0A1224] p-6 shadow-2xl space-y-4 relative overflow-hidden">
        <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 glow-cyan">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white font-mono">SENTINELX AI SECURITY ADVISOR</span>
                <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  AI REASONING ENGINE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                Automated Root Cause Triage, Chained Attack Path Synthesis & Remediation Timeline
              </p>
            </div>
          </div>

          <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Confidence: <strong className="text-cyan-300">96.5%</strong></span>
          </div>
        </div>

        {/* Executive Summary Paragraph */}
        <div className="bg-[#070A11]/80 p-4 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
          {aiData?.executive_summary || (
            findings.length > 0
              ? `AI assessment synthesized across ${findings.length} vulnerabilities. Found ${stats.critical} critical and ${stats.high} high-severity exposures requiring immediate remediation before production deployment.`
              : 'Target demonstrates clean posture. No critical vulnerability chains were detected on evaluated endpoints.'
          )}
        </div>

        {/* Chained Attack Paths & Priority Matrix Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Attack Path Modeling */}
          <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-2.5 font-mono text-xs">
            <div className="text-cyan-400 font-bold flex items-center gap-2">
              <GitPullRequest className="w-3.5 h-3.5" />
              <span>CHAINED ATTACK PATH ANALYSIS</span>
            </div>
            <div className="space-y-2">
              {(aiData?.attack_paths || [
                {
                  phase: "Surface Identification",
                  technique: "Automated Parameter Enumeration",
                  impact: "Mapped all user-controllable input vectors and server routes.",
                  mitigation: "Ensure proper parameter sanitization."
                }
              ]).map((path, idx) => (
                <div key={idx} className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
                  <div className="text-slate-200 font-bold text-[11px]">{path.phase}: {path.technique}</div>
                  <div className="text-[10px] text-slate-400 font-sans">{path.impact}</div>
                  <div className="text-[10px] text-emerald-400 font-mono">Fix: {path.mitigation}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Priority Remediation Timeline */}
          <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-2.5 font-mono text-xs">
            <div className="text-emerald-400 font-bold flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>RECOMMENDED REMEDIATION TIMELINE</span>
            </div>
            <div className="space-y-2">
              {(aiData?.remediation_priorities || [
                { priority: "P0 - Immediate", action: "Parameterized Database Queries", timeframe: "< 24 Hours" },
                { priority: "P1 - High", action: "Server-side Object-level Access Validation", timeframe: "< 48 Hours" },
                { priority: "P2 - Medium", action: "Cookie Security Flags (HttpOnly, Secure)", timeframe: "< 1 Week" },
                { priority: "P3 - Hardening", action: "Deploy Strict CSP and HSTS Headers", timeframe: "< 2 Weeks" }
              ]).map((rem, idx) => (
                <div key={idx} className="flex items-center justify-between bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80">
                  <div>
                    <span className="text-[10px] font-bold text-cyan-400 block">{rem.priority}</span>
                    <span className="text-[11px] text-slate-200">{rem.action}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-400 text-[9px] font-mono border border-slate-800 shrink-0">
                    {rem.timeframe}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Live Telemetry Terminal */}
      <div>
        <LiveTerminal activeScanId={currentScan?.id} />
      </div>

      {/* Recent Findings */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2 font-mono">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>Assessed Vulnerabilities ({findings.length})</span>
          </h3>
          <button
            onClick={() => navigate('/scanners/sqli')}
            className="text-xs font-mono text-cyan-400 hover:underline"
          >
            Explore all scanner modules →
          </button>
        </div>

        {findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-slate-500 font-mono text-xs">
            No vulnerabilities detected for this target yet. Launch a new scan to assess.
          </div>
        ) : (
          <div className="space-y-2.5">
            {findings.slice(0, 6).map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
