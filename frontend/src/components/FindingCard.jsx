import React, { useState } from 'react';
import { ChevronDown, ChevronRight, ShieldAlert, CheckCircle, ExternalLink, Terminal, FileCode2 } from 'lucide-react';

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  const getSeverityStyle = (sev) => {
    switch (sev) {
      case 'Critical':
        return 'text-red-400 bg-red-950/60 border-red-800/80 shadow-[0_0_10px_rgba(255,0,85,0.2)]';
      case 'High':
        return 'text-orange-400 bg-orange-950/60 border-orange-800/80';
      case 'Medium':
        return 'text-amber-400 bg-amber-950/60 border-amber-800/80';
      case 'Low':
        return 'text-blue-400 bg-blue-950/60 border-blue-800/80';
      default:
        return 'text-slate-400 bg-slate-800/60 border-slate-700';
    }
  };

  return (
    <div className="rounded-xl border border-slate-800/80 bg-[#0C1220] overflow-hidden transition-all duration-200 hover:border-slate-700">
      {/* Header / Summary Bar */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/30 transition select-none"
      >
        <div className="flex items-center gap-3.5 flex-1 min-w-0">
          <button className="text-slate-500 hover:text-slate-300">
            {expanded ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4" />}
          </button>

          <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${getSeverityStyle(finding.severity)}`}>
            {finding.severity?.toUpperCase()}
          </span>

          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-semibold text-slate-100 truncate">{finding.title}</h4>
              {finding.cve_id && (
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                  {finding.cve_id}
                </span>
              )}
            </div>
            <div className="text-xs font-mono text-slate-400 truncate mt-0.5 flex items-center gap-2">
              <span className="text-slate-300">{finding.owasp_category}</span>
              <span>•</span>
              <span className="text-slate-400 truncate">{finding.endpoint || finding.file_path || 'Target Host'}</span>
            </div>
          </div>
        </div>

        {/* CVSS Badge */}
        <div className="flex items-center gap-3 shrink-0 ml-4">
          <div className="text-right">
            <div className="text-xs font-mono font-bold text-slate-300">CVSS {finding.cvss_score || '5.0'}</div>
            <div className="text-[10px] text-slate-400 font-mono">Base Score</div>
          </div>
        </div>
      </div>

      {/* Expanded Details Body */}
      {expanded && (
        <div className="p-4.5 border-t border-slate-800 bg-[#080C14]/80 space-y-3.5 text-xs">
          {/* Description */}
          <div>
            <div className="text-[11px] font-mono text-slate-400 font-semibold mb-1">DESCRIPTION</div>
            <p className="text-slate-300 leading-relaxed">{finding.description}</p>
          </div>

          {/* Target & Parameter details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
            <div>
              <span className="text-[10px] font-mono text-slate-400 block mb-0.5">ENDPOINT / VECTOR:</span>
              <span className="font-mono text-slate-200 break-all">{finding.endpoint || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] font-mono text-slate-400 block mb-0.5">PARAMETER / SINK:</span>
              <span className="font-mono text-cyan-400">{finding.parameter || 'N/A'}</span>
            </div>
          </div>

          {/* Payload Used */}
          {finding.payload && (
            <div>
              <div className="text-[11px] font-mono text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>PAYLOAD INJECTED / DETECTED</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-emerald-400 text-[11px] break-all overflow-x-auto">
                {finding.payload}
              </div>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <div className="text-[11px] font-mono text-slate-400 font-semibold mb-1">EVIDENCE & TELEMETRY</div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-slate-300 text-[11px] break-all whitespace-pre-wrap">
                {finding.evidence}
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div className="bg-emerald-950/20 border border-emerald-800/40 p-3 rounded-lg flex items-start gap-2.5">
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-[11px] font-mono font-bold text-emerald-400 block mb-0.5">REMEDIATION GUIDANCE</span>
                <p className="text-slate-300 leading-relaxed">{finding.remediation}</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
