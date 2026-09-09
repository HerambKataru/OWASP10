import React, { useEffect, useState } from 'react';
import { FileCode, FolderTree, AlertCircle, CheckCircle, ShieldAlert, FileText } from 'lucide-react';
import { scanService } from '../services/api';
import FindingCard from '../components/FindingCard';

export default function StaticAnalysis({ currentScan }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    if (currentScan?.id) {
      setLoading(true);
      scanService.getScanFindings(currentScan.id, 'static')
        .then((res) => {
          setFindings(res.data);
          if (res.data.length > 0) {
            setSelectedFinding(res.data[0]);
          }
        })
        .catch((err) => console.error('Failed to load SAST findings:', err))
        .finally(() => setLoading(false));
    }
  }, [currentScan]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <FileCode className="w-6 h-6 text-cyan-400" />
            <span>Static Application Security Testing (SAST)</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Offline source code analysis inspecting AST patterns, dangerous execution sinks, and hardcoded secrets.
          </p>
        </div>

        <span className="px-3 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800 text-xs font-mono font-bold text-cyan-400">
          SAST Findings: {findings.length}
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-12 text-center text-slate-500 font-mono text-xs space-y-2">
          <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto" />
          <div className="text-slate-300 font-bold">No Static Vulnerabilities Logged</div>
          <p className="text-slate-500 max-w-md mx-auto">
            Upload a project archive in New Scan (Mode 2) to perform deep static source code analysis.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Findings List (Left 1 col) */}
          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-4 space-y-2.5 max-h-[600px] overflow-y-auto terminal-scroll">
            <div className="text-xs font-mono text-slate-400 font-bold mb-2">IDENTIFIED CODE ISSUES</div>
            {findings.map((f) => (
              <div
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className={`p-3 rounded-xl border text-xs font-mono cursor-pointer transition select-none ${
                  selectedFinding?.id === f.id
                    ? 'bg-cyan-950/60 border-cyan-500 text-slate-100 shadow-[0_0_12px_rgba(0,240,255,0.15)]'
                    : 'bg-[#070A11] border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`px-2 py-0.2 rounded text-[9px] font-bold ${
                    f.severity === 'Critical' ? 'text-red-400 bg-red-950' :
                    f.severity === 'High' ? 'text-orange-400 bg-orange-950' : 'text-amber-400 bg-amber-950'
                  }`}>
                    {f.severity}
                  </span>
                  <span className="text-[10px] text-slate-500">{f.cve_id}</span>
                </div>
                <div className="font-semibold text-slate-200 truncate">{f.title}</div>
                <div className="text-[10px] text-slate-500 truncate mt-1">{f.file_path}:{f.line_number}</div>
              </div>
            ))}
          </div>

          {/* Code Inspector & Remediation (Right 2 cols) */}
          <div className="lg:col-span-2 bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
            {selectedFinding ? (
              <>
                <div className="flex items-start justify-between">
                  <div>
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                      {selectedFinding.cve_id}
                    </span>
                    <h2 className="text-lg font-bold text-white mt-1.5">{selectedFinding.title}</h2>
                    <div className="text-xs font-mono text-slate-400 mt-0.5">
                      File: <strong className="text-slate-200">{selectedFinding.file_path}</strong> (Line {selectedFinding.line_number})
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-xs font-mono font-bold text-red-400">CVSS {selectedFinding.cvss_score}</span>
                  </div>
                </div>

                {/* Code Snippet Viewer */}
                <div>
                  <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center gap-2">
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    <span>SOURCE CODE SNIPPET</span>
                  </div>
                  <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 font-mono text-xs text-slate-200 overflow-x-auto space-y-1">
                    <div className="text-slate-400 select-none">...</div>
                    <div className="bg-red-950/40 border-l-2 border-red-500 pl-2 py-1 text-red-300">
                      <span className="text-slate-400 mr-3">{selectedFinding.line_number} |</span>
                      <span>{selectedFinding.payload || selectedFinding.evidence}</span>
                    </div>
                    <div className="text-slate-400 select-none">...</div>
                  </div>
                </div>

                {/* Explanation */}
                <div>
                  <div className="text-[11px] font-mono text-slate-400 font-bold mb-1">VULNERABILITY EXPLANATION</div>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded-xl border border-slate-800">
                    {selectedFinding.description}
                  </p>
                </div>

                {/* Remediation */}
                <div className="bg-emerald-950/20 border border-emerald-800/40 p-3.5 rounded-xl space-y-1">
                  <div className="text-[11px] font-mono font-bold text-emerald-400">SECURE CODING REMEDIATION</div>
                  <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.remediation}</p>
                </div>
              </>
            ) : (
              <div className="text-slate-500 font-mono text-xs flex items-center justify-center h-64">
                Select an issue on the left to inspect source code lines and remediation.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
