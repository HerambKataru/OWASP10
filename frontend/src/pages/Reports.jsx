import React, { useState } from 'react';
import {
  FileSpreadsheet,
  Download,
  FileText,
  FileCode,
  Shield,
  CheckCircle,
  ExternalLink,
  Layers
} from 'lucide-react';
import { reportService } from '../services/api';

export default function Reports({ currentScan, scans = [] }) {
  const [selectedScanId, setSelectedScanId] = useState(currentScan?.id || (scans[0]?.id || ''));

  const REPORT_SECTIONS = [
    '1. Professional Cover Page & Classification',
    '2. Executive Summary & Risk Gauge',
    '3. Target Scope & Assessment Bounds',
    '4. Penetration Testing Methodology (OWASP OTG / NIST)',
    '5. Reconnaissance Results & Discovered Paths',
    '6. Technology Fingerprint Breakdown',
    '7. Threat Intelligence Correlation (VT/AbuseIPDB/Shodan)',
    '8. Detailed OWASP Top 10 Findings Matrix',
    '9. Payloads Injected & Attack Vectors',
    '10. HTTP Request & Response Telemetry Evidence',
    '11. Proof of Concept Telemetry Screenshots',
    '12. CVE & CWE Compliance Mapping',
    '13. Remediation Roadmap & Prioritization',
    '14. Technical Appendix & Methodology Sign-off'
  ];

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <FileSpreadsheet className="w-6 h-6 text-cyan-400" />
          <span>Security Assessment Report Generator</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Export enterprise-ready 14-section PDF assessment reports and machine-readable JSON exports.
        </p>
      </div>

      {/* Target Selector & Download Action Card */}
      <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <label className="block text-xs font-mono font-bold text-slate-300 mb-1">
              SELECT ASSESSMENT TARGET / SCAN
            </label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(parseInt(e.target.value))}
              className="bg-[#070A11] border border-slate-700 text-xs font-mono text-slate-200 rounded-xl px-3.5 py-2.5 min-w-[280px] focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  Scan #{s.id} — {s.target} (Risk: {s.risk_score}/100)
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-3">
            <a
              href={selectedScanId ? reportService.getPdfUrl(selectedScanId) : '#'}
              download
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition shadow-[0_0_15px_rgba(0,240,255,0.25)] ${
                !selectedScanId ? 'pointer-events-none opacity-50' : ''
              }`}
            >
              <Download className="w-4 h-4" />
              <span>Download PDF (14 Sections)</span>
            </a>

            <a
              href={selectedScanId ? reportService.getJsonUrl(selectedScanId) : '#'}
              download
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold font-mono text-xs border border-slate-700 transition ${
                !selectedScanId ? 'pointer-events-none opacity-50' : ''
              }`}
            >
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>Export JSON</span>
            </a>
          </div>
        </div>
      </div>

      {/* PDF Structure Table of Contents */}
      <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl font-mono text-xs">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-slate-200">14-SECTION PDF REPORT STRUCTURE</span>
          </div>
          <span className="text-[10px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
            ReportLab Engine Active
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {REPORT_SECTIONS.map((sec, idx) => (
            <div key={idx} className="bg-[#070A11] p-3 rounded-xl border border-slate-800 flex items-center gap-2.5 text-slate-300">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="truncate">{sec}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
