import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Globe,
  Radio,
  Server,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Cpu
} from 'lucide-react';
import { intelService } from '../services/api';

export default function ThreatIntel() {
  const [activeEngine, setActiveEngine] = useState('virustotal'); // 'virustotal' | 'abuseipdb' | 'shodan' | 'whois'
  const [queryInput, setQueryInput] = useState('google.com');
  const [vtMode, setVtMode] = useState('domain'); // 'domain' | 'url' | 'hash'
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!queryInput.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      let res;
      if (activeEngine === 'virustotal') {
        if (vtMode === 'domain') res = await intelService.getVtDomain(queryInput.trim());
        else if (vtMode === 'url') res = await intelService.getVtUrl(queryInput.trim());
        else res = await intelService.getVtHash(queryInput.trim());
      } else if (activeEngine === 'abuseipdb') {
        res = await intelService.getAbuseIp(queryInput.trim());
      } else if (activeEngine === 'shodan') {
        res = await intelService.getShodan(queryInput.trim());
      } else if (activeEngine === 'whois') {
        res = await intelService.getWhoisDns(queryInput.trim());
      }

      setResult(res.data);
    } catch (err) {
      setResult({ error: err.response?.data?.detail || err.message || 'Lookup failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <ShieldAlert className="w-6 h-6 text-cyan-400" />
          <span>Threat Intelligence & Infrastructure OSINT</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Real-time threat scoring and infrastructure mapping via VirusTotal, AbuseIPDB, Shodan, and DNS/WHOIS databases.
        </p>
      </div>

      {/* Engine Switcher */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        {[
          { id: 'virustotal', label: 'VirusTotal Intelligence', icon: ShieldAlert },
          { id: 'abuseipdb', label: 'AbuseIPDB IP Reputation', icon: Radio },
          { id: 'shodan', label: 'Shodan Port & Banner Engine', icon: Server },
          { id: 'whois', label: 'WHOIS & DNS Records', icon: Globe },
        ].map((engine) => {
          const Icon = engine.icon;
          return (
            <button
              key={engine.id}
              onClick={() => {
                setActiveEngine(engine.id);
                setResult(null);
                if (engine.id === 'abuseipdb' || engine.id === 'shodan') setQueryInput('1.1.1.1');
                else setQueryInput('google.com');
              }}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium transition whitespace-nowrap ${
                activeEngine === engine.id
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{engine.label}</span>
            </button>
          );
        })}
      </div>

      {/* Search Input Bar */}
      <form onSubmit={handleSearch} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-4 flex flex-col md:flex-row gap-3 shadow-xl">
        {activeEngine === 'virustotal' && (
          <select
            value={vtMode}
            onChange={(e) => setVtMode(e.target.value)}
            className="bg-[#070A11] border border-slate-700 text-xs font-mono text-cyan-400 rounded-xl px-3 py-2.5 focus:outline-none"
          >
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash">File Hash</option>
          </select>
        )}

        <div className="relative flex-1">
          <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
          <input
            type="text"
            required
            value={queryInput}
            onChange={(e) => setQueryInput(e.target.value)}
            placeholder={
              activeEngine === 'abuseipdb' || activeEngine === 'shodan'
                ? 'Enter IP Address (e.g., 8.8.8.8)'
                : 'Enter domain, URL, or hash...'
            }
            className="w-full bg-[#070A11] border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold font-mono text-xs rounded-xl transition shadow-[0_0_15px_rgba(0,240,255,0.25)]"
        >
          {loading ? 'Querying Intel...' : 'Lookup Threat Intel'}
        </button>
      </form>

      {/* RESULT CARDS */}
      {result && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl font-mono text-xs">
          {result.error ? (
            <div className="text-red-400 p-4 bg-red-950/40 rounded-xl border border-red-800">
              {result.error}
            </div>
          ) : (
            <>
              {/* VIRUSTOTAL RESULT */}
              {activeEngine === 'virustotal' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="text-sm font-bold text-white">VirusTotal Analysis Telemetry</span>
                    {result.status && <span className="text-[10px] text-slate-400">({result.status})</span>}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="bg-[#070A11] p-3.5 rounded-xl border border-red-900/40">
                      <div className="text-[10px] text-red-400 uppercase">Malicious</div>
                      <div className="text-2xl font-black text-red-400">{result.malicious}</div>
                    </div>
                    <div className="bg-[#070A11] p-3.5 rounded-xl border border-orange-900/40">
                      <div className="text-[10px] text-orange-400 uppercase">Suspicious</div>
                      <div className="text-2xl font-black text-orange-400">{result.suspicious}</div>
                    </div>
                    <div className="bg-[#070A11] p-3.5 rounded-xl border border-emerald-900/40">
                      <div className="text-[10px] text-emerald-400 uppercase">Harmless</div>
                      <div className="text-2xl font-black text-emerald-400">{result.harmless}</div>
                    </div>
                    <div className="bg-[#070A11] p-3.5 rounded-xl border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Reputation</div>
                      <div className="text-2xl font-black text-cyan-400">{result.reputation || 0}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* ABUSEIPDB RESULT */}
              {activeEngine === 'abuseipdb' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="text-sm font-bold text-white">AbuseIPDB IP Reputation: {result.ipAddress}</span>
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                      result.abuseConfidenceScore > 50 ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      Abuse Score: {result.abuseConfidenceScore}%
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-2">
                      <div><span className="text-slate-400">Country:</span> <strong className="text-slate-200">{result.countryName} ({result.countryCode})</strong></div>
                      <div><span className="text-slate-400">ISP:</span> <strong className="text-slate-200">{result.isp}</strong></div>
                      <div><span className="text-slate-400">Usage Type:</span> <span className="text-slate-300">{result.usageType}</span></div>
                    </div>
                    <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-2">
                      <div><span className="text-slate-400">Total Abuse Reports:</span> <strong className="text-cyan-400">{result.totalReports}</strong></div>
                      <div><span className="text-slate-400">Last Reported:</span> <span className="text-slate-300">{result.lastReportedAt}</span></div>
                      <div><span className="text-slate-400">Whitelisted:</span> <span className="text-slate-300">{result.isWhitelisted ? 'Yes' : 'No'}</span></div>
                    </div>
                  </div>
                </div>
              )}

              {/* SHODAN RESULT */}
              {activeEngine === 'shodan' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="text-sm font-bold text-white">Shodan Host Intelligence: {result.ip}</span>
                    <span className="text-xs text-cyan-400 font-bold">OS: {result.os}</span>
                  </div>

                  <div className="bg-[#070A11] p-3 rounded-xl border border-slate-800">
                    <span className="text-slate-400 mr-2">Open Ports:</span>
                    {result.ports?.map((p) => (
                      <span key={p} className="inline-block px-2 py-0.5 mr-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 text-[10px] font-bold">
                        {p}
                      </span>
                    ))}
                  </div>

                  <div className="space-y-2">
                    <div className="text-slate-400 font-bold text-[11px]">DISCOVERED SERVICES & BANNERS</div>
                    {result.services?.map((svc, idx) => (
                      <div key={idx} className="bg-[#070A11] p-3 rounded-xl border border-slate-800">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-cyan-400 font-bold">Port {svc.port} ({svc.service})</span>
                          <span className="text-slate-500">{svc.product}</span>
                        </div>
                        <pre className="text-slate-300 text-[10px] whitespace-pre-wrap">{svc.banner}</pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* WHOIS & DNS RESULT */}
              {activeEngine === 'whois' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="text-sm font-bold text-white">DNS & Domain Registry: {result.domain}</span>
                    <span className="text-emerald-400 font-bold">{result.status}</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-1.5">
                      <div><span className="text-slate-400">Registrar:</span> <strong className="text-slate-200">{result.registrar}</strong></div>
                      <div><span className="text-slate-400">Created:</span> <span className="text-slate-300">{result.creation_date}</span></div>
                      <div><span className="text-slate-400">Expires:</span> <span className="text-slate-300">{result.expiry_date}</span></div>
                    </div>
                    <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 space-y-1.5">
                      <div><span className="text-slate-400">A Records:</span> <span className="text-emerald-400">{result.a_records?.join(', ')}</span></div>
                      <div><span className="text-slate-400">Nameservers:</span> <span className="text-slate-300">{result.nameservers?.join(', ')}</span></div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
