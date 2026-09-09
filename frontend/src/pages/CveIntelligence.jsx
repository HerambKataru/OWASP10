import React, { useState, useEffect } from 'react';
import { Bug, Search, ShieldAlert, Calendar, ExternalLink, ShieldCheck } from 'lucide-react';
import { intelService } from '../services/api';

export default function CveIntelligence({ currentScan }) {
  const [searchTerm, setSearchTerm] = useState('apache');
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // If target has tech, search first detected tech
    if (currentScan?.technologies && Array.isArray(currentScan.technologies) && currentScan.technologies.length > 0) {
      const firstTech = currentScan.technologies[0].split(' ')[0].toLowerCase();
      setSearchTerm(firstTech);
      fetchCves(firstTech);
    } else {
      fetchCves('apache');
    }
  }, [currentScan]);

  const fetchCves = (keyword) => {
    setLoading(true);
    intelService.getCves(keyword)
      .then((res) => setCves(res.data))
      .catch((err) => console.error('Failed to load CVEs:', err))
      .finally(() => setLoading(false));
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      fetchCves(searchTerm.trim());
    }
  };

  const getSeverityBadge = (sev, cvss) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-950/60 border-red-800';
      case 'high':
        return 'text-orange-400 bg-orange-950/60 border-orange-800';
      case 'medium':
        return 'text-amber-400 bg-amber-950/60 border-amber-800';
      default:
        return 'text-blue-400 bg-blue-950/60 border-blue-800';
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <Bug className="w-6 h-6 text-cyan-400" />
          <span>NVD NIST CVE Intelligence Explorer</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Search Common Vulnerabilities and Exposures (CVE) database and match known vulnerabilities against detected target technologies.
        </p>
      </div>

      {/* Search Bar */}
      <form onSubmit={handleSearch} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-4 flex gap-3 shadow-xl">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
          <input
            type="text"
            required
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search software, framework, or CVE ID (e.g. nginx, spring, log4j, CVE-2023-4863)..."
            className="w-full bg-[#070A11] border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold font-mono text-xs rounded-xl transition shadow-[0_0_15px_rgba(0,240,255,0.25)]"
        >
          {loading ? 'Searching NVD...' : 'Search CVEs'}
        </button>
      </form>

      {/* CVE Result List */}
      <div className="space-y-3">
        {cves.length === 0 ? (
          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-12 text-center text-slate-500 font-mono text-xs">
            No CVE records matched for "{searchTerm}".
          </div>
        ) : (
          cves.map((cve, idx) => (
            <div key={idx} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-3 shadow-lg hover:border-slate-700 transition">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-black font-mono text-cyan-400">{cve.cve_id}</span>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(cve.severity, cve.cvss)}`}>
                    {cve.severity?.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono text-slate-400">CVSS v3: <strong className="text-slate-200">{cve.cvss}</strong></span>
                </div>

                <div className="flex items-center gap-1 text-[11px] font-mono text-slate-500">
                  <Calendar className="w-3.5 h-3.5" />
                  <span>Published: {cve.published}</span>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {cve.description}
              </p>

              <div className="flex items-center justify-between text-[11px] font-mono pt-2 border-t border-slate-800/80">
                <span className="text-slate-500">Source: {cve.source || 'NIST National Vulnerability Database'}</span>
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-400 hover:underline flex items-center gap-1"
                >
                  <span>NVD Record</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
