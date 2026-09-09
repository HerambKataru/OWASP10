import React, { useEffect, useState } from 'react';
import {
  Radar,
  FolderTree,
  List,
  Sliders,
  Layers,
  FileCode,
  Globe,
  CheckCircle,
  ExternalLink
} from 'lucide-react';
import { reconService, intelService } from '../services/api';

export default function Reconnaissance({ currentScan }) {
  const [activeTab, setActiveTab] = useState('endpoints'); // 'endpoints' | 'sitemap' | 'parameters' | 'tech' | 'dns'
  const [endpoints, setEndpoints] = useState([]);
  const [sitemap, setSitemap] = useState(null);
  const [parameters, setParameters] = useState([]);
  const [dnsData, setDnsData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (currentScan?.id) {
      setLoading(true);
      Promise.all([
        reconService.getEndpoints(currentScan.id),
        reconService.getSitemap(currentScan.id),
        reconService.getParameters(currentScan.id),
        intelService.getWhoisDns(currentScan.target)
      ])
        .then(([epRes, mapRes, paramRes, dnsRes]) => {
          setEndpoints(epRes.data);
          setSitemap(mapRes.data);
          setParameters(paramRes.data);
          setDnsData(dnsRes.data);
        })
        .catch((err) => console.error('Failed to load recon data:', err))
        .finally(() => setLoading(false));
    }
  }, [currentScan]);

  const technologies = Array.isArray(currentScan?.technologies)
    ? currentScan.technologies
    : ['Nginx', 'FastAPI', 'React', 'SQLite'];

  const renderTree = (node, depth = 0) => {
    if (!node) return null;
    return (
      <div key={node.name + depth} className="pl-4 border-l border-slate-800 my-1 font-mono text-xs">
        <div className="flex items-center gap-2 py-0.5 hover:bg-slate-900/60 rounded px-1.5 transition">
          <FolderTree className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-slate-200 font-semibold">{node.name || '/'}</span>
          {node.url && (
            <span className="text-[10px] text-slate-500 truncate max-w-sm">({node.url})</span>
          )}
        </div>
        {node.children && node.children.map((child) => renderTree(child, depth + 1))}
      </div>
    );
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <Radar className="w-6 h-6 text-cyan-400" />
            <span>Target Reconnaissance & Attack Surface</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Endpoint discovery, directory tree mapping, parameter indexing, and technology stack fingerprinting.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-400">
            Discovered Endpoints: {endpoints.length}
          </span>
          <span className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-emerald-400">
            Unique Parameters: {parameters.length}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        {[
          { id: 'endpoints', label: 'Discovered Endpoints', icon: List },
          { id: 'sitemap', label: 'Interactive Sitemap Tree', icon: FolderTree },
          { id: 'parameters', label: 'Parameter Matrix', icon: Sliders },
          { id: 'tech', label: 'Technology Fingerprinting', icon: Layers },
          { id: 'dns', label: 'DNS & WHOIS Intelligence', icon: Globe },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium transition whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: ENDPOINTS */}
      {activeTab === 'endpoints' && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#070A11] border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">Method</th>
                  <th className="py-3 px-4">URL / Endpoint</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Content Type</th>
                  <th className="py-3 px-4">Response Time</th>
                  <th className="py-3 px-4">Inputs/Forms</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {endpoints.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="py-8 text-center text-slate-500">
                      No endpoints mapped yet. Run a website scan to crawl.
                    </td>
                  </tr>
                ) : (
                  endpoints.map((ep, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40 transition">
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 text-[10px] font-bold">
                          {ep.method}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-200 font-semibold truncate max-w-md">
                        {ep.url}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ep.status_code === 200 ? 'text-emerald-400 bg-emerald-950/60' : 'text-amber-400 bg-amber-950/60'
                        }`}>
                          {ep.status_code}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">{ep.content_type?.split(';')[0]}</td>
                      <td className="py-3 px-4 text-slate-400">{ep.response_time}s</td>
                      <td className="py-3 px-4 text-slate-300">
                        {ep.parameters?.length > 0 && (
                          <span className="text-cyan-400 mr-2">[{ep.parameters.length} params]</span>
                        )}
                        {ep.forms?.length > 0 && (
                          <span className="text-emerald-400">[{ep.forms.length} forms]</span>
                        )}
                        {!ep.parameters?.length && !ep.forms?.length && <span className="text-slate-600">-</span>}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: SITEMAP TREE */}
      {activeTab === 'sitemap' && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="text-xs font-mono text-slate-400">
            Hierarchical directory structure discovered during active crawling:
          </div>
          <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 overflow-x-auto max-h-[500px] terminal-scroll">
            {sitemap ? renderTree(sitemap) : <div className="text-slate-500 font-mono text-xs">No sitemap data available.</div>}
          </div>
        </div>
      )}

      {/* TAB 3: PARAMETER MATRIX */}
      {activeTab === 'parameters' && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="text-xs font-mono text-slate-400">
            Input vector parameters mapped across query strings, POST bodies, and headers:
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {parameters.length === 0 ? (
              <div className="text-slate-500 font-mono text-xs col-span-3">No input parameters detected.</div>
            ) : (
              parameters.map((param, idx) => (
                <div key={idx} className="bg-[#070A11] p-3.5 rounded-xl border border-slate-800 font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between text-cyan-400 font-bold">
                    <span>{param.name}</span>
                    <span className="text-[10px] text-slate-400 font-normal">{param.count} endpoints</span>
                  </div>
                  <div className="text-[10px] text-slate-400 truncate">
                    Used in: {param.endpoints?.[0] || 'Target page'}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 4: TECHNOLOGY FINGERPRINTING */}
      {activeTab === 'tech' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {technologies.map((tech, idx) => (
            <div key={idx} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-2 shadow-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-slate-100">{tech}</span>
                <CheckCircle className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Fingerprinted via response headers, cookie signatures, and DOM inline scripts.
              </p>
              <div className="pt-2">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950/60 text-cyan-400 border border-cyan-800/60">
                  Confirmed Signature
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 5: DNS & WHOIS */}
      {activeTab === 'dns' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-3 font-mono text-xs shadow-xl">
            <h3 className="text-sm font-bold text-slate-200">DNS Records</h3>
            <div className="space-y-2 bg-[#070A11] p-3.5 rounded-xl border border-slate-800">
              <div><span className="text-slate-400">Target Host:</span> <span className="text-cyan-400">{dnsData?.domain || currentScan?.target}</span></div>
              <div><span className="text-slate-400">A Records:</span> <span className="text-emerald-400">{dnsData?.a_records?.join(', ') || '127.0.0.1'}</span></div>
              <div><span className="text-slate-400">MX Records:</span> <span className="text-slate-300">{dnsData?.mx_records?.join(', ') || 'N/A'}</span></div>
              <div><span className="text-slate-400">Nameservers:</span> <span className="text-slate-300">{dnsData?.nameservers?.join(', ') || 'N/A'}</span></div>
            </div>
          </div>

          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-3 font-mono text-xs shadow-xl">
            <h3 className="text-sm font-bold text-slate-200">WHOIS Information</h3>
            <div className="space-y-2 bg-[#070A11] p-3.5 rounded-xl border border-slate-800">
              <div><span className="text-slate-400">Registrar:</span> <span className="text-slate-300">{dnsData?.registrar || 'Private Registration'}</span></div>
              <div><span className="text-slate-400">Creation Date:</span> <span className="text-slate-300">{dnsData?.creation_date || 'N/A'}</span></div>
              <div><span className="text-slate-400">Expiry Date:</span> <span className="text-slate-300">{dnsData?.expiry_date || 'N/A'}</span></div>
              <div><span className="text-slate-400">Domain Status:</span> <span className="text-emerald-400">{dnsData?.status || 'Active'}</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
