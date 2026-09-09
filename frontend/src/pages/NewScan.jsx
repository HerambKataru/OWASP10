import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe, Upload, Play, Shield, Settings, Sliders, CheckCircle2, AlertCircle } from 'lucide-react';
import { scanService, sastService } from '../services/api';

export default function NewScan({ onScanCreated }) {
  const navigate = useNavigate();
  const [scanMode, setScanMode] = useState('website'); // 'website' | 'project'
  
  // Website Form State
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [crawlDepth, setCrawlDepth] = useState(2);
  const [threads, setThreads] = useState(5);
  const [timeout, setTimeoutVal] = useState(10);
  const [userAgent, setUserAgent] = useState('SentinelX-VAPT-Agent/1.0');
  const [selectedScanners, setSelectedScanners] = useState([
    'recon', 'sqli', 'xss', 'idor', 'auth', 'upload', 'headers', 'exposure'
  ]);

  // Project Upload State
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const handleToggleScanner = (key) => {
    setSelectedScanners(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );
  };

  const handleStartWebsiteScan = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setStatusMsg('Initializing local automated assessment...');

    try {
      const res = await scanService.createScan({
        target: targetUrl,
        scan_type: 'website',
        crawl_depth: parseInt(crawlDepth),
        threads: parseInt(threads),
        timeout: parseInt(timeout),
        user_agent: userAgent,
        selected_scanners: selectedScanners
      });

      if (onScanCreated) {
        onScanCreated(res.data);
      }
      navigate('/');
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message || 'Failed to start scan');
      setStatusMsg('');
    }
  };

  const handleStartProjectUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('Please select a project ZIP file');
      return;
    }

    setUploading(true);
    setErrorMsg('');
    setStatusMsg('Extracting project archive and running local SAST analyzer...');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const res = await sastService.uploadProject(formData);
      if (onScanCreated) {
        const scanRes = await scanService.getScanById(res.data.scan_id);
        onScanCreated(scanRes.data);
      }
      navigate('/static-analysis');
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message || 'Failed to analyze project');
      setStatusMsg('');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <Play className="w-6 h-6 text-cyan-400 fill-cyan-400" />
          <span>Launch New Assessment</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          Configure an authorized local website assessment or upload a source code repository for offline SAST scanning.
        </p>
      </div>

      {/* Mode Selector Tabs */}
      <div className="grid grid-cols-2 gap-3 bg-[#0B0F19] p-1.5 rounded-xl border border-slate-800">
        <button
          type="button"
          onClick={() => setScanMode('website')}
          className={`flex items-center justify-center gap-2.5 py-3 rounded-lg text-xs font-bold transition select-none ${
            scanMode === 'website'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-[0_0_15px_rgba(0,240,255,0.15)]'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Mode 1: Live Target Website Scan</span>
        </button>

        <button
          type="button"
          onClick={() => setScanMode('project')}
          className={`flex items-center justify-center gap-2.5 py-3 rounded-lg text-xs font-bold transition select-none ${
            scanMode === 'project'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-[0_0_15px_rgba(0,240,255,0.15)]'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Upload className="w-4 h-4" />
          <span>Mode 2: Source Code Project (SAST ZIP)</span>
        </button>
      </div>

      {/* Alerts */}
      {errorMsg && (
        <div className="bg-red-950/40 border border-red-800/80 p-3 rounded-xl flex items-center gap-2 text-xs text-red-300 font-mono">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {statusMsg && (
        <div className="bg-cyan-950/40 border border-cyan-800/80 p-3 rounded-xl flex items-center gap-2 text-xs text-cyan-300 font-mono">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* MODE 1: WEBSITE SCAN FORM */}
      {scanMode === 'website' ? (
        <form onSubmit={handleStartWebsiteScan} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
          {/* Target URL */}
          <div>
            <label className="block text-xs font-mono font-bold text-slate-300 mb-1.5">
              TARGET URL (HOSTNAME / IP)
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
              <input
                type="text"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com or http://localhost:3000"
                className="w-full bg-[#070A11] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>
            <span className="text-[10px] text-slate-400 font-mono mt-1 block">
              Ensure you have explicit authorization to assess this target.
            </span>
          </div>

          {/* Crawler & Engine Settings */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Crawl Depth</label>
              <select
                value={crawlDepth}
                onChange={(e) => setCrawlDepth(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              >
                <option value={1}>1 (Single Page)</option>
                <option value={2}>2 (Standard Crawl)</option>
                <option value={3}>3 (Deep Crawl)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Worker Threads</label>
              <select
                value={threads}
                onChange={(e) => setThreads(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              >
                <option value={1}>1 (Conservative)</option>
                <option value={5}>5 (Recommended)</option>
                <option value={10}>10 (Fast / Local)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">HTTP Timeout (s)</label>
              <input
                type="number"
                min={2}
                max={30}
                value={timeout}
                onChange={(e) => setTimeoutVal(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              />
            </div>
          </div>

          {/* User Agent */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Custom User-Agent</label>
            <input
              type="text"
              value={userAgent}
              onChange={(e) => setUserAgent(e.target.value)}
              className="w-full bg-[#070A11] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>

          {/* Active Scanner Selection */}
          <div className="pt-2 border-t border-slate-800/80">
            <label className="block text-xs font-mono font-bold text-slate-300 mb-2.5">
              ACTIVE OWASP TOP 10 MODULES
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { id: 'recon', label: 'Recon & Fingerprint' },
                { id: 'sqli', label: 'SQL Injection' },
                { id: 'xss', label: 'Cross-Site Scripting' },
                { id: 'idor', label: 'Broken Access Control' },
                { id: 'auth', label: 'Authentication & Session' },
                { id: 'upload', label: 'File Upload Testing' },
                { id: 'headers', label: 'Misconfiguration' },
                { id: 'exposure', label: 'Data & Secret Leaks' }
              ].map((mod) => (
                <label
                  key={mod.id}
                  onClick={() => handleToggleScanner(mod.id)}
                  className={`flex items-center gap-2 p-2.5 rounded-lg border text-xs font-mono cursor-pointer transition select-none ${
                    selectedScanners.includes(mod.id)
                      ? 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
                      : 'bg-slate-900/60 border-slate-800 text-slate-500'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedScanners.includes(mod.id)}
                    onChange={() => {}}
                    className="accent-cyan-400"
                  />
                  <span>{mod.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Submit */}
          <div className="pt-4 flex justify-end">
            <button
              type="submit"
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition shadow-[0_0_20px_rgba(0,240,255,0.3)]"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Launch Automated Assessment</span>
            </button>
          </div>
        </form>
      ) : (
        /* MODE 2: SOURCE CODE ZIP UPLOAD FORM */
        <form onSubmit={handleStartProjectUpload} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
          <div className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-2xl p-8 text-center transition bg-[#070A11] flex flex-col items-center justify-center">
            <Upload className="w-10 h-10 text-cyan-400 mb-3" />
            <h3 className="text-sm font-bold text-slate-200">Upload Project Repository (.ZIP)</h3>
            <p className="text-xs text-slate-400 font-mono mt-1 max-w-md">
              Supports PHP, Python (Flask, Django), JavaScript, Node.js, HTML, and configuration files. Extracted and parsed 100% locally.
            </p>

            <label className="mt-4 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-bold cursor-pointer border border-slate-700 transition">
              <span>Choose ZIP File</span>
              <input
                type="file"
                accept=".zip"
                onChange={(e) => setSelectedFile(e.target.files[0])}
                className="hidden"
              />
            </label>

            {selectedFile && (
              <div className="mt-3 text-xs font-mono text-cyan-400 bg-cyan-950/40 px-3 py-1.5 rounded-lg border border-cyan-800/60">
                Selected: {selectedFile.name} ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
              </div>
            )}
          </div>

          <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
            <div className="text-slate-200 font-bold">Local SAST Engine Capabilities:</div>
            <div>• Detects dynamic code execution: exec(), eval(), system(), shell_exec()</div>
            <div>• Identifies unsafe deserialization: pickle.loads(), unserialize()</div>
            <div>• Detects SQL query concatenation & vulnerable database calls</div>
            <div>• Scans for hardcoded secrets, JWT tokens, AWS keys, and passwords</div>
          </div>

          <div className="pt-4 flex justify-end">
            <button
              type="submit"
              disabled={uploading || !selectedFile}
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs transition shadow-[0_0_20px_rgba(0,240,255,0.3)]"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{uploading ? 'Analyzing Source Code...' : 'Analyze Source Code (SAST)'}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
