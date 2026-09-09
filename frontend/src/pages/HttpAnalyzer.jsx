import React, { useState, useEffect } from 'react';
import {
  Send,
  History,
  Code,
  KeyRound,
  GitCompare,
  CheckCircle,
  AlertCircle,
  Copy,
  Clock,
  Sparkles
} from 'lucide-react';
import { httpAnalyzerService } from '../services/api';

export default function HttpAnalyzer({ currentScan }) {
  const [activeTab, setActiveTab] = useState('repeater'); // 'repeater' | 'history' | 'jwt' | 'diff'
  
  // Repeater State
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState(currentScan?.target || 'http://localhost:8000/docs');
  const [headersText, setHeadersText] = useState('{\n  "Accept": "*/*",\n  "User-Agent": "SentinelX-HTTP-Analyzer/1.0"\n}');
  const [bodyText, setBodyText] = useState('');
  const [response, setResponse] = useState(null);
  const [sending, setSending] = useState(false);
  const [historyList, setHistoryList] = useState([]);

  // JWT Decoder State
  const [jwtInput, setJwtInput] = useState('');
  const [jwtDecoded, setJwtDecoded] = useState(null);

  // Diff State
  const [diffBody1, setDiffBody1] = useState('{\n  "status": "success",\n  "user_id": 1,\n  "role": "admin"\n}');
  const [diffBody2, setDiffBody2] = useState('{\n  "status": "success",\n  "user_id": 2,\n  "role": "user"\n}');
  const [diffResult, setDiffResult] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, [currentScan]);

  const fetchHistory = () => {
    httpAnalyzerService.getHistory(currentScan?.id, 30)
      .then((res) => setHistoryList(res.data))
      .catch((err) => console.error('Failed to load history:', err));
  };

  const handleSendRequest = async (e) => {
    e.preventDefault();
    setSending(true);

    let parsedHeaders = {};
    try {
      if (headersText.trim()) {
        parsedHeaders = JSON.parse(headersText);
      }
    } catch (err) {
      alert('Invalid JSON in Request Headers field.');
      setSending(false);
      return;
    }

    try {
      const res = await httpAnalyzerService.replay({
        method,
        url,
        headers: parsedHeaders,
        body: bodyText
      });
      setResponse(res.data);
      fetchHistory();
    } catch (err) {
      setResponse({
        error: err.response?.data?.detail || err.message || 'Request failed'
      });
    } finally {
      setSending(false);
    }
  };

  const handleDecodeJwt = async () => {
    if (!jwtInput.trim()) return;
    try {
      const res = await httpAnalyzerService.decodeJwt(jwtInput.trim());
      setJwtDecoded(res.data);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to decode JWT');
    }
  };

  const handleRunDiff = async () => {
    try {
      const res = await httpAnalyzerService.compare(diffBody1, diffBody2);
      setDiffResult(res.data);
    } catch (err) {
      alert('Failed to compare responses');
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <Code className="w-6 h-6 text-cyan-400" />
          <span>HTTP Request & Response Analyzer</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Burp-like HTTP Repeater, live telemetry history, JWT security decoder, and response delta diff engine.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        {[
          { id: 'repeater', label: 'HTTP Repeater', icon: Send },
          { id: 'history', label: `Request History (${historyList.length})`, icon: History },
          { id: 'jwt', label: 'JWT Security Decoder', icon: KeyRound },
          { id: 'diff', label: 'Response Diff Comparison', icon: GitCompare }
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium transition ${
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

      {/* TAB 1: REPEATER */}
      {activeTab === 'repeater' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Request Panel */}
          <form onSubmit={handleSendRequest} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-200">RAW HTTP REQUEST</span>
              <button
                type="submit"
                disabled={sending}
                className="flex items-center gap-1.5 px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 text-xs font-bold font-mono rounded-lg transition"
              >
                <Send className="w-3.5 h-3.5 fill-current" />
                <span>{sending ? 'Sending...' : 'Send Request'}</span>
              </button>
            </div>

            {/* Method & URL Bar */}
            <div className="flex gap-2">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="bg-[#070A11] border border-slate-700 text-xs font-mono font-bold text-cyan-400 rounded-xl px-3 py-2 focus:outline-none"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>

              <input
                type="text"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="http://target.local/api"
                className="flex-1 bg-[#070A11] border border-slate-700 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Headers Textarea */}
            <div>
              <label className="block text-[10px] font-mono text-slate-400 mb-1">REQUEST HEADERS (JSON format)</label>
              <textarea
                rows={4}
                value={headersText}
                onChange={(e) => setHeadersText(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Request Body */}
            <div>
              <label className="block text-[10px] font-mono text-slate-400 mb-1">REQUEST BODY (Optional)</label>
              <textarea
                rows={6}
                value={bodyText}
                onChange={(e) => setBodyText(e.target.value)}
                placeholder="JSON, Form Data, or Raw Payload..."
                className="w-full bg-[#070A11] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </form>

          {/* Response Panel */}
          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-200">HTTP RESPONSE VIEWER</span>
              {response && (
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    response.status_code < 300 ? 'text-emerald-400 bg-emerald-950/60' : 'text-red-400 bg-red-950/60'
                  }`}>
                    HTTP {response.status_code || 'ERR'} {response.status_text || ''}
                  </span>
                  {response.elapsed_ms && (
                    <span className="text-[10px] font-mono text-slate-400">{response.elapsed_ms} ms</span>
                  )}
                </div>
              )}
            </div>

            {/* Response Output */}
            <div className="flex-1 bg-[#070A11] border border-slate-800 rounded-xl p-3 overflow-y-auto max-h-[420px] terminal-scroll font-mono text-xs">
              {response ? (
                response.error ? (
                  <div className="text-red-400">{response.error}</div>
                ) : (
                  <div className="space-y-3">
                    <div className="text-slate-400 text-[10px] border-b border-slate-800 pb-2">
                      {Object.entries(response.headers || {}).map(([k, v]) => (
                        <div key={k}><strong className="text-slate-300">{k}:</strong> {v}</div>
                      ))}
                    </div>
                    <pre className="text-emerald-400 text-[11px] whitespace-pre-wrap">{response.body}</pre>
                  </div>
                )
              ) : (
                <div className="text-slate-500 flex items-center justify-center h-48">
                  Response output will appear here after sending request.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: HISTORY */}
      {activeTab === 'history' && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#070A11] border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">#</th>
                  <th className="py-3 px-4">Method</th>
                  <th className="py-3 px-4">URL</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {historyList.length === 0 ? (
                  <tr><td colSpan="6" className="py-8 text-center text-slate-500">No requests recorded in history.</td></tr>
                ) : (
                  historyList.map((h) => (
                    <tr key={h.id} className="hover:bg-slate-900/40 cursor-pointer" onClick={() => {
                      setMethod(h.method);
                      setUrl(h.url);
                      setHeadersText(JSON.stringify(h.request_headers, null, 2));
                      setBodyText(h.request_body || '');
                      setActiveTab('repeater');
                    }}>
                      <td className="py-3 px-4 text-slate-500">{h.id}</td>
                      <td className="py-3 px-4 font-bold text-cyan-400">{h.method}</td>
                      <td className="py-3 px-4 text-slate-200 truncate max-w-sm">{h.url}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          h.response_status < 300 ? 'text-emerald-400 bg-emerald-950/60' : 'text-red-400 bg-red-950/60'
                        }`}>
                          {h.response_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">{h.response_time_ms} ms</td>
                      <td className="py-3 px-4 text-slate-500 text-[10px]">{h.timestamp}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: JWT DECODER */}
      {activeTab === 'jwt' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <span className="text-xs font-mono font-bold text-slate-200">JWT RAW TOKEN INPUT</span>
            <textarea
              rows={8}
              value={jwtInput}
              onChange={(e) => setJwtInput(e.target.value)}
              placeholder="Paste your JSON Web Token (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
              className="w-full bg-[#070A11] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="button"
              onClick={handleDecodeJwt}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs rounded-xl transition"
            >
              Decode & Inspect Claims
            </button>
          </div>

          <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-3 font-mono text-xs shadow-xl">
            <span className="text-xs font-bold text-slate-200">DECODED STRUCTURE</span>
            {jwtDecoded ? (
              <div className="space-y-3">
                <div className="bg-[#070A11] p-3 rounded-xl border border-slate-800">
                  <div className="text-red-400 font-bold mb-1">HEADER: Algorithm & Token Type</div>
                  <pre className="text-slate-300 text-[11px]">{JSON.stringify(jwtDecoded.header, null, 2)}</pre>
                </div>
                <div className="bg-[#070A11] p-3 rounded-xl border border-slate-800">
                  <div className="text-purple-400 font-bold mb-1">PAYLOAD: Data Claims</div>
                  <pre className="text-slate-300 text-[11px]">{JSON.stringify(jwtDecoded.payload, null, 2)}</pre>
                </div>
                {jwtDecoded.expired !== null && (
                  <div className={`p-2.5 rounded-lg border text-xs font-bold ${
                    jwtDecoded.expired ? 'text-red-400 bg-red-950/40 border-red-800' : 'text-emerald-400 bg-emerald-950/40 border-emerald-800'
                  }`}>
                    {jwtDecoded.expired ? '⚠️ Token Expired' : '✅ Token Active / Valid Time'}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-slate-500 h-48 flex items-center justify-center">
                Paste token and click decode to view algorithm, payload claims, and signature.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: RESPONSE DIFF */}
      {activeTab === 'diff' && (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-200">COMPARE TWO RESPONSES</span>
            <button
              type="button"
              onClick={handleRunDiff}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs rounded-xl transition"
            >
              Generate Diff
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-mono text-slate-400 mb-1">Response A</label>
              <textarea
                rows={6}
                value={diffBody1}
                onChange={(e) => setDiffBody1(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300"
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono text-slate-400 mb-1">Response B</label>
              <textarea
                rows={6}
                value={diffBody2}
                onChange={(e) => setDiffBody2(e.target.value)}
                className="w-full bg-[#070A11] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300"
              />
            </div>
          </div>

          {diffResult && (
            <div className="bg-[#070A11] p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
              <div className="text-cyan-400 font-bold">Similarity: {diffResult.similarity_ratio}%</div>
              <pre className="text-slate-300 text-[11px] whitespace-pre-wrap">{diffResult.diff_text || 'No differences found.'}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
