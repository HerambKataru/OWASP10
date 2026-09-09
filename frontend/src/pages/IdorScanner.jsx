import React, { useEffect, useState } from 'react';
import { Lock, ShieldAlert, CheckCircle2 } from 'lucide-react';
import FindingCard from '../components/FindingCard';
import { scannerService } from '../services/api';

export default function IdorScanner({ currentScan }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    scannerService.getIdor(currentScan?.id)
      .then((res) => setFindings(res.data))
      .catch((err) => console.error('Failed to load IDOR:', err))
      .finally(() => setLoading(false));
  }, [currentScan]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <Lock className="w-6 h-6 text-cyan-400" />
            <span>OWASP A01: Broken Access Control & IDOR</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Automated direct object reference mutations (user/1, order/100) and authorization bound verification.
          </p>
        </div>
        <span className="px-3 py-1 rounded-lg bg-orange-950/60 border border-orange-800 text-xs font-mono font-bold text-orange-400">
          Findings: {findings.length}
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-12 text-center text-slate-500 font-mono text-xs space-y-2">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
          <div className="text-slate-300 font-bold">No Broken Access Control Flaws Detected</div>
          <p className="text-slate-500 max-w-md mx-auto">
            Numeric path and parameter mutations were either forbidden or properly access-controlled.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
