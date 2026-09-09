import React, { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Key, Shield, CheckCircle2, Lock, Eye, EyeOff, Save, Trash2 } from 'lucide-react';
import { settingsService } from '../services/api';

export default function Settings() {
  const [settings, setSettings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [inputKeys, setInputKeys] = useState({});
  const [saveStatus, setSaveStatus] = useState('');

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = () => {
    setLoading(true);
    settingsService.getSettings()
      .then((res) => {
        setSettings(res.data);
        const initialInputs = {};
        res.data.forEach((s) => {
          initialInputs[s.key] = '';
        });
        setInputKeys(initialInputs);
      })
      .catch((err) => console.error('Failed to load settings:', err))
      .finally(() => setLoading(false));
  };

  const handleSaveKey = async (keyName) => {
    const val = inputKeys[keyName];
    if (!val || !val.trim()) return;

    try {
      await settingsService.updateSetting(keyName, val.trim());
      setSaveStatus(`Saved key '${keyName}' securely.`);
      fetchSettings();
      setTimeout(() => setSaveStatus(''), 4000);
    } catch (err) {
      alert('Failed to save API key');
    }
  };

  const handleDeleteKey = async (keyName) => {
    try {
      await settingsService.deleteSetting(keyName);
      setSaveStatus(`Removed key '${keyName}'.`);
      fetchSettings();
      setTimeout(() => setSaveStatus(''), 4000);
    } catch (err) {
      alert('Failed to remove API key');
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
          <SettingsIcon className="w-6 h-6 text-cyan-400" />
          <span>Workstation Configuration & API Key Vault</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Securely persist threat intelligence API keys (VirusTotal, AbuseIPDB, Shodan). Keys are stored encrypted in the local SQLite database.
        </p>
      </div>

      {saveStatus && (
        <div className="bg-emerald-950/60 border border-emerald-800 p-3 rounded-xl flex items-center gap-2 text-xs font-mono text-emerald-300">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{saveStatus}</span>
        </div>
      )}

      {/* Security Info Card */}
      <div className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 flex items-start gap-3.5 shadow-xl">
        <Lock className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs font-mono space-y-1">
          <div className="text-slate-200 font-bold">Local Key Security Guarantee</div>
          <p className="text-slate-400 leading-relaxed">
            API keys configured here are encrypted locally and never transmitted to external third-party telemetry services. You can also configure keys via <code className="text-cyan-400">backend/.env</code>.
          </p>
        </div>
      </div>

      {/* API Key Vault Cards */}
      <div className="space-y-4">
        {settings.map((item) => (
          <div key={item.key} className="bg-[#0C1220] border border-slate-800 rounded-2xl p-5 space-y-3 shadow-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-slate-100">{item.name}</span>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${
                item.is_configured
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                  : 'bg-slate-900 text-slate-500 border-slate-800'
              }`}>
                {item.is_configured ? `CONFIGURED (${item.masked_value})` : 'NOT CONFIGURED (OPTIONAL)'}
              </span>
            </div>

            <p className="text-xs text-slate-400 font-mono">{item.description}</p>

            <div className="flex gap-2 pt-1">
              <input
                type="password"
                value={inputKeys[item.key] || ''}
                onChange={(e) => setInputKeys({ ...inputKeys, [item.key]: e.target.value })}
                placeholder={`Enter new ${item.name}...`}
                className="flex-1 bg-[#070A11] border border-slate-700 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={() => handleSaveKey(item.key)}
                className="flex items-center gap-1.5 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs rounded-xl transition"
              >
                <Save className="w-3.5 h-3.5" />
                <span>Save Key</span>
              </button>
              {item.is_configured && (
                <button
                  type="button"
                  onClick={() => handleDeleteKey(item.key)}
                  className="px-3 py-2 bg-red-950/60 hover:bg-red-900/60 text-red-400 border border-red-800 rounded-xl text-xs transition"
                  title="Remove Key"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
