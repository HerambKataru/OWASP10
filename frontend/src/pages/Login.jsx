import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, ArrowRight, Zap, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const navigate = useNavigate();
  const { login, loginWithGoogle, demoLogin } = useAuth();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err.message?.replace('Firebase: ', '') || 'Failed to authenticate');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError('');
    setLoading(true);
    try {
      await loginWithGoogle();
      navigate('/');
    } catch (err) {
      setError('Google Sign-In failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoAccess = () => {
    demoLogin();
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-[#080C14] flex flex-col justify-center items-center px-4 selection:bg-cyan-500 selection:text-black font-sans relative overflow-hidden">
      {/* Background glow lines */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

      {/* Main Login Card */}
      <div className="w-full max-w-md bg-[#0C1220] border border-slate-800 rounded-3xl p-8 shadow-2xl space-y-6 relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 glow-cyan">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-wider text-white">
              SENTINEL<span className="text-cyan-400">X</span>
            </h1>
            <p className="text-xs font-mono text-slate-400 mt-0.5">
              Secure VAPT Workstation Authentication
            </p>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="bg-red-950/60 border border-red-800 p-3 rounded-xl flex items-center gap-2.5 text-xs font-mono text-red-300">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono font-bold text-slate-300 mb-1.5">
              SECURITY ANALYST EMAIL
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@sentinelx.io"
                className="w-full bg-[#070A11] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-bold text-slate-300 mb-1.5">
              ACCESS PASSPHRASE
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#070A11] border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold font-mono text-xs transition flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(0,240,255,0.3)]"
          >
            <span>{loading ? 'Authenticating with Firebase...' : 'Authorize Access'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Divider */}
        <div className="relative flex items-center justify-center">
          <div className="border-t border-slate-800 w-full"></div>
          <span className="bg-[#0C1220] px-3 text-[10px] font-mono text-slate-500 uppercase">Or Continue With</span>
        </div>

        {/* OAuth / Quick Access Options */}
        <div className="space-y-2.5">
          <button
            type="button"
            onClick={handleGoogleSignIn}
            disabled={loading}
            className="w-full py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-mono text-xs font-semibold rounded-xl transition flex items-center justify-center gap-2.5"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.4l3.7 2.9C6.5 7.4 9 5 12 5z"/>
              <path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.6h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.9z"/>
              <path fill="#FBBC05" d="M5.6 14.7c-.2-.7-.4-1.5-.4-2.4 0-.9.2-1.7.4-2.4L1.9 7C.7 9.4 0 12 0 14.7s.7 5.3 1.9 7.7l3.7-2.9z"/>
              <path fill="#34A853" d="M12 23.5c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2-6.4-4.8L1.9 17C3.7 20.8 7.5 23.5 12 23.5z"/>
            </svg>
            <span>Sign in with Google</span>
          </button>

          <button
            type="button"
            onClick={handleDemoAccess}
            className="w-full py-2.5 bg-emerald-950/40 hover:bg-emerald-900/40 text-emerald-400 border border-emerald-800/80 font-mono text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-[0_0_10px_rgba(0,255,157,0.15)]"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>1-Click Instant Analyst Access (Demo)</span>
          </button>
        </div>

        {/* Footer Link */}
        <div className="text-center text-xs font-mono text-slate-400">
          Need a new workstation account?{' '}
          <Link to="/signup" className="text-cyan-400 hover:underline font-bold">
            Create Security Credentials
          </Link>
        </div>
      </div>
    </div>
  );
}
