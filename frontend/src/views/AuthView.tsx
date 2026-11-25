import React, { useState } from 'react';
import { ShieldCheck, Lock, Mail, User as UserIcon, ArrowRight, AlertCircle, ShieldAlert } from 'lucide-react';
import { api } from '../api/client';
import { User } from '../types';

interface AuthViewProps {
  isAdminPortal: boolean;
  onAuthenticated: (user: User, isAdminLogin: boolean) => void;
  onSwitchPortal: (admin: boolean) => void;
}

export const AuthView: React.FC<AuthViewProps> = ({
  isAdminPortal,
  onAuthenticated,
  onSwitchPortal,
}) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const effectiveMode = isAdminPortal ? 'login' : mode;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (effectiveMode === 'register') {
        const res = await api.register(fullName, email, password);
        onAuthenticated(res.user, false);
      } else {
        const res = await api.login(email, password);
        if (isAdminPortal && res.user.role !== 'super_admin' && res.user.role !== 'org_admin') {
          api.logout();
          setError('Access denied: This account does not have Administrator privileges.');
          return;
        }
        onAuthenticated(res.user, isAdminPortal);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Subtle Background Grid Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.12),_transparent_55%)] pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-tr from-sky-500 to-indigo-600 shadow-lg shadow-sky-500/25 mb-3">
            {isAdminPortal ? <Lock className="w-6 h-6 text-white" /> : <ShieldCheck className="w-6 h-6 text-white" />}
          </div>
          <h1 className="text-2xl font-extrabold tracking-wide text-white">
            SUPPLY CHAIN <span className="text-sky-400">SENTINEL</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            {isAdminPortal
              ? 'RESTRICTED ADMINISTRATION & BACKEND CONSOLE'
              : 'Enterprise Software Supply Chain Risk Intelligence'}
          </p>
        </div>

        {/* Auth Card */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-2xl p-6 sm:p-7 shadow-2xl">
          {isAdminPortal ? (
            <div className="mb-5 p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 flex items-center gap-2.5 text-xs text-amber-300">
              <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400" />
              <span>Admin Sign-In Required. Authorized administrators only.</span>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2 p-1 bg-slate-900 rounded-xl border border-slate-800 mb-6">
              <button
                type="button"
                onClick={() => {
                  setMode('login');
                  setError(null);
                }}
                className={`py-2 rounded-lg text-xs font-semibold transition ${
                  mode === 'login'
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register');
                  setError(null);
                }}
                className={`py-2 rounded-lg text-xs font-semibold transition ${
                  mode === 'register'
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-start gap-2 text-xs text-red-300">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {effectiveMode === 'register' && (
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Full Name</label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Morgan"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Work Email</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={isAdminPortal ? 'admin@company.com' : 'you@company.com'}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  minLength={effectiveMode === 'register' ? 8 : 1}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={effectiveMode === 'register' ? 'Minimum 8 characters' : 'Enter password'}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full py-2.5 px-4 rounded-lg text-sm font-semibold text-white flex items-center justify-center gap-2 transition shadow-lg ${
                isAdminPortal
                  ? 'bg-indigo-600 hover:bg-indigo-500 shadow-indigo-600/20'
                  : 'bg-sky-600 hover:bg-sky-500 shadow-sky-600/20'
              } disabled:opacity-50`}
            >
              <span>
                {loading
                  ? 'Authenticating...'
                  : effectiveMode === 'register'
                  ? 'Create Analyst Account'
                  : isAdminPortal
                  ? 'Sign In to Admin Console'
                  : 'Sign In to Dashboard'}
              </span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Portal Switcher Footer */}
          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between text-xs">
            {isAdminPortal ? (
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  onSwitchPortal(false);
                }}
                className="text-sky-400 hover:text-sky-300 font-medium"
              >
                ← Back to User Portal
              </button>
            ) : (
              <>
                <span className="text-slate-500">New accounts receive Analyst access</span>
                <button
                  type="button"
                  onClick={() => {
                    setError(null);
                    onSwitchPortal(true);
                  }}
                  className="text-indigo-400 hover:text-indigo-300 font-medium"
                >
                  Admin Console →
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
