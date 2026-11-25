import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Server,
  Users,
  ScrollText,
  RefreshCw,
  Database,
  CheckCircle2,
  XCircle,
  Sliders,
  Lock,
  Search,
} from 'lucide-react';
import { api } from '../api/client';
import { AdminOverview, AdminUser, AuditLogEntry, User } from '../types';

interface AdminViewProps {
  currentUser: User;
  onNavigate: (view: string) => void;
}

const ROLE_OPTIONS = [
  'super_admin',
  'org_admin',
  'security_analyst',
  'security_engineer',
  'read_only_exec',
];

export const AdminView: React.FC<AdminViewProps> = ({ currentUser, onNavigate }) => {
  const [activeTab, setActiveTab] = useState<'system' | 'users' | 'audit'>('system');
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [auditFilter, setAuditFilter] = useState('');
  const [updatingUserId, setUpdatingUserId] = useState<string | null>(null);

  const isAdmin = currentUser.role === 'super_admin' || currentUser.role === 'org_admin';

  const loadAdminData = async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError(null);
    try {
      const [ov, usrList, logs] = await Promise.all([
        api.getAdminOverview(),
        api.getAdminUsers(),
        api.getAuditLogs(),
      ]);
      setOverview(ov);
      setUsers(usrList);
      setAuditLogs(logs);
    } catch (err: any) {
      setError(err.message || 'Failed to load administration data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAdminData();
  }, []);

  if (!isAdmin) {
    return (
      <div className="bg-slate-900 border border-red-500/30 rounded-xl p-8 text-center max-w-xl mx-auto mt-12">
        <Lock className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <h2 className="text-lg font-bold text-white">Administrator Access Required</h2>
        <p className="text-sm text-slate-400 mt-2">
          Your current role (<code className="text-sky-400">{currentUser.role}</code>) does not have permission to access the Admin Console.
        </p>
      </div>
    );
  }

  const handleUpdateUser = async (userId: string, update: { role?: string; is_active?: boolean }) => {
    setUpdatingUserId(userId);
    setError(null);
    setStatusMessage(null);
    try {
      const updated = await api.updateAdminUser(userId, update);
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
      setStatusMessage(`Updated ${updated.email} (${updated.role}, ${updated.is_active ? 'Active' : 'Suspended'}).`);
    } catch (err: any) {
      setError(err.message || 'Failed to update user.');
    } finally {
      setUpdatingUserId(null);
    }
  };

  const filteredLogs = auditLogs.filter(
    (log) =>
      log.action.toLowerCase().includes(auditFilter.toLowerCase()) ||
      log.user_email.toLowerCase().includes(auditFilter.toLowerCase()) ||
      log.target_resource.toLowerCase().includes(auditFilter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-indigo-400" />
            Private Administration & Backend Console
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Manage platform users, role permissions, backend runtime posture, and immutable security audit logs.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate('risk')}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 border border-slate-700"
          >
            <Sliders className="w-3.5 h-3.5 text-sky-400" />
            Risk Policy Weights
          </button>
          <button
            onClick={loadAdminData}
            disabled={loading}
            className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('system')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition ${
            activeTab === 'system'
              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <Server className="w-4 h-4" />
          Backend & System Status
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition ${
            activeTab === 'users'
              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <Users className="w-4 h-4" />
          User & Role Management ({users.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition ${
            activeTab === 'audit'
              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
              : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          <ScrollText className="w-4 h-4" />
          Security Audit Logs ({auditLogs.length})
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300">
          {error}
        </div>
      )}
      {statusMessage && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
          {statusMessage}
        </div>
      )}

      {/* Tab 1: Backend & System Overview */}
      {activeTab === 'system' && overview && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 uppercase font-mono">Environment</div>
              <div className="text-xl font-bold text-white mt-1 capitalize">{overview.environment}</div>
              <div className="text-[11px] text-slate-400 mt-1">
                Swagger Docs: {overview.docs_enabled ? 'Enabled (/docs)' : 'Disabled (Production Hardened)'}
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 uppercase font-mono flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-sky-400" /> Database Engine
              </div>
              <div className="text-xl font-bold text-sky-400 mt-1">{overview.database_engine}</div>
              <div className="text-[11px] text-slate-400 mt-1">
                {overview.total_sboms} SBOMs • {overview.total_applications} Applications
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 uppercase font-mono">Accounts</div>
              <div className="text-xl font-bold text-emerald-400 mt-1">
                {overview.active_users} / {overview.total_users} Active
              </div>
              <div className="text-[11px] text-slate-400 mt-1">JWT RBAC Enforcement Active</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 uppercase font-mono">Audit & Alerts</div>
              <div className="text-xl font-bold text-amber-400 mt-1">{overview.total_audit_logs} Events</div>
              <div className="text-[11px] text-slate-400 mt-1">
                {overview.unacknowledged_alerts} Unacknowledged Alerts
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Users & Roles */}
      {activeTab === 'users' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Last Login</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {users.map((u) => {
                  const isSelf = u.id === currentUser.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4 font-semibold text-white">
                        {u.full_name} {isSelf && <span className="text-[10px] text-sky-400">(You)</span>}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{u.email}</td>
                      <td className="py-3 px-4">
                        <select
                          value={u.role}
                          disabled={updatingUserId === u.id}
                          onChange={(e) => handleUpdateUser(u.id, { role: e.target.value })}
                          className="bg-slate-950 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        >
                          {ROLE_OPTIONS.map((roleOpt) => (
                            <option key={roleOpt} value={roleOpt}>
                              {roleOpt}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="py-3 px-4">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-400 font-medium">
                            <XCircle className="w-3.5 h-3.5" /> Suspended
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono">
                        {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          disabled={isSelf || updatingUserId === u.id}
                          onClick={() => handleUpdateUser(u.id, { is_active: !u.is_active })}
                          className={`px-2.5 py-1 rounded-md text-xs font-medium border transition disabled:opacity-40 ${
                            u.is_active
                              ? 'border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20'
                              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                          }`}
                        >
                          {u.is_active ? 'Suspend' : 'Activate'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Security Audit Logs */}
      {activeTab === 'audit' && (
        <div className="space-y-3">
          <div className="relative max-w-sm">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={auditFilter}
              onChange={(e) => setAuditFilter(e.target.value)}
              placeholder="Filter by action, email, or resource..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Target Resource</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : '-'}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-mono">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300 font-mono">{log.user_email}</td>
                      <td className="py-2.5 px-4 text-slate-400">{log.target_resource}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
