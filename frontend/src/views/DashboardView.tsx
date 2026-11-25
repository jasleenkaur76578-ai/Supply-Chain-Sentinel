import React, { useEffect, useState } from 'react';
import {
  Boxes,
  FileCode2,
  ShieldAlert,
  RadioTower,
  Gauge,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Activity,
  ArrowUpRight,
  TrendingUp,
  Server
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  CartesianGrid
} from 'recharts';
import { StatCard } from '../components/common/StatCard';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { DashboardOverview } from '../types';

interface DashboardViewProps {
  onNavigate: (view: string, targetId?: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onNavigate }) => {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadOverview();
  }, []);

  const loadOverview = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getDashboardOverview();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard overview');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono text-slate-400">Loading Enterprise Risk Telemetry...</span>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 rounded-xl bg-red-950/20 border border-red-500/30 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-2" />
        <h3 className="text-sm font-bold text-red-300">Telemetry Feed Disconnected</h3>
        <p className="text-xs text-slate-400 mt-1">{error}</p>
        <button
          onClick={loadOverview}
          className="mt-4 px-4 py-2 text-xs font-semibold bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded-lg border border-red-500/30 transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const { metrics, severity_distribution, risk_trends, urgent_attention_findings, top_vulnerable_dependencies, intelligence_source_health, remediation_progress } = data;

  const severityBarData = [
    { name: 'Critical', count: severity_distribution.CRITICAL || 0, color: '#EF4444' },
    { name: 'High', count: severity_distribution.HIGH || 0, color: '#F97316' },
    { name: 'Medium', count: severity_distribution.MEDIUM || 0, color: '#EAB308' },
    { name: 'Low', count: severity_distribution.LOW || 0, color: '#22C55E' },
  ];

  return (
    <div className="space-y-6">
      {/* 1. Executive Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Monitored Assets"
          value={metrics.total_assets}
          subtitle="4 Applications Active"
          icon={Boxes}
          variant="default"
        />
        <StatCard
          title="Unique Dependencies"
          value={metrics.total_unique_dependencies}
          subtitle="Direct & Transitive"
          icon={FileCode2}
          variant="default"
        />
        <StatCard
          title="Critical Findings"
          value={metrics.critical_vulnerabilities}
          subtitle={`${metrics.known_exploited_vulnerabilities} Known Exploited (KEV)`}
          icon={ShieldAlert}
          variant={metrics.critical_vulnerabilities > 0 ? 'critical' : 'success'}
        />
        <StatCard
          title="Affected Applications"
          value={metrics.affected_applications}
          subtitle="Production At Risk"
          icon={RadioTower}
          variant={metrics.affected_applications > 0 ? 'warning' : 'success'}
        />
        <StatCard
          title="Org Risk Score"
          value={`${metrics.org_risk_exposure_score}/100`}
          subtitle={`Remediation Rate: ${metrics.remediation_completion_rate}%`}
          icon={Gauge}
          variant={metrics.org_risk_exposure_score > 70 ? 'critical' : 'warning'}
        />
      </div>

      {/* 2. Charts Row: Risk Trend & Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Trend Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#111C30] border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">Enterprise Risk Exposure Trend</h2>
              <p className="text-xs text-slate-400 font-mono">Historical exposure posture over the last 30 days</p>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>-5.8 pts (Remediating)</span>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={risk_trends} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} domain={[0, 100]} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  labelStyle={{ color: '#F8FAFC', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="risk_score" name="Risk Exposure Score" stroke="#38BDF8" strokeWidth={2} fillOpacity={1} fill="url(#riskGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown Bar Chart */}
        <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800 flex flex-col">
          <div className="mb-4">
            <h2 className="text-sm font-bold text-white tracking-wide">Vulnerability Distribution</h2>
            <p className="text-xs text-slate-400 font-mono">Count by CVSS / CISA severity tier</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityBarData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 3. Urgent Attention Feed (CISA KEV / Critical Items) */}
      <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
            <h2 className="text-sm font-bold text-white tracking-wide">Urgent Security Attention Feed</h2>
          </div>
          <button
            onClick={() => onNavigate('propagation')}
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
          >
            <span>Blast Radius Simulator</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-3">
          {urgent_attention_findings.length === 0 ? (
            <div className="p-6 text-center text-slate-500 font-mono text-xs">
              No critical weaponized vulnerabilities identified.
            </div>
          ) : (
            urgent_attention_findings.map((item) => (
              <div
                key={item.id}
                className="p-4 rounded-xl bg-slate-900/80 border border-red-500/20 hover:border-red-500/40 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-white">{item.cve_id}</span>
                    <Badge variant="CRITICAL">CVSS {item.cvss}</Badge>
                    {item.is_kev && <Badge variant="KEV">CISA KEV ACTIVE</Badge>}
                    <span className="text-xs font-mono text-slate-400">
                      EPSS: {(item.epss_score * 100).toFixed(1)}% prob.
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">
                    Component: <span className="font-mono text-sky-400">{item.package}@{item.installed_version}</span>
                  </p>
                  <div className="flex items-center gap-2 text-xs text-slate-400 flex-wrap">
                    <span>Downstream Apps:</span>
                    {item.affected_apps.map((app) => (
                      <span key={app} className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-mono text-[11px] border border-slate-700">
                        {app}
                      </span>
                    ))}
                    <span className="text-slate-600">•</span>
                    <span>Critical Services:</span>
                    {item.critical_services.map((srv) => (
                      <span key={srv} className="text-indigo-400 font-mono text-[11px]">
                        {srv}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => onNavigate('propagation', item.cve_id)}
                    className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-sky-500/15 text-sky-300 border border-sky-500/30 hover:bg-sky-500/25 transition-colors flex items-center gap-1.5"
                  >
                    <RadioTower className="w-3.5 h-3.5" />
                    <span>Trace Propagation</span>
                  </button>
                  <button
                    onClick={() => onNavigate('remediation')}
                    className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors flex items-center gap-1.5"
                  >
                    <span>View Remediation</span>
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 4. Top Vulnerable Dependencies & Remediation Health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Vulnerable Dependencies */}
        <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800">
          <h2 className="text-sm font-bold text-white tracking-wide mb-3">Highest Risk Dependencies</h2>
          <div className="space-y-2">
            {top_vulnerable_dependencies.map((dep) => (
              <div
                key={`${dep.package}@${dep.version}`}
                className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-white">{dep.package}</span>
                    <span className="text-xs font-mono text-slate-400">@{dep.version}</span>
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-mono">{dep.ecosystem}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    {dep.vuln_count} Vulnerability detected
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {dep.has_kev && <Badge variant="KEV">KEV</Badge>}
                  <Badge variant={dep.highest_severity as any}>CVSS {dep.highest_cvss}</Badge>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Intelligence Source Health Grid */}
        <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-bold text-white tracking-wide">Threat Intelligence Feed Health</h2>
            <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              All Sources Live
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {Object.entries(intelligence_source_health).map(([key, src]) => (
              <div key={key} className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-slate-200">{key.replace('_', ' ')}</span>
                  <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    {src.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 truncate">{src.name}</p>
                <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                  <span>Latency: {src.latency_ms ? `${src.latency_ms}ms` : '45ms'}</span>
                  <span>Synced</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
