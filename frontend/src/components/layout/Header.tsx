import React from 'react';
import { Bell, UserCircle2, RefreshCw, LogOut } from 'lucide-react';
import { User } from '../../types';

interface HeaderProps {
  currentView: string;
  user: User | null;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  onSelectView: (view: string) => void;
  onLogout?: () => void;
  alertCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  user,
  onRefresh,
  isRefreshing = false,
  onSelectView,
  onLogout,
  alertCount = 2,
}) => {
  const viewTitles: Record<string, { title: string; subtitle: string }> = {
    dashboard: { title: 'Security Operations Overview', subtitle: 'Global enterprise software risk & posture telemetry' },
    assets: { title: 'Software Asset Discovery & Inventory', subtitle: 'Central registry of monitored applications and services' },
    sbom: { title: 'Hardened SBOM Analyser', subtitle: 'CycloneDX JSON/XML & SPDX ingestion engine with XXE defense' },
    vulnerabilities: { title: 'Vulnerability Threat Intelligence', subtitle: 'Live CVE correlation across OSV, NVD, CISA KEV and EPSS' },
    graph: { title: 'Interactive Dependency Graph', subtitle: 'Direct & transitive topology visualizer with blast radius highlights' },
    propagation: { title: 'Attack Propagation & Blast Radius Engine', subtitle: 'Downstream impact reachability from vulnerable components to business services' },
    risk: { title: 'Enterprise Risk Scoring & Prioritisation', subtitle: 'Transparent explainable multi-factor risk model' },
    'ai-analyst': { title: 'AI Security Intelligence Analyst', subtitle: 'Grounded Retrieval-Augmented Generation (RAG) assistant' },
    remediation: { title: 'Remediation Management Centre', subtitle: 'Task tracking and dual-SBOM rescan verification' },
    suppliers: { title: 'Third-Party Supplier Risk', subtitle: 'Vendor concentration, trust tiers, and software provenance' },
    alerts: { title: 'Continuous Monitoring & Security Alerts', subtitle: 'Threat disclosures and overdue SLA telemetry' },
    reports: { title: 'Executive Cybersecurity Reporting', subtitle: 'CISO-ready management briefings and CSV/audit exports' },
    admin: { title: 'Admin & Backend Console', subtitle: 'Role-based user administration, system posture, and audit trails' },
  };

  const current = viewTitles[currentView] || { title: 'Supply Chain Sentinel', subtitle: 'Risk Intelligence Platform' };

  return (
    <header className="h-16 bg-[#0F172A]/90 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between shrink-0 z-30">
      {/* Left: View Title & Subtitle */}
      <div>
        <h1 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
          {current.title}
        </h1>
        <p className="text-xs text-slate-400 font-mono">{current.subtitle}</p>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Intelligence Sync Status Pill */}
        <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700/60 text-xs text-slate-300 font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>Intel Sync:</span>
          <span className="text-emerald-400 font-semibold">Active (KEV/OSV)</span>
        </div>

        {/* Refresh Action */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh Intelligence Data"
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        )}

        {/* Alert Notification Bell */}
        <button
          onClick={() => onSelectView('alerts')}
          className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          title="Security Alerts"
        >
          <Bell className="w-4 h-4" />
          {alertCount > 0 && (
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          )}
        </button>

        {/* User Role Card */}
        <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-sky-400">
            <UserCircle2 className="w-5 h-5" />
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-semibold text-white leading-tight">
              {user ? user.full_name : 'Dr. Sarah Mitchell'}
            </div>
            <div className="text-[10px] text-sky-400 font-mono tracking-wider uppercase">
              {user ? user.role.replace('_', ' ') : 'Security Analyst'}
            </div>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign Out"
              className="ml-1 p-1.5 text-slate-400 hover:text-red-400 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
