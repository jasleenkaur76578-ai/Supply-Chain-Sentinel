import React from 'react';
import {
  LayoutDashboard,
  Boxes,
  FileCode2,
  ShieldAlert,
  GitFork,
  RadioTower,
  Gauge,
  Bot,
  Wrench,
  Building2,
  BellRing,
  FileSpreadsheet,
  ShieldCheck,
  ChevronRight,
  Lock
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  onSelectView: (view: string) => void;
  alertCount?: number;
  userRole?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onSelectView, alertCount = 2, userRole }) => {
  const isAdmin = userRole === 'super_admin' || userRole === 'org_admin';
  const navItems = [
    { id: 'dashboard', label: 'Operations Overview', icon: LayoutDashboard, badge: null },
    { id: 'assets', label: 'Asset Discovery', icon: Boxes, badge: null },
    { id: 'sbom', label: 'SBOM Analyser', icon: FileCode2, badge: 'Hardened' },
    { id: 'vulnerabilities', label: 'Vulnerability Intel', icon: ShieldAlert, badge: null },
    { id: 'graph', label: 'Dependency Graph', icon: GitFork, badge: null },
    { id: 'propagation', label: 'Attack Propagation', icon: RadioTower, badge: 'Core' },
    { id: 'risk', label: 'Risk Intelligence', icon: Gauge, badge: null },
    { id: 'ai-analyst', label: 'AI Security Analyst', icon: Bot, badge: 'RAG' },
    { id: 'remediation', label: 'Remediation Centre', icon: Wrench, badge: 'Verify' },
    { id: 'suppliers', label: 'Supplier Risk', icon: Building2, badge: null },
    { id: 'alerts', label: 'Alerts & Monitoring', icon: BellRing, count: alertCount },
    { id: 'reports', label: 'Executive Reports', icon: FileSpreadsheet, badge: 'Export' },
  ];

  return (
    <aside className="w-64 bg-[#0F172A] border-r border-slate-800 flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-extrabold tracking-wider text-sm text-white">SUPPLY CHAIN</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="text-xs font-mono font-bold tracking-widest text-[#38BDF8]">SENTINEL</span>
            <span className="text-[10px] bg-sky-500/10 text-sky-400 font-mono px-1 py-0.2 rounded border border-sky-500/20">v1.0</span>
          </div>
        </div>
      </div>

      {/* Navigation Modules */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        <div className="px-3 pb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
          Security Intelligence Modules
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? 'bg-sky-500/15 text-sky-300 font-semibold border border-sky-500/30 shadow-sm shadow-sky-500/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? 'text-sky-400' : 'text-slate-500 group-hover:text-slate-300'
                  }`}
                />
                <span className="tracking-wide">{item.label}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {item.count ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                    {item.count}
                  </span>
                ) : null}
                {item.badge ? (
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded tracking-wider ${
                      item.badge === 'Core'
                        ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                        : item.badge === 'RAG'
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                ) : null}
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-sky-400" />}
              </div>
            </button>
          );
        })}

        {isAdmin && (
          <div className="pt-4 mt-4 border-t border-slate-800/80">
            <div className="px-3 pb-2 text-[10px] font-bold uppercase tracking-wider text-indigo-400 font-mono">
              Administration
            </div>
            <button
              onClick={() => onSelectView('admin')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                currentView === 'admin'
                  ? 'bg-indigo-500/15 text-indigo-300 font-semibold border border-indigo-500/30 shadow-sm shadow-indigo-500/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Lock
                  className={`w-4 h-4 transition-colors ${
                    currentView === 'admin' ? 'text-indigo-400' : 'text-slate-500 group-hover:text-slate-300'
                  }`}
                />
                <span className="tracking-wide">Admin Console</span>
              </div>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Admin
              </span>
            </button>
          </div>
        )}
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-slate-800/80 bg-[#0B1120]/60">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[11px] font-mono text-slate-400">Defense Mesh</span>
          </div>
          <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/20">
            ARMED
          </span>
        </div>
        <p className="mt-1 text-[10px] text-slate-500 font-mono">
          NVD • OSV • CISA KEV • EPSS
        </p>
      </div>
    </aside>
  );
};
