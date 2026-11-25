import React, { useEffect, useState } from 'react';
import {
  Boxes,
  Plus,
  Search,
  Globe,
  Lock,
  ExternalLink,
  Shield,
  FileCode2,
  DollarSign,
  AlertCircle
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { api } from '../api/client';
import { Application, BusinessService } from '../types';

interface AssetInventoryViewProps {
  onNavigate: (view: string, targetId?: string) => void;
}

export const AssetInventoryView: React.FC<AssetInventoryViewProps> = ({ onNavigate }) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [services, setServices] = useState<BusinessService[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState('ALL');

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [appName, setAppName] = useState('');
  const [appRepo, setAppRepo] = useState('');
  const [appEnv, setAppEnv] = useState<'PRODUCTION' | 'STAGING' | 'DEVELOPMENT'>('PRODUCTION');
  const [appCrit, setAppCrit] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [appInternet, setAppInternet] = useState(false);
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadAssets();
  }, []);

  const loadAssets = async () => {
    try {
      setLoading(true);
      const [appsData, srvData] = await Promise.all([
        api.getApplications(),
        api.getBusinessServices(),
      ]);
      setApps(appsData);
      setServices(srvData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim()) return;
    try {
      setSubmitting(true);
      await api.createApplication({
        name: appName,
        repository_url: appRepo,
        environment: appEnv,
        business_criticality: appCrit,
        internet_exposed: appInternet,
        business_service_ids: selectedServices,
      });
      setIsModalOpen(false);
      setAppName('');
      setAppRepo('');
      setSelectedServices([]);
      loadAssets();
    } catch (err: any) {
      alert(err.message || 'Failed to create application');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredApps = apps.filter((app) => {
    const matchesSearch = app.name.toLowerCase().includes(search.toLowerCase());
    const matchesEnv = envFilter === 'ALL' || app.environment === envFilter;
    return matchesSearch && matchesEnv;
  });

  return (
    <div className="space-y-6">
      {/* Action Header */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search software applications..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#111C30] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>
          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="bg-[#111C30] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="ALL">All Environments</option>
            <option value="PRODUCTION">Production</option>
            <option value="STAGING">Staging</option>
            <option value="DEVELOPMENT">Development</option>
          </select>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition-colors shadow-lg shadow-sky-500/10"
        >
          <Plus className="w-4 h-4" />
          <span>Register Application</span>
        </button>
      </div>

      {/* Applications Cards Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">Loading Application Inventory...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredApps.map((app) => (
            <div
              key={app.id}
              className="p-5 rounded-xl bg-[#111C30] border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-base font-bold text-white tracking-wide">{app.name}</h3>
                    {app.repository_url && (
                      <a
                        href={app.repository_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-slate-400 hover:text-sky-400 font-mono flex items-center gap-1 mt-0.5 truncate"
                      >
                        <span>{app.repository_url}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                  <Badge variant={app.business_criticality as any}>{app.business_criticality}</Badge>
                </div>

                {/* Badges & Exposure */}
                <div className="mt-4 flex items-center gap-2 flex-wrap text-xs">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px] border border-slate-700">
                    {app.environment}
                  </span>
                  {app.internet_exposed ? (
                    <span className="px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-mono text-[11px] border border-red-500/30 flex items-center gap-1">
                      <Globe className="w-3 h-3" />
                      Public Internet Exposed
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[11px] border border-slate-700 flex items-center gap-1">
                      <Lock className="w-3 h-3" />
                      Internal Protected Network
                    </span>
                  )}
                  {app.active_sbom_id ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono text-[11px] border border-emerald-500/30 flex items-center gap-1">
                      <FileCode2 className="w-3 h-3" />
                      Active SBOM Verified
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 font-mono text-[11px] border border-amber-500/30">
                      No SBOM Uploaded
                    </span>
                  )}
                </div>

                {/* Associated Services */}
                <div className="mt-4 pt-3 border-t border-slate-800/80">
                  <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 font-mono block mb-1.5">
                    Supporting Business Services
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {app.business_services.length === 0 ? (
                      <span className="text-xs text-slate-500">None linked</span>
                    ) : (
                      app.business_services.map((srv) => (
                        <span
                          key={srv.id}
                          className="px-2 py-1 rounded bg-[#0F172A] text-slate-300 text-xs border border-slate-800 flex items-center gap-1.5"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                          <span>{srv.name}</span>
                          <span className="text-slate-500 font-mono text-[10px]">(${srv.financial_impact_rating.toLocaleString()}/hr)</span>
                        </span>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Bottom Card Actions */}
              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-mono">Calculated Risk:</span>
                  <span
                    className={`font-mono text-xs font-extrabold ${
                      app.current_risk_score >= 80
                        ? 'text-red-400'
                        : app.current_risk_score >= 60
                        ? 'text-orange-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {app.current_risk_score}/100
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onNavigate('sbom', app.id)}
                    className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                  >
                    Upload SBOM
                  </button>
                  <button
                    onClick={() => onNavigate('graph', app.id)}
                    className="px-2.5 py-1 text-xs rounded bg-sky-500/15 text-sky-400 border border-sky-500/30 hover:bg-sky-500/25 transition-colors"
                  >
                    View Graph
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Register Application Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Register Software Application"
        subtitle="Catalog a new enterprise asset into the software supply chain inventory"
      >
        <form onSubmit={handleCreateApp} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
              Application Name
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Core Settlement Pipeline"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
              Repository URL
            </label>
            <input
              type="url"
              placeholder="https://github.com/org/repo"
              value={appRepo}
              onChange={(e) => setAppRepo(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                Environment
              </label>
              <select
                value={appEnv}
                onChange={(e) => setAppEnv(e.target.value as any)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
              >
                <option value="PRODUCTION">Production</option>
                <option value="STAGING">Staging</option>
                <option value="DEVELOPMENT">Development</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                Criticality
              </label>
              <select
                value={appCrit}
                onChange={(e) => setAppCrit(e.target.value as any)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
              >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="internetExposed"
              checked={appInternet}
              onChange={(e) => setAppInternet(e.target.checked)}
              className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-sky-500 focus:ring-0"
            />
            <label htmlFor="internetExposed" className="text-xs text-slate-300 font-medium">
              Internet Exposed (Direct public ingress surface)
            </label>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
              Link Business Services
            </label>
            <div className="space-y-1 max-h-36 overflow-y-auto p-2 bg-slate-900 rounded-lg border border-slate-800">
              {services.map((srv) => (
                <label key={srv.id} className="flex items-center gap-2 text-xs text-slate-300 hover:text-white cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedServices.includes(srv.id)}
                    onChange={(e) => {
                      if (e.target.checked) setSelectedServices([...selectedServices, srv.id]);
                      else setSelectedServices(selectedServices.filter((id) => id !== srv.id));
                    }}
                    className="w-3.5 h-3.5 rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0"
                  />
                  <span>{srv.name}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="px-4 py-2 text-xs text-slate-400 hover:text-white rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs rounded-lg transition-colors"
            >
              {submitting ? 'Registering...' : 'Register Asset'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
