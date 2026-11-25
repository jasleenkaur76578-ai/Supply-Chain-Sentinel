import React, { useState, useEffect } from 'react';
import {
  RadioTower,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  Boxes,
  Layers,
  DollarSign,
  CheckCircle2,
  ExternalLink,
  Wrench,
  Sparkles
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { PropagationResult } from '../types';

interface AttackPropagationViewProps {
  initialTarget?: string;
  onNavigate: (view: string, targetId?: string) => void;
}

export const AttackPropagationView: React.FC<AttackPropagationViewProps> = ({ initialTarget, onNavigate }) => {
  const [targetQuery, setTargetQuery] = useState(initialTarget || 'log4j-core');
  const [result, setResult] = useState<PropagationResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialTarget) {
      setTargetQuery(initialTarget);
      handleAnalyze(initialTarget);
    } else {
      handleAnalyze('log4j-core');
    }
  }, [initialTarget]);

  const handleAnalyze = async (queryToRun?: string) => {
    const q = queryToRun || targetQuery;
    if (!q.trim()) return;

    try {
      setLoading(true);
      const isCve = q.toUpperCase().startsWith('CVE-');
      const payload: any = isCve ? { vulnerability_id: q } : { component_name: q };
      const data = await api.analyzePropagation(payload);
      setResult(data);
    } catch (err: any) {
      alert(err.message || 'Propagation analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search & Simulation Bar */}
      <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              <RadioTower className="w-4 h-4 text-sky-400" />
              <span>Downstream Attack Propagation & Blast Radius Simulator</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Graph traversal discovering reachability from vulnerable component to corporate business services
            </p>
          </div>

          {/* Quick preset selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-mono">Quick Preset:</span>
            {['log4j-core', 'spring-beans', 'lodash', 'CVE-2021-44228'].map((preset) => (
              <button
                key={preset}
                onClick={() => {
                  setTargetQuery(preset);
                  handleAnalyze(preset);
                }}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-sky-500/50 text-slate-300 text-xs font-mono transition-colors"
              >
                {preset}
              </button>
            ))}
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="flex gap-3"
        >
          <input
            type="text"
            placeholder="Enter package name (e.g. log4j-core) or CVE identifier (e.g. CVE-2021-44228)..."
            value={targetQuery}
            onChange={(e) => setTargetQuery(e.target.value)}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs font-mono flex items-center gap-2 transition-colors shadow-lg shadow-sky-500/10"
          >
            {loading ? 'Simulating Propagation...' : 'Simulate Blast Radius'}
          </button>
        </form>
      </div>

      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6 animate-fade-in">
          {/* Executive Blast Radius Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-5 rounded-xl bg-[#111C30] border border-red-500/30 flex flex-col justify-between">
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                Blast Radius Score
              </span>
              <div className="my-2 flex items-baseline gap-2">
                <span className="text-4xl font-extrabold font-mono text-red-400">
                  {result.blast_radius_score}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100 (Max Exposure)</span>
              </div>
              <Badge variant="CRITICAL">HIGH CONFIDENCE TRACE</Badge>
            </div>

            <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800 flex flex-col justify-between">
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                Exposed Applications
              </span>
              <div className="my-2 text-4xl font-extrabold font-mono text-white">
                {result.affected_applications_count}
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {result.affected_applications.some((a) => a.internet_exposed)
                  ? '⚠️ Public Internet Accessible'
                  : 'Internal isolated network'}
              </span>
            </div>

            <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800 flex flex-col justify-between">
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                Affected Business Services
              </span>
              <div className="my-2 text-4xl font-extrabold font-mono text-indigo-400">
                {result.associated_business_services.length}
              </div>
              <span className="text-xs text-slate-400 font-mono">Core Transaction Pipelines</span>
            </div>

            <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800 flex flex-col justify-between">
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                Disruption Exposure
              </span>
              <div className="my-2 text-2xl font-extrabold font-mono text-emerald-400 truncate">
                ${result.total_hourly_disruption_exposure.toLocaleString()}/hr
              </div>
              <span className="text-xs text-slate-400 font-mono">Estimated Downtime Cost</span>
            </div>
          </div>

          {/* Explainable Synthesis & Strict Industrial Disclaimer */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 font-mono">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-400 uppercase tracking-wider">
              <Sparkles className="w-4 h-4" />
              <span>Grounded Intelligence Summary</span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed bg-[#0B1120] p-4 rounded-lg border border-slate-800">
              {result.explainable_summary}
            </p>
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                <strong>INDUSTRIAL ACCURACY NOTICE:</strong> A mapped dependency relationship confirms structural reachability in code. It does NOT prove active runtime exploitation has occurred without corroborating SOC telemetry.
              </span>
            </div>
          </div>

          {/* Traced Propagation Paths & Exposed Applications Table */}
          <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Traced Downstream Attack Propagation Paths
            </h3>

            <div className="space-y-3">
              {result.affected_applications.map((app) => (
                <div
                  key={app.id}
                  className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all flex flex-col lg:flex-row lg:items-center justify-between gap-4 font-mono text-xs"
                >
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-white text-sm">{app.name}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] border border-slate-700">
                        {app.environment}
                      </span>
                      <Badge variant={app.business_criticality as any}>{app.business_criticality}</Badge>
                      {app.internet_exposed && (
                        <Badge variant="CRITICAL">INTERNET EXPOSED</Badge>
                      )}
                    </div>

                    {/* Step-by-Step Path Trace */}
                    <div className="flex items-center gap-2 text-slate-400 text-xs flex-wrap">
                      <span className="text-slate-500 font-semibold">Propagation Route:</span>
                      {app.path_trace.map((step, idx) => (
                        <React.Fragment key={idx}>
                          <span
                            className={`px-2 py-1 rounded text-xs ${
                              idx === 0
                                ? 'bg-indigo-950/60 text-indigo-300 border border-indigo-500/30 font-bold'
                                : idx === app.path_trace.length - 1
                                ? 'bg-red-950/60 text-red-300 border border-red-500/30 font-bold'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {step}
                          </span>
                          {idx < app.path_trace.length - 1 && (
                            <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => onNavigate('graph', app.id)}
                      className="px-3 py-1.5 rounded-lg bg-sky-500/15 text-sky-400 border border-sky-500/30 hover:bg-sky-500/25 transition-colors font-bold"
                    >
                      Inspect in Graph
                    </button>
                    <button
                      onClick={() => onNavigate('remediation')}
                      className="px-3 py-1.5 rounded-lg bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 transition-colors font-bold"
                    >
                      Remediate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Business Services & Recommended SecOps Playbook */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Impacted Business Services */}
            <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800">
              <h3 className="text-sm font-bold text-white tracking-wide mb-3">
                Supporting Business Services at Risk
              </h3>
              <div className="space-y-2">
                {result.associated_business_services.map((srv) => (
                  <div
                    key={srv.id}
                    className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between font-mono text-xs"
                  >
                    <div>
                      <div className="font-bold text-white">{srv.name}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">Owner: {srv.owner_team}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-indigo-400 font-bold">{srv.criticality}</div>
                      <div className="text-[10px] text-emerald-400">
                        ${srv.financial_impact_rating.toLocaleString()}/hr
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-5 rounded-xl bg-[#111C30] border border-slate-800">
              <h3 className="text-sm font-bold text-white tracking-wide mb-3">
                Recommended SecOps Remediation Playbook
              </h3>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                {result.recommended_actions.map((act, idx) => (
                  <li key={idx} className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
