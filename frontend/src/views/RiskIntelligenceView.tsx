import React, { useState, useEffect } from 'react';
import {
  Gauge,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Info,
  Shield,
  Layers,
  Save,
  RotateCcw
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { Application } from '../types';

export const RiskIntelligenceView: React.FC = () => {
  const [apps, setApps] = useState<Application[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>('');
  const [riskAssessment, setRiskAssessment] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);

  // Policy Weights State
  const [cvssWeight, setCvssWeight] = useState(0.25);
  const [epssWeight, setEpssWeight] = useState(0.20);
  const [kevWeight, setKevWeight] = useState(0.25);
  const [critWeight, setCritWeight] = useState(0.15);
  const [expWeight, setExpWeight] = useState(0.15);

  useEffect(() => {
    loadApps();
  }, []);

  useEffect(() => {
    if (selectedAppId) {
      loadAppRisk(selectedAppId);
    }
  }, [selectedAppId]);

  const loadApps = async () => {
    try {
      const data = await api.getApplications();
      setApps(data);
      if (data.length > 0) {
        setSelectedAppId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadAppRisk = async (appId: string) => {
    try {
      setLoading(true);
      const data = await api.getApplicationRisk(appId);
      setRiskAssessment(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSavePolicy = async () => {
    try {
      setSavingPolicy(true);
      await api.updateRiskPolicy({
        cvss_weight: cvssWeight,
        epss_weight: epssWeight,
        kev_weight: kevWeight,
        criticality_weight: critWeight,
        exposure_weight: expWeight,
      });
      alert('Risk policy updated and all application scores recalculated!');
      if (selectedAppId) {
        loadAppRisk(selectedAppId);
      }
    } catch (err: any) {
      alert(err.message || 'Failed to update policy');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleResetWeights = () => {
    setCvssWeight(0.25);
    setEpssWeight(0.20);
    setKevWeight(0.25);
    setCritWeight(0.15);
    setExpWeight(0.15);
  };

  return (
    <div className="space-y-6">
      {/* 1. Methodology & Transparent Multi-Factor Formula */}
      <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800 space-y-4 font-mono text-xs">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Gauge className="w-5 h-5 text-sky-400" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              Documented Multi-Factor Risk Prioritisation Methodology
            </h2>
          </div>
          <span className="text-[11px] text-slate-400 font-semibold bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            Model v1.0 Enterprise
          </span>
        </div>

        <p className="text-slate-300 leading-relaxed">
          Supply Chain Sentinel does not use arbitrary opaque scores. The enterprise risk engine normalizes 5 distinct signals
          with strict empirical grounding, factoring dependency tree depth attenuation:
        </p>

        <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-sky-300 text-center text-sm font-bold tracking-wide">
          Risk Score = [(w₁ · CVSS) + (w₂ · EPSS) + (w₃ · KEV) + (w₄ · AssetCriticality) + (w₅ · NetworkExposure)] × DepthAttenuation
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 text-[11px] text-slate-400">
          <div className="p-2 rounded bg-slate-900 border border-slate-800">
            <strong className="text-slate-200 block">CVSS (0-100)</strong>
            Normalized base flaw impact
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800">
            <strong className="text-slate-200 block">EPSS (0-100)</strong>
            30-day weaponization probability
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800">
            <strong className="text-slate-200 block">CISA KEV</strong>
            Active wild exploitation verification
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800">
            <strong className="text-slate-200 block">Asset Criticality</strong>
            Mission-critical tier weight
          </div>
          <div className="p-2 rounded bg-slate-900 border border-slate-800">
            <strong className="text-slate-200 block">Internet Exposure</strong>
            Public ingress accessibility
          </div>
        </div>
      </div>

      {/* 2. Interactive Risk Policy Configuration & Evaluator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Administrator Policy Weight Tuning Sliders */}
        <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold text-white tracking-wide">Configure Factor Weights</h3>
            </div>
            <button
              onClick={handleResetWeights}
              title="Reset to default baseline weights"
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-mono"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Defaults</span>
            </button>
          </div>

          <div className="space-y-4 font-mono text-xs">
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>CVSS Severity:</span>
                <span className="font-bold text-sky-400">{(cvssWeight * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={cvssWeight}
                onChange={(e) => setCvssWeight(Number(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>EPSS Probability:</span>
                <span className="font-bold text-sky-400">{(epssWeight * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={epssWeight}
                onChange={(e) => setEpssWeight(Number(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>CISA KEV Weaponization:</span>
                <span className="font-bold text-sky-400">{(kevWeight * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={kevWeight}
                onChange={(e) => setKevWeight(Number(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Asset Criticality:</span>
                <span className="font-bold text-sky-400">{(critWeight * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={critWeight}
                onChange={(e) => setCritWeight(Number(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Internet Exposure:</span>
                <span className="font-bold text-sky-400">{(expWeight * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={expWeight}
                onChange={(e) => setExpWeight(Number(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>
          </div>

          <button
            onClick={handleSavePolicy}
            disabled={savingPolicy}
            className="w-full py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs font-mono flex items-center justify-center gap-2 transition-colors shadow-lg shadow-sky-500/10"
          >
            <Save className="w-4 h-4" />
            <span>{savingPolicy ? 'Recalculating...' : 'Apply & Recalculate Enterprise Risk'}</span>
          </button>
        </div>

        {/* Application Attribution Card */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-[#111C30] border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">Application Risk Breakdown</h3>
              <p className="text-xs text-slate-400 font-mono">Factor attribution for the selected application</p>
            </div>

            <select
              value={selectedAppId}
              onChange={(e) => setSelectedAppId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
            >
              {apps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name} ({app.environment})
                </option>
              ))}
            </select>
          </div>

          {loading || !riskAssessment ? (
            <div className="p-12 text-center text-slate-500 font-mono text-xs">Computing Risk Assessment...</div>
          ) : (
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold block">Overall Prioritisation Tier</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-2xl font-extrabold text-white">{riskAssessment.overall_score}/100</span>
                    <Badge variant={riskAssessment.risk_tier}>{riskAssessment.risk_tier}</Badge>
                  </div>
                </div>

                <div className="text-right text-[11px] text-slate-400">
                  <div>Environment: {riskAssessment.environment}</div>
                  <div>Criticality: {riskAssessment.business_criticality}</div>
                  <div>Internet Exposed: {riskAssessment.internet_exposed ? 'YES' : 'NO'}</div>
                </div>
              </div>

              {/* Attribution Components Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">CVSS Sub-Score</span>
                  <span className="text-sm font-bold text-red-400">{riskAssessment.breakdown.cvss_component} pts</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">EPSS Sub-Score</span>
                  <span className="text-sm font-bold text-sky-400">{riskAssessment.breakdown.epss_component} pts</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">CISA KEV Boost</span>
                  <span className="text-sm font-bold text-purple-400">{riskAssessment.breakdown.kev_component} pts</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Criticality Sub-Score</span>
                  <span className="text-sm font-bold text-indigo-400">{riskAssessment.breakdown.criticality_component} pts</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Exposure Sub-Score</span>
                  <span className="text-sm font-bold text-amber-400">{riskAssessment.breakdown.exposure_component} pts</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Depth Attenuation</span>
                  <span className="text-sm font-bold text-emerald-400">×{riskAssessment.breakdown.depth_attenuation}</span>
                </div>
              </div>

              {/* Primary Risk Drivers */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
                  Identified Primary Risk Drivers
                </span>
                <ul className="space-y-1.5 text-[11px] text-slate-300">
                  {riskAssessment.primary_risk_drivers.map((driver: string, idx: number) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-red-400 font-bold">•</span>
                      <span>{driver}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
