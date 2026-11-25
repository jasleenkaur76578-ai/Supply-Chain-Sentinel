import React, { useEffect, useState } from 'react';
import {
  BellRing,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Clock,
  RadioTower
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { SecurityAlert } from '../types';

export const AlertsView: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAlerts();
  }, []);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const data = await api.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId);
      loadAlerts();
    } catch (err: any) {
      alert(err.message || 'Failed to acknowledge alert');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
          <BellRing className="w-4 h-4 text-sky-400" />
          <span>Continuous Threat Monitoring & Alerts</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Real-time disclosures, CISA KEV additions, and anomalous dependency modifications
        </p>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">Loading Security Alerts...</div>
      ) : (
        <div className="space-y-3 font-mono">
          {alerts.map((alt) => (
            <div
              key={alt.id}
              className={`p-4 rounded-xl bg-[#111C30] border transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                alt.is_acknowledged
                  ? 'border-slate-800 opacity-60'
                  : alt.severity === 'CRITICAL'
                  ? 'border-red-500/40 bg-red-950/10'
                  : 'border-orange-500/30 bg-orange-950/10'
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={alt.severity}>{alt.severity}</Badge>
                  <span className="font-bold text-sm text-white">{alt.title}</span>
                  {alt.entity_id && (
                    <span className="text-xs text-sky-400 font-mono">[{alt.entity_id}]</span>
                  )}
                </div>
                <p className="text-xs text-slate-300">{alt.message}</p>
                <div className="text-[10px] text-slate-500">
                  Detected: {new Date(alt.created_at).toLocaleString()}
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2">
                {alt.is_acknowledged ? (
                  <span className="text-xs text-emerald-400 flex items-center gap-1 font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Acknowledged</span>
                  </span>
                ) : (
                  <button
                    onClick={() => handleAcknowledge(alt.id)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
