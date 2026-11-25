import React, { useEffect, useState } from 'react';
import {
  Building2,
  ShieldCheck,
  AlertTriangle,
  Boxes,
  Mail,
  ShieldAlert,
  Search
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { Supplier } from '../types';

export const SupplierRiskView: React.FC = () => {
  const [suppliers, setSuppliers] = useState<Supplier[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadSuppliers();
  }, []);

  const loadSuppliers = async () => {
    try {
      setLoading(true);
      const data = await api.getSuppliers();
      setSuppliers(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const filteredSuppliers = suppliers.filter((s) => {
    return s.name.toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
            <Building2 className="w-4 h-4 text-sky-400" />
            <span>Third-Party Software Supplier Risk Management</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Evaluate vendor trust tiers, security postures, and dependency concentration risks
          </p>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search suppliers..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#111C30] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>
      </div>

      {/* Supplier Cards */}
      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">Loading Supplier Risk Profiles...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {filteredSuppliers.map((s) => (
            <div
              key={s.id}
              className={`p-5 rounded-xl bg-[#111C30] border transition-all flex flex-col justify-between ${
                s.trust_tier === 'TIER_1_VERIFIED'
                  ? 'border-emerald-500/30'
                  : s.trust_tier === 'HIGH_RISK' || s.trust_tier === 'TIER_3_UNVERIFIED'
                  ? 'border-orange-500/30'
                  : 'border-slate-800'
              }`}
            >
              <div className="space-y-3 font-mono">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-white">{s.name}</h3>
                    {s.contact_email && (
                      <span className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                        <Mail className="w-3 h-3 text-slate-500" />
                        <span>{s.contact_email}</span>
                      </span>
                    )}
                  </div>
                  <Badge variant={s.trust_tier === 'TIER_1_VERIFIED' ? 'RESOLVED' : 'HIGH'}>
                    {s.trust_tier.replace('_', ' ')}
                  </Badge>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-xs">
                  <span className="text-slate-400">Security Score</span>
                  <span
                    className={`font-bold ${
                      s.security_assessment_score >= 85
                        ? 'text-emerald-400'
                        : s.security_assessment_score >= 60
                        ? 'text-amber-400'
                        : 'text-red-400'
                    }`}
                  >
                    {s.security_assessment_score}/100
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Supplied Components:</span>
                  <span className="text-white font-bold">{s.supplied_components_count} Packages</span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <span>Status: {s.review_status}</span>
                <span className="text-sky-400">Monitored</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
