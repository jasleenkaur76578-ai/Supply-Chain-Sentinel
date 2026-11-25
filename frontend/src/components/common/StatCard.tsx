import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  variant?: 'default' | 'critical' | 'warning' | 'success' | 'indigo';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = 'default',
}) => {
  const borderVariants = {
    default: 'border-slate-800 hover:border-slate-700',
    critical: 'border-red-500/30 bg-red-950/10 hover:border-red-500/50',
    warning: 'border-orange-500/30 bg-orange-950/10 hover:border-orange-500/50',
    success: 'border-emerald-500/30 bg-emerald-950/10 hover:border-emerald-500/50',
    indigo: 'border-indigo-500/30 bg-indigo-950/10 hover:border-indigo-500/50',
  };

  const iconVariants = {
    default: 'text-sky-400 bg-sky-500/10',
    critical: 'text-red-400 bg-red-500/15',
    warning: 'text-orange-400 bg-orange-500/15',
    success: 'text-emerald-400 bg-emerald-500/15',
    indigo: 'text-indigo-400 bg-indigo-500/15',
  };

  return (
    <div className={`p-5 rounded-xl bg-[#111C30] border transition-all duration-200 ${borderVariants[variant]}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-wider uppercase text-slate-400">{title}</span>
        <div className={`p-2.5 rounded-lg ${iconVariants[variant]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-extrabold tracking-tight text-white font-mono">{value}</span>
        {trend && (
          <span
            className={`text-xs font-medium ${
              trend.isPositive ? 'text-emerald-400' : 'text-red-400'
            }`}
          >
            {trend.value}
          </span>
        )}
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
    </div>
  );
};
