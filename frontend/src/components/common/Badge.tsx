import React from 'react';

interface BadgeProps {
  variant?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'KEV' | 'DIRECT' | 'TRANSITIVE' | 'RESOLVED' | 'OPEN' | 'UNKNOWN' | string;
  children: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ variant = 'INFO', children, className = '', size = 'sm' }) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  const variantStyles: Record<string, string> = {
    CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
    MEDIUM: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    LOW: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    INFO: 'bg-sky-500/15 text-sky-400 border border-sky-500/30',
    KEV: 'bg-purple-500/20 text-purple-300 border border-purple-500/40 animate-pulse',
    DIRECT: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
    TRANSITIVE: 'bg-slate-700/50 text-slate-400 border border-slate-600/50',
    RESOLVED: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    OPEN: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  };

  const currentStyle = variantStyles[variant.toUpperCase()] || variantStyles.INFO;

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md font-mono tracking-wide ${sizeClasses} ${currentStyle} ${className}`}>
      {variant.toUpperCase() === 'KEV' && (
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-ping" />
      )}
      {children}
    </span>
  );
};
