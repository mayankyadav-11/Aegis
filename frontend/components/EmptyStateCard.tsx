import React from 'react';
import Link from 'next/link';

interface EmptyStateCardProps {
  title: string;
  badge?: string;
  description: string;
  actionLabel?: string;
  actionHref?: string;
  icon?: React.ReactNode;
}

export function EmptyStateCard({
  title,
  badge,
  description,
  actionLabel,
  actionHref,
  icon,
}: EmptyStateCardProps) {
  return (
    <div className="w-full max-w-2xl mx-auto rounded-2xl bg-[#0D0D12] border border-[#1C1C26] p-8 md:p-12 text-center shadow-xl">
      {icon && (
        <div className="w-12 h-12 mx-auto mb-5 rounded-xl bg-[#14141C] border border-[#1C1C26] flex items-center justify-center text-[#00E5FF]">
          {icon}
        </div>
      )}

      {badge && (
        <div className="inline-block px-3 py-1 mb-4 rounded-full text-xs font-medium tracking-wide uppercase bg-[#7B3FE4]/15 border border-[#7B3FE4]/30 text-[#7B3FE4]">
          {badge}
        </div>
      )}

      <h2 className="text-xl md:text-2xl font-semibold text-[#F5F5F7] tracking-tight mb-2">
        {title}
      </h2>

      <p className="text-sm md:text-base text-[#9A9AAE] max-w-md mx-auto leading-relaxed mb-6">
        {description}
      </p>

      {actionLabel && actionHref && (
        <Link
          href={actionHref}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-medium bg-[#7B3FE4] hover:bg-[#8E54F7] text-white transition-all duration-200 hover:shadow-[0_0_20px_rgba(123,63,228,0.4)]"
        >
          {actionLabel}
        </Link>
      )}
    </div>
  );
}

