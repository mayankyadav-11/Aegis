import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

export default function HistoryPage() {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Investigation History
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Complete audit trail of all examined phishing attacks, risk verdicts, and blockchain verification records.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F3 Staging"
        title="History Ledger Staging"
        description="Filterable investigation table with Case IDs, input categories, risk scores, and verification status."
        actionLabel="Run New Analysis"
        actionHref="/analyze"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        }
      />
    </div>
  );
}

