import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

export default function DashboardPage() {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Security Console Dashboard
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Overview of platform investigations, threat telemetry, and real-time detection rates.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F2 Staging"
        title="No active dashboard telemetry"
        description="The live investigation metrics, threat breakdown, and recent analysis log will be initialized in Phase F2."
        actionLabel="Start new analysis"
        actionHref="/analyze"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
        }
      />
    </div>
  );
}

