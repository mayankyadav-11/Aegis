import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

export default function AnalyzePage() {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Analyse Suspicious Target
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Submit an Email (.eml or raw), SMS text, URL, or instant message payload for deep inspection.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F2 Staging"
        title="Analysis Workbench Ready"
        description="The multi-channel input forms (Email, SMS, URL, Message) with quick test samples are staged for Phase F2."
        actionLabel="View Investigation History"
        actionHref="/history"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        }
      />
    </div>
  );
}

