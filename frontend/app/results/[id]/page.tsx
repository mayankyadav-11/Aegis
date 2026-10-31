import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

interface ResultsPageProps {
  params: {
    id: string;
  };
}

export default function ResultsPage({ params }: ResultsPageProps) {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Investigation Report: {params.id}
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Detailed breakdown of risk score, explainable findings, link redirects, and cryptographic evidence.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F3 Staging"
        title="Investigation Results Viewer"
        description={`Report view for investigation ${params.id} featuring risk gauge, NLP highlights, link trail, and Indian regulatory action guidance.`}
        actionLabel="Back to Analyse"
        actionHref="/analyze"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        }
      />
    </div>
  );
}

