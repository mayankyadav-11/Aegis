import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

export default function RedTeamPage() {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Adversarial Red-Team & Model Metrics
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Benchmark detector resilience against obfuscation, homoglyphs, zero-width attacks, and evaluate held-out metrics.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F4 Staging"
        title="Red-Team Evasion Benchmark"
        description="Automated adversarial test suite evaluating evasion resistance, precision, recall, F1, and false-positive rates across NLP and URL classifiers."
        actionLabel="Inspect Detector API"
        actionHref="/analyze"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        }
      />
    </div>
  );
}

