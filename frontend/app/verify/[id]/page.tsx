import React from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';

interface VerifyPageProps {
  params: {
    id: string;
  };
}

export default function VerifyPage({ params }: VerifyPageProps) {
  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-12 md:py-16">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-[#F5F5F7] tracking-tight">
          Evidence Integrity Verification: {params.id}
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE]">
          Cryptographic proof and blockchain registry verification for case evidence integrity.
        </p>
      </div>

      <EmptyStateCard
        badge="Phase F4 Staging"
        title="Evidence Registry Validator"
        description={`Interactive verification suite for case ${params.id}. Computes canonical SHA-256 evidence hashes and cross-references them against on-chain smart contract registries.`}
        actionLabel="Back to Investigation"
        actionHref={`/results/${params.id}`}
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        }
      />
    </div>
  );
}

