'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Loader2, AlertCircle } from 'lucide-react';
import { AnalysisResult } from '@/types';
import { getCase } from '@/lib/api';
import { AnalysisResultView } from '@/components/analysis/AnalysisResultView';

interface ResultsPageProps {
  params: {
    id: string;
  };
}

export default function ResultsPage({ params }: ResultsPageProps) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      const data = await getCase(params.id);
      if (data) {
        setResult(data);
      } else {
        setNotFound(true);
      }
      setLoading(false);
    }
    load();
  }, [params.id]);

  if (loading) {
    return (
      <div className="w-full max-w-6xl mx-auto px-5 py-20 flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-8 h-8 animate-spin text-[#00E5FF]" />
        <p className="text-sm text-[#9A9AAE]">Loading case investigation details...</p>
      </div>
    );
  }

  if (notFound || !result) {
    return (
      <div className="w-full max-w-4xl mx-auto px-5 py-16">
        <div className="p-8 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] text-center space-y-4">
          <div className="inline-flex p-3 rounded-xl bg-[#13131A] text-[#F59E0B]">
            <AlertCircle className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold text-[#F5F5F7]">Case Record Not Found</h2>
          <p className="text-sm text-[#9A9AAE] max-w-md mx-auto">
            Case <code className="text-[#00E5FF] font-mono">{params.id}</code> could not be found in active memory or mock records.
          </p>
          <div className="pt-2">
            <Link
              href="/analyze"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-[#F5F5F7] text-xs font-semibold transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Analysis Workbench</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-10 md:py-14 space-y-6">
      <div className="flex items-center justify-between">
        <Link
          href="/analyze"
          className="inline-flex items-center gap-2 text-xs font-medium text-[#9A9AAE] hover:text-[#00E5FF] transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Analysis Workbench</span>
        </Link>
      </div>

      <AnalysisResultView result={result} />
    </div>
  );
}
