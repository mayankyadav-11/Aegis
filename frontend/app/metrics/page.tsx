'use client';

import React, { useEffect, useState } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';
import { MetricsResult } from '@/types';
import { getMetrics } from '@/lib/api';
import { ModelMetricsView } from '@/components/metrics/ModelMetricsView';

export default function MetricsPage() {
  const [metrics, setMetrics] = useState<MetricsResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async (refresh = false) => {
    if (refresh) {
      setIsRefreshing(true);
    } else {
      setIsLoading(true);
    }
    setError(null);

    try {
      const data = await getMetrics();
      setMetrics(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load model metrics');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  if (isLoading) {
    return (
      <div className="w-full max-w-6xl mx-auto px-5 py-24 flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-8 h-8 animate-spin text-[#00E5FF]" />
        <p className="text-sm font-mono text-[#9A9AAE]">
          Loading held-out model evaluation benchmarks...
        </p>
      </div>
    );
  }

  if (error || !metrics) {
    return (
      <div className="w-full max-w-4xl mx-auto px-5 py-16">
        <div className="p-8 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] text-center space-y-4">
          <div className="inline-flex p-3 rounded-xl bg-[#13131A] text-[#EF4444]">
            <AlertCircle className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold text-[#F5F5F7]">Unable to Retrieve Metrics</h2>
          <p className="text-sm text-[#9A9AAE] max-w-md mx-auto">
            {error || 'An unexpected error occurred while loading held-out model metrics.'}
          </p>
          <div className="pt-2">
            <button
              onClick={() => fetchMetrics()}
              className="px-5 py-2.5 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-[#F5F5F7] text-xs font-semibold transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-10 md:py-14">
      <ModelMetricsView
        metrics={metrics}
        onRefresh={() => fetchMetrics(true)}
        isRefreshing={isRefreshing}
      />
    </div>
  );
}

