'use client';

import React, { useEffect, useState } from 'react';
import { motion, useMotionValue, animate, useReducedMotion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  AlertCircle,
  BarChart3,
  Clock,
  Layers,
  Sparkles,
  CheckCircle2,
} from 'lucide-react';
import { MetricsResult, ModelMetric } from '@/types';

interface ModelMetricsViewProps {
  metrics: MetricsResult;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

function CountUpNumber({
  value,
  decimals = 0,
  suffix = '',
}: {
  value: number;
  decimals?: number;
  suffix?: string;
}) {
  const prefersReduced = useReducedMotion();
  const [display, setDisplay] = useState(
    prefersReduced
      ? decimals > 0
        ? value.toFixed(decimals)
        : Math.round(value).toLocaleString()
      : '0'
  );
  const motionVal = useMotionValue(prefersReduced ? value : 0);

  useEffect(() => {
    if (prefersReduced) {
      setDisplay(decimals > 0 ? value.toFixed(decimals) : Math.round(value).toLocaleString());
      return;
    }
    const controls = animate(motionVal, value, {
      duration: 0.85,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (latest) => {
        setDisplay(decimals > 0 ? latest.toFixed(decimals) : Math.round(latest).toLocaleString());
      },
    });
    return () => controls.stop();
  }, [value, decimals, prefersReduced, motionVal]);

  return (
    <span>
      {display}
      {suffix}
    </span>
  );
}

export function ModelMetricsView({
  metrics,
  onRefresh,
  isRefreshing = false,
}: ModelMetricsViewProps) {
  const models = metrics.models || [];
  const totalSamples = models.reduce((acc, m) => acc + (m.sample_size || 0), 0);
  const avgF1 = models.length
    ? (models.reduce((acc, m) => acc + m.f1, 0) / models.length) * 100
    : 0;
  const avgPrecision = models.length
    ? (models.reduce((acc, m) => acc + m.precision, 0) / models.length) * 100
    : 0;
  const avgRecall = models.length
    ? (models.reduce((acc, m) => acc + m.recall, 0) / models.length) * 100
    : 0;

  return (
    <div className="space-y-8">
      {/* Header and Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2.5 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs font-mono text-[#00E5FF]">
              <Activity className="w-3.5 h-3.5" />
              Held-Out Model Benchmarks
            </span>

            {metrics.is_demo ? (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-[#F59E0B]/15 border border-[#F59E0B]/30 text-[#F59E0B]">
                <AlertTriangle className="w-3.5 h-3.5" />
                Demo data
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-[#10B981]/15 border border-[#10B981]/30 text-[#10B981]">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Live API Telemetry
              </span>
            )}
          </div>

          <h1 className="text-3xl font-bold text-[#F5F5F7] tracking-tight">
            Model Metrics
          </h1>
          <p className="mt-1 text-sm text-[#9A9AAE] max-w-2xl leading-relaxed">
            Independent held-out evaluation performance across lexical URL classifiers, NLP phishing
            intent analyzers, and anomaly detection engines.
          </p>
        </div>

        <div className="flex items-center gap-3 self-start md:self-center">
          <div className="text-right text-xs font-mono text-[#626274]">
            <span>Evaluated: </span>
            <span className="text-[#9A9AAE]">
              {new Date(metrics.evaluated_at).toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
              })}
            </span>
          </div>

          {onRefresh && (
            <motion.button
              whileTap={{ scale: 0.96 }}
              onClick={onRefresh}
              disabled={isRefreshing}
              className="px-3.5 py-2 rounded-xl bg-[#0D0D12] hover:bg-[#13131A] border border-[#1C1C26] text-xs font-medium text-[#F5F5F7] transition-all disabled:opacity-50 flex items-center gap-1.5"
            >
              <Activity className={`w-3.5 h-3.5 text-[#00E5FF] ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </motion.button>
          )}
        </div>
      </div>

      {/* Demo Notice Banner (if mock data) */}
      {metrics.is_demo && (
        <div className="p-4 rounded-xl bg-[#F59E0B]/10 border border-[#F59E0B]/25 flex items-start gap-3">
          <AlertCircle className="w-4 h-4 text-[#F59E0B] shrink-0 mt-0.5" />
          <div className="text-xs space-y-1">
            <span className="font-semibold text-[#F5F5F7]">
              Notice: Displaying Baseline Demo Metrics
            </span>
            <p className="text-[#9A9AAE] leading-relaxed">
              These figures reflect baseline validation scores on held-out synthetic test sets. When the live
              backend service provides real-time model evaluation telemetry, live metrics will replace this baseline automatically.
            </p>
          </div>
        </div>
      )}

      {/* Summary KPI Strip */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <div className="p-5 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <span className="text-xs text-[#9A9AAE] font-medium flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-[#00E5FF]" />
            Total Evaluation Samples
          </span>
          <div className="mt-2 text-2xl font-bold font-mono text-[#F5F5F7]">
            <CountUpNumber value={totalSamples} />
          </div>
          <span className="text-[11px] text-[#626274] mt-0.5 block">Held-out test vectors</span>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <span className="text-xs text-[#9A9AAE] font-medium flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#7B3FE4]" />
            Mean F1 Score
          </span>
          <div className="mt-2 text-2xl font-bold font-mono text-[#10B981]">
            <CountUpNumber value={avgF1} decimals={1} suffix="%" />
          </div>
          <span className="text-[11px] text-[#626274] mt-0.5 block">Harmonic mean precision/recall</span>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <span className="text-xs text-[#9A9AAE] font-medium flex items-center gap-1.5">
            <BarChart3 className="w-3.5 h-3.5 text-[#00E5FF]" />
            Mean Precision
          </span>
          <div className="mt-2 text-2xl font-bold font-mono text-[#00E5FF]">
            <CountUpNumber value={avgPrecision} decimals={1} suffix="%" />
          </div>
          <span className="text-[11px] text-[#626274] mt-0.5 block">True positive confidence</span>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <span className="text-xs text-[#9A9AAE] font-medium flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-[#10B981]" />
            Mean Recall
          </span>
          <div className="mt-2 text-2xl font-bold font-mono text-[#F5F5F7]">
            <CountUpNumber value={avgRecall} decimals={1} suffix="%" />
          </div>
          <span className="text-[11px] text-[#626274] mt-0.5 block">Threat capture rate</span>
        </div>
      </motion.div>

      {/* Model Cards Grid */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-[#F5F5F7]">
          Classifier Performance Breakdown
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {models.map((model: ModelMetric, idx: number) => {
            const isIndianSet =
              model.name.toLowerCase().includes('indian') || model.sample_size < 1000;

            return (
              <motion.div
                key={model.name || idx}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: idx * 0.08, ease: 'easeOut' }}
                className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] hover:border-[#1C1C26]/80 flex flex-col justify-between space-y-5"
              >
                <div>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="text-base font-bold text-[#F5F5F7] leading-snug">
                        {model.name}
                      </h3>
                      <span className="inline-flex items-center gap-1.5 mt-1 text-xs font-mono text-[#9A9AAE]">
                        <span>Sample Size: <strong>{model.sample_size.toLocaleString()}</strong> vectors</span>
                      </span>
                    </div>

                    <span className="text-xs font-mono text-[#626274] bg-[#13131A] px-2 py-0.5 rounded border border-[#1C1C26] shrink-0">
                      ~{model.latency_ms}ms
                    </span>
                  </div>

                  {/* Primary Metrics 4-Col Grid */}
                  <div className="grid grid-cols-4 gap-2 mt-5 p-3 rounded-xl bg-[#13131A]/70 border border-[#1C1C26]/60 text-center">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-[#9A9AAE] block">
                        Precision
                      </span>
                      <span className="text-sm font-bold font-mono text-[#00E5FF]">
                        <CountUpNumber value={model.precision * 100} decimals={1} suffix="%" />
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-[#9A9AAE] block">
                        Recall
                      </span>
                      <span className="text-sm font-bold font-mono text-[#10B981]">
                        <CountUpNumber value={model.recall * 100} decimals={1} suffix="%" />
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-[#9A9AAE] block">
                        F1 Score
                      </span>
                      <span className="text-sm font-bold font-mono text-[#F5F5F7]">
                        <CountUpNumber value={model.f1 * 100} decimals={1} suffix="%" />
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-[#9A9AAE] block">
                        FPR
                      </span>
                      <span className="text-sm font-bold font-mono text-[#F97316]">
                        <CountUpNumber value={model.false_positive_rate * 100} decimals={1} suffix="%" />
                      </span>
                    </div>
                  </div>

                  {/* Visual Progress Bar for F1 */}
                  <div className="mt-4 space-y-1.5">
                    <div className="flex justify-between text-xs font-mono text-[#9A9AAE]">
                      <span>F1 Harmonic Measure</span>
                      <span className="text-[#F5F5F7]">{(model.f1 * 100).toFixed(1)} / 100</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[#13131A] overflow-hidden border border-[#1C1C26]">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-[#7B3FE4] to-[#00E5FF]"
                        initial={{ width: 0 }}
                        whileInView={{ width: `${Math.min(100, Math.max(0, model.f1 * 100))}%` }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.65, ease: 'easeOut', delay: 0.1 + idx * 0.08 }}
                      />
                    </div>
                  </div>

                  {/* Small-Sample Caution Callout for Indian SMS / Hinglish model */}
                  {isIndianSet && (
                    <div className="mt-4 p-3 rounded-xl bg-[#F59E0B]/10 border border-[#F59E0B]/30 flex items-start gap-2.5 text-xs text-[#F59E0B]">
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                      <div className="space-y-0.5">
                        <span className="font-semibold block text-[#F59E0B]">
                          Small-Sample Size Caution (n={model.sample_size})
                        </span>
                        <p className="text-[#9A9AAE] leading-relaxed">
                          This regional dialect cohort uses an initial curated held-out partition of {model.sample_size} samples.
                          Confidence intervals are broader than the primary lexical models until continuous field validation expands.
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-[#1C1C26] flex items-center justify-between text-[11px] text-[#626274]">
                  <span>Validation Protocol: Disjoint Held-Out Set</span>
                  <span>Inference Latency: ~{model.latency_ms} ms</span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

