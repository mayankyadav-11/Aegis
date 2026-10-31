'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Cpu,
  Layers,
  ArrowRight,
  HelpCircle,
  FileText,
  Clock,
  Fingerprint,
  Download,
  CheckCircle2,
  FileCheck,
  FileCode,
  Image as ImageIcon,
  Loader2,
  Share2,
} from 'lucide-react';
import { motion, useMotionValue, animate, useReducedMotion } from 'framer-motion';
import { AnalysisResult, FindingSeverity, RiskLevel, Verdict, EvidenceVerifyResult } from '@/types';
import { downloadReport, verifyCaseEvidence, getStoredToken } from '@/lib/api';
import { useToast } from '@/components/ui/Toast';

interface AnalysisResultViewProps {
  result: AnalysisResult;
  onReset?: () => void;
}

// Numerical count-up component using framer-motion animate on a motion value
function AnimatedScore({ value }: { value: number }) {
  const prefersReduced = useReducedMotion();
  const [display, setDisplay] = useState(prefersReduced ? value : 0);
  const motionVal = useMotionValue(prefersReduced ? value : 0);

  useEffect(() => {
    if (prefersReduced) {
      setDisplay(value);
      return;
    }
    const controls = animate(motionVal, value, {
      duration: 0.85,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (latest) => {
        setDisplay(Math.round(latest));
      },
    });
    return () => controls.stop();
  }, [value, prefersReduced, motionVal]);

  return <span>{display}</span>;
}

export function AnalysisResultView({ result, onReset }: AnalysisResultViewProps) {
  const { showToast } = useToast();
  const prefersReduced = useReducedMotion();

  const [copiedHash, setCopiedHash] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<EvidenceVerifyResult | null>(null);

  // Bidirectional highlighting between findings and message text
  const [hoveredFindingIdx, setHoveredFindingIdx] = useState<number | null>(null);
  const [hoveredHighlightIdx, setHoveredHighlightIdx] = useState<number | null>(null);

  const copyEvidenceHash = () => {
    if (result.evidence_hash) {
      navigator.clipboard.writeText(result.evidence_hash);
      setCopiedHash(true);
      showToast('SHA-256 evidence digest copied to clipboard', 'success');
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleDownloadReport = async () => {
    setIsDownloading(true);
    try {
      const isEnterprise = Boolean(getStoredToken());
      await downloadReport(result.case_id, isEnterprise);
      showToast(`Forensic PDF report for ${result.case_id} downloaded`, 'success');
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Report download failed', 'error');
    } finally {
      setIsDownloading(false);
    }
  };

  const handleVerifyEvidence = async () => {
    setIsVerifying(true);
    try {
      const isEnterprise = Boolean(getStoredToken());
      const res = await verifyCaseEvidence(result.case_id, isEnterprise);
      setVerificationResult(res);
      if (res.verified) {
        showToast(`Case ${result.case_id}: Integrity confirmed`, 'success');
      } else {
        showToast(`Case ${result.case_id}: Hash mismatch detected`, 'error');
      }
    } catch (err: unknown) {
      setVerificationResult({
        case_id: result.case_id,
        verified: false,
        computed_hash: 'N/A',
        recorded_hash: result.evidence_hash || 'N/A',
        message: err instanceof Error ? err.message : 'Verification request failed.',
      });
      showToast('Verification request failed', 'error');
    } finally {
      setIsVerifying(false);
    }
  };

  // Color mapping based on risk score / level
  const getRiskColors = (level: RiskLevel) => {
    switch (level) {
      case 'critical':
        return {
          text: 'text-[#EF4444]',
          bg: 'bg-[#EF4444]/10',
          border: 'border-[#EF4444]/30',
          glow: 'rgba(239, 68, 68, 0.25)',
          bar: 'bg-[#EF4444]',
        };
      case 'high':
        return {
          text: 'text-[#F97316]',
          bg: 'bg-[#F97316]/10',
          border: 'border-[#F97316]/30',
          glow: 'rgba(249, 115, 22, 0.25)',
          bar: 'bg-[#F97316]',
        };
      case 'medium':
        return {
          text: 'text-[#F59E0B]',
          bg: 'bg-[#F59E0B]/10',
          border: 'border-[#F59E0B]/30',
          glow: 'rgba(245, 158, 11, 0.25)',
          bar: 'bg-[#F59E0B]',
        };
      case 'low':
      default:
        return {
          text: 'text-[#10B981]',
          bg: 'bg-[#10B981]/10',
          border: 'border-[#10B981]/30',
          glow: 'rgba(16, 185, 129, 0.25)',
          bar: 'bg-[#10B981]',
        };
    }
  };

  const getSeverityBadge = (severity: FindingSeverity) => {
    switch (severity) {
      case 'critical':
        return 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30';
      case 'high':
        return 'text-[#F97316] bg-[#F97316]/10 border-[#F97316]/30';
      case 'medium':
        return 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30';
      case 'low':
      default:
        return 'text-[#10B981] bg-[#10B981]/10 border-[#10B981]/30';
    }
  };

  const colors = getRiskColors(result.risk_level);
  const isFallback =
    result.ai_status?.mode === 'python_fallback' ||
    (!result.ai_status &&
      result.unavailable_checks.some(
        (c) => c.toLowerCase().includes('gemini') || c.toLowerCase().includes('api key')
      ));
  const isFullAi = result.ai_status?.mode === 'full_ai' || (!isFallback && !result.ai_status);
  const completeness = result.analysis_completeness?.level || (isFullAi ? 'complete' : 'partial');

  return (
    <div className="space-y-8" aria-live="polite">
      {/* Top Banner: Case Header & Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-[#0D0D12] border border-[#1C1C26]">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-[#13131A] border border-[#1C1C26] text-[#00E5FF]">
            {result.verdict === 'safe' ? (
              <ShieldCheck className="w-5 h-5 text-[#10B981]" />
            ) : result.verdict === 'suspicious' ? (
              <AlertTriangle className="w-5 h-5 text-[#F59E0B]" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-[#EF4444]" />
            )}
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-base font-semibold text-[#F5F5F7]">
                {result.case_id}
              </span>
              <span className="uppercase text-[11px] font-mono tracking-wider px-2 py-0.5 rounded-md bg-[#13131A] text-[#9A9AAE] border border-[#1C1C26]">
                {result.input_type}
              </span>

              {result.file_name && (
                <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded-md bg-[#13131A] text-[#00E5FF] border border-[#1C1C26]">
                  {result.input_type === 'screenshot' ? (
                    <ImageIcon className="w-3 h-3 text-[#00E5FF]" />
                  ) : (
                    <FileText className="w-3 h-3 text-[#7B3FE4]" />
                  )}
                  {result.file_name}
                </span>
              )}

              {isFullAi ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30">
                  <Sparkles className="w-3 h-3 text-[#10B981]" />
                  Full AI Mode (Gemini + Python)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">
                  <Cpu className="w-3 h-3 text-[#F59E0B]" />
                  Python Fallback Mode
                </span>
              )}

              {completeness === 'inconclusive' && (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30">
                  <AlertTriangle className="w-3 h-3 text-[#EF4444]" />
                  Inconclusive Evidence
                </span>
              )}
              {completeness === 'partial' && !isFullAi && (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#9A9AAE]/15 text-[#9A9AAE] border border-[#1C1C26]">
                  Partial Analysis
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-xs text-[#9A9AAE]">
              <Clock className="w-3.5 h-3.5" />
              <span>{new Date(result.created_at).toLocaleString()}</span>
              <span>•</span>
              <span>Confidence: <strong className="uppercase text-[#F5F5F7]">{result.confidence}</strong></span>
              <span>•</span>
              <span className="capitalize">Completeness: <strong className="text-[#F5F5F7]">{completeness}</strong></span>
            </div>
          </div>
        </div>

        {/* Action Buttons: PDF Report & Reset */}
        <div className="flex items-center gap-2 self-start sm:self-center">
          <Link
            href={`/verify/${result.case_id}`}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-[#F5F5F7] hover:text-[#00E5FF] bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] rounded-lg transition-colors"
          >
            <FileCheck className="w-3.5 h-3.5 text-[#00E5FF]" />
            <span>Verify Proof</span>
          </Link>

          <button
            onClick={handleDownloadReport}
            disabled={isDownloading}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-[#00E5FF] bg-[#00E5FF]/10 hover:bg-[#00E5FF]/20 border border-[#00E5FF]/30 rounded-lg transition-colors disabled:opacity-50"
            title="Download Tamper-Evident PDF Report"
          >
            {isDownloading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>PDF Report</span>
          </button>

          {onReset && (
            <button
              onClick={onReset}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-[#9A9AAE] hover:text-[#F5F5F7] bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] rounded-lg transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>New Analysis</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Score & Verdict Hero Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Risk Score Gauge Card with Count-Up & Pop-in Level Badge */}
        <div className={`p-6 rounded-2xl bg-[#0D0D12] border ${colors.border} flex flex-col justify-between relative overflow-hidden`}>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE]">
                Overall Risk Assessment
              </p>
              <h3 className="mt-1 text-xl font-bold text-[#F5F5F7] capitalize">
                {result.verdict} Threat
              </h3>
            </div>

            {/* Level Badge with Pop-In Animation (Icon + Label, Never Color Alone) */}
            <motion.div
              initial={prefersReduced ? false : { scale: 0.65, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.8, type: 'spring', stiffness: 400, damping: 25 }}
              className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border flex items-center gap-1.5 ${colors.bg} ${colors.text} ${colors.border}`}
            >
              {result.verdict === 'safe' ? (
                <ShieldCheck className="w-3.5 h-3.5" />
              ) : result.verdict === 'suspicious' ? (
                <AlertTriangle className="w-3.5 h-3.5" />
              ) : (
                <ShieldAlert className="w-3.5 h-3.5" />
              )}
              <span>{result.risk_level}</span>
            </motion.div>
          </div>

          {/* Large Numerical Score with Sweep Count-up */}
          <div className="my-6 flex items-baseline gap-2">
            <span className={`text-6xl font-extrabold tracking-tight font-mono ${colors.text}`}>
              <AnimatedScore value={result.risk_score} />
            </span>
            <span className="text-xl font-medium text-[#9A9AAE]">/ 100</span>
          </div>

          {/* Risk Level Bar with Sweep */}
          <div>
            <div className="h-2 w-full rounded-full bg-[#1C1C26] overflow-hidden">
              <motion.div
                initial={prefersReduced ? false : { width: 0 }}
                animate={{ width: `${Math.max(5, result.risk_score)}%` }}
                transition={{ duration: 0.85, ease: [0.16, 1, 0.3, 1] }}
                className={`h-full rounded-full ${colors.bar}`}
              />
            </div>
            <div className="flex justify-between mt-2 text-[11px] text-[#9A9AAE] font-mono">
              <span>0 (Safe)</span>
              <span>25 (Medium)</span>
              <span>55 (High)</span>
              <span>80+ (Critical)</span>
            </div>
          </div>
        </div>

        {/* Right 2 cols: Threat Explanation & Signal Breakdown */}
        <div className="lg:col-span-2 space-y-6">
          {/* Natural Language Summary (Fades in last) */}
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7, duration: 0.45 }}
            className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]"
          >
            <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] mb-2 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-[#00E5FF]" />
              Threat Intelligence Summary
            </h4>
            <p className="text-sm leading-relaxed text-[#F5F5F7]">
              {result.explanation || 'No malicious indicators or anomalies were detected in the analyzed payload.'}
            </p>
          </motion.div>

          {/* Multi-Signal Staggered Breakdown Bars */}
          <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] mb-4 flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-[#7B3FE4]" />
              Signal Contribution Breakdown
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {[
                { label: 'NLP Threat', val: result.signal_scores.nlp },
                { label: 'URL Reputation', val: result.signal_scores.url },
                { label: 'Sender Legitimacy', val: result.signal_scores.sender },
                { label: 'Email Auth', val: result.signal_scores.email_auth },
                { label: 'Context / Urgency', val: result.signal_scores.context },
              ].map((sig, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-[#13131A] border border-[#1C1C26]">
                  <p className="text-[11px] text-[#9A9AAE] truncate">{sig.label}</p>
                  <div className="mt-1 flex items-baseline justify-between">
                    <span className="text-base font-bold font-mono text-[#F5F5F7]">{sig.val}</span>
                    <span className="text-[10px] text-[#9A9AAE]">/ 100</span>
                  </div>
                  <div className="mt-1.5 h-1 w-full rounded-full bg-[#1C1C26] overflow-hidden">
                    <motion.div
                      initial={prefersReduced ? false : { width: 0 }}
                      animate={{ width: `${sig.val}%` }}
                      transition={{ duration: 0.6, delay: 0.25 + idx * 0.07, ease: 'easeOut' }}
                      className={`h-full rounded-full ${
                        sig.val >= 70
                          ? 'bg-[#EF4444]'
                          : sig.val >= 40
                          ? 'bg-[#F97316]'
                          : sig.val >= 20
                          ? 'bg-[#F59E0B]'
                          : 'bg-[#10B981]'
                      }`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Extracted Message Content with Bidirectional Highlight Sync */}
      {result.extracted_text && (
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] flex items-center gap-2">
              <FileCode className="w-3.5 h-3.5 text-[#00E5FF]" />
              Transcribed / Extracted Content Payload
            </h4>
            <span className="text-[11px] font-mono text-[#626274]">
              Hover highlighted terms to cross-reference findings
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[#13131A] border border-[#1C1C26] text-xs font-mono text-[#F5F5F7] max-h-56 overflow-y-auto whitespace-pre-wrap leading-relaxed">
            {result.extracted_text}
          </div>
        </div>
      )}

      {/* Explainable Findings List Staggered from Below with Bidirectional Hover */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-base font-semibold text-[#F5F5F7] flex items-center gap-2">
            <span>Explainable Findings</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-[#1C1C26] text-[#9A9AAE]">
              {result.findings.length}
            </span>
          </h3>
          <span className="text-xs text-[#626274]">Hover finding to isolate indicators</span>
        </div>

        {result.findings.length === 0 ? (
          <div className="p-8 text-center rounded-xl bg-[#13131A]/50 border border-[#1C1C26] text-sm text-[#9A9AAE]">
            No hostile indicators or suspicious patterns were identified.
          </div>
        ) : (
          <div className="space-y-4">
            {result.findings.map((finding, idx) => {
              const isHovered = hoveredFindingIdx === idx;

              return (
                <motion.div
                  key={idx}
                  initial={prefersReduced ? false : { opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.15 + idx * 0.06, duration: 0.3 }}
                  onMouseEnter={() => setHoveredFindingIdx(idx)}
                  onMouseLeave={() => setHoveredFindingIdx(null)}
                  className={`p-4 rounded-xl bg-[#13131A] border transition-all duration-200 ${
                    isHovered
                      ? 'border-[#00E5FF] shadow-[0_0_20px_rgba(0,229,255,0.18)] translate-x-1'
                      : 'border-[#1C1C26] hover:border-[#2A2A3A]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border ${getSeverityBadge(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="text-xs font-mono uppercase text-[#9A9AAE] px-2 py-0.5 rounded bg-[#1C1C26]">
                        {finding.category.replace('_', ' ')}
                      </span>
                    </div>
                    <span className="text-[11px] text-[#626274] font-mono">
                      Module: {finding.source_module}
                    </span>
                  </div>

                  <div className="mt-2 space-y-2">
                    {finding.evidence && (
                      <div className={`p-2.5 rounded-lg border text-xs font-mono transition-colors duration-200 ${
                        isHovered ? 'bg-[#00E5FF]/10 border-[#00E5FF]/30 text-[#00E5FF]' : 'bg-[#0D0D12] border-[#1C1C26] text-[#F5F5F7]'
                      }`}>
                        <strong className="text-[#9A9AAE] font-sans font-medium mr-2">Evidence:</strong>
                        &ldquo;{finding.evidence}&rdquo;
                      </div>
                    )}

                    <p className="text-xs text-[#9A9AAE] leading-relaxed">
                      {finding.explanation}
                    </p>

                    {finding.recommended_action && (
                      <div className="flex items-start gap-2 pt-1 text-xs text-[#00E5FF]">
                        <ArrowRight className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                        <span>{finding.recommended_action}</span>
                      </div>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      {/* Extracted URLs & Hop-by-Hop Link Trail */}
      {(result.extracted_urls.length > 0 || result.link_trail.length > 0) && (
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <h3 className="text-base font-semibold text-[#F5F5F7] mb-4 flex items-center gap-2">
            <ExternalLink className="w-4 h-4 text-[#00E5FF]" />
            URL Inspection & Link Trail
          </h3>

          <div className="space-y-3">
            {result.extracted_urls.map((u, i) => (
              <div
                key={i}
                className="p-3.5 rounded-xl bg-[#13131A] border border-[#1C1C26] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="font-mono text-[#F5F5F7] break-all">
                  <span className="text-[#9A9AAE] mr-2">Target:</span>
                  {u.url}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded border ${
                      u.reputation === 'malicious'
                        ? 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30'
                        : u.reputation === 'suspicious'
                        ? 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30'
                        : 'text-[#10B981] bg-[#10B981]/10 border-[#10B981]/30'
                    }`}
                  >
                    {u.reputation}
                  </span>
                  {u.flags.map((flag, fIdx) => (
                    <motion.span
                      key={fIdx}
                      initial={prefersReduced ? false : { scale: 1 }}
                      animate={{ scale: [1, 1.08, 1] }}
                      transition={{ delay: 0.5 + fIdx * 0.1, duration: 0.4 }}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1C1C26] text-[#9A9AAE]"
                    >
                      {flag}
                    </motion.span>
                  ))}
                </div>
              </div>
            ))}

            {result.link_trail.length > 0 && (
              <div className="mt-4 pt-4 border-t border-[#1C1C26]">
                <p className="text-xs uppercase tracking-wider text-[#9A9AAE] font-medium mb-3">
                  Hop-by-Hop Redirect Flow:
                </p>
                <div className="space-y-2.5">
                  {result.link_trail.map((hop, hIdx) => (
                    <motion.div
                      key={hIdx}
                      initial={prefersReduced ? false : { opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.2 + hIdx * 0.12, duration: 0.3 }}
                      className="flex items-center gap-3 p-2.5 rounded-lg bg-[#0D0D12] border border-[#1C1C26] text-xs font-mono relative"
                    >
                      <span className="text-[10px] text-[#00E5FF] font-bold px-1.5 py-0.5 rounded bg-[#00E5FF]/10">
                        Hop {hop.hop}
                      </span>
                      <span className="text-[#9A9AAE] px-1.5 py-0.5 rounded bg-[#1C1C26]">
                        HTTP {hop.status}
                      </span>
                      <span className="text-[#F5F5F7] break-all flex-1">{hop.url}</span>
                      {hop.final && (
                        <motion.span
                          initial={prefersReduced ? false : { scale: 1 }}
                          animate={{ scale: [1, 1.1, 1] }}
                          transition={{ delay: 0.6 + hIdx * 0.1, duration: 0.4 }}
                          className="text-[10px] uppercase font-bold text-[#EF4444] px-1.5 py-0.5 rounded bg-[#EF4444]/10 border border-[#EF4444]/30"
                        >
                          Final Target
                        </motion.span>
                      )}
                    </motion.div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recommendations & Digital Evidence Cryptographic Proof */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recommended Actions Staggered */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
          <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] mb-4 flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-[#00E5FF]" />
            Protective Recommendations & Helplines
          </h4>

          {result.recommendations.length === 0 ? (
            <p className="text-xs text-[#9A9AAE]">No immediate protective actions necessary.</p>
          ) : (
            <ul className="space-y-3">
              {result.recommendations.map((rec, rIdx) => (
                <motion.li
                  key={rIdx}
                  initial={prefersReduced ? false : { opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 + rIdx * 0.06, duration: 0.3 }}
                  className="flex items-start gap-2.5 text-xs text-[#F5F5F7] leading-relaxed p-2.5 rounded-lg bg-[#13131A] border border-[#1C1C26]"
                >
                  <ArrowRight className="w-3.5 h-3.5 text-[#00E5FF] mt-0.5 shrink-0" />
                  <span>{rec}</span>
                </motion.li>
              ))}
            </ul>
          )}

          {/* India Regulatory Helpdesk Quick Card */}
          <div className="mt-4 p-3.5 rounded-xl bg-[#7B3FE4]/10 border border-[#7B3FE4]/30 text-xs space-y-1.5">
            <p className="font-semibold text-[#F5F5F7] flex items-center gap-1.5">
              <span>National Cyber Crime Reporting Helpline (India)</span>
            </p>
            <p className="text-[#9A9AAE]">
              Dial <strong className="text-[#00E5FF] font-mono">1930</strong> immediately if money has been debited, or file a report at{' '}
              <strong className="text-[#F5F5F7]">cybercrime.gov.in</strong> within golden hour.
            </p>
          </div>
        </div>

        {/* Cryptographic Evidence Hash & Blockchain Status */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-6">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] flex items-center gap-2">
                <Fingerprint className="w-3.5 h-3.5 text-[#00E5FF]" />
                Evidence Digest & Ledger Anchor
              </h4>

              {/* Blockchain Status Chip with Subtle Pulse only while pending */}
              {result.blockchain_status === 'pending' ? (
                <motion.span
                  animate={{ opacity: [0.6, 1, 0.6] }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                  className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#F59E0B]/10 border border-[#F59E0B]/30 text-[#F59E0B] flex items-center gap-1"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]" />
                  Anchor Pending
                </motion.span>
              ) : result.blockchain_status === 'anchored' ? (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981] flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-[#10B981]" />
                  On-Chain Anchored
                </span>
              ) : (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#13131A] border border-[#1C1C26] text-[#626274]">
                  {result.blockchain_status.replace('_', ' ')}
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#13131A] border border-[#1C1C26]">
              <span className="font-mono text-[11px] text-[#9A9AAE] break-all select-all flex-1">
                {result.evidence_hash || 'SHA256 pending'}
              </span>
              {result.evidence_hash && (
                <button
                  onClick={copyEvidenceHash}
                  className="p-1.5 rounded-md text-[#9A9AAE] hover:text-[#00E5FF] hover:bg-[#1C1C26] transition-colors"
                  title="Copy evidence hash"
                >
                  {copiedHash ? <Check className="w-4 h-4 text-[#10B981]" /> : <Copy className="w-4 h-4" />}
                </button>
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-[#1C1C26] flex items-center justify-between text-xs">
            <span className="text-[#9A9AAE]">Verify integrity or run tamper test:</span>
            <Link
              href={`/verify/${result.case_id}`}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#00E5FF] hover:text-white px-3 py-1.5 rounded-lg bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] hover:border-[#7B3FE4]/50 transition-colors"
            >
              <span>Launch Verification Suite</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
