'use client';

import React, { useState } from 'react';
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
} from 'lucide-react';
import { AnalysisResult, FindingSeverity, RiskLevel, Verdict } from '@/types';

interface AnalysisResultViewProps {
  result: AnalysisResult;
  onReset?: () => void;
}

export function AnalysisResultView({ result, onReset }: AnalysisResultViewProps) {
  const [copiedHash, setCopiedHash] = useState(false);

  const copyEvidenceHash = () => {
    if (result.evidence_hash) {
      navigator.clipboard.writeText(result.evidence_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
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
  const isFallback = result.unavailable_checks.some((c) =>
    c.toLowerCase().includes('gemini') || c.toLowerCase().includes('api key')
  );

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
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
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-base font-semibold text-[#F5F5F7]">
                {result.case_id}
              </span>
              <span className="uppercase text-[11px] font-mono tracking-wider px-2 py-0.5 rounded-md bg-[#13131A] text-[#9A9AAE] border border-[#1C1C26]">
                {result.input_type}
              </span>
              {isFallback ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#1C1C26] text-[#9A9AAE]">
                  <Cpu className="w-3 h-3 text-[#9A9AAE]" />
                  Deterministic Engine
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-md bg-[#7B3FE4]/15 text-[#00E5FF] border border-[#7B3FE4]/30">
                  <Sparkles className="w-3 h-3 text-[#00E5FF]" />
                  Gemini AI Assisted
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-xs text-[#9A9AAE]">
              <Clock className="w-3.5 h-3.5" />
              <span>{new Date(result.created_at).toLocaleString()}</span>
              <span>•</span>
              <span>Confidence: <strong className="uppercase text-[#F5F5F7]">{result.confidence}</strong></span>
            </div>
          </div>
        </div>

        {onReset && (
          <button
            onClick={onReset}
            className="self-start sm:self-center inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-[#9A9AAE] hover:text-[#F5F5F7] bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] rounded-lg transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Analyze Another
          </button>
        )}
      </div>

      {/* Main Score & Verdict Hero Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Risk Score Gauge Card */}
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
            <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${colors.bg} ${colors.text} ${colors.border}`}>
              {result.risk_level}
            </div>
          </div>

          {/* Large Numerical Score Gauge */}
          <div className="my-6 flex items-baseline gap-2">
            <span className={`text-6xl font-extrabold tracking-tight font-mono ${colors.text}`}>
              {result.risk_score}
            </span>
            <span className="text-xl font-medium text-[#9A9AAE]">/ 100</span>
          </div>

          {/* Risk Level Bar */}
          <div>
            <div className="h-2 w-full rounded-full bg-[#1C1C26] overflow-hidden">
              <div
                className={`h-full rounded-full ${colors.bar} transition-all duration-500`}
                style={{ width: `${Math.max(5, result.risk_score)}%` }}
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
          {/* Natural Language Summary */}
          <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] mb-2 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-[#00E5FF]" />
              Threat Intelligence Summary
            </h4>
            <p className="text-sm leading-relaxed text-[#F5F5F7]">
              {result.explanation || 'No malicious indicators or anomalies were detected in the analyzed payload.'}
            </p>
          </div>

          {/* Multi-Signal Breakdown Bar */}
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
                    <div
                      className={`h-full rounded-full ${
                        sig.val >= 70
                          ? 'bg-[#EF4444]'
                          : sig.val >= 40
                          ? 'bg-[#F97316]'
                          : sig.val >= 20
                          ? 'bg-[#F59E0B]'
                          : 'bg-[#10B981]'
                      }`}
                      style={{ width: `${sig.val}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Explainable Findings List */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26]">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-base font-semibold text-[#F5F5F7] flex items-center gap-2">
            <span>Explainable Findings</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-[#1C1C26] text-[#9A9AAE]">
              {result.findings.length}
            </span>
          </h3>
        </div>

        {result.findings.length === 0 ? (
          <div className="p-8 text-center rounded-xl bg-[#13131A]/50 border border-[#1C1C26] text-sm text-[#9A9AAE]">
            No hostile indicators or suspicious patterns were identified.
          </div>
        ) : (
          <div className="space-y-4">
            {result.findings.map((finding, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-[#13131A] border border-[#1C1C26] hover:border-[#2A2A3A] transition-colors"
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
                    <div className="p-2.5 rounded-lg bg-[#0D0D12] border border-[#1C1C26] text-xs font-mono text-[#F5F5F7]">
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
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Extracted URLs & Link Trail (if present) */}
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
                    <span
                      key={fIdx}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1C1C26] text-[#9A9AAE]"
                    >
                      {flag}
                    </span>
                  ))}
                </div>
              </div>
            ))}

            {result.link_trail.length > 0 && (
              <div className="mt-4 pt-4 border-t border-[#1C1C26]">
                <p className="text-xs uppercase tracking-wider text-[#9A9AAE] font-medium mb-3">
                  Redirect Trail:
                </p>
                <div className="space-y-2">
                  {result.link_trail.map((hop, hIdx) => (
                    <div
                      key={hIdx}
                      className="flex items-center gap-3 p-2.5 rounded-lg bg-[#0D0D12] border border-[#1C1C26] text-xs font-mono"
                    >
                      <span className="text-[10px] text-[#00E5FF] font-bold px-1.5 py-0.5 rounded bg-[#00E5FF]/10">
                        Hop {hop.hop}
                      </span>
                      <span className="text-[#9A9AAE] px-1.5 py-0.5 rounded bg-[#1C1C26]">
                        HTTP {hop.status}
                      </span>
                      <span className="text-[#F5F5F7] break-all flex-1">{hop.url}</span>
                      {hop.final && (
                        <span className="text-[10px] uppercase font-bold text-[#EF4444] px-1.5 py-0.5 rounded bg-[#EF4444]/10">
                          Final Target
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Highlights & India-Specific Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recommended Actions */}
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
                <li
                  key={rIdx}
                  className="flex items-start gap-2.5 text-xs text-[#F5F5F7] leading-relaxed p-2.5 rounded-lg bg-[#13131A] border border-[#1C1C26]"
                >
                  <ArrowRight className="w-3.5 h-3.5 text-[#00E5FF] mt-0.5 shrink-0" />
                  <span>{rec}</span>
                </li>
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

        {/* Unavailable Checks & Evidence Cryptographic Signature */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-6">
          <div>
            <h4 className="text-xs uppercase tracking-wider font-semibold text-[#9A9AAE] mb-3 flex items-center gap-2">
              <HelpCircle className="w-3.5 h-3.5 text-[#9A9AAE]" />
              Unavailable Checks Disclosure
            </h4>

            {result.unavailable_checks.length === 0 ? (
              <p className="text-xs text-[#9A9AAE]">All security checks were executed successfully.</p>
            ) : (
              <ul className="space-y-2">
                {result.unavailable_checks.map((chk, cIdx) => (
                  <li
                    key={cIdx}
                    className="text-xs text-[#9A9AAE] font-mono flex items-center gap-2 p-2 rounded-md bg-[#13131A]"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]" />
                    <span>{chk}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Cryptographic Evidence Hash */}
          <div className="pt-4 border-t border-[#1C1C26]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-medium flex items-center gap-1.5">
                <Fingerprint className="w-3.5 h-3.5 text-[#00E5FF]" />
                Evidence SHA-256 Digest
              </span>
              <span className="text-[10px] font-mono text-[#9A9AAE] uppercase px-2 py-0.5 rounded bg-[#1C1C26]">
                {result.blockchain_status.replace('_', ' ')}
              </span>
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
        </div>
      </div>
    </div>
  );
}

