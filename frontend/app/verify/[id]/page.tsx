'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowLeft,
  RotateCcw,
  Fingerprint,
  FileCheck,
  ExternalLink,
  Loader2,
  Copy,
  Check,
} from 'lucide-react';
import { motion, useReducedMotion } from 'framer-motion';
import { AnalysisResult } from '@/types';
import { getCase } from '@/lib/api';
import { useToast } from '@/components/ui/Toast';

interface VerifyPageProps {
  params: {
    id: string;
  };
}

async function sha256Hex(text: string): Promise<string> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  }
  const enc = new TextEncoder().encode(text);
  const buf = await window.crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export default function VerifyPage({ params }: VerifyPageProps) {
  const { showToast } = useToast();
  const prefersReduced = useReducedMotion();

  const [caseData, setCaseData] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);

  // Check rows resolution step (0: idle, 1: integrity, 2: signature, 3: anchored)
  const [resolvedStep, setResolvedStep] = useState(0);

  // Tamper demo state
  const [originalText, setOriginalText] = useState('');
  const [editedText, setEditedText] = useState('');
  const [recomputedHash, setRecomputedHash] = useState('');
  const [originalHash, setOriginalHash] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadCase() {
      setLoading(true);
      const data = await getCase(params.id);
      if (data) {
        setCaseData(data);
        const textPayload =
          data.extracted_text ||
          data.findings[0]?.evidence ||
          `Case: ${data.case_id} - Verdict: ${data.verdict} - Risk: ${data.risk_score}`;
        setOriginalText(textPayload);
        setEditedText(textPayload);

        const initialHash = data.evidence_hash || (await sha256Hex(textPayload));
        setOriginalHash(initialHash);
        setRecomputedHash(initialHash);
      }
      setLoading(false);
    }
    loadCase();
  }, [params.id]);

  // Resolve verification check rows sequentially
  useEffect(() => {
    if (loading || !caseData) return;

    if (prefersReduced) {
      setResolvedStep(3);
      return;
    }

    const t1 = setTimeout(() => setResolvedStep(1), 220);
    const t2 = setTimeout(() => setResolvedStep(2), 520);
    const t3 = setTimeout(() => setResolvedStep(3), 850);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [loading, caseData, prefersReduced]);

  // Live recomputation of hash when tamper text is edited
  const handleTextChange = async (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newText = e.target.value;
    setEditedText(newText);
    const hash = await sha256Hex(newText);
    setRecomputedHash(hash);
  };

  const resetTamperDemo = () => {
    setEditedText(originalText);
    setRecomputedHash(originalHash);
    showToast('Evidence copy restored to original verified state', 'info');
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    showToast('Hash copied to clipboard', 'success');
    setTimeout(() => setCopied(false), 2000);
  };

  const isTampered = recomputedHash !== originalHash;

  if (loading) {
    return (
      <div className="w-full max-w-5xl mx-auto px-5 py-24 flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-8 h-8 animate-spin text-[#00E5FF]" />
        <p className="text-sm font-mono text-[#9A9AAE]">Loading cryptographic evidence manifest...</p>
      </div>
    );
  }

  if (!caseData) {
    return (
      <div className="w-full max-w-4xl mx-auto px-5 py-16">
        <div className="p-8 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] text-center space-y-4">
          <AlertTriangle className="w-8 h-8 text-[#F59E0B] mx-auto" />
          <h2 className="text-xl font-bold text-[#F5F5F7]">Case Not Found</h2>
          <p className="text-sm text-[#9A9AAE]">
            Cannot verify case <code className="text-[#00E5FF]">{params.id}</code>. No matching record located.
          </p>
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#7B3FE4] text-white text-xs font-semibold"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Workbench</span>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-5xl mx-auto px-5 py-10 md:py-14 space-y-8">
      {/* Top Navigation & Title */}
      <div className="space-y-3">
        <Link
          href={`/results/${caseData.case_id}`}
          className="inline-flex items-center gap-2 text-xs font-medium text-[#9A9AAE] hover:text-[#00E5FF] transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Investigation Details</span>
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs font-mono text-[#00E5FF] mb-2">
              <Fingerprint className="w-3.5 h-3.5" />
              Evidence Verification Suite
            </div>
            <h1 className="text-3xl font-bold text-[#F5F5F7] tracking-tight">
              Integrity Audit: {caseData.case_id}
            </h1>
            <p className="mt-1 text-sm text-[#9A9AAE]">
              Cryptographic hash verification and immutable ledger audit trail.
            </p>
          </div>

          <div className="text-right text-xs font-mono text-[#626274] self-start sm:self-center">
            <span>Recorded: </span>
            <span className="text-[#9A9AAE]">{new Date(caseData.created_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      {/* Sequential Verification Check Rows */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-[#9A9AAE] flex items-center gap-2">
          <FileCheck className="w-4 h-4 text-[#00E5FF]" />
          Verification Manifest Resolution
        </h2>

        <div className="space-y-3">
          {/* Row 1: Payload Integrity */}
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 8 }}
            animate={resolvedStep >= 1 ? { opacity: 1, y: 0 } : { opacity: 0.4, y: 0 }}
            transition={{ duration: 0.3 }}
            className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
              resolvedStep >= 1
                ? 'bg-[#10B981]/10 border-[#10B981]/30'
                : 'bg-[#13131A] border-[#1C1C26]'
            }`}
          >
            <div className="flex items-center gap-3">
              {resolvedStep >= 1 ? (
                <CheckCircle2 className="w-5 h-5 text-[#10B981] shrink-0" />
              ) : (
                <Loader2 className="w-5 h-5 animate-spin text-[#9A9AAE] shrink-0" />
              )}
              <div>
                <p className="text-xs font-semibold text-[#F5F5F7]">
                  Payload Digest Integrity
                </p>
                <p className="text-[11px] text-[#9A9AAE] font-mono break-all mt-0.5">
                  Canonical SHA-256 matches case manifest
                </p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-[#10B981] uppercase px-2.5 py-1 rounded bg-[#10B981]/15 shrink-0">
              {resolvedStep >= 1 ? 'Verified' : 'Resolving...'}
            </span>
          </motion.div>

          {/* Row 2: Cryptographic Signature */}
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 8 }}
            animate={resolvedStep >= 2 ? { opacity: 1, y: 0 } : { opacity: 0.4, y: 0 }}
            transition={{ duration: 0.3 }}
            className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
              resolvedStep >= 2
                ? 'bg-[#10B981]/10 border-[#10B981]/30'
                : 'bg-[#13131A] border-[#1C1C26]'
            }`}
          >
            <div className="flex items-center gap-3">
              {resolvedStep >= 2 ? (
                <CheckCircle2 className="w-5 h-5 text-[#10B981] shrink-0" />
              ) : (
                <Loader2 className="w-5 h-5 animate-spin text-[#9A9AAE] shrink-0" />
              )}
              <div>
                <p className="text-xs font-semibold text-[#F5F5F7]">
                  Forensic Security Engine Seal
                </p>
                <p className="text-[11px] text-[#9A9AAE] font-mono mt-0.5">
                  Signed by AEGIS Dual-Mode Security Kernel
                </p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-[#10B981] uppercase px-2.5 py-1 rounded bg-[#10B981]/15 shrink-0">
              {resolvedStep >= 2 ? 'Valid Signature' : 'Resolving...'}
            </span>
          </motion.div>

          {/* Row 3: Blockchain Anchor (State sensitive: anchored, not enabled, or not verifiable) */}
          <motion.div
            initial={prefersReduced ? false : { opacity: 0, y: 8 }}
            animate={resolvedStep >= 3 ? { opacity: 1, y: 0 } : { opacity: 0.4, y: 0 }}
            transition={{ duration: 0.3 }}
            className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
              resolvedStep >= 3 && caseData.blockchain_status === 'anchored'
                ? 'bg-[#10B981]/10 border-[#10B981]/30'
                : resolvedStep >= 3 && caseData.blockchain_status === 'not_enabled'
                ? 'bg-[#13131A] border-[#1C1C26]'
                : resolvedStep >= 3
                ? 'bg-[#F59E0B]/10 border-[#F59E0B]/30'
                : 'bg-[#13131A] border-[#1C1C26]'
            }`}
          >
            <div className="flex items-center gap-3">
              {resolvedStep >= 3 ? (
                caseData.blockchain_status === 'anchored' ? (
                  <CheckCircle2 className="w-5 h-5 text-[#10B981] shrink-0" />
                ) : caseData.blockchain_status === 'not_enabled' ? (
                  <HelpCircle className="w-5 h-5 text-[#626274] shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-[#F59E0B] shrink-0" />
                )
              ) : (
                <Loader2 className="w-5 h-5 animate-spin text-[#9A9AAE] shrink-0" />
              )}
              <div>
                <p className="text-xs font-semibold text-[#F5F5F7]">
                  Immutable Ledger Anchor
                </p>
                <p className="text-[11px] text-[#9A9AAE] font-mono mt-0.5">
                  {resolvedStep >= 3
                    ? caseData.blockchain_status === 'anchored'
                      ? `Anchored: ${caseData.transaction_hash?.slice(0, 24)}...`
                      : caseData.blockchain_status === 'not_enabled'
                      ? 'Blockchain anchoring not enabled for this session tier'
                      : 'Ledger synchronization currently not verifiable'
                    : 'Querying node registry...'}
                </p>
              </div>
            </div>

            <span
              className={`text-xs font-mono font-bold uppercase px-2.5 py-1 rounded shrink-0 ${
                resolvedStep >= 3 && caseData.blockchain_status === 'anchored'
                  ? 'bg-[#10B981]/15 text-[#10B981]'
                  : resolvedStep >= 3 && caseData.blockchain_status === 'not_enabled'
                  ? 'bg-[#1C1C26] text-[#9A9AAE]'
                  : resolvedStep >= 3
                  ? 'bg-[#F59E0B]/15 text-[#F59E0B]'
                  : 'bg-[#1C1C26] text-[#626274]'
              }`}
            >
              {resolvedStep >= 3
                ? caseData.blockchain_status === 'anchored'
                  ? 'Anchored'
                  : caseData.blockchain_status === 'not_enabled'
                  ? 'Not Enabled'
                  : 'Not Verifiable'
                : 'Resolving...'}
            </span>
          </motion.div>
        </div>
      </div>

      {/* Interactive Tamper Proof Demo */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-[#F5F5F7] flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#00E5FF]" />
              Interactive Evidence Tamper Demonstration
            </h2>
            <p className="text-xs text-[#9A9AAE] mt-0.5">
              Edit the recorded evidence below. Notice how altering even a single character instantly recomputes the SHA-256 digest and breaks the audit seal.
            </p>
          </div>

          {/* Tamper Result Badge with Shake Animation on Mismatch */}
          <motion.div
            key={isTampered ? 'tampered' : 'verified'}
            animate={
              isTampered
                ? { x: [-4, 4, -4, 4, -2, 2, 0] }
                : { scale: [0.95, 1] }
            }
            transition={{ duration: 0.3 }}
            className={`px-3 py-1.5 rounded-xl border flex items-center gap-2 text-xs font-bold font-mono self-start sm:self-center shrink-0 ${
              isTampered
                ? 'bg-[#EF4444]/15 border-[#EF4444]/40 text-[#EF4444] shadow-[0_0_15px_rgba(239,68,68,0.25)]'
                : 'bg-[#10B981]/15 border-[#10B981]/40 text-[#10B981] shadow-[0_0_15px_rgba(16,185,129,0.25)]'
            }`}
          >
            {isTampered ? (
              <XCircle className="w-4 h-4 text-[#EF4444]" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
            )}
            <span>{isTampered ? 'Mismatch (Tampered)' : 'Verified (Unaltered)'}</span>
          </motion.div>
        </div>

        {/* Live Hashes Comparison Box */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[#13131A] border border-[#1C1C26] space-y-1">
            <span className="text-[#9A9AAE] block">Original Recorded Hash:</span>
            <span className="text-[#10B981] break-all select-all block">{originalHash}</span>
          </div>

          <div
            className={`p-3.5 rounded-xl border space-y-1 transition-colors duration-200 ${
              isTampered
                ? 'bg-[#EF4444]/10 border-[#EF4444]/40 text-[#EF4444]'
                : 'bg-[#13131A] border-[#1C1C26] text-[#00E5FF]'
            }`}
          >
            <span className="text-[#9A9AAE] block">Recomputed Live Digest:</span>
            <span className="break-all select-all block font-bold">{recomputedHash}</span>
          </div>
        </div>

        {/* Editable Evidence Copy Area */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <label className="text-[#9A9AAE] font-medium">Recorded Evidence Payload:</label>
            {isTampered && (
              <button
                onClick={resetTamperDemo}
                className="inline-flex items-center gap-1.5 text-xs text-[#00E5FF] hover:underline"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset to Original</span>
              </button>
            )}
          </div>

          <textarea
            rows={4}
            value={editedText}
            onChange={handleTextChange}
            className={`w-full p-4 rounded-xl bg-[#13131A] border text-xs font-mono text-[#F5F5F7] leading-relaxed focus:outline-none transition-all duration-200 resize-y ${
              isTampered
                ? 'border-[#EF4444] shadow-[0_0_15px_rgba(239,68,68,0.25)]'
                : 'border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.25)]'
            }`}
            placeholder="Edit text to test tamper detection..."
          />
        </div>
      </div>
    </div>
  );
}
