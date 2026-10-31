'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  Cpu,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Sparkles,
  Server,
  Zap,
  Globe,
  Smartphone,
  Mail,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { SystemHealth, AnalysisResult } from '@/types';
import { checkHealth, getCases, API_BASE_URL } from '@/lib/api';

export default function DashboardPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isOnline, setIsOnline] = useState<boolean | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(true);
  const [cases, setCases] = useState<AnalysisResult[]>([]);

  const fetchStatus = async () => {
    setIsChecking(true);
    const [healthRes, casesList] = await Promise.all([
      checkHealth(),
      getCases(),
    ]);

    setIsOnline(healthRes.online);
    if (healthRes.online && healthRes.health) {
      setHealth(healthRes.health);
      setHealthError(null);
    } else {
      setHealth(null);
      setHealthError(healthRes.error || 'Backend unreachable');
    }
    setCases(casesList);
    setIsChecking(false);
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-10 md:py-14 space-y-8">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs text-[#00E5FF] mb-2 font-mono">
            <Activity className="w-3.5 h-3.5" />
            Live Security Console
          </div>
          <h1 className="text-3xl font-bold text-[#F5F5F7] tracking-tight">
            System Operations & Telemetry
          </h1>
          <p className="mt-1 text-sm text-[#9A9AAE]">
            Real-time status of backend detection engines, Gemini AI connectivity, and active threat cases.
          </p>
        </div>

        <button
          onClick={fetchStatus}
          disabled={isChecking}
          className="self-start sm:self-center inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#0D0D12] hover:bg-[#13131A] border border-[#1C1C26] hover:border-[#7B3FE4]/50 text-xs font-medium text-[#F5F5F7] transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin text-[#00E5FF]' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Backend & AI Engine Health Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Backend API Status */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-semibold flex items-center gap-2">
              <Server className="w-4 h-4 text-[#00E5FF]" />
              Core API Status
            </span>
            {isChecking ? (
              <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B] animate-pulse" />
            ) : isOnline ? (
              <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[#10B981] px-2 py-0.5 rounded-full bg-[#10B981]/10 border border-[#10B981]/20">
                <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
                Online
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[#EF4444] px-2 py-0.5 rounded-full bg-[#EF4444]/10 border border-[#EF4444]/20">
                <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" />
                Offline
              </span>
            )}
          </div>

          <div>
            <h3 className="text-lg font-bold text-[#F5F5F7]">
              {isOnline ? 'FastAPI Service Ready' : 'Backend Server Offline'}
            </h3>
            <p className="mt-1 text-xs text-[#9A9AAE] font-mono break-all">
              {API_BASE_URL}
            </p>
          </div>

          <div className="pt-2 border-t border-[#1C1C26] text-[11px] text-[#626274]">
            {isOnline
              ? `Service: ${health?.service || 'AEGIS 2.0 Security Core'}`
              : `Error: ${healthError || 'Could not reach server on port 8000'}`}
          </div>
        </div>

        {/* Card 2: AI Engine Telemetry */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-semibold flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#7B3FE4]" />
              AI Threat Intelligence
            </span>
            {health?.ai_engine.configured ? (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#00E5FF] px-2 py-0.5 rounded-full bg-[#7B3FE4]/15 border border-[#7B3FE4]/30">
                Live Gemini API
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#9A9AAE] px-2 py-0.5 rounded-full bg-[#1C1C26]">
                Deterministic Fallback
              </span>
            )}
          </div>

          <div>
            <h3 className="text-lg font-bold text-[#F5F5F7]">
              {health?.ai_engine.model || 'gemini-2.5-flash'}
            </h3>
            <p className="mt-1 text-xs text-[#9A9AAE]">
              {health?.ai_engine.configured
                ? 'Consolidated prompt-injection hardened model'
                : 'Deterministic heuristics active (GEMINI_API_KEY not configured)'}
            </p>
          </div>

          <div className="pt-2 border-t border-[#1C1C26] text-[11px] text-[#626274] flex items-center justify-between">
            <span>Provider: Google DeepMind</span>
            <span className="font-mono text-[#00E5FF]">Ready</span>
          </div>
        </div>

        {/* Card 3: Deterministic Detectors */}
        <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-semibold flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#10B981]" />
              Rule-Based Security Engines
            </span>
            <span className="text-xs font-mono text-[#10B981]">4 Active</span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>SSRF & Port 80/443</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Indian Brand Spoofing</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Email Display Forensics</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Unicode Homoglyph Guard</span>
            </div>
          </div>

          <div className="pt-2 border-t border-[#1C1C26] text-[11px] text-[#626274]">
            Zero-latency local evaluation
          </div>
        </div>
      </div>

      {/* Quick Launch Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0D0D12] to-[#13131A] border border-[#1C1C26] flex flex-col sm:flex-row items-center justify-between gap-6">
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-[#F5F5F7] flex items-center gap-2">
            <span>Ready to Inspect a Suspicious Link, SMS or Email?</span>
          </h2>
          <p className="text-xs text-[#9A9AAE]">
            Launch the analysis workbench with pre-configured banking and smishing test samples.
          </p>
        </div>

        <Link
          href="/analyze"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-[#F5F5F7] text-xs font-semibold shadow-lg shadow-[#7B3FE4]/20 transition-all hover:-translate-y-0.5"
        >
          <span>Launch Workbench</span>
          <ArrowRight className="w-4 h-4 text-[#00E5FF]" />
        </Link>
      </div>

      {/* Recent Investigations List */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold text-[#F5F5F7] flex items-center gap-2">
            <span>Recent Analysis Log</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-[#1C1C26] text-[#9A9AAE]">
              {cases.length} cases
            </span>
          </h3>
          <span className="text-xs text-[#626274]">
            In-memory session log (Persistent database scheduled for Phase 3)
          </span>
        </div>

        <div className="space-y-2">
          {cases.map((c) => (
            <Link
              key={c.case_id}
              href={`/results/${c.case_id}`}
              className="flex items-center justify-between p-3.5 rounded-xl bg-[#13131A] border border-[#1C1C26] hover:border-[#7B3FE4]/50 transition-colors group"
            >
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-[#0D0D12] border border-[#1C1C26] flex items-center justify-center text-[#9A9AAE]">
                  {c.input_type === 'url' ? (
                    <Globe className="w-4 h-4 text-[#00E5FF]" />
                  ) : c.input_type === 'sms' ? (
                    <Smartphone className="w-4 h-4 text-[#7B3FE4]" />
                  ) : (
                    <Mail className="w-4 h-4 text-[#9A9AAE]" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-[#F5F5F7] group-hover:text-[#00E5FF] transition-colors">
                      {c.case_id}
                    </span>
                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#1C1C26] text-[#9A9AAE]">
                      {c.input_type}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#9A9AAE] truncate max-w-md mt-0.5">
                    {c.explanation}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div
                    className={`text-xs font-bold font-mono ${
                      c.risk_score >= 80
                        ? 'text-[#EF4444]'
                        : c.risk_score >= 55
                        ? 'text-[#F97316]'
                        : c.risk_score >= 25
                        ? 'text-[#F59E0B]'
                        : 'text-[#10B981]'
                    }`}
                  >
                    {c.risk_score}/100
                  </div>
                  <span className="text-[10px] uppercase text-[#626274] font-mono">
                    {c.verdict}
                  </span>
                </div>
                <ArrowRight className="w-4 h-4 text-[#626274] group-hover:text-[#00E5FF] group-hover:translate-x-0.5 transition-all" />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
