'use client';

import React, { useEffect, useState } from 'react';
import { motion, useMotionValue, animate, useReducedMotion } from 'framer-motion';
import { useToast } from '@/components/ui/Toast';
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
  FileText,
  Image as ImageIcon,
  Shield,
  Lock,
  LogOut,
  Trash2,
  Download,
  FileCheck,
  Search,
  Filter,
  Info,
} from 'lucide-react';
import { SystemHealth, AnalysisResult, AuthStatus } from '@/types';
import {
  checkHealth,
  listCases,
  getAuthStatus,
  enterpriseLogin,
  enterpriseLogout,
  clearSession,
  downloadReport,
  verifyCaseEvidence,
  API_BASE_URL,
} from '@/lib/api';


function CountUpNumber({ value }: { value: number }) {
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

export default function DashboardPage() {
  const { showToast } = useToast();
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isOnline, setIsOnline] = useState<boolean | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(true);

  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [cases, setCases] = useState<AnalysisResult[]>([]);
  const [totalCases, setTotalCases] = useState(0);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [channelFilter, setChannelFilter] = useState('');

  // Enterprise Login modal state
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginEmail, setLoginEmail] = useState('secops@acme.com');
  const [loginPassword, setLoginPassword] = useState('Password123!');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Case action states
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchTelemetryAndCases = async () => {
    setIsChecking(true);
    setActionMessage(null);

    const [healthRes, auth, caseList] = await Promise.all([
      checkHealth(),
      getAuthStatus(),
      listCases({
        query: searchQuery || undefined,
        verdict: verdictFilter || undefined,
        input_type: channelFilter || undefined,
      }),
    ]);

    setIsOnline(healthRes.online);
    if (healthRes.online && healthRes.health) {
      setHealth(healthRes.health);
      setHealthError(null);
    } else {
      setHealth(null);
      setHealthError(healthRes.error || 'Backend unreachable');
    }

    setAuthStatus(auth);
    setCases(caseList.cases);
    setTotalCases(caseList.total);
    setIsChecking(false);
  };

  useEffect(() => {
    fetchTelemetryAndCases();
  }, [verdictFilter, channelFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchTelemetryAndCases();
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setLoginError(null);
    try {
      await enterpriseLogin(loginEmail, loginPassword);
      setShowLoginModal(false);
      await fetchTelemetryAndCases();
    } catch (err: unknown) {
      setLoginError(err instanceof Error ? err.message : 'Login failed.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = async () => {
    await enterpriseLogout();
    await fetchTelemetryAndCases();
  };

  const handleClearSession = async () => {
    if (confirm('Clear all temporary investigations in this active session?')) {
      await clearSession();
      await fetchTelemetryAndCases();
      setActionMessage('Active session purged. Temporary cases cleared.');
      showToast('Active session purged. Temporary cases cleared.', 'info');
    }
  };

  const handleDownloadPdf = async (caseId: string) => {
    try {
      await downloadReport(caseId, authStatus?.mode === 'enterprise');
      showToast(`Report for case ${caseId} downloaded`, 'success');
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Report download failed.');
    }
  };

  const handleVerify = async (caseId: string) => {
    try {
      const res = await verifyCaseEvidence(caseId, authStatus?.mode === 'enterprise');
      setActionMessage(`Case ${caseId}: ${res.message} (SHA-256 Digest: ${res.recorded_hash.slice(0, 16)}...)`);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Verification failed.');
    }
  };

  const isEnterprise = authStatus?.mode === 'enterprise';

  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-10 md:py-14 space-y-8">
      {/* Top Header & Mode Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs text-[#00E5FF] mb-2 font-mono">
            <Activity className="w-3.5 h-3.5" />
            Security Console Telemetry
          </div>
          <h1 className="text-3xl font-bold text-[#F5F5F7] tracking-tight">
            System Operations & Threat Log
          </h1>
          <p className="mt-1 text-sm text-[#9A9AAE]">
            {isEnterprise
              ? `Enterprise Portal: ${authStatus?.user?.org_name} — Persistent Multi-Tenant Case Vault`
              : 'Anonymous User Console — Ephemeral in-memory session (No permanent case retention)'}
          </p>
        </div>

        {/* User Account Actions */}
        <div className="flex items-center gap-2 self-start sm:self-center">
          {isEnterprise ? (
            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-[#EF4444] bg-[#EF4444]/10 hover:bg-[#EF4444]/20 border border-[#EF4444]/30 rounded-xl transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Log Out ({authStatus?.user?.email})</span>
            </button>
          ) : (
            <>
              <button
                onClick={handleClearSession}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#9A9AAE] hover:text-[#EF4444] bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] rounded-xl transition-colors"
                title="Purge all cases in current active session"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear Session</span>
              </button>

              <button
                onClick={() => setShowLoginModal(true)}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-[#F5F5F7] bg-[#7B3FE4] hover:bg-[#8E54F7] rounded-xl transition-all shadow-md shadow-[#7B3FE4]/20"
              >
                <Lock className="w-3.5 h-3.5 text-[#00E5FF]" />
                <span>Enterprise Sign-in</span>
              </button>
            </>
          )}

          <button
            onClick={fetchTelemetryAndCases}
            disabled={isChecking}
            className="p-2.5 rounded-xl bg-[#0D0D12] hover:bg-[#13131A] border border-[#1C1C26] text-[#9A9AAE] hover:text-[#F5F5F7] transition-all disabled:opacity-50"
            title="Refresh Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin text-[#00E5FF]' : ''}`} />
          </button>
        </div>
      </div>

      {/* Mode Advisory Banner */}
      {!isEnterprise ? (
        <div className="p-4 rounded-xl bg-[#13131A] border border-[#1C1C26] flex items-start gap-3">
          <Info className="w-5 h-5 text-[#F59E0B] shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <p className="font-semibold text-[#F5F5F7]">
              Ephemeral Session Mode Active (Session: <code className="text-[#00E5FF] font-mono">{authStatus?.session_id || 'active'}</code>)
            </p>
            <p className="text-[#9A9AAE] leading-relaxed">
              Your investigations and uploaded files are temporary and exist solely in RAM during your active session.
              Temporary files and cases automatically expire upon inactivity. Enterprise users can authenticate for permanent multi-tenant archiving.
            </p>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-[#7B3FE4]/10 border border-[#7B3FE4]/30 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-[#00E5FF] shrink-0" />
            <div className="text-xs">
              <span className="font-semibold text-[#F5F5F7]">
                Authenticated as {authStatus?.user?.email} ({authStatus?.user?.role})
              </span>
              <span className="text-[#9A9AAE] block">
                Organization: <strong>{authStatus?.user?.org_name}</strong> (Tenant ID: {authStatus?.user?.org_id}) • Data isolation active
              </span>
            </div>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#13131A] text-[#00E5FF] border border-[#1C1C26]">
            Persistent DB
          </span>
        </div>
      )}

      {/* Action Notification Banner */}
      {actionMessage && (
        <div className="p-3.5 rounded-xl bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-xs text-[#F5F5F7] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#00E5FF]" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-[#9A9AAE] hover:text-[#F5F5F7]">
            ✕
          </button>
        </div>
      )}

      {/* Backend & AI Engine Health Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Backend API Status */}
        <motion.div initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.35, delay: 0.05 }} className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
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
        </motion.div>

        {/* Card 2: AI Engine Telemetry */}
        <motion.div initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.35, delay: 0.12 }} className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-semibold flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#7B3FE4]" />
              AI Threat Intelligence
            </span>
            {health?.ai_engine.available ? (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#10B981] px-2 py-0.5 rounded-full bg-[#10B981]/15 border border-[#10B981]/30">
                <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
                Full AI Mode
              </span>
            ) : health?.ai_engine.configured ? (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#F59E0B] px-2 py-0.5 rounded-full bg-[#F59E0B]/15 border border-[#F59E0B]/30">
                <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]" />
                Fallback (Key Set)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#9A9AAE] px-2 py-0.5 rounded-full bg-[#1C1C26]">
                Fallback (No Key)
              </span>
            )}
          </div>

          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-[#F5F5F7]">
                {health?.ai_engine.model || 'gemini-2.5-flash'}
              </h3>
              <span className="text-xs font-mono text-[#00E5FF]">
                {health?.ai_engine.provider || 'Google Gemini'}
              </span>
            </div>
            <p className="mt-1 text-xs text-[#9A9AAE]">
              {health?.ai_engine.available
                ? 'Primary AI active — Gemini contextual analysis + Python rules'
                : health?.ai_engine.configured
                ? `Operating in Python fallback: ${health?.ai_engine.last_failure_reason || 'API currently idle or rate limited'}`
                : 'Deterministic heuristics active (GEMINI_API_KEY not configured)'}
            </p>
          </div>

          <div className="pt-2 border-t border-[#1C1C26] text-[11px] text-[#626274] flex items-center justify-between">
            <span className="font-mono">
              Requests: <strong className="text-[#10B981]">{health?.ai_engine.success_count ?? 0} OK</strong> / <strong className="text-[#F59E0B]">{health?.ai_engine.failure_count ?? 0} Fail</strong>
            </span>
            <span className="text-[10px] text-[#9A9AAE]">
              {health?.ai_engine.last_success_at
                ? `Last OK: ${new Date(health.ai_engine.last_success_at).toLocaleTimeString()}`
                : 'No calls yet'}
            </span>
          </div>
        </motion.div>

        {/* Card 3: Storage & Forensics Engines */}
        <motion.div initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.35, delay: 0.19 }} className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-[#9A9AAE] font-semibold flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#10B981]" />
              Security Engines & Storage
            </span>
            <span className="text-xs font-mono text-[#10B981]">Dual-Mode</span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>.eml & .pdf Parser</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Screenshot Vision</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Ephemeral RAM TTL</span>
            </div>
            <div className="p-2 rounded-lg bg-[#13131A] text-[#9A9AAE] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Tenant SQLite DB</span>
            </div>
          </div>

          <div className="pt-2 border-t border-[#1C1C26] text-[11px] text-[#626274]">
            {isEnterprise ? 'Storage Mode: Persistent (Enterprise)' : 'Storage Mode: Ephemeral Session (RAM)'}
          </div>
        </motion.div>
      </div>

      {/* Search, Filter & Investigation History Vault */}
      <div className="p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-[#F5F5F7] flex items-center gap-2">
              <span>{isEnterprise ? 'Enterprise Investigation Vault' : 'Active Session Investigations'}</span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-[#1C1C26] text-[#9A9AAE]">
                <CountUpNumber value={totalCases} /> cases
              </span>
            </h3>
            <p className="text-xs text-[#9A9AAE] mt-0.5">
              {isEnterprise
                ? 'Permanent forensic records for your organization with cryptographic evidence verification.'
                : 'Current session records. Expired or purged when the session ends.'}
            </p>
          </div>

          {/* Quick Filter Selectors */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={channelFilter}
              onChange={(e) => setChannelFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-[#13131A] border border-[#1C1C26] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#7B3FE4]"
            >
              <option value="">All Channels</option>
              <option value="url">URL</option>
              <option value="sms">SMS</option>
              <option value="email">Email</option>
              <option value="file">File (.eml/.pdf)</option>
              <option value="screenshot">Screenshot</option>
            </select>

            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-[#13131A] border border-[#1C1C26] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#7B3FE4]"
            >
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="safe">Safe</option>
            </select>
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-3 text-[#626274]" />
            <input
              type="text"
              placeholder="Search by Case ID, keywords, or sender..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-xs text-[#F5F5F7] placeholder-[#626274]"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-xl bg-[#1C1C26] hover:bg-[#2A2A3A] text-xs font-medium text-[#F5F5F7] transition-colors"
          >
            Search
          </button>
        </form>

        {/* Investigation List */}
        {cases.length === 0 ? (
          <div className="p-12 text-center rounded-xl bg-[#13131A]/40 border border-[#1C1C26] space-y-3">
            <div className="inline-flex p-3 rounded-full bg-[#1C1C26] text-[#9A9AAE]">
              <FileText className="w-6 h-6" />
            </div>
            <p className="text-sm font-medium text-[#F5F5F7]">No investigation records found</p>
            <p className="text-xs text-[#626274] max-w-sm mx-auto">
              {isEnterprise
                ? 'Your organization has no cases matching the filter. Launch an analysis from the workbench.'
                : 'No cases recorded in this active session. Run an inspection to populate the ephemeral log.'}
            </p>
            <div className="pt-2">
              <Link
                href="/analyze"
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#7B3FE4] hover:bg-[#8E54F7] text-xs font-semibold text-white transition-colors"
              >
                <span>Launch Analysis Workbench</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {cases.map((c, cIdx) => (
              <motion.div
                key={c.case_id}
                initial={{ opacity: 0, y: 8 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.25, delay: Math.min(cIdx * 0.04, 0.4) }}
                className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl bg-[#13131A] border border-[#1C1C26] hover:border-[#7B3FE4]/50 hover:bg-[#161620] hover:shadow-[0_0_15px_rgba(123,63,228,0.12)] transition-all duration-150 gap-3"
              >
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-[#0D0D12] border border-[#1C1C26] flex items-center justify-center shrink-0">
                    {c.input_type === 'url' ? (
                      <Globe className="w-4 h-4 text-[#00E5FF]" />
                    ) : c.input_type === 'sms' ? (
                      <Smartphone className="w-4 h-4 text-[#7B3FE4]" />
                    ) : c.input_type === 'email' ? (
                      <Mail className="w-4 h-4 text-[#9A9AAE]" />
                    ) : c.input_type === 'screenshot' ? (
                      <ImageIcon className="w-4 h-4 text-[#00E5FF]" />
                    ) : (
                      <FileText className="w-4 h-4 text-[#F59E0B]" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/results/${c.case_id}`}
                        className="text-xs font-mono font-bold text-[#F5F5F7] hover:text-[#00E5FF] transition-colors"
                      >
                        {c.case_id}
                      </Link>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#1C1C26] text-[#9A9AAE]">
                        {c.input_type}
                      </span>
                      {c.file_name && (
                        <span className="text-[10px] font-mono text-[#626274] truncate max-w-[150px]">
                          {c.file_name}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-[#9A9AAE] line-clamp-1 mt-0.5 max-w-xl">
                      {c.explanation}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 self-end sm:self-center">
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

                  {/* Actions: PDF Report, Verify, Open */}
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => handleDownloadPdf(c.case_id)}
                      className="p-1.5 rounded-lg bg-[#0D0D12] hover:bg-[#1C1C26] border border-[#1C1C26] text-[#9A9AAE] hover:text-[#00E5FF] transition-colors"
                      title="Download PDF Report"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>

                    <button
                      onClick={() => handleVerify(c.case_id)}
                      className="p-1.5 rounded-lg bg-[#0D0D12] hover:bg-[#1C1C26] border border-[#1C1C26] text-[#9A9AAE] hover:text-[#10B981] transition-colors"
                      title="Verify SHA-256 Digest"
                    >
                      <FileCheck className="w-3.5 h-3.5" />
                    </button>

                    <Link
                      href={`/results/${c.case_id}`}
                      className="p-1.5 rounded-lg bg-[#0D0D12] hover:bg-[#1C1C26] border border-[#1C1C26] text-[#9A9AAE] hover:text-[#F5F5F7] transition-colors"
                      title="View Full Report"
                    >
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>

      {/* Enterprise Login Modal */}
      {showLoginModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-md p-6 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-[#00E5FF] font-semibold text-sm">
                <Lock className="w-4 h-4" />
                <span>Enterprise Portal Authentication</span>
              </div>
              <button
                onClick={() => setShowLoginModal(false)}
                className="text-[#9A9AAE] hover:text-white"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-[#9A9AAE]">
              Log in with your corporate security credentials to access persistent case archiving and organization-level data vaults.
            </p>

            {/* 1-Click Demo Accounts */}
            <div className="p-3 rounded-xl bg-[#13131A] border border-[#1C1C26] space-y-2">
              <span className="text-[11px] font-medium text-[#9A9AAE]">1-Click Demo Enterprise Accounts:</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setLoginEmail('secops@acme.com');
                    setLoginPassword('Password123!');
                  }}
                  className="px-2.5 py-1 text-[11px] rounded bg-[#1C1C26] hover:bg-[#7B3FE4] text-[#F5F5F7] transition-colors"
                >
                  Acme Corp (Lead)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setLoginEmail('analyst@cybershield.com');
                    setLoginPassword('Password123!');
                  }}
                  className="px-2.5 py-1 text-[11px] rounded bg-[#1C1C26] hover:bg-[#7B3FE4] text-[#F5F5F7] transition-colors"
                >
                  CyberShield (Analyst)
                </button>
              </div>
            </div>

            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#9A9AAE] mb-1">Corporate Email</label>
                <input
                  type="email"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-[#13131A] border border-[#1C1C26] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#7B3FE4]"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#9A9AAE] mb-1">Password</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-[#13131A] border border-[#1C1C26] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#7B3FE4]"
                  required
                />
              </div>

              {loginError && (
                <div className="p-2.5 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/30 text-xs text-[#EF4444]">
                  {loginError}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowLoginModal(false)}
                  className="px-4 py-2 rounded-xl bg-[#13131A] text-xs text-[#9A9AAE] hover:text-[#F5F5F7]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLoggingIn}
                  className="px-5 py-2 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-xs font-semibold text-white transition-colors disabled:opacity-50"
                >
                  {isLoggingIn ? 'Signing in...' : 'Sign In'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
