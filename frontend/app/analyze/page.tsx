'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
  Globe,
  MessageSquare,
  Smartphone,
  Mail,
  Send,
  Loader2,
  AlertCircle,
  Sparkles,
  Zap,
  UploadCloud,
  FileText,
  FileCode,
  Image as ImageIcon,
  X,
  Info,
  Shield,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { InputType, AnalysisResult, AuthStatus } from '@/types';
import { analyze, analyzeFile, getAuthStatus } from '@/lib/api';
import { AnalysisResultView } from '@/components/analysis/AnalysisResultView';

// Quick pre-filled test sample fixtures for instant 1-click verification
const SAMPLE_PRESETS: Record<
  string,
  Array<{
    label: string;
    description: string;
    content: string;
    sender?: string;
    subject?: string;
  }>
> = {
  url: [
    {
      label: 'SBI Typosquatting Phish',
      description: 'Newly registered deceptive .top domain targeting SBI net-banking',
      content: 'http://sbi-kyc-verification.top',
    },
    {
      label: 'Official Bank Portal (Safe)',
      description: 'Legitimate State Bank of India secure portal',
      content: 'https://www.onlinesbi.sbi',
    },
    {
      label: 'Target Custom Port URL',
      description: 'Suspicious URL running on non-standard port 8080',
      content: 'http://verify-portal.in:8080/login',
    },
  ],
  sms: [
    {
      label: 'SBI KYC Freeze Scam (Indian Threat)',
      description: 'Urgent account suspension threat with 10-digit mobile sender ID',
      sender: '+919876543210',
      content:
        'Dear Customer, Your SBI account will be blocked today due to pending KYC. Click http://sbi-kyc-update.top to update PAN urgently to avoid penalty.',
    },
    {
      label: 'Electricity Power Cut Fraud',
      description: 'Evening disconnection panic threat prompting call to personal number',
      sender: '+919988776655',
      content:
        'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our officer at 9876543210.',
    },
  ],
  email: [
    {
      label: 'Income Tax Refund Phishing',
      description: 'Lookalike sender pretending to disburse Rs 24,490 tax refund',
      sender: 'refunds@incometax-gov.online',
      subject: 'URGENT: Income Tax Refund Approved - Action Required',
      content:
        'Dear Taxpayer, An outstanding income tax refund of Rs 24,490 has been approved by the Income Tax Department. Please verify your bank account details at http://incometaxindia-refund.site to credit the amount within 24 hours.',
    },
    {
      label: 'Google Security Notice (Legitimate)',
      description: 'Authentic security sign-in notification from official domain',
      sender: 'no-reply@accounts.google.com',
      subject: 'Security alert for your linked Google Account',
      content:
        'Your Google Account was recently signed in to from a new Windows device. If this was you, you can safely ignore this alert. If not, secure your account.',
    },
  ],
  text: [
    {
      label: 'YouTube Likes Part-Time Job Scam',
      description: 'Telegram/WhatsApp task scam promising daily returns for hotel ratings',
      content:
        'Part time work from home opportunity! Earn Rs 3000 to 5000 daily by liking YouTube videos and rating hotels on Google Maps. No investment required. Contact HR manager immediately on WhatsApp.',
    },
    {
      label: 'Standard Bank Transaction (Safe)',
      description: 'Informational bank debit notification with no panic phrasing',
      content:
        'INR 2500.00 debited from A/C XX1234 at ATM MUMBAI on 31-OCT-26. Avail Bal: INR 45,210.00. If not done by you, SMS BLOCK to 567676.',
    },
  ],
};

type WorkspaceMode = 'text' | 'file';

export default function AnalyzePage() {
  const [activeTab, setActiveTab] = useState<InputType>('url');
  const [inputMode, setInputMode] = useState<WorkspaceMode>('text');
  const [fileTypeHint, setFileTypeHint] = useState<'eml' | 'pdf' | 'screenshot'>('eml');

  const [content, setContent] = useState('');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [userContext, setUserContext] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const typingRafRef = useRef<number | null>(null);

  useEffect(() => {
    getAuthStatus().then(setAuthStatus).catch(() => {});
  }, []);

  // Scan sequence timer in-flight (advances through stages, last stage waits for real response)
  useEffect(() => {
    if (!isLoading) {
      setScanStep(0);
      return;
    }

    const t1 = setTimeout(() => setScanStep(1), 450);
    const t2 = setTimeout(() => setScanStep(2), 1000);
    const t3 = setTimeout(() => setScanStep(3), 1600);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [isLoading]);

  // Clean up typing animation on unmount
  useEffect(() => {
    return () => {
      if (typingRafRef.current) cancelAnimationFrame(typingRafRef.current);
    };
  }, []);

  const handleTabChange = (tab: InputType) => {
    setActiveTab(tab);
    setErrorMessage(null);
    setSelectedFile(null);

    // Default submode based on tab
    if (tab === 'url') {
      setInputMode('text');
    }
  };

  // Deterministic typing-in animation (~400ms total, no random delays)
  const typeInPreset = (targetContent: string, targetSender?: string, targetSubject?: string) => {
    if (typingRafRef.current) cancelAnimationFrame(typingRafRef.current);
    setInputMode('text');
    setSelectedFile(null);
    setErrorMessage(null);

    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced) {
      setContent(targetContent);
      setSender(targetSender || '');
      setSubject(targetSubject || '');
      return;
    }

    const duration = 380;
    const startTime = performance.now();
    const len = targetContent.length;

    const step = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      const charCount = Math.floor(progress * len);
      setContent(targetContent.slice(0, charCount));

      if (progress < 1) {
        typingRafRef.current = requestAnimationFrame(step);
      } else {
        setContent(targetContent);
        if (targetSender) setSender(targetSender);
        if (targetSubject) setSubject(targetSubject);
      }
    };

    typingRafRef.current = requestAnimationFrame(step);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 10 * 1024 * 1024) {
        setErrorMessage('File size exceeds the 10MB limit.');
        return;
      }
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    // If file mode, validate file presence
    if (inputMode === 'file') {
      if (!selectedFile) {
        setErrorMessage('Please select a file (.eml, .pdf, or screenshot image) to upload.');
        return;
      }

      setIsLoading(true);
      try {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('channel', activeTab);
        if (userContext.trim()) formData.append('context', userContext.trim());
        if (sender.trim()) formData.append('sender', sender.trim());
        if (subject.trim()) formData.append('subject', subject.trim());

        const res = await analyzeFile(formData);
        // Instant response display as soon as response arrives
        setAnalysisResult(res);
      } catch (err: unknown) {
        setErrorMessage(err instanceof Error ? err.message : 'File analysis failed.');
      } finally {
        setIsLoading(false);
      }
      return;
    }

    // Text / URL mode
    if (!content.trim()) {
      setErrorMessage('Please provide a URL, text, SMS body or email payload to analyze.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await analyze({
        type: activeTab,
        content: content.trim(),
        sender: sender.trim() || undefined,
        subject: subject.trim() || undefined,
      });
      // Instant response display as soon as response arrives
      setAnalysisResult(res);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Analysis failed. Please check backend status.');
    } finally {
      setIsLoading(false);
    }
  };

  const resetForm = () => {
    setAnalysisResult(null);
    setSelectedFile(null);
    setErrorMessage(null);
  };

  return (
    <div className="w-full max-w-6xl mx-auto px-5 py-10 md:py-14">
      {/* Header with Staggered Entrance */}
      <div className="mb-8">
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.04, ease: 'easeOut' }}
          className="flex flex-wrap items-center justify-between gap-3 mb-3"
        >
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs text-[#00E5FF] font-mono">
            <Zap className="w-3.5 h-3.5" />
            <span>Dual-Mode Forensic Workbench</span>
          </div>

          {/* Privacy & Retention Badge */}
          {authStatus?.mode === 'enterprise' ? (
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#7B3FE4]/15 border border-[#7B3FE4]/30 text-xs text-[#F5F5F7]">
              <Shield className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>Enterprise Mode: <strong>{authStatus.user?.org_name}</strong> (Persistent)</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#13131A] border border-[#1C1C26] text-xs text-[#9A9AAE]">
              <Info className="w-3.5 h-3.5 text-[#F59E0B]" />
              <span>Ephemeral Session Mode (Temporary — No permanent file storage)</span>
            </div>
          )}
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.1, ease: 'easeOut' }}
          className="text-3xl md:text-4xl font-bold text-[#F5F5F7] tracking-tight"
        >
          Inspect Suspicious Target
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.16, ease: 'easeOut' }}
          className="mt-2 text-sm text-[#9A9AAE] max-w-2xl leading-relaxed"
        >
          Submit phishing links, fraudulent SMS messages, deceptive emails, uploaded .eml files, PDF notices, or mobile chat screenshots.
          AEGIS correlates deterministic forensic checks with Gemini AI threat intelligence.
        </motion.p>
      </div>

      {/* Main Content Area */}
      {analysisResult ? (
        <AnalysisResultView result={analysisResult} onReset={resetForm} />
      ) : (
        <div className="space-y-6">
          {/* Channel Tabs with Sliding layoutId Active Indicator */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35, delay: 0.22, ease: 'easeOut' }}
            className="flex flex-wrap items-center gap-2 p-1.5 rounded-xl bg-[#0D0D12] border border-[#1C1C26]"
          >
            {[
              { id: 'url', label: 'URL / Domain', icon: Globe },
              { id: 'text', label: 'Free Text / Chat', icon: MessageSquare },
              { id: 'sms', label: 'SMS / Smishing', icon: Smartphone },
              { id: 'email', label: 'Email Phishing', icon: Mail },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => handleTabChange(tab.id as InputType)}
                  disabled={isLoading}
                  className="relative flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs md:text-sm font-medium transition-colors select-none disabled:opacity-50"
                >
                  {isActive && (
                    <motion.span
                      layoutId="activeChannelTabPill"
                      className="absolute inset-0 rounded-lg bg-[#1C1C26] shadow-sm border border-[#7B3FE4]/50"
                      transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                    />
                  )}
                  <span className="relative z-10 flex items-center gap-2">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-[#00E5FF]' : 'text-[#9A9AAE]'}`} />
                    <span className={isActive ? 'text-[#00E5FF] font-semibold' : 'text-[#9A9AAE] hover:text-[#F5F5F7]'}>
                      {tab.label}
                    </span>
                  </span>
                </button>
              );
            })}
          </motion.div>

          {/* Sub-mode selector (Type vs File/Screenshot Upload) */}
          {activeTab !== 'url' && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: 0.28, ease: 'easeOut' }}
              className="flex items-center gap-2 text-xs"
            >
              <span className="text-[#9A9AAE] mr-1 font-medium">Input Method:</span>
              <button
                type="button"
                onClick={() => {
                  setInputMode('text');
                  setSelectedFile(null);
                }}
                className={`px-3 py-1.5 rounded-lg border transition-all duration-150 ${
                  inputMode === 'text'
                    ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold shadow-[0_0_10px_rgba(123,63,228,0.25)]'
                    : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7] hover:bg-[#13131A]'
                }`}
              >
                {activeTab === 'email' ? 'Type / Paste Email' : 'Type / Paste Message'}
              </button>

              {activeTab === 'email' && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      setInputMode('file');
                      setFileTypeHint('eml');
                    }}
                    className={`px-3 py-1.5 rounded-lg border transition-all duration-150 flex items-center gap-1.5 ${
                      inputMode === 'file' && fileTypeHint === 'eml'
                        ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold shadow-[0_0_10px_rgba(123,63,228,0.25)]'
                        : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7] hover:bg-[#13131A]'
                    }`}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Upload .eml File</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setInputMode('file');
                      setFileTypeHint('pdf');
                    }}
                    className={`px-3 py-1.5 rounded-lg border transition-all duration-150 flex items-center gap-1.5 ${
                      inputMode === 'file' && fileTypeHint === 'pdf'
                        ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold shadow-[0_0_10px_rgba(123,63,228,0.25)]'
                        : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7] hover:bg-[#13131A]'
                    }`}
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Upload .pdf Notice</span>
                  </button>
                </>
              )}

              {(activeTab === 'sms' || activeTab === 'text') && (
                <button
                  type="button"
                  onClick={() => {
                    setInputMode('file');
                    setFileTypeHint('screenshot');
                  }}
                  className={`px-3 py-1.5 rounded-lg border transition-all duration-150 flex items-center gap-1.5 ${
                    inputMode === 'file'
                      ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold shadow-[0_0_10px_rgba(123,63,228,0.25)]'
                      : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7] hover:bg-[#13131A]'
                  }`}
                >
                  <ImageIcon className="w-3.5 h-3.5" />
                  <span>Upload Screenshot</span>
                </button>
              )}
            </motion.div>
          )}

          {/* Quick Preset Samples Banner with Hover Lift & Tap Ripple */}
          {inputMode === 'text' && SAMPLE_PRESETS[activeTab]?.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: 0.34, ease: 'easeOut' }}
              className="p-4 rounded-xl bg-[#0D0D12] border border-[#1C1C26]"
            >
              <div className="flex items-center gap-1.5 text-xs text-[#9A9AAE] mb-2.5 font-medium">
                <Sparkles className="w-3.5 h-3.5 text-[#7B3FE4]" />
                <span>Quick Test Presets (Click to Auto-Populate):</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_PRESETS[activeTab].map((preset, idx) => (
                  <motion.button
                    key={idx}
                    type="button"
                    disabled={isLoading}
                    onClick={() => typeInPreset(preset.content, preset.sender, preset.subject)}
                    whileHover={{ y: -2, boxShadow: '0 0 15px rgba(0,229,255,0.2)' }}
                    whileTap={{ scale: 0.97 }}
                    transition={{ duration: 0.15 }}
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] hover:border-[#7B3FE4]/50 text-xs text-[#F5F5F7] transition-all disabled:opacity-50 text-left"
                    title={preset.description}
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF]" />
                    <span className="font-medium">{preset.label}</span>
                  </motion.button>
                ))}
              </div>
            </motion.div>
          )}

          {/* In-Flight Multi-Step Forensic Sequence Panel (Active during request) */}
          <AnimatePresence>
            {isLoading && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.25 }}
                className="p-5 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-4"
                aria-live="polite"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase tracking-wider text-[#9A9AAE] flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#00E5FF] animate-spin" />
                    Forensic Inspection Sequence In Progress
                  </span>
                  <span className="text-xs font-mono text-[#00E5FF] font-semibold">
                    Step {scanStep + 1} of 4
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                  {[
                    { id: 0, label: 'Normalising Payload', desc: 'Character encodings & tokens' },
                    { id: 1, label: 'Detecting Threats', desc: 'Social engineering & NLP markers' },
                    { id: 2, label: 'Inspecting Links', desc: 'Domain hops & registrar age' },
                    { id: 3, label: 'Synthesising Score', desc: 'Composite risk & verifiability' },
                  ].map((st) => {
                    const isDone = scanStep > st.id;
                    const isCurrent = scanStep === st.id;
                    return (
                      <div
                        key={st.id}
                        className={`p-3 rounded-xl border transition-all duration-300 ${
                          isDone
                            ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#10B981]'
                            : isCurrent
                            ? 'bg-[#00E5FF]/10 border-[#00E5FF]/40 text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                            : 'bg-[#13131A] border-[#1C1C26] text-[#626274]'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 font-semibold">
                          {isDone ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-[#10B981]" />
                          ) : isCurrent ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-[#00E5FF]" />
                          ) : (
                            <span className="w-1.5 h-1.5 rounded-full bg-[#626274]" />
                          )}
                          <span>{st.label}</span>
                        </div>
                        <p className="text-[10px] mt-1 text-[#9A9AAE]">{st.desc}</p>
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Submission Form with Cross-Fade + 8px Rise on Tab Change */}
          <motion.form
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.4, ease: 'easeOut' }}
            onSubmit={handleSubmit}
            className="p-6 md:p-8 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-6 shadow-xl"
          >
            <AnimatePresence mode="wait">
              <motion.div
                key={`${activeTab}-${inputMode}`}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
                className="space-y-6"
              >
                {/* Contextual Fields for Email */}
                {activeTab === 'email' && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-[#9A9AAE] mb-1.5 uppercase tracking-wider">
                        Sender Email Address (Optional if inside .eml)
                      </label>
                      <input
                        type="text"
                        disabled={isLoading}
                        placeholder="e.g. refunds@incometax-gov.online"
                        value={sender}
                        onChange={(e) => setSender(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-all duration-200 disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-[#9A9AAE] mb-1.5 uppercase tracking-wider">
                        Email Subject Line (Optional if inside .eml)
                      </label>
                      <input
                        type="text"
                        disabled={isLoading}
                        placeholder="e.g. URGENT: Income Tax Refund Approved"
                        value={subject}
                        onChange={(e) => setSubject(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] transition-all duration-200 disabled:opacity-50"
                      />
                    </div>
                  </div>
                )}

                {/* Contextual Field for SMS */}
                {activeTab === 'sms' && inputMode === 'text' && (
                  <div className="max-w-sm">
                    <label className="block text-xs font-medium text-[#9A9AAE] mb-1.5 uppercase tracking-wider">
                      Sender Header / Mobile Number
                    </label>
                    <input
                      type="text"
                      disabled={isLoading}
                      placeholder="e.g. +919876543210 or VK-SBIINB"
                      value={sender}
                      onChange={(e) => setSender(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-all duration-200 disabled:opacity-50"
                    />
                  </div>
                )}

                {/* FILE UPLOAD MODE */}
                {inputMode === 'file' ? (
                  <div className="space-y-4">
                    <label className="block text-xs font-medium text-[#9A9AAE] uppercase tracking-wider">
                      {fileTypeHint === 'eml'
                        ? 'Upload RFC-822 Email File (.eml)'
                        : fileTypeHint === 'pdf'
                        ? 'Upload Document / Tax Notice (.pdf)'
                        : 'Upload Screenshot (PNG, JPG, WEBP)'}
                    </label>

                    {/* File Dropzone */}
                    <div
                      onClick={() => fileInputRef.current?.click()}
                      className="border-2 border-dashed border-[#1C1C26] hover:border-[#7B3FE4]/60 bg-[#13131A]/60 hover:bg-[#13131A] rounded-2xl p-8 text-center cursor-pointer transition-all duration-200"
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        accept={
                          fileTypeHint === 'eml'
                            ? '.eml,message/rfc822'
                            : fileTypeHint === 'pdf'
                            ? '.pdf,application/pdf'
                            : 'image/png,image/jpeg,image/webp'
                        }
                        onChange={handleFileChange}
                      />

                      {selectedFile ? (
                        <div className="flex items-center justify-center gap-3">
                          <div className="p-3 rounded-xl bg-[#0D0D12] text-[#00E5FF] border border-[#1C1C26]">
                            {fileTypeHint === 'screenshot' ? (
                              <ImageIcon className="w-6 h-6" />
                            ) : (
                              <FileText className="w-6 h-6 text-[#7B3FE4]" />
                            )}
                          </div>
                          <div className="text-left">
                            <p className="text-sm font-semibold text-[#F5F5F7]">{selectedFile.name}</p>
                            <p className="text-xs text-[#9A9AAE]">
                              {(selectedFile.size / 1024).toFixed(1)} KB • Ready for deep inspection
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFile(null);
                            }}
                            className="ml-4 p-1.5 rounded-lg text-[#9A9AAE] hover:text-[#EF4444] hover:bg-[#1C1C26]"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          <div className="inline-flex p-3 rounded-2xl bg-[#0D0D12] text-[#00E5FF] border border-[#1C1C26] mb-1">
                            <UploadCloud className="w-6 h-6 text-[#7B3FE4]" />
                          </div>
                          <p className="text-sm font-medium text-[#F5F5F7]">
                            Click to select or drag and drop your file here
                          </p>
                          <p className="text-xs text-[#626274]">
                            Max 10MB. Files are sanitized in-memory and never executed.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Additional Context Note */}
                    <div>
                      <label className="block text-xs font-medium text-[#9A9AAE] mb-1.5 uppercase tracking-wider">
                        Additional Context or Suspicious Details (Optional)
                      </label>
                      <input
                        type="text"
                        disabled={isLoading}
                        placeholder="e.g. Received this message from someone claiming to be SBI net-banking support"
                        value={userContext}
                        onChange={(e) => setUserContext(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-xs text-[#F5F5F7] placeholder-[#626274] transition-all duration-200 disabled:opacity-50"
                      />
                    </div>
                  </div>
                ) : (
                  /* TEXT / URL INPUT MODE */
                  <div>
                    <label className="block text-xs font-medium text-[#9A9AAE] mb-1.5 uppercase tracking-wider">
                      {activeTab === 'url'
                        ? 'Target URL or Domain to Inspect'
                        : activeTab === 'email'
                        ? 'Email Body Text or Raw Headers'
                        : activeTab === 'sms'
                        ? 'SMS Message Body'
                        : 'Message Content or Chat Transcript'}
                    </label>

                    {activeTab === 'url' ? (
                      <input
                        type="text"
                        disabled={isLoading}
                        placeholder="https://example.com or http://sbi-kyc-update.top"
                        value={content}
                        onChange={(e) => setContent(e.target.value)}
                        className="w-full px-4 py-3 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-all duration-200 disabled:opacity-50"
                      />
                    ) : (
                      <textarea
                        rows={6}
                        disabled={isLoading}
                        placeholder={
                          activeTab === 'email'
                            ? 'Paste the full email body, recipient details, or raw headers here...'
                            : activeTab === 'sms'
                            ? 'Paste the received SMS text here...'
                            : 'Paste the suspicious WhatsApp, Telegram, or social message here...'
                        }
                        value={content}
                        onChange={(e) => setContent(e.target.value)}
                        className="w-full px-4 py-3 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#00E5FF] focus:shadow-[0_0_15px_rgba(0,229,255,0.3)] focus:ring-1 focus:ring-[#7B3FE4]/50 focus:outline-none text-sm text-[#F5F5F7] placeholder-[#626274] leading-relaxed transition-all duration-200 disabled:opacity-50 resize-y"
                      />
                    )}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>

            {/* Error Banner */}
            {errorMessage && (
              <div className="p-4 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/30 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-[#EF4444] shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-[#EF4444]">Analysis Request Failed</p>
                  <p className="text-[#9A9AAE] leading-relaxed">{errorMessage}</p>
                </div>
              </div>
            )}

            {/* Submit Action & Indicator with Shimmer Sweep */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <span className="text-xs text-[#626274]">
                Inputs are sanitized and never executed. Multi-layer defense applies deterministic port 80/443 & SSRF guards.
              </span>

              <motion.button
                type="submit"
                disabled={isLoading || (inputMode === 'file' ? !selectedFile : !content.trim())}
                whileHover={!isLoading ? { y: -1, boxShadow: '0 0 20px rgba(123,63,228,0.4)' } : undefined}
                whileTap={!isLoading ? { scale: 0.97 } : undefined}
                className="relative overflow-hidden w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-[#F5F5F7] font-semibold text-xs md:text-sm shadow-lg shadow-[#7B3FE4]/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {isLoading && (
                  <div className="absolute inset-0 -translate-x-full animate-[shimmer_1.5s_infinite] bg-gradient-to-r from-transparent via-white/20 to-transparent pointer-events-none" />
                )}
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-[#00E5FF]" />
                    <span>Analyzing Target...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Run Security Analysis</span>
                  </>
                )}
              </motion.button>
            </div>
          </motion.form>
        </div>
      )}
    </div>
  );
}
