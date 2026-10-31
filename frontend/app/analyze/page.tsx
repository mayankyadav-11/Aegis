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
} from 'lucide-react';
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
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getAuthStatus().then(setAuthStatus).catch(() => {});
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

  const applyPreset = (preset: { content: string; sender?: string; subject?: string }) => {
    setInputMode('text');
    setSelectedFile(null);
    setContent(preset.content);
    setSender(preset.sender || '');
    setSubject(preset.subject || '');
    setErrorMessage(null);
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
      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
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
        </div>

        <h1 className="text-3xl md:text-4xl font-bold text-[#F5F5F7] tracking-tight">
          Inspect Suspicious Target
        </h1>
        <p className="mt-2 text-sm text-[#9A9AAE] max-w-2xl leading-relaxed">
          Submit phishing links, fraudulent SMS messages, deceptive emails, uploaded .eml files, PDF notices, or mobile chat screenshots.
          AEGIS correlates deterministic forensic checks with Gemini AI threat intelligence.
        </p>
      </div>

      {/* Main Content Area */}
      {analysisResult ? (
        <AnalysisResultView result={analysisResult} onReset={resetForm} />
      ) : (
        <div className="space-y-6">
          {/* Channel Tabs */}
          <div className="flex flex-wrap items-center gap-2 p-1.5 rounded-xl bg-[#0D0D12] border border-[#1C1C26]">
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
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs md:text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-[#1C1C26] text-[#00E5FF] shadow-sm font-semibold'
                      : 'text-[#9A9AAE] hover:text-[#F5F5F7] hover:bg-[#13131A]'
                  } disabled:opacity-50`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#00E5FF]' : 'text-[#9A9AAE]'}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Sub-mode selector (Type vs File/Screenshot Upload) */}
          {activeTab !== 'url' && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-[#9A9AAE] mr-1 font-medium">Input Method:</span>
              <button
                type="button"
                onClick={() => {
                  setInputMode('text');
                  setSelectedFile(null);
                }}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  inputMode === 'text'
                    ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold'
                    : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7]'
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
                    className={`px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5 ${
                      inputMode === 'file' && fileTypeHint === 'eml'
                        ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold'
                        : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7]'
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
                    className={`px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5 ${
                      inputMode === 'file' && fileTypeHint === 'pdf'
                        ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold'
                        : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7]'
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
                  className={`px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5 ${
                    inputMode === 'file'
                      ? 'bg-[#1C1C26] text-[#00E5FF] border-[#7B3FE4]/50 font-semibold'
                      : 'bg-[#0D0D12] text-[#9A9AAE] border-[#1C1C26] hover:text-[#F5F5F7]'
                  }`}
                >
                  <ImageIcon className="w-3.5 h-3.5" />
                  <span>Upload Screenshot</span>
                </button>
              )}
            </div>
          )}

          {/* Quick Preset Samples Banner (when in text mode) */}
          {inputMode === 'text' && SAMPLE_PRESETS[activeTab]?.length > 0 && (
            <div className="p-4 rounded-xl bg-[#0D0D12] border border-[#1C1C26]">
              <div className="flex items-center gap-1.5 text-xs text-[#9A9AAE] mb-2.5 font-medium">
                <Sparkles className="w-3.5 h-3.5 text-[#7B3FE4]" />
                <span>Quick Test Presets (1-Click Sample Testing):</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_PRESETS[activeTab].map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    disabled={isLoading}
                    onClick={() => applyPreset(preset)}
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#13131A] hover:bg-[#1A1A24] border border-[#1C1C26] hover:border-[#7B3FE4]/50 text-xs text-[#F5F5F7] transition-all disabled:opacity-50 text-left"
                    title={preset.description}
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF]" />
                    <span className="font-medium">{preset.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Submission Form */}
          <form
            onSubmit={handleSubmit}
            className="p-6 md:p-8 rounded-2xl bg-[#0D0D12] border border-[#1C1C26] space-y-6 shadow-xl"
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
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-colors disabled:opacity-50"
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
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] transition-colors disabled:opacity-50"
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
                  className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-xs md:text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-colors disabled:opacity-50"
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
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-xs text-[#F5F5F7] placeholder-[#626274] transition-colors disabled:opacity-50"
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
                    className="w-full px-4 py-3 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-sm text-[#F5F5F7] placeholder-[#626274] font-mono transition-colors disabled:opacity-50"
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
                    className="w-full px-4 py-3 rounded-xl bg-[#13131A] border border-[#1C1C26] focus:border-[#7B3FE4] focus:outline-none text-sm text-[#F5F5F7] placeholder-[#626274] leading-relaxed transition-colors disabled:opacity-50 resize-y"
                  />
                )}
              </div>
            )}

            {/* Error Banner */}
            {errorMessage && (
              <div className="p-4 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/30 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-[#EF4444] shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-[#EF4444]">Analysis Request Failed</p>
                  <p className="text-[#9A9AAE] leading-relaxed">{errorMessage}</p>
                  {errorMessage.includes('unreachable') && (
                    <p className="text-[11px] text-[#626274] pt-1">
                      Tip: Run the backend server locally using{' '}
                      <code className="text-[#00E5FF] bg-[#13131A] px-1 py-0.5 rounded">
                        uvicorn main:app --port 8000
                      </code>{' '}
                      in the <code className="text-[#F5F5F7]">backend/</code> folder.
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Submit Action & Indicator */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <span className="text-xs text-[#626274]">
                Inputs are sanitized and never executed. Multi-layer defense applies deterministic port 80/443 & SSRF guards.
              </span>

              <button
                type="submit"
                disabled={isLoading || (inputMode === 'file' ? !selectedFile : !content.trim())}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3 rounded-xl bg-[#7B3FE4] hover:bg-[#8E54F7] text-[#F5F5F7] font-semibold text-xs md:text-sm shadow-lg shadow-[#7B3FE4]/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed hover:-translate-y-0.5 active:translate-y-0"
              >
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
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
