'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import Link from 'next/link';
import { TransitionLink } from '@/components/transition/TransitionProvider';
import { motion, useMotionValue, animate, useReducedMotion } from 'framer-motion';
import { Reveal } from '@/components/Reveal';

interface HighlightPhrase {
  phrase: string;
  label: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface Finding {
  title: string;
  detail: string;
}

interface SampleData {
  id: string;
  title: string;
  category: string;
  sender: string;
  time: string;
  text: string;
  score: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  icon: string;
  highlights: HighlightPhrase[];
  findings: Finding[];
  actions: string[];
  caveats: string[];
}

const SAMPLES: SampleData[] = [
  {
    id: 'bank-kyc',
    title: 'Bank KYC SMS',
    category: 'Urgent Impersonation',
    sender: 'AX-ALERTS',
    time: '10:42 AM',
    text: 'Your SBI account will be blocked today. Complete KYC immediately at sbi-update-example.com.',
    score: 91,
    severity: 'Critical',
    icon: '🏦',
    highlights: [
      { phrase: 'will be blocked today', label: 'Artificial Urgency', severity: 'critical' },
      { phrase: 'Complete KYC immediately', label: 'Credential Harvest', severity: 'critical' },
      { phrase: 'sbi-update-example.com', label: 'Lookalike Domain', severity: 'high' },
    ],
    findings: [
      {
        title: 'Deceptive Lookalike Domain',
        detail: "Domain 'sbi-update-example.com' was registered 3 days ago and impersonates a state banking portal.",
      },
      {
        title: 'High-Pressure Coercion',
        detail: 'Imposes immediate account blocking threat to manipulate user into bypassing standard verification.',
      },
      {
        title: 'Unauthorized KYC Harvester',
        detail: 'Standard banks never collect confidential net-banking KYC credentials over unsolicited SMS links.',
      },
    ],
    actions: [
      'Do not click the link or input banking credentials.',
      'Forward this SMS to 1930 (National Cyber Crime Helpline).',
      'Verify your account status via official mobile banking app only.',
    ],
    caveats: ['Sender identity: not verifiable from pasted text'],
  },
  {
    id: 'hinglish-kyc',
    title: 'Hinglish Scam',
    category: 'Regional Coercion',
    sender: '+91 9XXXXXXXXX',
    time: '12:15 PM',
    text: 'Aapka KYC expire ho gaya hai. Abhi update karein warna account band ho jayega: bit.ly/xxxx',
    score: 84,
    severity: 'High',
    icon: '💬',
    highlights: [
      { phrase: 'KYC expire ho gaya hai', label: 'False Expiry Claim', severity: 'high' },
      { phrase: 'warna account band ho jayega', label: 'Fear / Coercion', severity: 'high' },
      { phrase: 'bit.ly/xxxx', label: 'Obfuscated Shortlink', severity: 'critical' },
    ],
    findings: [
      {
        title: 'URL Shortener Masking',
        detail: 'Generic bit.ly redirect hides untrusted destination IP registered in unverified jurisdiction.',
      },
      {
        title: 'Social Engineering Bait',
        detail: 'Bilingual Hinglish panic framing targets regional banking panic without authentic reference numbers.',
      },
    ],
    actions: [
      'Do not open the shortened bit.ly link.',
      'Report the sender number as spam and block immediately.',
      'Check your official bank branch or net banking portal directly.',
    ],
    caveats: ['Sender identity: not verifiable from pasted text'],
  },
  {
    id: 'job-offer',
    title: 'Fake Job Offer',
    category: 'Advance-Fee Fraud',
    sender: 'GLOBAL-HR',
    time: '02:30 PM',
    text: 'Congratulations! You are selected. Pay Rs 1,500 registration fee to confirm your job.',
    score: 78,
    severity: 'High',
    icon: '💼',
    highlights: [
      { phrase: 'Congratulations! You are selected', label: 'Unsolicited Selection', severity: 'high' },
      { phrase: 'Pay Rs 1,500 registration fee', label: 'Advance-Fee Fraud', severity: 'critical' },
    ],
    findings: [
      {
        title: 'Advance Fee Employment Fraud',
        detail: 'Legitimate recruiters and employers never charge registration fees or onboarding deposits.',
      },
      {
        title: 'Zero Application Context',
        detail: 'Purports direct selection without prior applications, interviews, or verifiable corporate identity.',
      },
    ],
    actions: [
      'Refuse any upfront payment or fee transfer requests.',
      'Verify company vacancy through their official careers page.',
      'Report the fraudulent recruitment listing to cybercrime.gov.in.',
    ],
    caveats: ['Sender identity: not verifiable from pasted text'],
  },
  {
    id: 'legitimate-order',
    title: 'Legitimate Notice',
    category: 'Verified Dispatch',
    sender: 'SHIP-UPDATE',
    time: '04:10 PM',
    text: 'Your order #48213 has shipped and will arrive Tuesday. Track it in the app.',
    score: 8,
    severity: 'Low',
    icon: '📦',
    highlights: [],
    findings: [
      {
        title: 'No Coercion or Urgency Detected',
        detail: 'Message contains factual tracking notice without threatening ultimatums or countdowns.',
      },
      {
        title: 'No Credential or Payment Requests',
        detail: 'Does not ask for OTP, passwords, UPI pin, or advance financial transfers.',
      },
      {
        title: 'Zero Unverified External Links',
        detail: 'No deceptive or shortened links included; directs user to authenticated application.',
      },
    ],
    actions: [
      'Safe to read; proceed to open official store app to track package.',
      'Always verify order status directly in your registered account.',
    ],
    caveats: [
      'Sender identity: not verifiable from pasted text',
      'A low score is not a guarantee.',
    ],
  },
];

const SCAN_STEPS = [
  'Normalising',
  'Detecting',
  'Inspecting links',
  'Scoring',
] as const;

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return {
        text: 'text-[#EF4444]',
        bg: 'bg-[#EF4444]/15',
        border: 'border-[#EF4444]/60',
        stroke: '#EF4444',
        badgeBg: 'bg-[#EF4444]',
        chipBg: 'bg-[#EF4444]/20 border-[#EF4444]/50 text-[#EF4444]',
      };
    case 'high':
      return {
        text: 'text-[#F97316]',
        bg: 'bg-[#F97316]/15',
        border: 'border-[#F97316]/60',
        stroke: '#F97316',
        badgeBg: 'bg-[#F97316]',
        chipBg: 'bg-[#F97316]/20 border-[#F97316]/50 text-[#F97316]',
      };
    case 'medium':
      return {
        text: 'text-[#F59E0B]',
        bg: 'bg-[#F59E0B]/15',
        border: 'border-[#F59E0B]/60',
        stroke: '#F59E0B',
        badgeBg: 'bg-[#F59E0B]',
        chipBg: 'bg-[#F59E0B]/20 border-[#F59E0B]/50 text-[#F59E0B]',
      };
    default:
      return {
        text: 'text-[#10B981]',
        bg: 'bg-[#10B981]/15',
        border: 'border-[#10B981]/60',
        stroke: '#10B981',
        badgeBg: 'bg-[#10B981]',
        chipBg: 'bg-[#10B981]/20 border-[#10B981]/50 text-[#10B981]',
      };
  }
}

function getVerdictIcon(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return (
        <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      );
    case 'high':
      return (
        <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
    case 'medium':
      return (
        <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
    default:
      return (
        <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
  }
}

export function TryScannerScene() {
  const [selectedId, setSelectedId] = useState<string>('bank-kyc');
  const [scanStatus, setScanStatus] = useState<'idle' | 'scanning' | 'complete'>('idle');
  const [activeStep, setActiveStep] = useState<number>(0);

  const sectionRef = useRef<HTMLElement>(null);
  const scoreTextRef = useRef<HTMLSpanElement>(null);
  const circleRef = useRef<SVGCircleElement>(null);
  const timersRef = useRef<NodeJS.Timeout[]>([]);

  const shouldReduceMotion = useReducedMotion();
  const sample = SAMPLES.find((s) => s.id === selectedId) || SAMPLES[0];
  const colors = getSeverityColor(sample.severity);

  // Framer-motion values for the radial gauge (no per-frame setState)
  const scoreMotion = useMotionValue(0);
  const circleOffsetMotion = useMotionValue(276.46); // 2 * PI * 44 = 276.46

  const clearAllTimers = useCallback(() => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
  }, []);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      clearAllTimers();
    };
  }, [clearAllTimers]);

  // Reset to idle state when a different sample is picked (NO auto-start)
  const handleSelectSample = (newSample: SampleData) => {
    clearAllTimers();
    setSelectedId(newSample.id);
    setScanStatus('idle');
    setActiveStep(0);
    scoreMotion.set(0);
    circleOffsetMotion.set(276.46);
    if (scoreTextRef.current) scoreTextRef.current.textContent = '--';
    if (circleRef.current) circleRef.current.style.strokeDashoffset = '276.46';
  };

  // Manual start / analyse again trigger
  const handleStartAnalysis = () => {
    clearAllTimers();

    if (shouldReduceMotion) {
      setScanStatus('complete');
      setActiveStep(4);
      if (scoreTextRef.current) scoreTextRef.current.textContent = `${sample.score}`;
      if (circleRef.current) {
        circleRef.current.style.strokeDashoffset = `${276.46 * (1 - sample.score / 100)}`;
      }
      return;
    }

    setScanStatus('scanning');
    setActiveStep(0);

    // Reset gauge visual immediately
    scoreMotion.set(0);
    circleOffsetMotion.set(276.46);
    if (scoreTextRef.current) scoreTextRef.current.textContent = '0';
    if (circleRef.current) circleRef.current.style.strokeDashoffset = '276.46';

    const t1 = setTimeout(() => setActiveStep(1), 350);
    const t2 = setTimeout(() => setActiveStep(2), 700);
    const t3 = setTimeout(() => setActiveStep(3), 1050);
    const t4 = setTimeout(() => {
      setActiveStep(4);
      setScanStatus('complete');

      // Animate gauge count-up smoothly via motion values (no per-frame setState)
      animate(scoreMotion, sample.score, {
        duration: 1.0,
        ease: 'easeOut',
        onUpdate: (latest) => {
          if (scoreTextRef.current) {
            scoreTextRef.current.textContent = Math.round(latest).toString();
          }
        },
      });

      const targetOffset = 276.46 * (1 - sample.score / 100);
      animate(circleOffsetMotion, targetOffset, {
        duration: 1.0,
        ease: 'easeOut',
        onUpdate: (latest) => {
          if (circleRef.current) {
            circleRef.current.style.strokeDashoffset = `${latest}`;
          }
        },
      });
    }, 1400);

    timersRef.current = [t1, t2, t3, t4];
  };

  // Render message body with highlighted phrases only when scan is complete
  const renderMessageBody = () => {
    if (scanStatus !== 'complete' || sample.highlights.length === 0) {
      return (
        <p className="font-heading font-medium text-[clamp(18px,1.2vw,20px)] leading-[1.6] text-[#E6E6EA]">
          {sample.text}
        </p>
      );
    }

    let remaining = sample.text;
    const elements: React.ReactNode[] = [];
    let keyIdx = 0;

    sample.highlights.forEach((hl) => {
      const idx = remaining.indexOf(hl.phrase);
      if (idx !== -1) {
        if (idx > 0) {
          elements.push(
            <span key={`plain-${keyIdx++}`} className="text-[#E6E6EA]">
              {remaining.slice(0, idx)}
            </span>
          );
        }

        const hlColors = getSeverityColor(hl.severity);
        elements.push(
          <span
            key={`hl-${keyIdx++}`}
            className="inline-block my-1 px-1.5 py-0.5 rounded-lg bg-[#1C1C26] border border-white/10"
          >
            <span className="font-heading font-semibold text-[#F5F5F7]">
              {hl.phrase}
            </span>
            <span
              className={`ml-1.5 inline-flex items-center px-2 py-0.5 rounded-full font-mono text-[13px] font-bold tracking-tight uppercase ${hlColors.chipBg}`}
            >
              {hl.label}
            </span>
          </span>
        );

        remaining = remaining.slice(idx + hl.phrase.length);
      }
    });

    if (remaining.length > 0) {
      elements.push(
        <span key={`plain-${keyIdx++}`} className="text-[#E6E6EA]">
          {remaining}
        </span>
      );
    }

    return (
      <div className="font-heading font-medium text-[clamp(18px,1.2vw,20px)] leading-[1.7]">
        {elements}
      </div>
    );
  };

  return (
    <section
      id="try"
      ref={sectionRef}
      className="relative w-full bg-transparent px-6 py-20 sm:py-28 scroll-mt-[var(--landing-header-h)]"
    >
      <div className="max-w-6xl mx-auto">
        {/* Section Header (03 / Try it yourself) */}
        <Reveal>
          <div className="text-center mb-12 sm:mb-16">
            <div className="inline-flex items-baseline justify-center gap-2 sm:gap-3 mb-4 sm:mb-6">
              <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#7B3FE4]">
                03
              </span>
              <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.12em] uppercase text-[#7B3FE4]">
                / Try it yourself
              </span>
            </div>
            <h2 className="font-heading font-bold text-[clamp(32px,4.5vw,64px)] tracking-tight leading-[1.12] text-[#E6E6EA]">
              See a scan in action.
            </h2>
            <p className="mt-4 font-heading font-medium text-[clamp(18px,1.6vw,24px)] leading-[1.6] text-[#9A9AAE] max-w-2xl mx-auto">
              Pick a sample message and watch AEGIS investigate it.
            </p>
          </div>
        </Reveal>

        {/* Two-Column Interactive Stage */}
        <div className="flex flex-col lg:grid lg:grid-cols-12 gap-8 lg:gap-10 items-start">
          {/* Left Column: Sample Picker, Phone Message Card, Start Button (5 cols) */}
          <div className="w-full lg:col-span-5 flex flex-col gap-6">
            {/* Sample Selector RadioGroup */}
            <div
              role="radiogroup"
              aria-label="Sample message options"
              className="grid grid-cols-2 gap-3"
            >
              {SAMPLES.map((s) => {
                const isSelected = s.id === selectedId;
                return (
                  <button
                    key={s.id}
                    type="button"
                    role="radio"
                    aria-checked={isSelected}
                    onClick={() => handleSelectSample(s)}
                    className={`p-3.5 rounded-xl border text-left transition-all flex flex-col justify-between select-none ${
                      isSelected
                        ? 'bg-[#13131A] border-[#7B3FE4] shadow-[0_0_20px_rgba(123,63,228,0.25)]'
                        : 'bg-[#0D0D12] border-[#1C1C26] hover:border-[#2A2A3A] hover:bg-[#13131A]/60'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full mb-1.5">
                      <span className="text-lg">{s.icon}</span>
                      <span
                        className={`font-mono text-[12px] font-semibold uppercase px-2 py-0.5 rounded-full ${
                          isSelected
                            ? 'bg-[#7B3FE4]/20 text-[#7B3FE4]'
                            : 'bg-white/5 text-[#9A9AAE]'
                        }`}
                      >
                        {s.severity}
                      </span>
                    </div>
                    <span className="font-heading font-semibold text-sm sm:text-base text-[#E6E6EA] line-clamp-1">
                      {s.title}
                    </span>
                    <span className="font-mono text-[11px] text-[#9A9AAE] mt-0.5 line-clamp-1">
                      {s.category}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Phone-Style Message Card */}
            <div className="relative rounded-2xl border border-[#1C1C26] bg-[#0D0D12]/95 p-6 shadow-2xl backdrop-blur-md">
              {/* Phone Status Bar Simulation */}
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/5">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      scanStatus === 'scanning'
                        ? 'bg-[#7B3FE4] animate-ping'
                        : scanStatus === 'complete'
                        ? 'bg-[#00E5FF]'
                        : 'bg-[#9A9AAE]'
                    }`}
                  />
                  <span className="font-mono text-sm sm:text-base font-semibold tracking-wide text-[#E6E6EA]">
                    {sample.sender}
                  </span>
                </div>
                <span className="font-mono text-xs sm:text-[13px] text-[#9A9AAE]">
                  {sample.time}
                </span>
              </div>

              {/* Message Content */}
              <div className="min-h-[110px] flex items-center">
                {renderMessageBody()}
              </div>

              {/* Bottom Scripted Demo Disclaimer */}
              <div className="mt-5 pt-3 border-t border-white/5 flex items-center justify-between">
                <span className="font-mono text-[13px] text-[#9A9AAE]">
                  Sample analysis: scripted demo, not a live result
                </span>
              </div>
            </div>

            {/* Primary Action Button: Start Analysis */}
            <div className="flex flex-col gap-3 pt-1">
              <button
                type="button"
                onClick={handleStartAnalysis}
                disabled={scanStatus === 'scanning'}
                aria-label={
                  scanStatus === 'scanning'
                    ? 'Analysing message...'
                    : scanStatus === 'complete'
                    ? 'Analyse again'
                    : 'Start analysis of this sample message'
                }
                className="w-full inline-flex items-center justify-center gap-3 px-7 py-3.5 rounded-full bg-[#7B3FE4] hover:bg-[#8E54F7] text-white font-heading font-semibold text-base shadow-[0_0_25px_rgba(123,63,228,0.4)] hover:shadow-[0_0_35px_rgba(123,63,228,0.6)] transition-all disabled:opacity-60 disabled:cursor-not-allowed group active:translate-y-0.5"
              >
                {scanStatus === 'scanning' ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analysing...</span>
                  </>
                ) : scanStatus === 'complete' ? (
                  <>
                    <svg
                      className="w-4 h-4 text-[#00E5FF] transition-transform group-hover:rotate-180 duration-300"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth="2.2"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                      />
                    </svg>
                    <span>Analyse again</span>
                  </>
                ) : (
                  <>
                    <svg
                      className="w-4 h-4 text-[#00E5FF] transition-transform group-hover:scale-110"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth="2.2"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                      />
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <span>Start analysis</span>
                  </>
                )}
              </button>

              {/* Link to live analyzer */}
              <div className="text-center pt-1">
                <TransitionLink
                  href="/analyze"
                  className="font-mono text-xs sm:text-sm text-[#9A9AAE] hover:text-[#00E5FF] transition-colors inline-flex items-center gap-1.5"
                >
                  <span>Analyse your own message</span>
                  <span>→</span>
                </TransitionLink>
              </div>
            </div>
          </div>

          {/* Right Column: Results Panel (7 cols) */}
          <div
            className="w-full lg:col-span-7 rounded-2xl border border-[#1C1C26] bg-[#0B0B0F]/90 p-6 sm:p-8 backdrop-blur-md relative overflow-hidden"
            aria-live="polite"
          >
            {/* Step Chips & Thin Progress Bar Header */}
            <div className="mb-6 pb-6 border-b border-white/5">
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-xs uppercase tracking-[0.14em] text-[#00E5FF] font-semibold">
                  Investigation Pipeline
                </span>
                <span className="font-mono text-xs text-[#9A9AAE]">
                  {scanStatus === 'idle'
                    ? 'Awaiting analysis'
                    : scanStatus === 'scanning'
                    ? `Step ${activeStep + 1} of ${SCAN_STEPS.length}`
                    : 'Inspection Complete'}
                </span>
              </div>

              {/* Thin Progress Bar (Amethyst to Cyan) */}
              <div className="w-full h-1 bg-[#1C1C26] rounded-full overflow-hidden mb-4">
                <motion.div
                  className="h-full bg-gradient-to-r from-[#7B3FE4] to-[#00E5FF]"
                  initial={false}
                  animate={{
                    width:
                      scanStatus === 'idle'
                        ? '0%'
                        : scanStatus === 'complete'
                        ? '100%'
                        : `${Math.min(100, ((activeStep + 1) / SCAN_STEPS.length) * 100)}%`,
                  }}
                  transition={{ duration: 0.3, ease: 'easeOut' }}
                />
              </div>

              {/* Step Chips */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {SCAN_STEPS.map((step, idx) => {
                  const stepDone = scanStatus === 'complete' || (scanStatus === 'scanning' && activeStep > idx);
                  const stepCurrent = scanStatus === 'scanning' && activeStep === idx;
                  return (
                    <div
                      key={step}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-center transition-colors ${
                        stepDone
                          ? 'border-[#00E5FF]/40 bg-[#00E5FF]/10 text-[#00E5FF]'
                          : stepCurrent
                          ? 'border-[#7B3FE4] bg-[#7B3FE4]/20 text-[#E6E6EA]'
                          : 'border-white/5 bg-[#0D0D12] text-[#626274]'
                      }`}
                    >
                      <span className="text-[12px]">
                        {stepDone ? '✓' : stepCurrent ? '●' : '○'}
                      </span>
                      <span className="font-mono text-[12px] font-medium truncate">
                        {step}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Results Display Area */}
            {scanStatus === 'idle' ? (
              /* Calm Idle Placeholder */
              <div className="py-14 sm:py-16 flex flex-col items-center justify-center text-center px-4">
                {/* Dim Empty Gauge */}
                <div className="relative w-24 h-24 mb-5 flex items-center justify-center opacity-40">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="44"
                      fill="transparent"
                      stroke="#1C1C26"
                      strokeWidth="8"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-mono font-bold text-2xl text-[#9A9AAE]">--</span>
                    <span className="font-mono text-[10px] text-[#626274] -mt-1">/ 100</span>
                  </div>
                </div>

                <h3 className="font-heading font-semibold text-lg sm:text-xl text-[#E6E6EA] tracking-tight">
                  Ready to scan this message.
                </h3>
                <p className="mt-2 font-heading font-normal text-sm sm:text-base text-[#9A9AAE] max-w-sm leading-relaxed">
                  Press <span className="text-[#00E5FF] font-medium">Start analysis</span> to inspect linguistic markers, domain hops, and fraud heuristics.
                </p>
              </div>
            ) : scanStatus === 'scanning' ? (
              /* Live Scanning Step Display */
              <div className="py-14 sm:py-16 flex flex-col items-center justify-center text-center px-4">
                <div className="w-12 h-12 rounded-full border-2 border-[#1C1C26] border-t-[#00E5FF] animate-spin mb-5" />
                <h3 className="font-heading font-semibold text-lg sm:text-xl text-[#E6E6EA]">
                  {activeStep === 0 && 'Normalising character encodings & deceptive characters...'}
                  {activeStep === 1 && 'Detecting social engineering intents & urgent coercion...'}
                  {activeStep === 2 && 'Inspecting redirects, shortlinks & domain registries...'}
                  {activeStep === 3 && 'Synthesising indicators into composite threat score...'}
                </h3>
                <p className="font-mono text-xs text-[#9A9AAE] mt-2">
                  Scanning target sample payload with AEGIS inspection heuristics
                </p>
              </div>
            ) : (
              /* Complete State: Score Gauge, Verdict Badge, Findings & Actions */
              <div className="space-y-6">
                {/* Score & Verdict Row */}
                <div className="flex flex-col sm:flex-row items-center sm:items-start justify-between gap-6 p-4 rounded-xl bg-[#0D0D12] border border-[#1C1C26]">
                  {/* Radial Gauge */}
                  <div
                    className="flex items-center gap-4"
                    aria-label={`Risk score ${sample.score} of 100, ${sample.severity}`}
                  >
                    <div className="relative w-24 h-24 flex items-center justify-center">
                      <svg
                        className="w-full h-full -rotate-90"
                        viewBox="0 0 100 100"
                      >
                        {/* Track Circle */}
                        <circle
                          cx="50"
                          cy="50"
                          r="44"
                          fill="transparent"
                          stroke="#1C1C26"
                          strokeWidth="8"
                        />
                        {/* Animated Arc Circle */}
                        <circle
                          ref={circleRef}
                          cx="50"
                          cy="50"
                          r="44"
                          fill="transparent"
                          stroke={colors.stroke}
                          strokeWidth="8"
                          strokeLinecap="round"
                          strokeDasharray="276.46"
                          strokeDashoffset={276.46 * (1 - sample.score / 100)}
                          className="transition-[stroke] duration-300"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span
                          ref={scoreTextRef}
                          className="font-mono font-bold text-2xl text-[#F5F5F7]"
                        >
                          {sample.score}
                        </span>
                        <span className="font-mono text-[10px] text-[#9A9AAE] -mt-1">
                          / 100
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-col">
                      <span className="font-mono text-xs uppercase tracking-wider text-[#9A9AAE]">
                        Threat Score
                      </span>
                      {/* Verdict Badge: Colour + Icon + Label (never colour alone) */}
                      <div
                        className={`inline-flex items-center gap-2 mt-1 px-3 py-1.5 rounded-full border transition-all ${colors.chipBg}`}
                      >
                        {getVerdictIcon(sample.severity)}
                        <span className="font-mono text-xs sm:text-[13px] font-bold tracking-wider uppercase">
                          {sample.severity} Risk
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Caveats / Not Verifiable Notice */}
                  <div className="text-left sm:text-right max-w-xs space-y-1">
                    {sample.caveats.map((c, i) => (
                      <p
                        key={i}
                        className="font-mono text-xs text-[#9A9AAE] flex items-center sm:justify-end gap-1.5"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-[#7B3FE4] flex-shrink-0" />
                        <span>{c}</span>
                      </p>
                    ))}
                  </div>
                </div>

                {/* Findings Section */}
                <div>
                  <h4 className="font-mono text-xs uppercase tracking-[0.14em] text-[#9A9AAE] mb-3">
                    Detected Findings ({sample.findings.length})
                  </h4>
                  <div className="space-y-2.5">
                    {sample.findings.map((f, i) => (
                      <div
                        key={i}
                        className="p-3.5 rounded-xl border border-white/5 bg-[#0D0D12] text-left transition-all"
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF]" />
                          <span className="font-heading font-semibold text-sm sm:text-base text-[#E6E6EA]">
                            {f.title}
                          </span>
                        </div>
                        <p className="mt-1 font-heading font-normal text-xs sm:text-sm text-[#9A9AAE] pl-3.5 leading-relaxed">
                          {f.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Actions */}
                <div>
                  <h4 className="font-mono text-xs uppercase tracking-[0.14em] text-[#9A9AAE] mb-3">
                    Recommended Actions
                  </h4>
                  <div className="space-y-2">
                    {sample.actions.map((act, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2.5 p-3 rounded-xl border border-white/5 bg-[#0D0D12]/70 text-left transition-all"
                      >
                        <span className="font-mono text-xs font-bold text-[#00E5FF] mt-0.5">
                          0{i + 1}
                        </span>
                        <p className="font-heading font-normal text-xs sm:text-sm text-[#E6E6EA] leading-relaxed">
                          {act}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
