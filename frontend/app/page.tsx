import React from 'react';
import Link from 'next/link';
import { DotMatrixHands } from '@/components/hero/DotMatrixHands';

export default function LandingPage() {
  const channels = [
    {
      name: 'Email',
      icon: (
        <svg
          className="w-4 h-4 text-[#9A9AAE]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect width="20" height="16" x="2" y="4" rx="2" />
          <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
        </svg>
      ),
    },
    {
      name: 'SMS',
      icon: (
        <svg
          className="w-4 h-4 text-[#9A9AAE]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect width="14" height="20" x="5" y="2" rx="2" ry="2" />
          <path d="M12 18h.01" />
        </svg>
      ),
    },
    {
      name: 'URL',
      icon: (
        <svg
          className="w-4 h-4 text-[#9A9AAE]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
        </svg>
      ),
    },
    {
      name: 'Messages',
      icon: (
        <svg
          className="w-4 h-4 text-[#9A9AAE]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z" />
        </svg>
      ),
    },
  ];

  return (
    <section className="relative w-full h-[calc(100vh-80px)] min-h-[660px] overflow-hidden flex flex-col justify-between">
      {/* Background Dot-Matrix Hands Canvas */}
      <DotMatrixHands />

      {/* Hero Copy Block */}
      <div className="relative z-10 w-full max-w-[760px] mx-auto px-5 text-center mt-[10vh] md:mt-[14vh] select-none">
        {/* Two-line Headline */}
        <h1 className="font-medium tracking-[-0.035em] leading-[1.06] text-[clamp(38px,4.2vw,70px)]">
          <span className="block text-[#9A9AAE] font-medium">
            Detect the Threat.
          </span>
          <span className="block text-[#F5F5F7] font-semibold mt-1">
            Understand the Risk.
          </span>
        </h1>

        {/* Subline */}
        <p className="mt-5 mx-auto max-w-[460px] text-[#9A9AAE] text-[clamp(13.5px,1.1vw,16px)] leading-relaxed">
          AI-powered phishing and scam detection that shows you why, across
          email, SMS, URLs and messages.
        </p>

        {/* CTA Pill with Amethyst-to-Cyan Underglow */}
        <div className="relative inline-block mt-[clamp(32px,3.8vw,52px)]">
          <Link href="/analyze" className="hero-cta-btn relative inline-block group">
            {/* Soft spectrum underglow */}
            <div className="hero-cta-glow" />

            {/* Jet black pill */}
            <div className="hero-cta-pill flex items-center gap-2.5 px-6 py-3 rounded-full bg-[#0D0D12] border border-[#1C1C26] hover:border-[#7B3FE4]/70 shadow-2xl">
              <span className="text-[14px] font-medium text-[#F5F5F7] tracking-tight">
                Analyse a message
              </span>
              <svg
                className="w-4 h-4 text-[#00E5FF] transition-transform group-hover:translate-x-0.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2.2"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M14 5l7 7m0 0l-7 7m7-7H3"
                />
              </svg>
            </div>
          </Link>
        </div>
      </div>

      {/* Four Channel Badges at bottom */}
      <div className="relative z-10 w-full pb-[clamp(28px,6vh,56px)] px-4">
        <div className="flex items-center justify-center flex-wrap gap-6 sm:gap-10 md:gap-14 text-[clamp(13px,1.1vw,15.5px)] font-medium text-[#9A9AAE]">
          {channels.map((channel) => (
            <div
              key={channel.name}
              className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg border border-transparent hover:border-[#1C1C26] hover:bg-[#0D0D12]/60 transition-all duration-200"
            >
              <span className="opacity-80">{channel.icon}</span>
              <span className="tracking-tight text-[#9A9AAE] hover:text-[#F5F5F7] transition-colors">
                {channel.name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

