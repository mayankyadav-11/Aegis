'use client';

import React, { useRef, useEffect } from 'react';
import Link from 'next/link';
import { motion, useScroll, useTransform } from 'framer-motion';
import { DotMatrixHands } from '@/components/hero/DotMatrixHands';
import { SmoothScroll } from '@/components/SmoothScroll';
import { Reveal } from '@/components/Reveal';
import { ScamWallScene } from '@/components/landing/ScamWallScene';
import { StoryScene } from '@/components/landing/StoryScene';
import { TryScannerScene } from '@/components/landing/TryScannerScene';
import { FAQScene } from '@/components/landing/FAQScene';
import { SectionDivider } from '@/components/landing/SectionDivider';
import { LandingBackground } from '@/components/landing/LandingBackground';

export default function LandingPage() {
  const heroRef = useRef<HTMLElement>(null);

  // Set history.scrollRestoration = 'manual' and start at the top on mount/reload
  useEffect(() => {
    if (typeof window !== 'undefined') {
      if ('scrollRestoration' in window.history) {
        window.history.scrollRestoration = 'manual';
      }
      window.scrollTo(0, 0);
    }
  }, []);

  // Hero section scroll progress (0 at top, 1 when hero finishes scrolling out)
  const { scrollYProgress: heroScroll } = useScroll({
    target: heroRef,
    offset: ['start start', 'end start'],
  });

  // Global page scroll progress for top gradient progress bar
  const { scrollYProgress: pageScroll } = useScroll();

  // Hero text exit transforms: move up, scale down slightly, fade out
  // Strictly 0% at scroll position 0
  const textY = useTransform(heroScroll, [0, 0.05, 1], ['0%', '0%', '-35%']);
  const textScale = useTransform(heroScroll, [0, 1], [1, 0.92]);
  const textOpacity = useTransform(heroScroll, [0, 0.75, 1], [1, 0.25, 0]);

  // Canvas container exit transforms: slides up ~15% and fades out
  const canvasY = useTransform(heroScroll, [0, 1], ['0%', '-15%']);
  const canvasOpacity = useTransform(heroScroll, [0, 0.85, 1], [1, 0.3, 0]);

  // Bottom scroll cue: fades out as soon as user starts scrolling
  const cueOpacity = useTransform(heroScroll, [0, 0.15], [1, 0]);

  return (
    <div className="relative w-full bg-[#050507] text-[#E6E6EA] min-h-screen">
      {/* Interactive Layered Background (Aurora + Reactive Grid + Spotlight) */}
      <LandingBackground />

      {/* 1. Client-only Lenis smooth scroll on landing page */}
      <SmoothScroll />

      {/* 5. Thin scroll progress bar at the top (Amethyst to Cyan gradient) */}
      <motion.div
        className="fixed top-0 left-0 right-0 h-[2px] z-50 origin-left bg-gradient-to-r from-[#7B3FE4] to-[#00E5FF] pointer-events-none"
        style={{ scaleX: pageScroll }}
      />

      {/* Hero Section — exactly 100svh one-screen layout */}
      <section
        ref={heroRef}
        className="relative z-10 w-full h-[100svh] min-h-[100svh] max-h-[100svh] bg-transparent flex flex-col overflow-hidden"
        style={{
          height: '100svh',
          minHeight: '100svh',
          maxHeight: '100svh',
          paddingTop: 'var(--landing-header-h)',
        }}
      >
        {/* ── Zone A: Text block ────────────────────────────────────────────── */}
        {/* Compact, natural height, gap at bottom to hands zone: ~16 to 24px */}
        <div
          className="relative z-10 w-full bg-transparent flex flex-col items-center px-4 sm:px-6 text-center select-none shrink-0"
          style={{ paddingBottom: 'min(2.2vh, 18px)' }}
        >
          <motion.div
            style={{ y: textY, scale: textScale, opacity: textOpacity }}
            className="w-full max-w-[720px] mx-auto will-change-transform"
          >
            {/* Two-line Headline (clamp with vw and vh so it fits without pushing hands down) */}
            <h1 className="font-heading tracking-[-0.02em] leading-[1.06] text-[clamp(28px,min(5.2vw,7.5vh),62px)]">
              <span className="block text-[#9A9AAE] font-semibold">
                Detect the Threat.
              </span>
              <span className="block text-[#E6E6EA] font-bold mt-0.5">
                Understand the Risk.
              </span>
            </h1>

            {/* Subline */}
            <p className="mt-[min(1.5vh,12px)] mx-auto max-w-[500px] font-body text-[#9A9AAE] text-[clamp(14px,min(1.5vw,2.2vh),17px)] leading-[1.5]">
              AI-powered phishing and scam detection that shows you why, across
              email, SMS, URLs and messages.
            </p>

            {/* CTA Pill navigating to /analyze */}
            <div className="relative inline-block mt-[min(2vh,18px)]">
              <Link
                href="/analyze"
                className="hero-cta-btn relative inline-block group"
              >
                {/* Soft spectrum underglow */}
                <div className="hero-cta-glow" />

                {/* Jet black pill */}
                <div className="hero-cta-pill flex items-center gap-2 px-5 py-2.5 sm:px-6 sm:py-3 rounded-full bg-[#0D0D12] border border-[#1C1C26] hover:border-[#7B3FE4]/70 shadow-2xl transition-all">
                  <span className="font-body text-[14px] sm:text-[15px] font-medium text-[#E6E6EA] tracking-tight">
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
          </motion.div>
        </div>

        {/* ── Zone B: Canvas zone ───────────────────────────────────────────── */}
        {/* flex-1 and min-h-0 so it takes ALL remaining space down to the bottom */}
        <motion.div
          style={{ y: canvasY, opacity: canvasOpacity }}
          className="relative flex-1 min-h-0 w-full bg-transparent pointer-events-none will-change-transform"
        >
          {/* DotMatrixHands renders <div class="absolute inset-0"> inside this zone only */}
          <DotMatrixHands />

          {/* ── Scroll Cue inside hands zone bottom ────────────────────────── */}
          {/* Centred, hidden below 700px viewport height via .hero-scroll-cue */}
          <motion.div
            style={{ opacity: cueOpacity }}
            className="hero-scroll-cue absolute bottom-3 sm:bottom-4 left-1/2 -translate-x-1/2 z-10 flex flex-col items-center gap-1 pointer-events-none select-none"
          >
            <span className="font-mono text-[10px] tracking-[0.14em] uppercase text-[#9A9AAE]">
              Scroll
            </span>
            <svg
              className="w-3.5 h-3.5 text-[#9A9AAE] animate-bounce"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M19 9l-7 7-7-7"
              />
            </svg>
          </motion.div>
        </motion.div>
      </section>

      {/* Sections below hero (transparent so LandingBackground shines through) */}
      <div className="relative z-10 bg-transparent">
        {/* SCENE 01: #problem ("The Scam Wall") */}
        <ScamWallScene />

        {/* 1. Divider between problem and story */}
        <SectionDivider />

        {/* SCENE 02: #story ("What AEGIS Is") */}
        <StoryScene />

        {/* 2. Divider between story and try */}
        <SectionDivider />

        {/* SCENE 03: #try ("Try It Yourself Scanner") */}
        <TryScannerScene />

        {/* 3. Divider between try and faq */}
        <SectionDivider />

        {/* SCENE 04: #faq ("Questions, answered.") */}
        <FAQScene />

        {/* 4. Divider between faq and cta */}
        <SectionDivider />

        {/* SCENE 05: #cta ("Get Started") */}
        <section
          id="cta"
          className="relative w-full min-h-[60vh] bg-transparent flex items-center justify-center px-6 py-24 sm:py-32 scroll-mt-[var(--landing-header-h)]"
        >
          <Reveal>
            <div className="max-w-3xl mx-auto text-center">
              <div className="inline-flex items-baseline justify-center gap-2 sm:gap-3 mb-4 sm:mb-6">
                <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#7B3FE4]">
                  05
                </span>
                <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.12em] uppercase text-[#7B3FE4]">
                  / Get Started
                </span>
              </div>
              <h2 className="font-heading font-bold text-[clamp(32px,4.5vw,64px)] tracking-tight leading-[1.12] text-[#E6E6EA]">
                Ready to inspect a suspicious target?
              </h2>
              <div className="mt-10">
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-3 px-8 py-4 rounded-full bg-[#7B3FE4] hover:bg-[#8E54F7] text-white font-heading font-semibold text-[clamp(16px,1.2vw,18px)] transition-all shadow-[0_0_30px_rgba(123,63,228,0.4)] hover:shadow-[0_0_40px_rgba(123,63,228,0.6)]"
                >
                  <span>Launch Security Console</span>
                  <svg
                    className="w-4 h-4 text-[#00E5FF]"
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
                </Link>
              </div>
            </div>
          </Reveal>
        </section>

        {/* Landing Page Semantic Footer */}
        <footer className="w-full border-t border-[#1C1C26] bg-[#050507] py-10 px-6 sm:px-10">
          <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6 text-center sm:text-left">
            <div className="flex items-center gap-2.5">
              <div className="w-6 h-6 rounded-md bg-[#0D0D12] border border-[#1C1C26] flex items-center justify-center">
                <span className="text-[#00E5FF] text-xs font-bold font-mono">A</span>
              </div>
              <span className="font-heading font-bold text-sm tracking-[0.08em] text-[#E6E6EA]">
                AEGIS
              </span>
              <span className="font-mono text-xs text-[#9A9AAE] ml-2">
                AI Phishing & Scam Detection Platform
              </span>
            </div>

            <p className="font-mono text-xs text-[#626274]">
              Experimental Security Tool. Always verify critical banking and account alerts through official channels.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}
