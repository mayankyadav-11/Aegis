'use client';

import React, { useRef, useState, useEffect } from 'react';
import { motion, useScroll, useTransform, useReducedMotion } from 'framer-motion';

interface MessageCardData {
  id: string;
  type: 'sms' | 'whatsapp';
  sender: string;
  time: string;
  text: string;
  desktopPos: {
    top: string;
    left?: string;
    right?: string;
    rotate: number;
    depth: number; // 1 to 3 for scale & parallax multiplier
  };
  stampStart: number; // scroll progress threshold for stamping
}

const CARDS: MessageCardData[] = [
  {
    id: 'c1',
    type: 'sms',
    sender: 'AX-ALERTS',
    time: '10:42 AM',
    text: 'Dear customer, your bank account will be blocked today. Update KYC now: bit.ly/xxxx',
    desktopPos: { top: '8%', left: '4%', rotate: -3.5, depth: 1 },
    stampStart: 0.16,
  },
  {
    id: 'c2',
    type: 'whatsapp',
    sender: '+91 9XXXXXXXXX',
    time: '11:15 AM',
    text: 'UPI refund pending. Click the link to claim your cashback voucher.',
    desktopPos: { top: '10%', right: '5%', rotate: 4, depth: 1.2 },
    stampStart: 0.25,
  },
  {
    id: 'c3',
    type: 'sms',
    sender: 'VM-SECURE',
    time: '01:20 PM',
    text: 'Your OTP is 4821. Share it with support executive to claim your prize.',
    desktopPos: { top: '38%', left: '8%', rotate: 2, depth: 1.1 },
    stampStart: 0.34,
  },
  {
    id: 'c4',
    type: 'sms',
    sender: 'AD-COURIER',
    time: '03:05 PM',
    text: 'Parcel on hold at terminal. Pay Rs 29 clearance fee to release delivery.',
    desktopPos: { top: '40%', right: '7%', rotate: -4, depth: 0.95 },
    stampStart: 0.43,
  },
  {
    id: 'c5',
    type: 'whatsapp',
    sender: '+91 9XXXXXXXXX',
    time: '04:30 PM',
    text: 'Job offer! Work from home. Pay Rs 1,500 registration fee to confirm slot.',
    desktopPos: { top: '68%', left: '12%', rotate: -2, depth: 1.05 },
    stampStart: 0.52,
  },
  {
    id: 'c6',
    type: 'sms',
    sender: 'VK-VERIFY',
    time: '06:12 PM',
    text: 'Aapka KYC expire ho gaya hai, abhi update karein turant.',
    desktopPos: { top: '70%', right: '11%', rotate: 3.5, depth: 1 },
    stampStart: 0.61,
  },
];

function SingleCard({
  card,
  scrollYProgress,
  isMobile = false,
}: {
  card: MessageCardData;
  scrollYProgress: any;
  isMobile?: boolean;
}) {
  const { stampStart } = card;

  // Stamping path lengths (first stroke draws, then second stroke draws)
  const line1 = useTransform(
    scrollYProgress,
    [stampStart, stampStart + 0.03],
    [0, 1]
  );
  const line2 = useTransform(
    scrollYProgress,
    [stampStart + 0.025, stampStart + 0.055],
    [0, 1]
  );

  // Badge chip scale and opacity
  const chipScale = useTransform(
    scrollYProgress,
    [stampStart + 0.035, stampStart + 0.065],
    [0, 1]
  );
  const chipOpacity = useTransform(
    scrollYProgress,
    [stampStart + 0.035, stampStart + 0.05],
    [0, 1]
  );

  // Dimming once stamped
  const dimOpacity = useTransform(
    scrollYProgress,
    [stampStart + 0.05, stampStart + 0.09, 0.72, 0.84],
    [1, 0.6, 0.6, 0.2]
  );

  // Subtle Parallax float along Y
  const parallaxY = useTransform(
    scrollYProgress,
    [0, 1],
    [30 * card.desktopPos.depth, -35 * card.desktopPos.depth]
  );

  return (
    <motion.div
      style={{
        opacity: dimOpacity,
        y: isMobile ? 0 : parallaxY,
      }}
      className={`relative rounded-2xl border p-5 sm:p-6 shadow-2xl transition-shadow select-none will-change-transform ${
        card.type === 'whatsapp'
          ? 'bg-[#0B1512]/90 border-[#16382C] text-[#E6E6EA]'
          : 'bg-[#0D0D12]/90 border-[#1C1C26] text-[#E6E6EA]'
      } ${
        isMobile
          ? 'w-full mb-3.5'
          : 'w-[clamp(280px,28vw,420px)] absolute'
      }`}
    >
      {/* Header: Sender ID and Timestamp */}
      <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          {card.type === 'whatsapp' ? (
            <span className="w-2.5 h-2.5 rounded-full bg-[#25D366]" />
          ) : (
            <span className="w-2.5 h-2.5 rounded-full bg-[#00E5FF]" />
          )}
          <span className="font-mono text-sm sm:text-base font-semibold tracking-wide text-[#E6E6EA]">
            {card.sender}
          </span>
        </div>
        <span className="font-mono text-xs sm:text-[13px] text-[#9A9AAE]">{card.time}</span>
      </div>

      {/* Message Body (17-20px with comfortable line height) */}
      <p className="font-body text-[clamp(17px,1.2vw,20px)] leading-[1.55] text-[#D6D6DC]">
        {card.text}
      </p>

      {/* Red Cross Stamp SVG (Strokes draw with pathLength, scaled proportionally) */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none p-4 sm:p-5 overflow-visible"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
      >
        <motion.line
          x1="12"
          y1="15"
          x2="88"
          y2="85"
          stroke="#EF4444"
          strokeWidth="7"
          strokeLinecap="round"
          style={{ pathLength: line1 }}
        />
        <motion.line
          x1="88"
          y1="15"
          x2="12"
          y2="85"
          stroke="#EF4444"
          strokeWidth="7"
          strokeLinecap="round"
          style={{ pathLength: line2 }}
        />
      </svg>

      {/* "Scam" chip scaled proportionally */}
      <motion.div
        style={{
          scale: chipScale,
          opacity: chipOpacity,
        }}
        className="absolute -top-3.5 -right-2.5 z-20 px-3 py-0.5 sm:px-3.5 sm:py-1 rounded-full bg-[#EF4444] text-white font-mono text-xs sm:text-sm font-bold tracking-wider uppercase shadow-[0_0_18px_rgba(239,68,68,0.55)] border border-[#EF4444]/60 flex items-center gap-1.5"
      >
        <span>✕</span>
        <span>Scam</span>
      </motion.div>
    </motion.div>
  );
}

export function ScamWallScene() {
  const sectionRef = useRef<HTMLElement>(null);
  const framerReduced = useReducedMotion();
  const [isReduced, setIsReduced] = useState(false);

  useEffect(() => {
    if (framerReduced) {
      setIsReduced(true);
    }
  }, [framerReduced]);

  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end end'],
  });

  // Final overlay headline animation
  const headlineOpacity = useTransform(scrollYProgress, [0.72, 0.84], [0, 1]);
  const headlineY = useTransform(scrollYProgress, [0.72, 0.84], [30, 0]);

  // If user requests reduced motion, render static readable cards
  if (isReduced) {
    return (
      <section
        id="problem"
        className="relative w-full bg-transparent py-24 px-6 border-t border-[#1C1C26]/40"
      >
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <div className="inline-flex items-baseline justify-center gap-2 sm:gap-3 mb-4">
              <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#7B3FE4]">
                01
              </span>
              <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.14em] uppercase text-[#7B3FE4]">
                / The Scam Wall
              </span>
            </div>
            <h2 className="font-heading text-3xl md:text-5xl font-bold text-[#F5F5F7]">
              Scams look real. That&apos;s the point.
            </h2>
            <p className="font-body text-[#9A9AAE] text-lg mt-3">
              Urgency, fear and borrowed trust do the work.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {CARDS.map((card) => (
              <div
                key={card.id}
                className="relative rounded-2xl border border-[#EF4444]/50 bg-[#0D0D12]/90 p-6"
              >
                <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-white/5 font-mono text-sm text-[#9A9AAE]">
                  <span className="font-semibold text-[#E6E6EA]">{card.sender}</span>
                  <span>{card.time}</span>
                </div>
                <p className="font-body text-[17px] leading-relaxed text-[#E6E6EA]">{card.text}</p>
                <div className="mt-4 inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#EF4444] text-white text-xs font-mono font-bold uppercase">
                  <span>✕</span>
                  <span>Scam</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    );
  }

  return (
    <section
      id="problem"
      ref={sectionRef}
      className="relative w-full h-[300vh] bg-transparent scroll-mt-[var(--landing-header-h)]"
    >
      {/* Sticky Fullscreen Stage */}
      <div className="sticky top-0 w-full h-screen overflow-hidden flex items-center justify-center bg-transparent">
        {/* Consistent Section Eyebrow Badge at Stage Top */}
        <div className="absolute top-8 sm:top-12 left-1/2 -translate-x-1/2 z-20 pointer-events-none">
          <div className="inline-flex items-baseline gap-2 sm:gap-3 px-5 py-2 rounded-full bg-[#0D0D12]/80 backdrop-blur-sm border border-[#1C1C26]">
            <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#7B3FE4]">
              01
            </span>
            <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.14em] uppercase text-[#7B3FE4]">
              / The Scam Wall
            </span>
          </div>
        </div>

        {/* Desktop Layout (>= 768px): Parallax tilted cards entering and floating */}
        <div className="hidden md:block absolute inset-0 w-full h-full pointer-events-none">
          {CARDS.map((card) => (
            <div
              key={card.id}
              style={{
                position: 'absolute',
                top: card.desktopPos.top,
                left: card.desktopPos.left,
                right: card.desktopPos.right,
                transform: `rotate(${card.desktopPos.rotate}deg)`,
              }}
            >
              <SingleCard card={card} scrollYProgress={scrollYProgress} />
            </div>
          ))}
        </div>

        {/* Mobile Layout (< 768px): Stacked cards at ~85% screen width */}
        <div className="md:hidden flex flex-col items-center justify-center w-full px-4 py-6 overflow-hidden">
          {CARDS.slice(0, 4).map((card, idx) => (
            <div
              key={card.id}
              style={{
                transform: `rotate(${idx % 2 === 0 ? -1.5 : 1.5}deg)`,
              }}
              className="w-[85%] max-w-[380px] flex justify-center"
            >
              <SingleCard
                card={card}
                scrollYProgress={scrollYProgress}
                isMobile
              />
            </div>
          ))}
        </div>

        {/* Final Headline: Fades in over the scene when all cards are crossed out */}
        <motion.div
          style={{
            opacity: headlineOpacity,
            y: headlineY,
          }}
          className="absolute z-30 max-w-2xl px-6 text-center pointer-events-none"
        >
          <div className="p-8 sm:p-10 rounded-2xl bg-[#050507]/90 backdrop-blur-md border border-[#1C1C26] shadow-2xl">
            <div className="inline-flex items-baseline justify-center gap-2 sm:gap-3 mb-3">
              <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#7B3FE4]">
                01
              </span>
              <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.14em] uppercase text-[#7B3FE4]">
                / The Scam Wall
              </span>
            </div>
            <h2 className="mt-2 font-heading text-3xl sm:text-4xl md:text-5xl font-bold text-[#F5F5F7] tracking-tight leading-tight">
              Scams look real. That&apos;s the point.
            </h2>
            <p className="mt-4 font-body text-[#9A9AAE] text-base sm:text-lg leading-relaxed">
              Urgency, fear and borrowed trust do the work.
            </p>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
