'use client';

import React, { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import {
  useScroll,
  useTransform,
  useReducedMotion,
  useMotionValueEvent,
  motion,
} from 'framer-motion';

/* ─── DATA ─── */

interface LineData {
  id: number;
  text: string;
  range: readonly [number, number];
  isFinal?: boolean;
  highlights?: { start: number; end: number }[];
}

const LINES: LineData[] = [
  {
    id: 0,
    text: 'Messages that look real cost people real money.',
    range: [0.0, 0.16],
    highlights: [
      { start: 24, end: 28 }, // "real" (first)
      { start: 41, end: 45 }, // "real" (second)
    ],
  },
  {
    id: 1,
    text: 'AEGIS is an AI-powered scam and phishing detector.',
    range: [0.17, 0.33],
    highlights: [
      { start: 0, end: 5 },  // "AEGIS"
      { start: 24, end: 43 }, // "scam and phishing"
    ],
  },
  {
    id: 2,
    text: 'Paste an email, an SMS, a link, or any message.',
    range: [0.34, 0.5],
  },
  {
    id: 3,
    text: "It shows what's fake, explains why it's risky, and tells you what to do next.",
    range: [0.51, 0.67],
    highlights: [
      { start: 9, end: 21 },  // "what's fake"
      { start: 32, end: 45 },  // "why it's risky"
      { start: 66, end: 77 },  // "what to do next"
    ],
  },
  {
    id: 4,
    text: 'And it keeps a tamper-evident record of the investigation.',
    range: [0.68, 0.84],
    highlights: [
      { start: 15, end: 29 }, // "tamper-evident"
    ],
  },
  {
    id: 5,
    text: 'Detect the Threat. Understand the Risk. Protect the User.',
    range: [0.85, 1.0],
    isFinal: true,
    highlights: [
      { start: 40, end: 58 }, // "Protect the User."
    ],
  },
];

const SCRAMBLE_CHARS = '0123456789ABCDEF█▓░▒◆◇●○■□';

function randomGlyph(): string {
  return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
}

// Deterministic glyph generator for initial render to guarantee SSR & client hydration match
function getDeterministicGlyph(index: number, lineId: number): string {
  return SCRAMBLE_CHARS[(index * 7 + lineId * 13 + 3) % SCRAMBLE_CHARS.length];
}

/* ─── KEYWORD HIGHLIGHT (static helper for reduced-motion & resolved text) ─── */

function renderHighlightedText(text: string, highlights?: { start: number; end: number }[]) {
  if (!highlights || highlights.length === 0) {
    return <span className="text-[#F5F5F7]">{text}</span>;
  }

  const parts: React.ReactNode[] = [];
  let cursor = 0;

  const sorted = [...highlights].sort((a, b) => a.start - b.start);

  for (const hl of sorted) {
    if (cursor < hl.start) {
      parts.push(
        <span key={`t-${cursor}`} className="text-[#F5F5F7]">
          {text.slice(cursor, hl.start)}
        </span>
      );
    }
    parts.push(
      <span
        key={`h-${hl.start}`}
        className="bg-gradient-to-r from-[#7B3FE4] via-[#A855F7] to-[#00E5FF] bg-clip-text text-transparent font-bold"
        style={{ textShadow: '0 0 20px rgba(123,63,228,0.3), 0 0 40px rgba(0,229,255,0.15)' }}
      >
        {text.slice(hl.start, hl.end)}
      </span>
    );
    cursor = hl.end;
  }

  if (cursor < text.length) {
    parts.push(
      <span key={`t-${cursor}`} className="text-[#F5F5F7]">
        {text.slice(cursor)}
      </span>
    );
  }

  return <>{parts}</>;
}

/* ─── DECRYPT LINE ─── */

function DecryptLine({ line, scrollYProgress }: { line: LineData; scrollYProgress: any }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const charsRef = useRef<(HTMLSpanElement | null)[]>([]);
  const scanHeadRef = useRef<HTMLDivElement>(null);
  const rafId = useRef<number>(0);
  const lastTime = useRef<number>(0);
  const isVisible = useRef(true);
  const pulseRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);

  const [start, end] = line.range;
  const isFinal = !!line.isFinal;
  const chars = useMemo(() => line.text.split(''), [line.text]);
  const totalChars = chars.length;

  // Fully deterministic initial scramble for SSR and first client render
  const deterministicScramble = useMemo(
    () => chars.map((c, i) => (c === ' ' ? ' ' : getDeterministicGlyph(i, line.id))),
    [chars, line.id]
  );

  const highlightMask = useMemo(() => {
    const mask = new Array(totalChars).fill(false);
    if (line.highlights) {
      for (const hl of line.highlights) {
        for (let i = hl.start; i < hl.end && i < totalChars; i++) {
          mask[i] = true;
        }
      }
    }
    return mask;
  }, [line.highlights, totalChars]);

  const rangeLen = end - start;
  const enterLen = rangeLen * 0.12;
  const decryptLen = rangeLen * 0.60;
  const exitLen = isFinal ? 0 : rangeLen * 0.28;

  const enterStart = start;
  const enterEnd = start + enterLen;
  const decryptStart = enterEnd;
  const decryptEnd = decryptStart + decryptLen;
  const exitStart = isFinal ? end : end - exitLen;
  const exitEnd = end;

  const enterOpacity = useTransform(scrollYProgress, [enterStart, enterEnd], [0, 1]);
  const enterY = useTransform(scrollYProgress, [enterStart, enterEnd], [30, 0]);

  const exitOpacity = useTransform(
    scrollYProgress,
    isFinal ? [exitStart, 1] : [exitStart, exitEnd],
    isFinal ? [1, 1] : [1, 0]
  );
  const exitScale = useTransform(
    scrollYProgress,
    isFinal ? [exitStart, 1] : [exitStart, exitEnd],
    isFinal ? [1, 1] : [1, 0.92]
  );
  const exitZ = useTransform(
    scrollYProgress,
    isFinal ? [exitStart, 1] : [exitStart, exitEnd],
    isFinal ? [0, 0] : [0, -80]
  );
  const exitY2 = useTransform(
    scrollYProgress,
    isFinal ? [exitStart, 1] : [exitStart, exitEnd],
    isFinal ? [0, 0] : [0, -30]
  );

  const resolveProgress = useTransform(
    scrollYProgress,
    [decryptStart, decryptEnd],
    [0, 1]
  );

  const updateChars = useCallback(
    (progress: number) => {
      const resolvedCount = Math.floor(progress * totalChars);
      const flickerZone = 3;

      for (let i = 0; i < totalChars; i++) {
        const span = charsRef.current[i];
        if (!span) continue;

        if (i < resolvedCount) {
          span.textContent = chars[i];
          if (highlightMask[i]) {
            span.className = 'decrypt-char resolved highlight';
          } else {
            span.className = 'decrypt-char resolved';
          }
        } else if (i < resolvedCount + flickerZone) {
          span.textContent = randomGlyph();
          span.className = 'decrypt-char flickering';
        } else {
          span.textContent = deterministicScramble[i];
          span.className = 'decrypt-char scrambled';
        }
      }

      if (scanHeadRef.current) {
        if (progress <= 0 || progress >= 1) {
          scanHeadRef.current.style.opacity = '0';
        } else {
          scanHeadRef.current.style.opacity = '1';
          const edgeSpan = charsRef.current[resolvedCount];
          const container = containerRef.current;
          if (edgeSpan && container) {
            const containerRect = container.getBoundingClientRect();
            const spanRect = edgeSpan.getBoundingClientRect();
            const left = spanRect.left - containerRect.left;
            const top = spanRect.top - containerRect.top;
            scanHeadRef.current.style.transform = `translate(${left}px, ${top}px)`;
            scanHeadRef.current.style.height = `${spanRect.height}px`;
          }
        }
      }

      if (isFinal && progress >= 1 && pulseRef.current && ringRef.current) {
        pulseRef.current.classList.add('finale-pulse');
        ringRef.current.classList.add('finale-ring');
      }
    },
    [chars, totalChars, highlightMask, deterministicScramble, isFinal]
  );

  useMotionValueEvent(resolveProgress, 'change', (latest: number) => {
    if (!isVisible.current) return;
    const now = performance.now();
    if (now - lastTime.current < 33) return;
    lastTime.current = now;
    rafId.current = requestAnimationFrame(() => updateChars(latest));
  });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        isVisible.current = entry.isIntersecting;
      },
      { threshold: 0.05 }
    );
    obs.observe(el);
    return () => {
      obs.disconnect();
      if (rafId.current) cancelAnimationFrame(rafId.current);
    };
  }, []);

  useEffect(() => {
    updateChars(0);
  }, [updateChars]);

  const charSpans = useMemo(() => {
    const result: React.ReactNode[] = [];
    let wordBuffer: React.ReactNode[] = [];
    let wordIdx = 0;

    for (let i = 0; i < totalChars; i++) {
      wordBuffer.push(
        <span
          key={i}
          ref={(el) => {
            charsRef.current[i] = el;
          }}
          className="decrypt-char scrambled"
          aria-hidden="true"
        >
          {deterministicScramble[i]}
        </span>
      );

      if (chars[i] === ' ' || i === totalChars - 1) {
        result.push(
          <span key={`w-${wordIdx}`} className="decrypt-word">
            {wordBuffer}
          </span>
        );
        wordBuffer = [];
        wordIdx++;
      }
    }
    return result;
  }, [totalChars, chars, deterministicScramble]);

  return (
    <motion.div
      ref={containerRef}
      style={{
        opacity: enterOpacity,
        y: enterY,
        scale: exitScale,
        translateZ: exitZ,
      }}
      className="absolute inset-0 flex items-center justify-center p-6 text-center pointer-events-none select-none"
    >
      <motion.div style={{ opacity: exitOpacity, y: exitY2 }} className="relative max-w-4xl mx-auto">
        <span className="sr-only">{line.text}</span>

        <div className="decrypt-line-chars text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight leading-snug relative">
          {charSpans}
          <div
            ref={scanHeadRef}
            className="absolute top-0 left-0 w-[2px] pointer-events-none"
            style={{
              opacity: 0,
              background: '#00E5FF',
              boxShadow: '0 0 8px rgba(0,229,255,0.7), 0 0 20px rgba(0,229,255,0.4), 0 0 40px rgba(0,229,255,0.2)',
              transition: 'opacity 0.15s ease',
              willChange: 'transform',
            }}
          />
        </div>

        {isFinal && (
          <>
            <div ref={pulseRef} className="finale-pulse-container" />
            <div ref={ringRef} className="finale-ring-container" />
          </>
        )}
      </motion.div>
    </motion.div>
  );
}

/* ─── PROGRESS DOTS ─── */

function ProgressDots({ scrollYProgress }: { scrollYProgress: any }) {
  return (
    <div className="absolute right-6 sm:right-10 top-1/2 -translate-y-1/2 z-20 flex flex-col gap-3 pointer-events-none">
      {LINES.map((line) => {
        const [s, e] = line.range;
        const mid = (s + e) / 2;
        const dotScale = useTransform(scrollYProgress, [s, mid, e], [1, 1.45, 1]);
        const dotOpacity = useTransform(scrollYProgress, [s, mid, e], [0.25, 1, 0.25]);

        return (
          <motion.div
            key={line.id}
            style={{ scale: dotScale, opacity: dotOpacity }}
            className="w-2 h-2 rounded-full bg-[#00E5FF] shadow-[0_0_8px_rgba(0,229,255,0.6)]"
          />
        );
      })}
    </div>
  );
}

/* ─── MAIN EXPORT ─── */

export function StoryScene() {
  const storyRef = useRef<HTMLElement>(null);
  const framerReduced = useReducedMotion();
  const [isReduced, setIsReduced] = useState(false);

  useEffect(() => {
    if (framerReduced) {
      setIsReduced(true);
    }
  }, [framerReduced]);

  const { scrollYProgress } = useScroll({
    target: storyRef,
    offset: ['start start', 'end end'],
  });

  if (isReduced) {
    return (
      <section
        id="story"
        className="relative w-full bg-transparent py-24 px-6 border-t border-[#1C1C26]/40"
      >
        <div className="max-w-4xl mx-auto space-y-12 text-center">
          <div className="inline-flex items-baseline justify-center gap-2 sm:gap-3 mb-4">
            <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#00E5FF]">
              02
            </span>
            <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.14em] uppercase text-[#00E5FF]">
              / What AEGIS Is
            </span>
          </div>
          {LINES.map((line) => (
            <div key={line.id} className="py-4">
              <p className="font-heading text-2xl sm:text-4xl font-semibold tracking-tight">
                {renderHighlightedText(line.text, line.highlights)}
              </p>
            </div>
          ))}
        </div>
      </section>
    );
  }

  return (
    <section
      id="story"
      ref={storyRef}
      className="relative w-full h-[400vh] bg-transparent scroll-mt-[var(--landing-header-h)]"
    >
      {/* Sticky Fullscreen Stage */}
      <div
        className="sticky top-0 w-full h-screen overflow-hidden flex flex-col items-center justify-center bg-transparent"
        style={{ perspective: '1200px' }}
      >
        {/* Consistent Section Eyebrow Badge at Stage Top */}
        <div className="absolute top-8 sm:top-12 left-1/2 -translate-x-1/2 z-20 pointer-events-none">
          <div className="inline-flex items-baseline gap-2 sm:gap-3 px-5 py-2 rounded-full bg-[#0D0D12]/80 backdrop-blur-sm border border-[#1C1C26]">
            <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#00E5FF]">
              02
            </span>
            <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.14em] uppercase text-[#00E5FF]">
              / What AEGIS Is
            </span>
          </div>
        </div>

        {/* Decrypt Lines */}
        <div className="relative w-full h-full">
          {LINES.map((line) => (
            <DecryptLine
              key={line.id}
              line={line}
              scrollYProgress={scrollYProgress}
            />
          ))}
        </div>

        {/* Progress Dots */}
        <ProgressDots scrollYProgress={scrollYProgress} />
      </div>
    </section>
  );
}
