'use client';

import React, { useRef, useState, useEffect } from 'react';
import { useReducedMotion } from 'framer-motion';

const DESKTOP_DOT_COUNT = 48;
const MOBILE_DOT_COUNT = 24;

export function SectionDivider() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hasSwept, setHasSwept] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const framerReduced = useReducedMotion();
  const [isReduced, setIsReduced] = useState(false);

  useEffect(() => {
    if (framerReduced) setIsReduced(true);
  }, [framerReduced]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        setIsInView(entry.isIntersecting);
        if (entry.isIntersecting && !hasSwept) {
          setHasSwept(true);
        }
      },
      { threshold: 0.2 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [hasSwept]);

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[64px] md:h-[96px] flex flex-col items-center justify-center bg-transparent select-none pointer-events-none overflow-hidden"
      aria-hidden="true"
    >
      {/* 1px Gradient Line (80% width, centered) */}
      <div className="relative w-[80%] max-w-5xl h-[1px] bg-gradient-to-r from-transparent via-[#7B3FE4]/70 to-transparent">
        {/* Subtle Cyan Overlay Gradient */}
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#00E5FF]/50 to-transparent opacity-80" />

        {/* Scan Head (sweeps left-to-right once when in view) */}
        {!isReduced && hasSwept && (
          <div className="absolute top-[-1px] left-0 w-24 h-[3px] rounded-full bg-gradient-to-r from-transparent via-[#00E5FF] to-transparent animate-scan-sweep will-change-transform" />
        )}

        {/* Central Diamond Node */}
        <div
          className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-2.5 h-2.5 rotate-45 bg-[#050507] border border-[#00E5FF]/70 z-10 transition-shadow ${
            !isReduced && hasSwept ? 'animate-diamond-pulse' : ''
          }`}
        />
      </div>

      {/* Row of Travelling Wave Dots */}
      <div className="mt-3.5 flex items-center justify-center">
        {/* Desktop Dots (48) */}
        <div className="hidden md:flex items-center gap-2.5">
          {Array.from({ length: DESKTOP_DOT_COUNT }).map((_, i) => (
            <span
              key={i}
              className="w-1 h-1 rounded-full bg-[#00E5FF]/40 will-change-transform"
              style={
                isReduced
                  ? { opacity: 0.35 }
                  : {
                      animation: 'dividerDotWave 2.8s ease-in-out infinite',
                      animationDelay: `${i * 0.055}s`,
                      animationPlayState: isInView ? 'running' : 'paused',
                    }
              }
            />
          ))}
        </div>

        {/* Mobile Dots (24) */}
        <div className="flex md:hidden items-center gap-2">
          {Array.from({ length: MOBILE_DOT_COUNT }).map((_, i) => (
            <span
              key={i}
              className="w-1 h-1 rounded-full bg-[#00E5FF]/40 will-change-transform"
              style={
                isReduced
                  ? { opacity: 0.35 }
                  : {
                      animation: 'dividerDotWave 2.8s ease-in-out infinite',
                      animationDelay: `${i * 0.08}s`,
                      animationPlayState: isInView ? 'running' : 'paused',
                    }
              }
            />
          ))}
        </div>
      </div>
    </div>
  );
}

