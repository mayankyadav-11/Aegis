'use client';

import React, {
  createContext,
  useContext,
  useState,
  useRef,
  useEffect,
  useCallback,
} from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';

interface TransitionOrigin {
  x: number;
  y: number;
}

interface TransitionContextValue {
  startTransition: (href: string, origin?: TransitionOrigin) => void;
  isTransitioning: boolean;
}

const TransitionContext = createContext<TransitionContextValue>({
  startTransition: () => {},
  isTransitioning: false,
});

export function usePageTransition() {
  return useContext(TransitionContext);
}

export function TransitionProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();

  const [isTransitioning, setIsTransitioning] = useState(false);
  const [stage, setStage] = useState<'idle' | 'expanding' | 'holding' | 'retracting'>('idle');
  const [origin, setOrigin] = useState<TransitionOrigin>({ x: 0, y: 0 });
  const [targetScale, setTargetScale] = useState(25);

  const pendingHref = useRef<string | null>(null);
  const routeChangedRef = useRef(false);
  const safetyTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const minHoldTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Clean up all timers and unlock scroll
  const cleanup = useCallback(() => {
    if (safetyTimeoutRef.current) clearTimeout(safetyTimeoutRef.current);
    if (minHoldTimeoutRef.current) clearTimeout(minHoldTimeoutRef.current);
    safetyTimeoutRef.current = null;
    minHoldTimeoutRef.current = null;
    if (typeof document !== 'undefined') {
      document.body.style.overflow = '';
    }
  }, []);

  // Finish and retract overlay
  const finishTransition = useCallback(() => {
    setStage('retracting');
    setTimeout(() => {
      setIsTransitioning(false);
      setStage('idle');
      pendingHref.current = null;
      routeChangedRef.current = false;
      cleanup();
    }, 350);
  }, [cleanup]);

  // Track pathname changes to detect when the new route has rendered
  useEffect(() => {
    if (!isTransitioning || !pendingHref.current) return;

    if (pathname === pendingHref.current || pathname.startsWith(pendingHref.current)) {
      routeChangedRef.current = true;

      // Wait minimum 200ms after route render before retracting
      minHoldTimeoutRef.current = setTimeout(() => {
        finishTransition();
      }, 200);
    }
  }, [pathname, isTransitioning, finishTransition]);

  // Safety cleanup on unmount
  useEffect(() => {
    return () => cleanup();
  }, [cleanup]);

  const startTransition = useCallback(
    (href: string, clickOrigin?: TransitionOrigin) => {
      if (isTransitioning) return; // Prevent duplicate clicks

      // Prefetch destination immediately
      router.prefetch(href);

      // Check prefers-reduced-motion
      if (
        typeof window !== 'undefined' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches
      ) {
        router.push(href);
        return;
      }

      // Calculate origin coordinates safely
      const winW = typeof window !== 'undefined' ? window.innerWidth : 1920;
      const winH = typeof window !== 'undefined' ? window.innerHeight : 1080;
      const ox = clickOrigin ? clickOrigin.x : winW / 2;
      const oy = clickOrigin ? clickOrigin.y : winH / 2;

      // Base circle radius is 140px. Compute scale needed to cover the furthest corner
      const maxCornerDist = Math.hypot(Math.max(ox, winW - ox), Math.max(oy, winH - oy));
      const neededScale = (maxCornerDist / 140) * 1.08;

      setOrigin({ x: ox, y: oy });
      setTargetScale(Math.max(12, neededScale));
      setIsTransitioning(true);
      setStage('expanding');
      pendingHref.current = href;
      routeChangedRef.current = false;

      // Lock scroll during transition
      if (typeof document !== 'undefined') {
        document.body.style.overflow = 'hidden';
      }

      // Safety timeout: retract after 2.5s if navigation stalls
      safetyTimeoutRef.current = setTimeout(() => {
        if (!routeChangedRef.current) {
          router.push(href);
        }
        finishTransition();
      }, 2500);

      // At ~420ms (when circle expands to full coverage), trigger route push
      setTimeout(() => {
        setStage('holding');
        router.push(href);
      }, 420);
    },
    [isTransitioning, router, finishTransition]
  );

  return (
    <TransitionContext.Provider value={{ startTransition, isTransitioning }}>
      {children}

      {/* Transition Overlay */}
      <AnimatePresence>
        {isTransitioning && (
          <div
            className="fixed inset-0 z-[9999] pointer-events-auto overflow-hidden select-none"
            aria-hidden="true"
          >
            {/* 1. Expanding & Retracting Circle (Pure Transform & Opacity) */}
            <motion.div
              initial={{ scale: 0, opacity: 1 }}
              animate={
                stage === 'retracting'
                  ? { scale: targetScale, opacity: 0 }
                  : { scale: targetScale, opacity: 1 }
              }
              transition={
                stage === 'retracting'
                  ? { duration: 0.35, ease: 'easeOut' }
                  : { duration: 0.44, ease: [0.22, 1, 0.36, 1] }
              }
              style={{
                position: 'absolute',
                left: origin.x,
                top: origin.y,
                width: 280,
                height: 280,
                marginLeft: -140,
                marginTop: -140,
                borderRadius: '9999px',
                backgroundColor: '#050507',
                boxShadow:
                  '0 0 0 2px rgba(123, 63, 228, 0.7), 0 0 20px rgba(0, 229, 255, 0.5), inset 0 0 30px rgba(123, 63, 228, 0.3)',
                willChange: 'transform, opacity',
              }}
            />

            {/* 2. Interior Elements (Dot Grid, Shield SVG, Scan Line, Mono Text) */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={stage === 'retracting' ? { opacity: 0, scale: 0.92 } : { opacity: 1, scale: 1 }}
              transition={{ duration: stage === 'retracting' ? 0.25 : 0.3 }}
              className="absolute inset-0 flex flex-col items-center justify-center will-change-transform"
            >
              {/* Faint Dot Grid */}
              <div
                className="absolute inset-0 pointer-events-none opacity-40"
                style={{
                  backgroundImage: 'radial-gradient(rgba(0, 229, 255, 0.3) 1px, transparent 1px)',
                  backgroundSize: '24px 24px',
                }}
              />

              {/* Cyan Scan Line Sweeping Across */}
              <motion.div
                initial={{ y: '-10vh', opacity: 0 }}
                animate={{ y: '110vh', opacity: [0, 1, 1, 0] }}
                transition={{ duration: 0.85, delay: 0.25, ease: 'easeInOut' }}
                className="absolute left-0 right-0 h-[2px] pointer-events-none"
                style={{
                  background:
                    'linear-gradient(90deg, transparent 0%, rgba(123,63,228,0.5) 20%, #00E5FF 50%, rgba(123,63,228,0.5) 80%, transparent 100%)',
                  boxShadow: '0 0 16px #00E5FF, 0 0 32px rgba(0,229,255,0.4)',
                }}
              />

              {/* Center Shield Graphic */}
              <div className="relative z-10 flex flex-col items-center">
                <div className="relative w-20 h-20 md:w-24 md:h-24 flex items-center justify-center">
                  {/* Subtle Glow behind Shield */}
                  <div
                    className="absolute inset-0 rounded-full blur-xl opacity-50"
                    style={{
                      background: 'radial-gradient(circle, rgba(0,229,255,0.4) 0%, rgba(123,63,228,0.2) 70%, transparent 100%)',
                    }}
                  />

                  {/* AEGIS Shield SVG with Stroke Draw */}
                  <svg
                    viewBox="0 0 24 24"
                    className="w-16 h-16 md:w-20 md:h-20 text-[#00E5FF] relative z-10"
                    fill="none"
                  >
                    {/* Outer Shield Outline */}
                    <motion.path
                      d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
                      stroke="#00E5FF"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      initial={{ pathLength: 0, opacity: 0 }}
                      animate={{ pathLength: 1, opacity: 1 }}
                      transition={{ duration: 0.55, delay: 0.2, ease: 'easeInOut' }}
                    />
                    {/* Inner Amethyst Check Mark */}
                    <motion.path
                      d="m9 12 2 2 4-4"
                      stroke="#7B3FE4"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      initial={{ pathLength: 0, opacity: 0 }}
                      animate={{ pathLength: 1, opacity: 1 }}
                      transition={{ duration: 0.35, delay: 0.5, ease: 'easeOut' }}
                    />
                  </svg>
                </div>

                {/* Static Mono Status Text */}
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.4 }}
                  className="mt-6 flex flex-col items-center gap-1.5"
                >
                  <span className="font-mono text-xs sm:text-sm font-semibold tracking-[0.2em] uppercase text-[#00E5FF]">
                    Initialising console...
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.14em] uppercase text-[#9A9AAE]">
                    AEGIS Forensic Workbench
                  </span>
                </motion.div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </TransitionContext.Provider>
  );
}

/**
 * TransitionLink component: renders an interactive button/link that triggers
 * the radial expansion overlay from the click origin when navigating to /analyze.
 */
export function TransitionLink({
  href,
  onClick,
  children,
  className = '',
  ...props
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  const { startTransition, isTransitioning } = usePageTransition();
  const [isPressed, setIsPressed] = useState(false);

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented) return;

    if (href === '/analyze' || href.startsWith('/analyze')) {
      e.preventDefault();
      if (isTransitioning) return;

      setIsPressed(true);
      setTimeout(() => setIsPressed(false), 250);

      const rect = e.currentTarget.getBoundingClientRect();
      const origin = {
        x: e.clientX && e.clientX > 0 ? e.clientX : rect.left + rect.width / 2,
        y: e.clientY && e.clientY > 0 ? e.clientY : rect.top + rect.height / 2,
      };

      startTransition(href, origin);
    }
  };

  return (
    <a
      href={href}
      onClick={handleClick}
      className={`${className} ${isPressed ? 'scale-95 shadow-[0_0_25px_rgba(0,229,255,0.6)]' : ''} transition-transform duration-150`}
      {...props}
    >
      {children}
    </a>
  );
}

