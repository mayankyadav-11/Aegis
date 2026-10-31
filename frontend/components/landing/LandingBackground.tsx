'use client';

import React, { useEffect, useRef } from 'react';

export function LandingBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const spotlightRef = useRef<HTMLDivElement | null>(null);
  const ringRef = useRef<HTMLDivElement | null>(null);
  const auroraRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    // 1. Check reduced motion and device capabilities
    const prefersReducedMotion = window.matchMedia(
      '(prefers-reduced-motion: reduce)'
    ).matches;
    const isTouch = window.matchMedia('(pointer: coarse)').matches;

    // 2. State & Coordinates (stored in refs/primitives, zero React re-renders)
    const mouse = {
      x: -1000,
      y: -1000,
      targetX: -1000,
      targetY: -1000,
      active: false,
      isHoveringClickable: false,
    };

    const spotlight = {
      x: -1000,
      y: -1000,
    };

    const ring = {
      x: -1000,
      y: -1000,
    };

    let scrollY = window.scrollY;

    // Ripple click ripples
    interface Ripple {
      x: number;
      y: number;
      radius: number;
      maxRadius: number;
      speed: number;
    }
    const ripples: Ripple[] = [];

    // Pointer events
    const handlePointerMove = (e: PointerEvent) => {
      mouse.targetX = e.clientX;
      mouse.targetY = e.clientY;
      mouse.active = true;

      // Check if hovering clickable element for ring scale
      const target = e.target as HTMLElement | null;
      if (target) {
        const clickable = target.closest('a, button, [role="button"], input, textarea');
        mouse.isHoveringClickable = Boolean(clickable);
      }
    };

    const handlePointerLeave = () => {
      mouse.active = false;
      mouse.targetX = -1000;
      mouse.targetY = -1000;
      mouse.isHoveringClickable = false;
    };

    const handleClick = (e: MouseEvent) => {
      if (prefersReducedMotion) return;
      ripples.push({
        x: e.clientX,
        y: e.clientY,
        radius: 0,
        maxRadius: 360,
        speed: 8.5,
      });
      if (ripples.length > 5) ripples.shift();
    };

    const handleScroll = () => {
      scrollY = window.scrollY;
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    document.addEventListener('mouseleave', handlePointerLeave);
    window.addEventListener('click', handleClick, { passive: true });
    window.addEventListener('scroll', handleScroll, { passive: true });

    // 3. Canvas Dot Grid setup
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;
    const SPACING = 30;

    interface Dot {
      baseX: number;
      baseY: number;
      offsetX: number;
      offsetY: number;
      row: number;
      col: number;
    }
    let dots: Dot[] = [];

    const buildGrid = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      width = window.innerWidth;
      height = window.innerHeight;

      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      dots = [];
      const cols = Math.ceil(width / SPACING) + 1;
      const rows = Math.ceil(height / SPACING) + 1;

      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          dots.push({
            baseX: c * SPACING,
            baseY: r * SPACING,
            offsetX: 0,
            offsetY: 0,
            row: r,
            col: c,
          });
        }
      }
    };

    let resizeTimer: NodeJS.Timeout;
    const handleResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        buildGrid();
      }, 150);
    };
    window.addEventListener('resize', handleResize);
    buildGrid();

    // If reduced motion, draw static frame and stop
    if (prefersReducedMotion) {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = 'rgba(154, 154, 174, 0.12)';
      for (let i = 0; i < dots.length; i++) {
        const dot = dots[i];
        ctx.beginPath();
        ctx.arc(dot.baseX, dot.baseY, 1.1, 0, Math.PI * 2);
        ctx.fill();
      }
      return () => {
        window.removeEventListener('pointermove', handlePointerMove);
        document.removeEventListener('mouseleave', handlePointerLeave);
        window.removeEventListener('click', handleClick);
        window.removeEventListener('scroll', handleScroll);
        window.removeEventListener('resize', handleResize);
      };
    }

    // 4. Animation Frame Loop (with 60fps/30fps throttling and visibility pause)
    let animId: number;
    let lastTime = performance.now();
    let isVisible = true;
    const FPS_INTERVAL = 1000 / 60; // 60fps target

    const onVisibilityChange = () => {
      isVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    const loop = (now: number) => {
      animId = requestAnimationFrame(loop);
      if (!isVisible) return;

      const elapsed = now - lastTime;
      if (elapsed < FPS_INTERVAL) return;
      lastTime = now - (elapsed % FPS_INTERVAL);

      // Lerp mouse positions
      const lerpSpeed = 0.15;
      mouse.x += (mouse.targetX - mouse.x) * lerpSpeed;
      mouse.y += (mouse.targetY - mouse.y) * lerpSpeed;

      // Update Cursor Spotlight (lagged follow)
      if (spotlightRef.current && !isTouch) {
        spotlight.x += (mouse.targetX - spotlight.x) * 0.08;
        spotlight.y += (mouse.targetY - spotlight.y) * 0.08;
        spotlightRef.current.style.transform = `translate3d(${spotlight.x - 225}px, ${spotlight.y - 225}px, 0)`;
        spotlightRef.current.style.opacity = mouse.active ? '1' : '0';
      }

      // Update Cursor Ring
      if (ringRef.current && !isTouch) {
        ring.x += (mouse.targetX - ring.x) * 0.35;
        ring.y += (mouse.targetY - ring.y) * 0.35;
        const ringScale = mouse.isHoveringClickable ? 2.1 : 1;
        ringRef.current.style.transform = `translate3d(${ring.x - 10}px, ${ring.y - 10}px, 0) scale(${ringScale})`;
        ringRef.current.style.borderColor = mouse.isHoveringClickable
          ? '#7B3FE4'
          : '#00E5FF';
        ringRef.current.style.opacity = mouse.active ? '0.85' : '0';
      }

      // Update Aurora Parallax Shift
      if (auroraRef.current) {
        const centerOffsetX = (mouse.x - width / 2) * 0.035;
        const centerOffsetY = (mouse.y - height / 2) * 0.035;
        const scrollShiftY = scrollY * 0.06;
        auroraRef.current.style.transform = `translate3d(${centerOffsetX}px, ${centerOffsetY - scrollShiftY}px, 0)`;
      }

      // 5. Update & Render Ripples
      for (let rIdx = ripples.length - 1; rIdx >= 0; rIdx--) {
        const rip = ripples[rIdx];
        rip.radius += rip.speed;
        if (rip.radius >= rip.maxRadius) {
          ripples.splice(rIdx, 1);
        }
      }

      // 6. Render Dot Grid
      ctx.clearRect(0, 0, width, height);

      const timeSec = now * 0.001;
      const INTERACTION_RADIUS = 160;
      const RADIUS_SQ = INTERACTION_RADIUS * INTERACTION_RADIUS;

      // Batch dots for performance
      const baseDots: [number, number, number][] = [];
      const brightDots: [number, number, number, number, number][] = []; // x, y, r, cyanFactor, spotlightFactor

      for (let i = 0; i < dots.length; i++) {
        const dot = dots[i];

        // Ambient idle wave (very subtle sinusoidal breath)
        const wave =
          Math.sin(dot.col * 0.18 + dot.row * 0.14 + timeSec * 1.2) * 1.8;

        // Proximity calculation to cursor
        const dx = dot.baseX - mouse.x;
        const dy = dot.baseY - mouse.y;
        const distSq = dx * dx + dy * dy;

        let targetDispX = 0;
        let targetDispY = 0;
        let proximityFactor = 0;

        if (mouse.active && distSq < RADIUS_SQ) {
          const dist = Math.sqrt(distSq);
          proximityFactor = 1 - dist / INTERACTION_RADIUS;
          const pushAmount = proximityFactor * 14;
          const angle = Math.atan2(dy, dx);
          targetDispX = Math.cos(angle) * pushAmount;
          targetDispY = Math.sin(angle) * pushAmount;
        }

        // Ripple displacement calculation
        for (let j = 0; j < ripples.length; j++) {
          const rip = ripples[j];
          const rdx = dot.baseX - rip.x;
          const rdy = dot.baseY - rip.y;
          const rDist = Math.hypot(rdx, rdy);
          const diff = Math.abs(rDist - rip.radius);
          if (diff < 35) {
            const ripForce = (1 - diff / 35) * (1 - rip.radius / rip.maxRadius) * 12;
            const ripAngle = Math.atan2(rdy, rdx);
            targetDispX += Math.cos(ripAngle) * ripForce;
            targetDispY += Math.sin(ripAngle) * ripForce;
          }
        }

        // Spring-back damping physics
        dot.offsetX += (targetDispX - dot.offsetX) * 0.18;
        dot.offsetY += (targetDispY - dot.offsetY) * 0.18;

        const renderX = dot.baseX + dot.offsetX;
        const renderY = dot.baseY + dot.offsetY + wave;

        // Flashlight spotlight proximity
        const sDx = renderX - spotlight.x;
        const sDy = renderY - spotlight.y;
        const sDistSq = sDx * sDx + sDy * sDy;
        const spotlightFactor =
          mouse.active && sDistSq < 50000
            ? (1 - Math.sqrt(sDistSq) / 225) * 0.4
            : 0;

        if (proximityFactor > 0.02 || spotlightFactor > 0.05) {
          const radius = 1.1 + proximityFactor * 1.4 + spotlightFactor * 0.6;
          brightDots.push([renderX, renderY, radius, proximityFactor, spotlightFactor]);
        } else {
          baseDots.push([renderX, renderY, 1.05]);
        }
      }

      // Draw resting faint dots in single batch
      if (baseDots.length > 0) {
        ctx.fillStyle = 'rgba(123, 63, 228, 0.14)';
        ctx.beginPath();
        for (let i = 0; i < baseDots.length; i++) {
          const [x, y, r] = baseDots[i];
          ctx.moveTo(x + r, y);
          ctx.arc(x, y, r, 0, Math.PI * 2);
        }
        ctx.fill();
      }

      // Draw brightened dots near cursor / spotlight
      for (let i = 0; i < brightDots.length; i++) {
        const [x, y, r, prox, spot] = brightDots[i];
        const cyanAlpha = Math.min(0.48, 0.14 + prox * 0.32 + spot * 0.2);
        ctx.fillStyle = `rgba(0, 229, 255, ${cyanAlpha})`;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fill();
      }
    };

    animId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('pointermove', handlePointerMove);
      document.removeEventListener('mouseleave', handlePointerLeave);
      window.removeEventListener('click', handleClick);
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleResize);
      document.removeEventListener('visibilitychange', onVisibilityChange);
      clearTimeout(resizeTimer);
    };
  }, []);

  return (
    <div
      aria-hidden="true"
      className="fixed inset-0 w-full h-full pointer-events-none overflow-hidden z-0"
    >
      {/* LAYER 1: AURORA (CSS Radial Blobs with ambient drift keyframes & parallax) */}
      <div
        ref={auroraRef}
        className="absolute inset-0 w-full h-full pointer-events-none will-change-transform transition-transform duration-100 ease-out"
      >
        {/* Blob 1: Amethyst Drift */}
        <div
          className="absolute -top-[10%] -left-[10%] w-[680px] h-[680px] rounded-full opacity-[0.16] animate-aurora-slow"
          style={{
            background:
              'radial-gradient(circle, rgba(123, 63, 228, 0.45) 0%, rgba(123, 63, 228, 0.12) 50%, transparent 70%)',
          }}
        />

        {/* Blob 2: Cyan Drift */}
        <div
          className="absolute top-[35%] -right-[12%] w-[720px] h-[720px] rounded-full opacity-[0.14] animate-aurora-reverse"
          style={{
            background:
              'radial-gradient(circle, rgba(0, 229, 255, 0.38) 0%, rgba(0, 229, 255, 0.09) 50%, transparent 70%)',
          }}
        />

        {/* Blob 3: Center Amethyst-Cyan Blend */}
        <div
          className="absolute -bottom-[15%] left-[25%] w-[820px] h-[820px] rounded-full opacity-[0.12] animate-aurora-mid"
          style={{
            background:
              'radial-gradient(circle, rgba(123, 63, 228, 0.35) 0%, rgba(0, 229, 255, 0.15) 45%, transparent 70%)',
          }}
        />
      </div>

      {/* LAYER 2: REACTIVE CANVAS DOT GRID */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full block pointer-events-none"
      />

      {/* LAYER 3A: CURSOR SPOTLIGHT (Soft flashlight glow following cursor) */}
      <div
        ref={spotlightRef}
        className="absolute top-0 left-0 w-[450px] h-[450px] rounded-full pointer-events-none opacity-0 transition-opacity duration-300 will-change-transform"
        style={{
          background:
            'radial-gradient(circle, rgba(0, 229, 255, 0.08) 0%, rgba(123, 63, 228, 0.05) 40%, transparent 70%)',
        }}
      />

      {/* LAYER 3B: INTERACTIVE CURSOR RING (Scales up over clickable elements) */}
      <div
        ref={ringRef}
        className="absolute top-0 left-0 w-5 h-5 rounded-full border border-[#00E5FF] pointer-events-none opacity-0 transition-all duration-150 ease-out will-change-transform"
      />
    </div>
  );
}

