'use client';

import React, { useEffect, useRef, useState } from 'react';

// Higgsfield hand source sheet
const LOCAL_IMAGE_URL = '/hands.webp';
const REMOTE_IMAGE_URL =
  'https://images.higgs.ai/?default=1&output=webp&url=https%3A%2F%2Fd8j0ntlcm91z4.cloudfront.net%2Fuser_38xzZboKViGWJOttwIXH07lWA1P%2Fhf_20261030_025250_100df7b8-31fd-4614-aa4a-c1b7d5b6b273.png&w=1600&q=85';

// Sheet fractions [x, y, w, h]
const RECT_LA = [0, 0.06, 0.47, 0.40] as const;
const RECT_RA = [0.53, 0.06, 0.47, 0.40] as const;
const RECT_LB = [0, 0.55, 0.47, 0.40] as const;
const RECT_RB = [0.53, 0.55, 0.47, 0.40] as const;

function hash(a: number, b: number): number {
  const s = Math.sin(a * 127.1 + b * 311.7) * 43758.5453;
  return s - Math.floor(s);
}

function smooth(a: number, b: number, x: number): number {
  const t = Math.max(0, Math.min(1, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
}

function mixAt(t: number, on: number, off: number, dur: number): number {
  return smooth(on, on + dur, t) * (1 - smooth(off, off + dur, t));
}

export function DotMatrixHands() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [imageLoaded, setImageLoaded] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let isTabVisible = true;
    let isIntersecting = true;
    let prefersReducedMotion = false;
    let loopStartTime = performance.now();

    // Check prefers-reduced-motion
    if (typeof window !== 'undefined' && window.matchMedia) {
      prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    // Four downscaled tile canvases (420px wide)
    let tileLA: HTMLCanvasElement | null = null;
    let tileRA: HTMLCanvasElement | null = null;
    let tileLB: HTMLCanvasElement | null = null;
    let tileRB: HTMLCanvasElement | null = null;

    // Offscreen field canvases
    const fieldACanvas = document.createElement('canvas');
    const fieldBCanvas = document.createElement('canvas');
    const fA = fieldACanvas.getContext('2d', { willReadFrequently: true });
    const fB = fieldBCanvas.getContext('2d', { willReadFrequently: true });

    let W = 0;
    let H = 0;
    let cols = 0;
    let rows = 0;
    let step = 0;
    let rowStep = 0;
    let baseRadius = 0;
    let seeds: Float32Array = new Float32Array(0);

    const createTile = (
      img: HTMLImageElement,
      rect: readonly [number, number, number, number]
    ): HTMLCanvasElement => {
      const tile = document.createElement('canvas');
      const targetW = 420;
      const srcX = rect[0] * img.width;
      const srcY = rect[1] * img.height;
      const srcW = rect[2] * img.width;
      const srcH = rect[3] * img.height;
      const targetH = Math.round(targetW * (srcH / srcW));

      tile.width = targetW;
      tile.height = targetH;
      const tCtx = tile.getContext('2d');
      if (tCtx) {
        tCtx.imageSmoothingQuality = 'high';
        tCtx.drawImage(img, srcX, srcY, srcW, srcH, 0, 0, targetW, targetH);
      }
      return tile;
    };

    const handleResize = () => {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      W = rect.width;
      H = rect.height;
      if (W === 0 || H === 0) return;

      const dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      step = Math.max(5, W / 205);
      rowStep = step * 2.05;
      cols = Math.ceil(W / step);
      rows = Math.ceil(H / rowStep);
      baseRadius = step * 0.46;

      fieldACanvas.width = cols;
      fieldACanvas.height = rows;
      fieldBCanvas.width = cols;
      fieldBCanvas.height = rows;

      // Precompute per-cell seeds
      seeds = new Float32Array(cols * rows);
      for (let j = 0; j < rows; j++) {
        for (let i = 0; i < cols; i++) {
          seeds[j * cols + i] = 0.55 * hash(i, j) + 0.45 * hash(j * 3.1, 7.7);
        }
      }
    };

    const render = (timeSec: number) => {
      if (!ctx || !fA || !fB || !tileLA || !tileRA || !tileLB || !tileRB) return;
      if (cols === 0 || rows === 0 || W === 0 || H === 0) return;

      const LOOP = 20;
      const t = timeSec % LOOP;
      const a = (2 * Math.PI * t) / LOOP;
      const isPortrait = H > W;

      const SHEET_ASPECT = (0.4 * 1520) / (0.47 * 2688);
      const targetHwFromW = isPortrait ? W * 0.66 : W * 0.53;
      // If the hands zone is short, uniformly scale down to keep full hands visible without cropping
      const targetHwFromH = (H * 0.78) / SHEET_ASPECT;
      const hw = Math.min(targetHwFromW, targetHwFromH);
      const hh = hw * SHEET_ASPECT;
      const cy = isPortrait ? Math.min(H * 0.60, H - hh * 0.52) : H * 0.50;

      // 1. Clear offscreen fields with white
      fA.fillStyle = '#ffffff';
      fA.fillRect(0, 0, cols, rows);
      fB.fillStyle = '#ffffff';
      fB.fillRect(0, 0, cols, rows);

      // Draw hand helper
      const drawHand = (
        fCtx: CanvasRenderingContext2D,
        tile: HTMLCanvasElement,
        isLeft: boolean
      ) => {
        const ph = isLeft ? 0 : Math.PI;
        const reach =
          (0.035 * Math.sin(a + ph) + 0.012 * Math.sin(2 * a + 1.3 + ph)) * W;
        const scale = 1 + 0.07 * Math.sin(a + 0.9 + ph);
        const rot = (isLeft ? 1 : -1) * 0.045 * Math.sin(a + 2.1 + ph);
        const x = isLeft ? reach - W * 0.045 : W - hw + W * 0.045 - reach;
        const px = isLeft ? 0 : W;
        const py = cy;

        fCtx.save();
        fCtx.scale(cols / W, rows / H);
        fCtx.translate(px, py);
        fCtx.rotate(rot);
        fCtx.scale(scale, scale);
        fCtx.translate(-px, -py);
        fCtx.drawImage(tile, x, cy - hh / 2, hw, hh);
        fCtx.restore();
      };

      // Draw Pose A into fA and Pose B into fB
      drawHand(fA, tileLA, true);
      drawHand(fA, tileRA, false);
      drawHand(fB, tileLB, true);
      drawHand(fB, tileRB, false);

      const dataA = fA.getImageData(0, 0, cols, rows).data;
      const dataB = fB.getImageData(0, 0, cols, rows).data;

      // Pose mix curves
      const mL = mixAt(t, 6.2, 14.6, 1.6);
      const mR = mixAt(t, 2.4, 10.4, 1.6);
      const halfCols = Math.floor(cols / 2);
      const tick = Math.floor(t * 7);

      // 2. Clear canvas to transparent so LandingBackground shows through
      ctx.clearRect(0, 0, W, H);

      // Row glitch precomputation
      const rowShifts = new Int32Array(rows);
      for (let j = 0; j < rows; j++) {
        if (hash(j, tick) > 0.965) {
          rowShifts[j] = Math.round((hash(tick, j) - 0.5) * 8);
        } else {
          rowShifts[j] = 0;
        }
      }

      // Group dot paths by color and size level for high performance batch rendering
      // Colors: Left = Amethyst (#7B3FE4), Right = Electric Cyan (#00E5FF)
      const amethystDots: [number, number, number][] = [];
      const cyanDots: [number, number, number][] = [];

      for (let j = 0; j < rows; j++) {
        const shift = rowShifts[j];
        const rowCenterY = (j + 0.5) * rowStep;

        for (let i = 0; i < cols; i++) {
          const sampleI = Math.max(0, Math.min(cols - 1, i - shift));
          const cellIdx = j * cols + i;
          const sampleIdx = (j * cols + sampleI) * 4;
          const seed = seeds[cellIdx];

          const isLeft = i < halfCols;
          const m = isLeft ? mL : mR;
          const useB = seed < m;
          const lum = (useB ? dataB[sampleIdx] : dataA[sampleIdx]) / 255;

          // Luminance mapping
          let v = (1 - lum - 0.16) / 0.42;
          if (v <= 0) continue;
          v = Math.min(1, Math.max(0, v));

          // Glitch front flicker
          if (m > 0.001 && m < 0.999) {
            const diff = Math.abs(seed - m);
            if (diff < 0.12) {
              v *= diff / 0.12;
              if (hash(i + tick, j) <= 0.4) {
                v *= 0.3;
              }
            }
          }

          // Shimmer
          v *= 0.86 + 0.14 * Math.sin(t * 3.2 + seed * 40);

          // Centre fade (fingertips dissolve before center)
          const cx = Math.abs((i + 0.5) / cols - 0.5);
          v *= smooth(0.035, 0.11, cx);

          // Copy quiet zone
          const quietCenterX = isPortrait ? 0.44 : 0.20;
          const quietCenterY = isPortrait ? 0.33 : 0.385;
          const ex = cx / quietCenterX;
          const ey = (rowCenterY / H - quietCenterY) / 0.085;
          v *= smooth(0.85, 1.25, Math.hypot(ex, ey));

          if (v <= 0.13) continue;

          // Quantise into 5 discrete levels [0, 0.26, 0.52, 0.78, 1.0]
          let level = 0;
          if (v >= 1.0 - 0.13) level = 1.0;
          else if (v >= 0.78 - 0.13) level = 0.78;
          else if (v >= 0.52 - 0.13) level = 0.52;
          else if (v >= 0.26 - 0.13) level = 0.26;

          if (level === 0) continue;

          const dotRadius = level === 0.26 ? baseRadius * 0.38 : baseRadius * level;
          const dotCenterX = (i + 0.5) * step;

          if (isLeft) {
            amethystDots.push([dotCenterX, rowCenterY, dotRadius]);
          } else {
            cyanDots.push([dotCenterX, rowCenterY, dotRadius]);
          }
        }
      }

      // Render Left Hand in Royal Amethyst #7B3FE4
      if (amethystDots.length > 0) {
        ctx.fillStyle = '#7B3FE4';
        ctx.beginPath();
        for (let idx = 0; idx < amethystDots.length; idx++) {
          const [x, y, r] = amethystDots[idx];
          ctx.moveTo(x + r, y);
          ctx.arc(x, y, r, 0, Math.PI * 2);
        }
        ctx.fill();
      }

      // Render Right Hand in Electric Cyan #00E5FF
      if (cyanDots.length > 0) {
        ctx.fillStyle = '#00E5FF';
        ctx.beginPath();
        for (let idx = 0; idx < cyanDots.length; idx++) {
          const [x, y, r] = cyanDots[idx];
          ctx.moveTo(x + r, y);
          ctx.arc(x, y, r, 0, Math.PI * 2);
        }
        ctx.fill();
      }
    };

    // Expose render function for testing / deterministic recorder
    (window as unknown as { __render?: (t: number) => void }).__render = render;

    // Load hand image
    const img = new Image();
    img.crossOrigin = 'anonymous';

    const onImageReady = () => {
      tileLA = createTile(img, RECT_LA);
      tileRA = createTile(img, RECT_RA);
      tileLB = createTile(img, RECT_LB);
      tileRB = createTile(img, RECT_RB);
      setImageLoaded(true);
      handleResize();

      if (prefersReducedMotion) {
        // Render single static frame at t = 2.0s
        render(2.0);
      } else {
        const loop = (now: number) => {
          if (isTabVisible && isIntersecting) {
            const elapsed = (now - loopStartTime) / 1000;
            render(elapsed);
          }
          animId = requestAnimationFrame(loop);
        };
        animId = requestAnimationFrame(loop);
      }
    };

    img.onload = onImageReady;
    img.onerror = () => {
      // Fallback to remote URL
      if (img.src !== REMOTE_IMAGE_URL) {
        img.src = REMOTE_IMAGE_URL;
      }
    };
    img.src = LOCAL_IMAGE_URL;

    // Intersection observer to pause loop when off-screen
    const observer = new IntersectionObserver(
      ([entry]) => {
        isIntersecting = entry.isIntersecting;
      },
      { threshold: 0 }
    );
    observer.observe(canvas);

    // ResizeObserver for exact container sizing in flexbox
    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && canvas.parentElement) {
      resizeObserver = new ResizeObserver(() => {
        handleResize();
      });
      resizeObserver.observe(canvas.parentElement);
    }

    // Page visibility listener
    const handleVisibilityChange = () => {
      isTabVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('resize', handleResize);

    return () => {
      if (animId) cancelAnimationFrame(animId);
      observer.disconnect();
      if (resizeObserver) resizeObserver.disconnect();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <div className="absolute inset-0 w-full h-full bg-transparent pointer-events-none overflow-hidden">
      <canvas
        ref={canvasRef}
        id="dots"
        className={`w-full h-full block bg-transparent pointer-events-none transition-opacity duration-700 ${
          imageLoaded ? 'opacity-100' : 'opacity-0'
        }`}
      />
    </div>
  );
}
