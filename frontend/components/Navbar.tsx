'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';

interface SectionLink {
  label: string;
  id: string;
}

const LANDING_SECTIONS: SectionLink[] = [
  { label: 'The problem', id: 'problem' },
  { label: 'What AEGIS is', id: 'story' },
  { label: 'Try it yourself', id: 'try' },
  { label: 'Questions', id: 'faq' },
];

export function Navbar() {
  const pathname = usePathname();
  const isLanding = pathname === '/';

  const [activeSection, setActiveSection] = useState<string>('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  // App-specific navigation tabs
  const appNavLinks = [
    {
      label: 'Dashboard',
      href: '/dashboard',
      isActive: pathname.startsWith('/dashboard'),
    },
    {
      label: 'Analyse',
      href: '/analyze',
      isActive:
        pathname.startsWith('/analyze') ||
        pathname.startsWith('/results') ||
        pathname.startsWith('/verify'),
    },
    {
      label: 'Metrics',
      href: '/metrics',
      isActive: pathname.startsWith('/metrics'),
    },
  ];

  // Hero scroll-spy clearing when scrolled back into hero zone
  useEffect(() => {
    if (!isLanding) return;

    const handleScroll = () => {
      // While hero is in view (before problem scene enters under header), no nav link is highlighted
      const problemEl = document.getElementById('problem');
      const headerH = window.innerWidth >= 768 ? 72 : 60;
      if (problemEl) {
        const rect = problemEl.getBoundingClientRect();
        if (rect.top > headerH + 15) {
          setActiveSection((prev) => (prev ? '' : prev));
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, [isLanding]);

  // Scroll-spy observer for landing sections using header height as rootMargin offset
  useEffect(() => {
    if (!isLanding) return;

    const sectionElements = LANDING_SECTIONS.map((sec) =>
      document.getElementById(sec.id)
    ).filter(Boolean) as HTMLElement[];

    if (sectionElements.length === 0) return;

    const headerH = window.innerWidth >= 768 ? 72 : 60;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      {
        rootMargin: `-${headerH}px 0px -55% 0px`,
        threshold: 0,
      }
    );

    sectionElements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, [isLanding]);

  // Close mobile menu on Escape key and outside click
  useEffect(() => {
    if (!isMobileMenuOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsMobileMenuOpen(false);
      }
    };

    const handleClickOutside = (e: MouseEvent) => {
      if (
        mobileMenuRef.current &&
        !mobileMenuRef.current.contains(e.target as Node)
      ) {
        setIsMobileMenuOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isMobileMenuOpen]);

  // Smooth scroll handler using Lenis instance
  const scrollToTarget = (target: HTMLElement | number, offset: number = 0) => {
    const lenis = (window as any).__lenis;
    const prefersReduced = window.matchMedia(
      '(prefers-reduced-motion: reduce)'
    ).matches;

    if (lenis && !prefersReduced) {
      lenis.scrollTo(target, { offset });
    } else {
      if (typeof target === 'number') {
        window.scrollTo({ top: target, behavior: prefersReduced ? 'auto' : 'smooth' });
      } else {
        target.scrollIntoView({ behavior: prefersReduced ? 'auto' : 'smooth' });
      }
    }
  };

  const handleLogoClick = (e: React.MouseEvent) => {
    if (isLanding) {
      e.preventDefault();
      setIsMobileMenuOpen(false);
      scrollToTarget(0);
    }
  };

  const handleSectionLinkClick = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    setIsMobileMenuOpen(false);
    const target = document.getElementById(id);
    if (!target) return;

    // Header height is 80px on desktop, 64px on mobile
    const headerHeight = window.innerWidth >= 768 ? 80 : 64;
    scrollToTarget(target, -headerHeight);
  };

  /* ─────────────────────────────────────────────────────────────
     1. APP HEADER: Rendered on internal pages (/analyze, /dashboard, etc.)
     Preserved exactly as-is
  ───────────────────────────────────────────────────────────── */
  if (!isLanding) {
    return (
      <header className="relative z-20 w-full pt-7 md:pt-9 px-5 md:px-10">
        <div className="max-w-6xl mx-auto grid grid-cols-[1fr_auto_1fr] items-center">
          {/* Brand: Shield Mark + AEGIS (Links to '/') */}
          <Link
            href="/"
            className="flex items-center gap-2.5 text-[15px] font-semibold tracking-tight text-[#E6E6EA] group transition-opacity hover:opacity-90 justify-self-start"
          >
            <div className="relative flex items-center justify-center w-7 h-7 rounded-md bg-[#0D0D12] border border-[#1C1C26] shadow-inner group-hover:border-[#7B3FE4]/50 transition-colors">
              <svg
                className="w-4 h-4 text-[#00E5FF] transition-transform group-hover:scale-105"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" stroke="#7B3FE4" strokeWidth="2.5" />
              </svg>
            </div>
            <span className="font-heading tracking-[0.08em] font-bold text-sm text-[#E6E6EA]">
              AEGIS
            </span>
          </Link>

          {/* Nav Tabs with sliding active indicator — centred */}
          <nav className="flex items-center gap-2 sm:gap-5 lg:gap-7 font-body text-[13px] sm:text-[14px] font-medium text-[#9A9AAE]">
            {appNavLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="relative py-1.5 px-3 rounded-lg transition-colors duration-200 hover:text-[#E6E6EA] group select-none"
              >
                {link.isActive && (
                  <motion.span
                    layoutId="appHeaderActiveIndicator"
                    className="absolute bottom-0 left-2 right-2 h-[2px] bg-gradient-to-r from-[#7B3FE4] to-[#00E5FF] rounded-full shadow-[0_0_12px_rgba(0,229,255,0.7)]"
                    transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                  />
                )}
                {/* Soft hover glow */}
                <span className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 bg-gradient-to-r from-[#7B3FE4]/10 to-[#00E5FF]/10 pointer-events-none" />
                <span
                  className={`relative z-10 transition-colors duration-200 ${
                    link.isActive ? 'text-[#00E5FF] font-semibold' : ''
                  }`}
                >
                  {link.label}
                </span>
              </Link>
            ))}
          </nav>

          {/* Right slot — empty, keeps nav centred */}
          <div className="justify-self-end" />
        </div>
      </header>
    );
  }

  /* ─────────────────────────────────────────────────────────────
     2. LANDING PAGE HEADER: Transparent overlay, logo on left,
     compact nav pill on right, mobile menu-button pill
  ───────────────────────────────────────────────────────────── */
  return (
    <header className="fixed top-0 left-0 right-0 z-40 w-full h-[var(--landing-header-h)] px-5 md:px-10 flex items-center bg-transparent pointer-events-none">
      <div className="max-w-6xl mx-auto w-full flex items-center justify-between">
        {/* Logo (left, on its own with pointer-events-auto and no background) */}
        <Link
          href="/"
          onClick={handleLogoClick}
          className="pointer-events-auto flex items-center gap-2.5 sm:gap-3 group focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00E5FF] rounded-lg select-none"
          aria-label="AEGIS home - scroll to top"
        >
          {/* Logo icon: ~44px desktop, ~36px mobile */}
          <div className="relative flex items-center justify-center w-9 h-9 md:w-11 md:h-11">
            <svg
              className="w-9 h-9 md:w-11 md:h-11 text-[#00E5FF] transition-transform duration-200 group-hover:scale-105"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" stroke="#7B3FE4" strokeWidth="2.5" />
            </svg>
          </div>

          {/* Wordmark: ~26px desktop, ~21px mobile */}
          <span className="font-heading font-bold text-[21px] md:text-[26px] tracking-[0.08em] text-[#E6E6EA] group-hover:text-white transition-colors">
            AEGIS
          </span>
        </Link>

        {/* Desktop Compact Nav Pill (right, hidden under 768px) */}
        <nav
          aria-label="Landing page sections"
          className="pointer-events-auto hidden md:flex items-center gap-1 rounded-full bg-[#050507]/70 border border-[#7B3FE4]/25 px-2.5 py-1.5 shadow-[0_4px_20px_rgba(0,0,0,0.4)]"
        >
          {LANDING_SECTIONS.map((section) => {
            const isActive = activeSection === section.id;
            return (
              <a
                key={section.id}
                href={`#${section.id}`}
                onClick={(e) => handleSectionLinkClick(e, section.id)}
                className={`relative px-3.5 py-1 rounded-full font-heading text-[15px] lg:text-[16px] font-medium transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00E5FF] select-none ${
                  isActive
                    ? 'text-[#00E5FF] font-semibold'
                    : 'text-[#9A9AAE] hover:text-[#E6E6EA]'
                }`}
              >
                <span>{section.label}</span>
                {/* Active Underline / Subtle Glow inside pill */}
                {isActive && (
                  <span className="absolute bottom-0.5 left-3 right-3 h-[2px] bg-gradient-to-r from-[#7B3FE4] to-[#00E5FF] rounded-full shadow-[0_0_8px_rgba(0,229,255,0.7)]" />
                )}
              </a>
            );
          })}
        </nav>

        {/* Mobile menu-button pill (right, under 768px) */}
        <div className="pointer-events-auto md:hidden relative" ref={mobileMenuRef}>
          <button
            type="button"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            aria-expanded={isMobileMenuOpen}
            aria-label="Toggle navigation menu"
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#050507]/70 border border-[#7B3FE4]/25 text-[#E6E6EA] hover:text-[#00E5FF] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00E5FF] shadow-[0_4px_20px_rgba(0,0,0,0.4)] transition-colors"
          >
            <span className="font-heading font-medium text-xs tracking-wider uppercase text-[#9A9AAE]">
              Menu
            </span>
            {isMobileMenuOpen ? (
              /* Cross Icon */
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
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            ) : (
              /* Hamburger Icon */
              <svg
                className="w-4 h-4 text-[#E6E6EA]"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2.2"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            )}
          </button>

          {/* Mobile Dropdown Panel */}
          {isMobileMenuOpen && (
            <div className="absolute right-0 top-11 w-56 rounded-2xl bg-[#050507]/95 border border-[#7B3FE4]/30 shadow-2xl p-2.5 flex flex-col gap-1 z-50">
              {LANDING_SECTIONS.map((section) => {
                const isActive = activeSection === section.id;
                return (
                  <a
                    key={section.id}
                    href={`#${section.id}`}
                    onClick={(e) => handleSectionLinkClick(e, section.id)}
                    className={`px-3.5 py-2.5 rounded-xl font-heading text-[15px] font-medium transition-colors text-left flex items-center justify-between ${
                      isActive
                        ? 'bg-[#00E5FF]/10 text-[#00E5FF] font-semibold border border-[#00E5FF]/30'
                        : 'text-[#9A9AAE] hover:bg-white/5 hover:text-[#E6E6EA]'
                    }`}
                  >
                    <span>{section.label}</span>
                    {isActive && (
                      <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF] shadow-[0_0_6px_#00E5FF]" />
                    )}
                  </a>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
