'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function Navbar() {
  const pathname = usePathname();

  const navLinks = [
    { label: 'Analyse', href: '/analyze' },
    { label: 'History', href: '/history' },
    { label: 'Red-Team', href: '/redteam' },
  ];

  return (
    <header className="relative z-20 w-full pt-7 md:pt-9 px-5 md:px-10">
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        {/* Brand: Shield Mark + AEGIS */}
        <Link
          href="/"
          className="flex items-center gap-2.5 text-[15px] font-semibold tracking-tight text-[#E6E6EA] group transition-opacity hover:opacity-90"
        >
          <div className="relative flex items-center justify-center w-7 h-7 rounded-md bg-[#0D0D12] border border-[#1C1C26] shadow-inner group-hover:border-[#7B3FE4]/50 transition-colors">
            {/* Minimalist modern shield SVG */}
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

        {/* Center Links (hidden on mobile <= 760px) */}
        <nav className="hidden md:flex items-center gap-7 lg:gap-9 font-body text-[14px] font-medium text-[#9A9AAE]">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`transition-colors duration-200 hover:text-[#E6E6EA] ${
                  isActive ? 'text-[#00E5FF] font-semibold' : ''
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        {/* Action: Launch console pill */}
        <div className="flex items-center">
          <Link
            href="/dashboard"
            className="group relative inline-flex items-center justify-center px-4 md:px-5 py-2 md:py-2.5 font-body text-[13.5px] font-medium text-[#E6E6EA] bg-[#0D0D12] hover:bg-[#13131A] border border-[#1C1C26] hover:border-[#7B3FE4]/60 rounded-full transition-all duration-200 hover:-translate-y-0.5 shadow-sm active:translate-y-0"
          >
            <span className="relative z-10 flex items-center gap-2">
              <span>Launch console</span>
              <svg
                className="w-3.5 h-3.5 text-[#00E5FF] transition-transform group-hover:translate-x-0.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
            </span>
          </Link>
        </div>
      </div>
    </header>
  );
}
