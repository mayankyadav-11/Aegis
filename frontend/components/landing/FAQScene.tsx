'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Reveal } from '@/components/Reveal';

interface FAQItem {
  id: string;
  question: string;
  answer: string;
}

const FAQ_ITEMS: FAQItem[] = [
  {
    id: 'risk-score',
    question: 'What does the risk score mean?',
    answer:
      "It's a risk indicator from 0 to 100, not the probability that something is a scam. Always read the evidence behind it.",
  },
  {
    id: 'open-link',
    question: 'Does AEGIS open the link on my device?',
    answer:
      'No. Your browser never opens it. AEGIS inspects links from its own server under strict safety limits and reports where they really lead.',
  },
  {
    id: 'message-saved',
    question: 'Is my message saved?',
    answer:
      'AEGIS saves each analysis as a case so you can review it in the Dashboard. Avoid pasting passwords, card numbers or other secrets.',
  },
  {
    id: 'cant-check',
    question: "What if AEGIS can't check something?",
    answer:
      "It says 'Not verifiable' instead of guessing. A missing check is never counted as safe.",
  },
  {
    id: 'already-clicked',
    question: 'I already clicked or shared an OTP. What now?',
    answer:
      'Contact your bank straight away using the number on your card or official app, change affected passwords, and report it on the national cybercrime helpline 1930.',
  },
];

export function FAQScene() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  const shouldReduceMotion = useReducedMotion();

  const toggleItem = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section
      id="faq"
      className="relative w-full bg-transparent px-6 py-20 sm:py-28 scroll-mt-[var(--landing-header-h)]"
    >
      <div className="max-w-6xl mx-auto">
        <div className="flex flex-col lg:grid lg:grid-cols-12 gap-10 lg:gap-16 items-start">
          {/* Left Column (Sticky on desktop, stacked on mobile) */}
          <div className="w-full lg:col-span-5 lg:sticky lg:top-28 text-left">
            <Reveal>
              <div>
                {/* 04 / Questions Eyebrow */}
                <div className="inline-flex items-baseline gap-2 sm:gap-3 mb-4 sm:mb-6">
                  <span className="font-mono font-bold text-[clamp(28px,3.5vw,48px)] leading-none text-[#00E5FF]">
                    04
                  </span>
                  <span className="font-mono font-semibold text-[clamp(18px,2vw,28px)] tracking-[0.12em] uppercase text-[#00E5FF]">
                    / Questions
                  </span>
                </div>

                {/* Section Heading */}
                <h2 className="font-heading font-bold text-[clamp(32px,4.5vw,64px)] tracking-tight leading-[1.12] text-[#E6E6EA]">
                  Questions, answered.
                </h2>

                {/* Subline */}
                <p className="mt-4 font-heading font-medium text-[clamp(18px,1.6vw,24px)] leading-[1.6] text-[#9A9AAE]">
                  Short answers, no jargon.
                </p>
              </div>
            </Reveal>
          </div>

          {/* Right Column (Accordion List) */}
          <div className="w-full lg:col-span-7 flex flex-col gap-3.5">
            {FAQ_ITEMS.map((item, index) => {
              const isOpen = openIndex === index;

              return (
                <div
                  key={item.id}
                  className={`rounded-2xl border transition-all duration-300 bg-[#0D0D12]/90 backdrop-blur-sm ${
                    isOpen
                      ? 'border-[#00E5FF]/50 shadow-[0_0_25px_rgba(0,229,255,0.1)]'
                      : 'border-[#1C1C26] hover:border-[#7B3FE4]/60 hover:shadow-[0_0_20px_rgba(123,63,228,0.12)]'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => toggleItem(index)}
                    aria-expanded={isOpen}
                    aria-controls={`faq-panel-${index}`}
                    id={`faq-header-${index}`}
                    className="w-full p-5 sm:p-6 flex items-center justify-between gap-4 text-left select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00E5FF] rounded-2xl group"
                  >
                    <span className="font-heading font-semibold text-lg sm:text-xl text-[#F5F5F7] tracking-tight group-hover:text-[#E6E6EA]">
                      {item.question}
                    </span>

                    {/* Plus icon that rotates 45deg to a cross when open */}
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 border transition-all duration-300 ${
                        isOpen
                          ? 'border-[#00E5FF]/60 bg-[#00E5FF]/15 text-[#00E5FF] rotate-45'
                          : 'border-white/10 bg-white/5 text-[#9A9AAE] group-hover:border-[#7B3FE4]/50 group-hover:text-[#E6E6EA] rotate-0'
                      }`}
                    >
                      <svg
                        className="w-4 h-4"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        strokeWidth="2.4"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          d="M12 4v16m8-8H4"
                        />
                      </svg>
                    </div>
                  </button>

                  <AnimatePresence initial={false}>
                    {isOpen && (
                      <motion.div
                        id={`faq-panel-${index}`}
                        role="region"
                        aria-labelledby={`faq-header-${index}`}
                        initial={
                          shouldReduceMotion ? false : { height: 0, opacity: 0 }
                        }
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={
                          shouldReduceMotion
                            ? undefined
                            : { height: 0, opacity: 0 }
                        }
                        transition={{ duration: 0.28, ease: 'easeOut' }}
                        className="overflow-hidden"
                      >
                        <div className="px-5 sm:px-6 pb-6 pt-1 border-t border-white/5">
                          <p className="font-body text-[17px] sm:text-[18px] leading-[1.6] text-[#9A9AAE]">
                            {item.answer}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
