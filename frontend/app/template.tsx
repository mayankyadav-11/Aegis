'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { motion, useReducedMotion } from 'framer-motion';

export default function Template({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const prefersReduced = useReducedMotion();

  // 1. Landing page must never receive app wrapper animations
  if (pathname === '/') {
    return <>{children}</>;
  }

  // 2. Respect reduced-motion preference
  if (prefersReduced) {
    return <>{children}</>;
  }

  // 3. /analyze page has its own fine-grained staggered entrance sequence
  if (pathname.startsWith('/analyze')) {
    return <div className="w-full flex-1 flex flex-col">{children}</div>;
  }

  // 4. Other app pages (/dashboard, /results, /verify, /metrics): simple 250ms fade + 12px rise on entry
  return (
    <motion.div
      key={pathname}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      className="w-full flex-1 flex flex-col"
    >
      {children}
    </motion.div>
  );
}

