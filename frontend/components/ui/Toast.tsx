'use client';

import React, { createContext, useContext, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

interface ToastItem {
  id: string;
  message: string;
  type?: 'success' | 'error' | 'info';
}

interface ToastContextValue {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const ToastContext = createContext<ToastContextValue>({
  showToast: () => {},
});

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const showToast = useCallback((message: string, type: 'success' | 'error' | 'info' = 'success') => {
    const id = `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    setToasts((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3200);
  }, []);

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div
        className="fixed bottom-5 right-5 z-[9999] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none px-4"
        aria-live="polite"
      >
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 16, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 12, scale: 0.95 }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
              className="pointer-events-auto p-3.5 rounded-xl bg-[#0D0D12] border border-[#1C1C26] shadow-2xl flex items-center justify-between gap-3 text-xs"
              style={{
                boxShadow:
                  toast.type === 'error'
                    ? '0 10px 25px -5px rgba(239, 68, 68, 0.25)'
                    : '0 10px 25px -5px rgba(0, 229, 255, 0.25)',
              }}
            >
              <div className="flex items-center gap-2.5">
                {toast.type === 'error' ? (
                  <AlertCircle className="w-4 h-4 text-[#EF4444] shrink-0" />
                ) : toast.type === 'info' ? (
                  <Info className="w-4 h-4 text-[#7B3FE4] shrink-0" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0" />
                )}
                <span className="text-[#F5F5F7] font-medium leading-snug">{toast.message}</span>
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="text-[#626274] hover:text-[#F5F5F7] p-1 rounded-md transition-colors"
                aria-label="Close notification"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

