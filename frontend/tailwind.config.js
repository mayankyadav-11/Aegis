/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#050507',
        surface: {
          DEFAULT: '#0D0D12',
          card: '#0D0D12',
          hover: '#13131A',
          subtle: '#101017',
        },
        border: {
          DEFAULT: '#1C1C26',
          strong: '#2A2A3A',
        },
        amethyst: {
          DEFAULT: '#7B3FE4',
          hover: '#8E54F7',
          subtle: 'rgba(123, 63, 228, 0.15)',
          glow: 'rgba(123, 63, 228, 0.35)',
        },
        cyan: {
          DEFAULT: '#00E5FF',
          hover: '#33EBFF',
          subtle: 'rgba(0, 229, 255, 0.15)',
          glow: 'rgba(0, 229, 255, 0.35)',
        },
        brand: {
          heading: '#F5F5F7',
          secondary: '#9A9AAE',
          muted: '#626274',
        },
        // Risk tokens (strict separation from brand palette)
        risk: {
          safe: '#10B981',
          'safe-bg': 'rgba(16, 185, 129, 0.12)',
          suspicious: '#F59E0B',
          'suspicious-bg': 'rgba(245, 158, 11, 0.12)',
          high: '#F97316',
          'high-bg': 'rgba(249, 115, 22, 0.12)',
          critical: '#EF4444',
          'critical-bg': 'rgba(239, 68, 68, 0.12)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};

