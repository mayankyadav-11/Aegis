import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'AEGIS | AI Phishing & Scam Detection Platform',
  description:
    'AI-powered phishing and scam detection that shows you why, across email, SMS, URLs and messages.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen bg-[#050507] text-[#F5F5F7] flex flex-col selection:bg-[#7B3FE4]/30 selection:text-[#00E5FF] overflow-x-hidden font-sans">
        <Navbar />
        <main className="flex-1 flex flex-col relative">{children}</main>
      </body>
    </html>
  );
}
