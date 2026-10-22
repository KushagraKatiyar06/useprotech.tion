import type { Metadata, Viewport } from 'next';
// Note: 'use client' must NOT be here — layout.tsx uses static metadata export
import './globals.css';
import GlobalBackdrop from '@/components/GlobalBackdrop';
import { RunActiveProvider } from '@/contexts/RunActiveContext';

export const metadata: Metadata = {
  title: 'Use-Protection-Tech — Malware Analysis Platform',
  description: 'AI-powered sandbox malware analysis and threat detection',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="grid-bg">
        <RunActiveProvider>
          {/* Persistent backdrop — lives outside #page-content so a
              navigation's fade transition never touches it; it just keeps
              flowing underneath while the foreground content fades. */}
          <GlobalBackdrop />
          <div id="page-content">{children}</div>
        </RunActiveProvider>
      </body>
    </html>
  );
}
