import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Use-Protection-Tech — Malware Analysis Platform',
  description: 'AI-powered sandbox malware analysis and threat detection',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="grid-bg">{children}</body>
    </html>
  );
}
