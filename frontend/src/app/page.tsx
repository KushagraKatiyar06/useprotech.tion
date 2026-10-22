'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { navigateWithFade } from '@/lib/pageTransition';

export default function Home() {
  const router = useRouter();
  const [clock, setClock] = useState('');

  useEffect(() => {
    const update = () => setClock(new Date().toUTCString().slice(17, 25) + ' UTC');
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  const scrollToOverview = () => {
    document.getElementById('overview')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      {/* FloatingLines now renders globally from layout.tsx (GlobalBackdrop)
          so it's one persistent canvas across every page instead of
          restarting per route — see RunActiveContext/pageTransition.ts. */}
      {/* Dark overlay to keep text readable */}
      <div style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none', background: 'rgba(6,12,26,0.55)' }} />
      {/* Nav */}
      <nav style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '20px 48px',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        background: 'rgba(6,12,26,0.8)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 200,
      }}>
        <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
          <img src="/icon.svg" alt="UseProtection" width={28} height={28} />
          <div style={{
            fontFamily: 'Orbitron, monospace',
            fontWeight: 900,
            fontSize: '14px',
            letterSpacing: '3px',
            color: '#e2e8f0',
            textTransform: 'uppercase',
          }}>
            Use<span style={{ color: '#3b82f6' }}>Protection</span>
          </div>
        </Link>
      </nav>

      {/* Hero */}
      <main style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: '80px 24px',
        position: 'relative',
        zIndex: 200,
      }}>
        {/* Glow orbs */}
        <div style={{
          position: 'absolute',
          top: '20%',
          left: '50%',
          transform: 'translateX(-50%)',
          width: '600px',
          height: '600px',
          background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          top: '30%',
          left: '30%',
          width: '300px',
          height: '300px',
          background: 'radial-gradient(circle, rgba(139,92,246,0.08) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          top: '25%',
          right: '25%',
          width: '250px',
          height: '250px',
          background: 'radial-gradient(circle, rgba(6,182,212,0.07) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />


        {/* Title */}
        <h1 style={{
          fontFamily: 'Orbitron, monospace',
          fontWeight: 900,
          // 42px was too high a floor — at narrow phone widths 8vw stays
          // below it, so the floor wins and the full "UseProtection"
          // string overflows past the viewport edge. Lowering the floor to
          // 24px lets it keep shrinking down to small phones; 8vw already
          // exceeds 42px past ~525px width, so nothing above that changes.
          fontSize: 'clamp(24px, 8vw, 80px)',
          letterSpacing: '4px',
          textTransform: 'uppercase',
          lineHeight: 1.1,
          marginBottom: '28px',
          color: '#ffffff',
          overflowWrap: 'break-word',
        }}>
          Use<span style={{
            color: '#3b82f6',
            textShadow: '0 0 40px rgba(59,130,246,0.5)',
          }}>Protection</span>
        </h1>


        {/* CTA */}
        <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap', justifyContent: 'center' }}>
          <button onClick={scrollToOverview} style={{
            fontFamily: 'Orbitron, monospace',
            fontSize: '10px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: '#ffffff',
            background: '#3b82f6',
            border: '1px solid #3b82f6',
            borderRadius: '8px',
            padding: '14px 32px',
            cursor: 'pointer',
            boxShadow: '0 0 24px rgba(59,130,246,0.35)',
          }}>
            Get Started
          </button>
        </div>

      </main>

      {/* Overview */}
      <section id="overview" className="overview-section">
        <div className="overview-wrap">
          <h2 className="overview-heading">
            From suspicious file to full report, automatically
          </h2>
          <p className="overview-sub">
            Upload a file and an AI agent pipeline takes it from there, analyzing,
            mapping, and reporting on the threat while you watch it happen live.
          </p>

          <div className="overview-grid">
            {[
              {
                step: '01',
                title: 'Upload a File',
                desc: "Drop any suspicious file into the dashboard to kick off a fully automated analysis, no setup required.",
                accent: '#3b82f6',
                glow: '0 0 16px rgba(59,130,246,0.4)',
                border: 'rgba(59,130,246,0.35)',
              },
              {
                step: '02',
                title: 'Agent Pipeline Runs',
                desc: 'AI agents analyze the file in a sandboxed environment in parallel: static analysis, MITRE ATT&CK mapping, and remediation planning.',
                accent: '#8b5cf6',
                glow: '0 0 16px rgba(139,92,246,0.4)',
                border: 'rgba(139,92,246,0.35)',
              },
              {
                step: '03',
                title: 'Watch It Live',
                desc: 'Every finding streams straight to your dashboard in real time over WebSocket, so you see the investigation as it unfolds.',
                accent: '#06b6d4',
                glow: '0 0 16px rgba(6,182,212,0.35)',
                border: 'rgba(6,182,212,0.35)',
              },
              {
                step: '04',
                title: 'Get Your Report',
                desc: 'Walk away with a complete threat report and a downloadable PDF, ready to share with your team.',
                accent: '#10b981',
                glow: '0 0 16px rgba(16,185,129,0.35)',
                border: 'rgba(16,185,129,0.35)',
              },
            ].map((card) => (
              <div
                key={card.step}
                className="overview-card"
                style={{
                  '--accent': card.accent,
                  '--accent-glow': card.glow,
                  '--accent-border': card.border,
                } as React.CSSProperties}
              >
                <div className="overview-step">{card.step}</div>
                <div className="overview-card-title">{card.title}</div>
                <div className="overview-card-desc">{card.desc}</div>
              </div>
            ))}
          </div>

          <Link
            href="/dashboard"
            onClick={e => { e.preventDefault(); navigateWithFade(router.push, '/dashboard'); }}
            style={{
              display: 'inline-block',
              marginTop: '56px',
              fontFamily: 'Orbitron, monospace',
              fontSize: '10px',
              letterSpacing: '2px',
              textTransform: 'uppercase',
              color: '#ffffff',
              background: '#3b82f6',
              border: '1px solid #3b82f6',
              borderRadius: '8px',
              padding: '14px 32px',
              textDecoration: 'none',
              boxShadow: '0 0 24px rgba(59,130,246,0.35)',
            }}
          >
             Start
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer style={{
        padding: '20px 48px',
        borderTop: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'relative',
        zIndex: 200,
      }}>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#475569', letterSpacing: '1px' }}>
          © 2026 USEPROTECTION
        </span>
        <div style={{ display: 'flex', gap: '4px' }}>
          {['#10b981','#3b82f6','#8b5cf6','#f43f5e'].map((c, i) => (
            <div key={i} style={{ width: '6px', height: '6px', borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}` }} />
          ))}
        </div>
      </footer>
    </div>
  );
}
