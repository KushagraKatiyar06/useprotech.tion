'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';

const FloatingLines = dynamic(() => import('@/components/FloatingLines'), { ssr: false });

export default function Home() {
  const [clock, setClock] = useState('');

  useEffect(() => {
    const update = () => setClock(new Date().toUTCString().slice(17, 25) + ' UTC');
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      {/* FloatingLines background */}
      <div style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', opacity: 0.35 }}>
        <FloatingLines
          enabledWaves={['top', 'middle', 'bottom']}
          lineCount={5}
          lineDistance={5}
          bendRadius={5}
          bendStrength={-0.5}
          interactive={true}
          parallax={true}
          linesGradient={['#3b82f6', '#8b5cf6', '#06b6d4']}
          mixBlendMode="screen"
        />
      </div>
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
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#475569' }}>{clock}</span>
          <Link href="/dashboard" style={{
            fontFamily: 'Orbitron, monospace',
            fontSize: '9px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: '#3b82f6',
            border: '1px solid rgba(59,130,246,0.4)',
            borderRadius: '6px',
            padding: '8px 18px',
            textDecoration: 'none',
            transition: 'all 0.2s',
          }}>
            Sign In
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <main style={{
        flex: 1,
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

        {/* Badge */}
        <div style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '10px',
          letterSpacing: '3px',
          textTransform: 'uppercase',
          color: '#3b82f6',
          border: '1px solid rgba(59,130,246,0.3)',
          borderRadius: '20px',
          padding: '6px 18px',
          marginBottom: '40px',
          background: 'rgba(59,130,246,0.06)',
        }}>
          AI-Powered Malware Analysis
        </div>

        {/* Title */}
        <h1 style={{
          fontFamily: 'Orbitron, monospace',
          fontWeight: 900,
          fontSize: 'clamp(42px, 8vw, 80px)',
          letterSpacing: '4px',
          textTransform: 'uppercase',
          lineHeight: 1.1,
          marginBottom: '28px',
          color: '#ffffff',
        }}>
          Use<span style={{
            color: '#3b82f6',
            textShadow: '0 0 40px rgba(59,130,246,0.5)',
          }}>Protection</span>
        </h1>

        {/* Subtitle */}
        <p style={{
          fontSize: '16px',
          color: '#94a3b8',
          maxWidth: '520px',
          lineHeight: 1.8,
          marginBottom: '52px',
          fontWeight: 400,
        }}>
          Detonate suspicious files in an isolated sandbox. Get instant MITRE ATT&CK mapping, behavioral analysis, and AI-generated threat reports.
        </p>

        {/* CTA */}
        <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap', justifyContent: 'center' }}>
          <Link href="/dashboard" style={{
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
          }}>
            Get Started
          </Link>
          <Link href="/dashboard" style={{
            fontFamily: 'Orbitron, monospace',
            fontSize: '10px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: '#94a3b8',
            background: 'transparent',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '8px',
            padding: '14px 32px',
            textDecoration: 'none',
          }}>
            View Demo
          </Link>
        </div>

        {/* Stats row */}
        <div style={{
          display: 'flex',
          gap: '48px',
          marginTop: '80px',
          flexWrap: 'wrap',
          justifyContent: 'center',
        }}>
          {[
            { val: '99.7%', label: 'Detection Rate' },
            { val: '<30s', label: 'Analysis Time' },
            { val: '200+', label: 'MITRE Techniques' },
          ].map(({ val, label }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{
                fontFamily: 'Orbitron, monospace',
                fontSize: '28px',
                fontWeight: 700,
                color: '#ffffff',
                textShadow: '0 0 20px rgba(59,130,246,0.4)',
              }}>{val}</div>
              <div style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '10px',
                letterSpacing: '2px',
                textTransform: 'uppercase',
                color: '#475569',
                marginTop: '6px',
              }}>{label}</div>
            </div>
          ))}
        </div>
      </main>

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
