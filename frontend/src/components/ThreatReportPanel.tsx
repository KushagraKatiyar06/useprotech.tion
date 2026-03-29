'use client';

import { useEffect, useRef } from 'react';
import Panel from './Panel';
import { DEMO_FINDINGS, DEMO_MITIGATIONS, DEMO_REASONING } from '@/lib/data';

interface Props {
  visible: boolean;
}

export default function ThreatReportPanel({ visible }: Props) {
  const riskFillRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (visible) {
      setTimeout(() => {
        if (riskFillRef.current) riskFillRef.current.style.width = '94%';
      }, 100);
    } else {
      if (riskFillRef.current) riskFillRef.current.style.width = '0%';
    }
  }, [visible]);

  return (
    <Panel title="// AI THREAT REPORT" className="ai-panel" style={{ gridRow: 1 }}>
      {!visible ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Awaiting analysis...<br /><span className="blink">_</span>
        </div>
      ) : (
        <>
          <div className="f9 text-dim">CLASSIFICATION</div>
          <div className="malware-type-badge">RANSOMWARE</div>

          <div className="f9 text-dim mt4">RISK SCORE</div>
          <div className="risk-gauge">
            <div className="risk-fill" ref={riskFillRef} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-dim)' }}>
            <span>LOW</span>
            <span className="text-cyan" style={{ fontFamily: "'Orbitron', monospace" }}>94%</span>
            <span>CRITICAL</span>
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">CONFIDENCE</div>
          <div className="confidence-row mt4">
            <span>Classification accuracy</span>
            <span className="confidence-val">97%</span>
          </div>
          <div className="confidence-row">
            <span>Behavior signature match</span>
            <span className="confidence-val">91%</span>
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">KEY FINDINGS</div>
          <div style={{ marginTop: 6 }}>
            {DEMO_FINDINGS.map((f, i) => (
              <div key={i} className={`ai-finding ${f.type}`}>
                <div className={`finding-label ${f.type}`}>{f.label}</div>
                {f.text}
              </div>
            ))}
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">MITIGATIONS</div>
          <div style={{ fontSize: 10, lineHeight: 1.8, marginTop: 6, color: 'var(--text-cyan)' }}>
            {DEMO_MITIGATIONS.map((m, i) => (
              <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid rgba(0,245,255,0.06)' }}>{m}</div>
            ))}
          </div>

          <div className="section-divider" />
          <div className="f9 text-dim">AI REASONING</div>
          <div style={{ fontSize: 10, lineHeight: 1.65, marginTop: 6, color: '#7ab8cc', fontStyle: 'italic' }}>
            {DEMO_REASONING}
          </div>
        </>
      )}
    </Panel>
  );
}
