'use client';

import { useEffect, useRef } from 'react';
import Panel from './Panel';

// ── Stage type definitions ────────────────────────────────────────────────────

export interface Stage1Data {
  malware_family: string;
  verdict: string;
  risk_score: number;
  severity: string;
  confidence: number;
  one_line_summary: string;
}

export interface Stage2Data {
  executive_summary: string;
  affected_systems: string[];
  business_impact: string;
  confidence: number;
}

export interface Stage3Data {
  mitre_techniques: Array<{ id: string; name: string; tactic: string; description: string }>;
  iocs: { domains: string[]; ips: string[]; files: string[]; registry_keys: string[] };
  attack_chain: string;
  confidence: number;
}

export interface Stage4Data {
  action_plan: Array<{ priority: number; action: string; urgency: string }>;
  yara_rule: string;
  iocs_to_block: string[];
  long_term_recommendations: string[];
  confidence: number;
}

export interface ReportStages {
  stage1?: Stage1Data;
  stage2?: Stage2Data;
  stage3?: Stage3Data;
  stage4?: Stage4Data;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const URGENCY_COLOR: Record<string, string> = {
  immediate: 'var(--magenta)',
  '24h':     '#ffcc00',
  '72h':     '#00f5ff',
};

const CIRCLED = ['①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧'];

function ConfidenceBadge({ value }: { value: number }) {
  const pct = Math.round(value <= 1 ? value * 100 : value);
  const color = pct >= 90 ? '#00ff88' : pct >= 70 ? '#ffcc00' : 'var(--magenta)';
  return (
    <span style={{
      display: 'inline-block', padding: '1px 7px', marginLeft: 8,
      border: `1px solid ${color}`, borderRadius: 3,
      fontSize: 8, color, fontFamily: "'Orbitron', monospace", verticalAlign: 'middle',
    }}>
      {pct}% CONF
    </span>
  );
}

function StagePending({ label }: { label: string }) {
  return (
    <div style={{
      padding: '10px 0', fontSize: 9, color: 'var(--text-dim)',
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <span className="blink" style={{ color: '#00f5ff' }}>▸</span>
      {label}
    </div>
  );
}

// ── Stage 1: Threat Identity ──────────────────────────────────────────────────

function Stage1Card({ data }: { data: Stage1Data }) {
  const riskRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      if (riskRef.current) riskRef.current.style.width = `${data.risk_score}%`;
    }, 80);
    return () => clearTimeout(t);
  }, [data.risk_score]);

  const severityColor =
    data.severity === 'CRITICAL' ? 'var(--magenta)' :
    data.severity === 'HIGH'     ? '#ffcc00'         : '#00f5ff';

  return (
    <div className="stage-card">
      {/* Banner */}
      <div style={{
        padding: '10px 12px', marginBottom: 10,
        background: 'rgba(255,45,158,0.08)',
        border: '1px solid rgba(255,45,158,0.3)',
        borderRadius: 3,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: 8, color: 'var(--text-dim)', letterSpacing: 2 }}>MALWARE FAMILY</div>
            <div style={{
              fontSize: 15, fontFamily: "'Orbitron', monospace",
              color: 'var(--magenta)', marginTop: 2, lineHeight: 1.2,
            }}>
              {data.malware_family}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 8, color: 'var(--text-dim)', letterSpacing: 2 }}>VERDICT</div>
            <div style={{ fontSize: 11, color: severityColor, fontFamily: "'Orbitron', monospace" }}>
              {data.verdict}
            </div>
          </div>
        </div>

        <div style={{ marginTop: 8, fontSize: 9, color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.5 }}>
          {data.one_line_summary}
        </div>
      </div>

      {/* Risk gauge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <div className="f9 text-dim">RISK SCORE</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{
            fontSize: 16, fontFamily: "'Orbitron', monospace",
            color: data.risk_score >= 80 ? 'var(--magenta)' : '#ffcc00',
          }}>
            {data.risk_score}
          </span>
          <span style={{ fontSize: 9, color: 'var(--text-dim)' }}>/100</span>
          <ConfidenceBadge value={data.confidence} />
        </div>
      </div>
      <div className="risk-gauge">
        <div className="risk-fill" ref={riskRef} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: 'var(--text-dim)', marginTop: 2 }}>
        <span>LOW</span>
        <span style={{ color: severityColor, fontFamily: "'Orbitron', monospace", fontSize: 9 }}>
          {data.severity}
        </span>
        <span>CRITICAL</span>
      </div>
    </div>
  );
}

// ── Stage 2: Executive Summary ────────────────────────────────────────────────

function Stage2Card({ data }: { data: Stage2Data }) {
  return (
    <div className="stage-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div className="f9 text-dim">EXECUTIVE SUMMARY</div>
        <ConfidenceBadge value={data.confidence} />
      </div>
      <div style={{ fontSize: 10, lineHeight: 1.7, color: '#7ab8cc', fontStyle: 'italic', marginBottom: 10 }}>
        {data.executive_summary}
      </div>

      {data.affected_systems?.length > 0 && (
        <>
          <div className="f9 text-dim" style={{ marginBottom: 4 }}>AFFECTED SYSTEMS</div>
          {data.affected_systems.map((s, i) => (
            <div key={i} style={{
              padding: '3px 0', fontSize: 9, color: '#ffcc00',
              borderBottom: '1px solid rgba(255,204,0,0.08)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
              <span style={{ color: 'var(--text-dim)' }}>▸</span>{s}
            </div>
          ))}
        </>
      )}

      {data.business_impact && (
        <div style={{
          marginTop: 8, padding: '6px 10px',
          background: 'rgba(255,204,0,0.05)',
          border: '1px solid rgba(255,204,0,0.2)',
          borderRadius: 3, fontSize: 9, color: '#ffcc00', lineHeight: 1.5,
        }}>
          <span style={{ color: 'var(--text-dim)', marginRight: 6 }}>IMPACT:</span>
          {data.business_impact}
        </div>
      )}
    </div>
  );
}

// ── Stage 3: Technical Analysis ───────────────────────────────────────────────

function Stage3Card({ data }: { data: Stage3Data }) {
  const iocs = data.iocs ?? { domains: [], ips: [], files: [], registry_keys: [] };
  const allIocs = [
    ...iocs.domains.map(d => ({ label: 'DOMAIN', val: d, color: 'var(--magenta)' })),
    ...iocs.ips.map(ip => ({ label: 'IP', val: ip, color: 'var(--magenta)' })),
    ...iocs.files.slice(0, 4).map(f => ({ label: 'FILE', val: f, color: '#ffcc00' })),
    ...iocs.registry_keys.slice(0, 3).map(r => ({ label: 'REG', val: r, color: '#00f5ff' })),
  ];

  return (
    <div className="stage-card">
      {/* MITRE table */}
      {data.mitre_techniques?.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <div className="f9 text-dim">MITRE ATT&amp;CK — {data.mitre_techniques.length} TECHNIQUES</div>
            <ConfidenceBadge value={data.confidence} />
          </div>
          <div style={{ overflowX: 'auto', marginBottom: 10 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 9 }}>
              <thead>
                <tr style={{ color: 'var(--text-dim)', borderBottom: '1px solid rgba(0,245,255,0.15)' }}>
                  <th style={{ textAlign: 'left', padding: '2px 4px', fontWeight: 400, whiteSpace: 'nowrap' }}>ID</th>
                  <th style={{ textAlign: 'left', padding: '2px 4px', fontWeight: 400 }}>TECHNIQUE</th>
                  <th style={{ textAlign: 'left', padding: '2px 4px', fontWeight: 400, whiteSpace: 'nowrap' }}>TACTIC</th>
                </tr>
              </thead>
              <tbody>
                {data.mitre_techniques.map((t, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(0,245,255,0.05)' }}>
                    <td style={{
                      padding: '3px 4px', fontFamily: "'Orbitron', monospace",
                      color: 'var(--magenta)', fontSize: 8, whiteSpace: 'nowrap',
                    }}>{t.id}</td>
                    <td style={{ padding: '3px 4px', color: 'var(--text-cyan)' }}>
                      {t.name}
                      {t.description && (
                        <div style={{ fontSize: 8, color: 'var(--text-dim)', marginTop: 1 }}>{t.description}</div>
                      )}
                    </td>
                    <td style={{ padding: '3px 4px', color: 'var(--text-dim)', fontSize: 8, whiteSpace: 'nowrap' }}>{t.tactic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* IOCs */}
      {allIocs.length > 0 && (
        <>
          <div className="f9 text-dim" style={{ marginBottom: 4 }}>INDICATORS OF COMPROMISE</div>
          <div style={{ fontSize: 9, lineHeight: 1.9 }}>
            {allIocs.map((ioc, i) => (
              <div key={i} style={{
                padding: '2px 0',
                borderBottom: '1px solid rgba(255,45,158,0.06)',
                display: 'flex', alignItems: 'baseline', gap: 6,
                wordBreak: 'break-all',
              }}>
                <span style={{
                  fontSize: 7, padding: '1px 4px', border: `1px solid ${ioc.color}`,
                  color: ioc.color, borderRadius: 2, whiteSpace: 'nowrap', flexShrink: 0,
                }}>{ioc.label}</span>
                <span style={{ color: ioc.color }}>{ioc.val}</span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Attack chain */}
      {data.attack_chain && (
        <div style={{
          marginTop: 8, padding: '7px 10px',
          background: '#010814', border: '1px solid rgba(0,245,255,0.1)',
          borderRadius: 3, fontSize: 9, color: '#7ab8cc', lineHeight: 1.6,
        }}>
          <div style={{ color: 'var(--text-dim)', marginBottom: 3, fontSize: 8, letterSpacing: 1 }}>ATTACK CHAIN</div>
          {data.attack_chain}
        </div>
      )}
    </div>
  );
}

// ── Stage 4: Remediation ──────────────────────────────────────────────────────

function Stage4Card({ data }: { data: Stage4Data }) {
  return (
    <div className="stage-card">
      {/* Action plan */}
      {data.action_plan?.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <div className="f9 text-dim">PRIORITIZED ACTION PLAN</div>
            <ConfidenceBadge value={data.confidence} />
          </div>
          {data.action_plan
            .slice()
            .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
            .map((step, i) => {
              const urgColor = URGENCY_COLOR[step.urgency] ?? '#00f5ff';
              return (
                <div key={i} style={{
                  padding: '5px 8px', marginBottom: 4,
                  background: 'rgba(0,245,255,0.03)',
                  border: '1px solid rgba(0,245,255,0.1)',
                  borderLeft: `3px solid ${urgColor}`,
                  borderRadius: 2,
                  display: 'flex', alignItems: 'flex-start', gap: 8,
                }}>
                  <span style={{
                    fontFamily: "'Orbitron', monospace", fontSize: 11,
                    color: urgColor, flexShrink: 0, lineHeight: 1.3,
                  }}>
                    {CIRCLED[i] ?? `${i + 1}.`}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 9, color: 'var(--text-cyan)', lineHeight: 1.5 }}>{step.action}</div>
                    <div style={{ fontSize: 7, color: urgColor, marginTop: 2, letterSpacing: 1 }}>
                      {step.urgency?.toUpperCase()}
                    </div>
                  </div>
                </div>
              );
            })}
        </>
      )}

      {/* Long-term recommendations */}
      {data.long_term_recommendations?.length > 0 && (
        <>
          <div className="f9 text-dim" style={{ marginTop: 10, marginBottom: 4 }}>LONG-TERM RECOMMENDATIONS</div>
          {data.long_term_recommendations.map((rec, i) => (
            <div key={i} style={{
              padding: '3px 0', fontSize: 9, color: '#7ab8cc', lineHeight: 1.5,
              borderBottom: '1px solid rgba(0,245,255,0.05)',
              display: 'flex', gap: 6,
            }}>
              <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>▸</span>{rec}
            </div>
          ))}
        </>
      )}

      {/* YARA rule */}
      {data.yara_rule && (
        <>
          <div className="f9 text-dim" style={{ marginTop: 10, marginBottom: 4 }}>YARA DETECTION RULE</div>
          <pre style={{
            padding: 10,
            background: '#010814',
            border: '1px solid rgba(0,245,255,0.12)',
            fontSize: 8,
            color: '#00ff88',
            overflowX: 'auto',
            lineHeight: 1.6,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            borderRadius: 3,
          }}>
            {data.yara_rule}
          </pre>
        </>
      )}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

interface Props {
  stages: ReportStages;
}

export default function ThreatReportPanel({ stages }: Props) {
  const hasAny = !!(stages.stage1 || stages.stage2 || stages.stage3 || stages.stage4);
  const allDone = !!(stages.stage1 && stages.stage2 && stages.stage3 && stages.stage4);

  const titleSuffix = allDone
    ? ' ✓'
    : hasAny
    ? ` [${[stages.stage1, stages.stage2, stages.stage3, stages.stage4].filter(Boolean).length}/4]`
    : '';

  return (
    <Panel title={`// AI THREAT REPORT${titleSuffix}`} className="ai-panel" style={{ gridRow: 1 }}>
      <style>{`
        @keyframes fadeInCard {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .stage-card {
          animation: fadeInCard 0.35s ease forwards;
        }
      `}</style>

      {!hasAny ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Awaiting analysis...<br /><span className="blink">_</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          {/* Stage 1 — Threat Identity */}
          {stages.stage1
            ? <Stage1Card data={stages.stage1} />
            : <StagePending label="Identifying malware family and risk score..." />
          }

          {/* Stage 2 — Executive Summary */}
          {stages.stage1 && (
            stages.stage2
              ? <>
                  <div className="section-divider" />
                  <Stage2Card data={stages.stage2} />
                </>
              : <StagePending label="Writing executive summary..." />
          )}

          {/* Stage 3 — Technical */}
          {stages.stage2 && (
            stages.stage3
              ? <>
                  <div className="section-divider" />
                  <Stage3Card data={stages.stage3} />
                </>
              : <StagePending label="Building MITRE map and IOC list..." />
          )}

          {/* Stage 4 — Remediation */}
          {stages.stage3 && (
            stages.stage4
              ? <>
                  <div className="section-divider" />
                  <Stage4Card data={stages.stage4} />
                </>
              : <StagePending label="Generating action plan and YARA rule..." />
          )}

        </div>
      )}
    </Panel>
  );
}
