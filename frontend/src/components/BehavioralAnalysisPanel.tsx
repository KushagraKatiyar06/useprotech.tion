'use client';

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Panel from './Panel';
import WidgetWires from './WidgetWires';
import { useRunActive } from '@/contexts/RunActiveContext';
import { type ReportStages, type Stage1Data, type Stage2Data, type Stage3Data, type Stage4Data } from './ThreatReportPanel';

// ── Agent status types (exported for dashboard/page.tsx) ──────────────────────

export type AgentStatus = 'idle' | 'running' | 'complete' | 'skipped' | 'error';

export interface AgentState {
  status: AgentStatus;
  detail: string;
}

export type AgentStatuses = Record<
  'ingestion' | 'static_analysis' | 'mitre_mapping' | 'remediation' | 'report' | 'virustotal',
  AgentState
>;

// Keep StaticResult exported so dashboard/page.tsx can use it
export interface StaticResult {
  file_type: string;
  file_name?: string;
  sha256?: string;
  entropy?: number;
  is_obfuscated?: boolean;
  threat_level?: string;
  behaviors?: string[];
  mitre_techniques?: string[];
  dangerous_functions?: string[];
  suspicious_imports?: string[];
  urls_found?: string[];
  ips_found?: string[];
  domains_found?: string[];
  registry_keys?: string[];
  dropped_files?: string[];
  yara_matches?: string[];
  strings_sample?: string[];
  pe_info?: {
    architecture?: string;
    compile_time?: string;
    is_dll?: boolean;
    sections?: { name: string; entropy: number }[];
    imports?: string[];
  };
}

const STAGES = ['UPLOAD', 'SANDBOX', 'AGENTS', 'REPORT'];
const CORE_AGENT_KEYS = ['ingestion', 'static_analysis', 'mitre_mapping', 'remediation'] as const;

const AGENT_LABELS: Record<string, string> = {
  ingestion: 'INGESTION AGENT',
  static_analysis: 'STATIC ANALYSIS',
  mitre_mapping: 'MITRE MAPPING',
  remediation: 'REMEDIATION AGENT',
  report: 'REPORT GENERATION',
  virustotal: 'VIRUSTOTAL',
};

export interface SandboxStep {
  message: string;
  step: number;
  total: number;
}

interface Props {
  fileName?: string;
  currentStage: number;
  stageDone: boolean[];
  agentStatuses: AgentStatuses;
  agentElapsed: Record<string, number>;
  sandboxStep: SandboxStep | null;
  sandboxResult: string | null;
  onSkipVirusTotal: () => void;
  reportStages: ReportStages;
  terminalLogs: string[];
  /** Below the dashboard's 860px breakpoint — Agents/Raw Logs/Reports stack
   *  into one column instead of sharing a row (see the main render below). */
  isNarrow?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function stageClass(i: number, currentStage: number, stageDone: boolean[]) {
  if (stageDone[i]) return 'stage done';
  if (currentStage === i) return 'stage active';
  return 'stage';
}

// ── Widget — the shared boxed-card chrome for Agents/Raw Logs/Reports, each
// its own self-contained section with its own accent color, rather than
// three different bespoke border/header treatments. Exported so
// LinuxSandboxPanel can reuse the exact same minimize/expand mechanics for
// its own console/graph/live-code row instead of reimplementing it. ───────

// Puzzle pieces sharing one row. Each is individually toggleable between
// expanded (grows via flex-grow) and minimized (collapses to a thin strip)
// — minimizing one is what frees up the room the others expand into, via
// ordinary flexbox redistribution, no layout math needed. A plain CSS
// `flex`/width transition (not Framer's `layout`) drives the resize so it
// interpolates the real size instead of scaling content, which is what
// caused the jitter earlier.
export function Widget({ accent, label, badge, live, bgAlpha = 0.035, minimized, onToggleMinimize, horizontal, style, children }: {
  accent: string; label: string; badge?: string; live?: boolean; bgAlpha?: number;
  minimized?: boolean; onToggleMinimize?: () => void;
  /** Minimized strip lays out as a short horizontal bar with normal-orientation
   *  text instead of a tall vertical-text sliver — used when these widgets are
   *  stacked in a column (mobile) rather than sharing a row (desktop), where a
   *  vertical strip would make no sense next to full-width siblings. */
  horizontal?: boolean;
  style?: React.CSSProperties; children: React.ReactNode;
}) {
  const { active: wiresActive } = useRunActive();
  const border = `1px solid rgba(var(--${accent}-rgb), 0.25)`;
  const bg = `rgba(var(--${accent}-rgb), ${bgAlpha})`;

  if (minimized) {
    return (
      <div
        onClick={onToggleMinimize}
        title={`Expand ${label}`}
        className="clickable"
        style={{
          border, borderRadius: 10, background: bg, cursor: 'pointer',
          display: 'flex',
          flexDirection: horizontal ? 'row' : 'column',
          alignItems: 'center',
          justifyContent: horizontal ? 'flex-start' : 'flex-start',
          gap: 10, padding: horizontal ? '10px 14px' : '14px 0',
          transition: 'flex 0.35s cubic-bezier(0.65,0,0.35,1)',
          ...style,
        }}
      >
        <span
          className={live ? 'blink' : undefined}
          style={{ width: 6, height: 6, borderRadius: '50%', background: `var(--${accent})`, flexShrink: 0 }}
        />
        <span style={horizontal ? {
          fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: 1.5,
          color: `var(--${accent})`, textTransform: 'uppercase',
        } : {
          writingMode: 'vertical-rl', transform: 'rotate(180deg)',
          fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: 1.5,
          color: `var(--${accent})`, textTransform: 'uppercase', whiteSpace: 'nowrap',
        }}>
          {label}{badge ? ` · ${badge}` : ''}
        </span>
      </div>
    );
  }

  return (
    <div style={{
      border, borderRadius: 10, padding: 12, background: bg,
      display: 'flex', flexDirection: 'column', minHeight: 0, minWidth: 0,
      position: 'relative', overflow: 'hidden',
      transition: 'flex 0.35s cubic-bezier(0.65,0,0.35,1)',
      ...style,
    }}>
      {/* Absolutely-positioned content paints *above* normal-flow siblings
          by default regardless of DOM order (CSS stacking, not z-index) —
          so without an explicit stacking layer of its own, this wires
          background would sit on top of the header/body text, not behind
          it. The wrapper below opts the real content into its own layer. */}
      <div className={`widget-wires-wrap${wiresActive ? ' active' : ''}`}>
        <WidgetWires accent={accent} />
      </div>

      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexShrink: 0 }}>
          <span
            className={live ? 'blink' : undefined}
            style={{ width: 6, height: 6, borderRadius: '50%', background: `var(--${accent})`, flexShrink: 0 }}
          />
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: 1.5,
            color: `var(--${accent})`, textTransform: 'uppercase',
          }}>
            {label}
          </span>
          {badge && (
            <span style={{ marginLeft: 8, fontSize: 8, color: `var(--${accent})`, fontFamily: "'JetBrains Mono', monospace" }}>
              {badge}
            </span>
          )}
          {onToggleMinimize && (
            <span
              onClick={onToggleMinimize}
              title={`Minimize ${label}`}
              className="clickable"
              style={{ marginLeft: 'auto', cursor: 'pointer', color: 'var(--text-dim)', fontSize: 11, padding: '0 4px', lineHeight: 1 }}
            >
              −
            </span>
          )}
        </div>
        <div style={{ flex: 1, minHeight: 0 }}>{children}</div>
      </div>
    </div>
  );
}

// ── Agent node ────────────────────────────────────────────────────────────────

function StatusDot({ status, accent }: { status: AgentStatus; accent: string }) {
  const color = status === 'error' ? 'var(--rose)'
    : status === 'skipped' ? 'var(--text-mid)'
    : status === 'idle' ? 'var(--text-dim)'
    : `var(--${accent})`;

  // Complete gets a ✓ glyph (not just a filled dot) so "done" still reads
  // as a distinct shape at a glance even though it's drawn in the agent's
  // own color now, rather than a universal green.
  if (status === 'complete') {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        width: 11, height: 11, borderRadius: '50%', flexShrink: 0,
        background: color, color: 'var(--bg)', fontSize: 8, lineHeight: 1, fontWeight: 700,
      }}>
        ✓
      </span>
    );
  }

  return (
    <span style={{
      display: 'inline-block', width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
      background: status === 'idle' ? 'transparent' : color,
      border: `1.5px solid ${color}`,
    }} />
  );
}

// Each agent gets its own identity hue (used for the border/glow in every
// non-error state) instead of every node converging on the same amber —
// error still always overrides to rose so danger stays universally
// recognizable regardless of which agent hit it.
const AGENT_ACCENT: Record<string, string> = {
  sandbox: 'cyan',
  virustotal: 'violet',
  ingestion: 'blue',
  static_analysis: 'amber',
  mitre_mapping: 'teal',
  remediation: 'pink',
  report: 'emerald',
};

function AgentNode({ label, status, detail, elapsedSeconds, compact, fill = false, onSkip, accent = 'cyan' }: {
  label: string; status: AgentStatus; detail?: string; elapsedSeconds?: number; compact?: boolean; fill?: boolean;
  onSkip?: () => void; accent?: string;
}) {
  const varc = `var(--${accent})`;
  const rgb = `var(--${accent}-rgb)`;

  const color = status === 'error' ? 'var(--rose)'
    : status === 'skipped' ? 'var(--text-mid)'
    : status === 'idle' ? 'var(--text-dim)'
    : varc;
  const borderColor = status === 'error' ? 'var(--rose)'
    : status === 'idle' ? `rgba(${rgb}, 0.3)`
    : varc;
  const bg = status === 'error' ? 'rgba(var(--rose-rgb), 0.06)'
    : status === 'idle' ? 'var(--bg-panel-alt)'
    : `rgba(${rgb}, 0.08)`;
  const glow = status === 'error' ? 'var(--rose-glow)'
    : status === 'running' ? `0 0 16px rgba(${rgb}, 0.4)`
    : 'none';
  // Only offer the skip affordance while the agent is actually running —
  // clicking it otherwise would have nothing to skip.
  const skippable = status === 'running' && !!onSkip;

  return (
    <div
      onClick={skippable ? onSkip : undefined}
      title={skippable ? 'Click to skip — taking too long?' : undefined}
      style={{
        border: `1px solid ${borderColor}`,
        borderRadius: 8,
        padding: compact ? '12px 14px' : '16px 20px',
        background: bg,
        boxShadow: glow,
        animation: status === 'running' ? 'pulse-border 1.8s ease-in-out infinite' : 'none',
        textAlign: 'center',
        cursor: skippable ? 'pointer' : 'default',
        // Solo nodes (fill=false) are capped and centered so they read as cards,
        // not full-width bars; the two parallel nodes (fill=true) share their row.
        flex: fill ? 1 : undefined,
        width: fill ? undefined : '100%',
        maxWidth: fill ? undefined : 420,
        margin: fill ? undefined : '0 auto',
        transition: 'border-color 0.4s ease, background 0.4s ease, box-shadow 0.4s ease',
        minWidth: 0,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, fontSize: compact ? 11 : 13, color, fontFamily: "'Orbitron', monospace", letterSpacing: 1 }}>
        <StatusDot status={status} accent={accent} />
        <span>{label}</span>
      </div>
      {status === 'running' && (
        <>
          <div style={{ fontSize: 10, color: varc, marginTop: 6, fontFamily: "'JetBrains Mono', monospace" }}>
            running{typeof elapsedSeconds === 'number' ? ` · ${elapsedSeconds}s` : ''}
          </div>
          {detail && (
            <div style={{ fontSize: 10, color: 'var(--text-mid)', marginTop: 4, lineHeight: 1.5, wordBreak: 'break-word' }}>{detail}</div>
          )}
          {skippable && (
            <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 6, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}>
              ✕ taking too long? click to skip
            </div>
          )}
        </>
      )}
      {status !== 'running' && detail && (
        <div style={{
          fontSize: 10,
          color: status === 'error' ? 'var(--rose)' : status === 'idle' ? 'var(--text-dim)' : 'var(--text-mid)',
          marginTop: 6, lineHeight: 1.5, wordBreak: 'break-word',
        }}>
          {detail}
        </div>
      )}
    </div>
  );
}

// ── Connectors — a single SVG per joint instead of stacks of hairline divs ────

function Connector({ type }: { type: 'straight' | 'fork' | 'join' }) {
  const stroke = 'rgba(var(--cyan-rgb), 0.3)';
  const h = 36;
  if (type === 'straight') {
    return (
      <svg width="100%" height={h} style={{ display: 'block' }}>
        <line x1="50%" y1="0" x2="50%" y2={h} stroke={stroke} strokeWidth="1.5" />
      </svg>
    );
  }
  const mid = h / 2;
  const d = type === 'fork'
    ? `M50,0 L50,${mid} M25,${mid} L75,${mid} M25,${mid} L25,${h} M75,${mid} L75,${h}`
    : `M25,0 L25,${mid} M75,0 L75,${mid} M25,${mid} L75,${mid} M50,${mid} L50,${h}`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 100 ${h}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <path d={d} stroke={stroke} strokeWidth="1.5" fill="none" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function ParallelLabel() {
  return (
    <div style={{ textAlign: 'center', fontSize: 8, color: 'var(--text-dim)', letterSpacing: 1, marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>
      ⇄ RUNS IN PARALLEL
    </div>
  );
}

// ── AGENTS tab ────────────────────────────────────────────────────────────────

function AgentsTab({ agentStatuses, agentElapsed, currentStage, stageDone, sandboxStep, sandboxResult, onSkipVirusTotal, isNarrow }: {
  agentStatuses: AgentStatuses; agentElapsed: Record<string, number>;
  currentStage: number; stageDone: boolean[];
  sandboxStep: SandboxStep | null; sandboxResult: string | null;
  onSkipVirusTotal: () => void;
  isNarrow?: boolean;
}) {
  const a = agentStatuses;

  // SANDBOX (stage index 1) isn't one of the AI agents — it's the tool-based
  // pass (strings/pefile/exiftool/binwalk/YARA/.NET) that runs before the AI
  // pipeline even starts. Shown here too so the whole real sequence is
  // visible in one place, not split across the stepper and this diagram.
  const sandboxStatus: AgentStatus = stageDone[1] ? 'complete' : currentStage === 1 ? 'running' : 'idle';
  const sandboxDetail = sandboxStatus === 'running'
    ? (sandboxStep ? `${sandboxStep.message} · ${sandboxStep.step}/${sandboxStep.total}` : undefined)
    : sandboxStatus === 'complete'
      ? (sandboxResult ?? undefined)
      : undefined;

  return (
    <div style={{ padding: '8px 4px 4px', maxWidth: 720, margin: '0 auto' }}>
      {/* Sandbox static analysis + VirusTotal — these two run concurrently
          (see app.py's ThreadPoolExecutor around _run_sandbox_static_analysis
          and _fetch_vt_behavior): VT only needs the filepath, never the
          static-analysis result, and its own upload+poll loop can take
          minutes, so there's no reason to make either wait on the other. */}
      <ParallelLabel />
      <div style={{ display: 'flex', flexDirection: isNarrow ? 'column' : 'row', gap: 16 }}>
        <AgentNode label="SANDBOX STATIC ANALYSIS" status={sandboxStatus} detail={sandboxDetail} accent={AGENT_ACCENT.sandbox} compact fill={!isNarrow} />
        <AgentNode
          label="VIRUSTOTAL"
          status={a.virustotal.status}
          detail={a.virustotal.detail}
          elapsedSeconds={agentElapsed.virustotal}
          onSkip={onSkipVirusTotal}
          accent={AGENT_ACCENT.virustotal}
          compact
          fill={!isNarrow}
        />
      </div>
      <Connector type="join" />

      {/* Ingestion */}
      <AgentNode label="INGESTION AGENT" status={a.ingestion.status} detail={a.ingestion.detail} elapsedSeconds={agentElapsed.ingestion} accent={AGENT_ACCENT.ingestion} />
      <Connector type="fork" />

      {/* Parallel pair — the two AI agents that actually run concurrently
          (see agents/pipeline.py's ThreadPoolExecutor around
          run_static_analysis + run_mitre_mapping) */}
      <ParallelLabel />
      <div style={{ display: 'flex', flexDirection: isNarrow ? 'column' : 'row', gap: 16 }}>
        <AgentNode label="MALWARE CLASSIFIER" status={a.static_analysis.status} detail={a.static_analysis.detail} elapsedSeconds={agentElapsed.static_analysis} accent={AGENT_ACCENT.static_analysis} compact fill={!isNarrow} />
        <AgentNode label="MITRE MAPPING"      status={a.mitre_mapping.status}   detail={a.mitre_mapping.detail}   elapsedSeconds={agentElapsed.mitre_mapping} accent={AGENT_ACCENT.mitre_mapping} compact fill={!isNarrow} />
      </div>
      <Connector type="join" />

      {/* Remediation */}
      <AgentNode label="REMEDIATION AGENT" status={a.remediation.status} detail={a.remediation.detail} elapsedSeconds={agentElapsed.remediation} accent={AGENT_ACCENT.remediation} />
      <Connector type="straight" />

      {/* Report */}
      <AgentNode label="REPORT GENERATION" status={a.report.status} detail={a.report.detail} elapsedSeconds={agentElapsed.report} accent={AGENT_ACCENT.report} />

      {/* Sub-stage indicators for report */}
      {(a.report.status === 'running' || a.report.status === 'complete') && (
        <div style={{ marginTop: 8, paddingLeft: 8 }}>
          <div style={{ fontSize: 7, color: 'var(--text-dim)', marginBottom: 4, letterSpacing: 1 }}>REPORT SUB-STAGES</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['THREAT ID', 'EXEC SUM', 'TECHNICAL', 'REMEDIATION'].map((lbl, i) => {
              const stageKey = `stage${i + 1}` as keyof ReportStages;
              const done = !!(agentStatuses.report.status === 'complete' ||
                             (i === 0 && agentStatuses.report.detail));
              const color = done ? 'var(--emerald)' : 'rgba(var(--cyan-rgb), 0.2)';
              return (
                <div key={i} style={{
                  flex: 1, textAlign: 'center', padding: '2px 0',
                  border: `1px solid ${color}`, borderRadius: 2,
                  fontSize: 6, color, letterSpacing: 0.5,
                }}>
                  {lbl}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── LOGS tab ──────────────────────────────────────────────────────────────────

function LogsTab({ terminalLogs, agentStatuses, agentElapsed, sandboxStep }: {
  terminalLogs: string[]; agentStatuses: AgentStatuses; agentElapsed: Record<string, number>;
  sandboxStep: SandboxStep | null;
}) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [terminalLogs]);

  const running = (Object.keys(agentStatuses) as (keyof AgentStatuses)[])
    .filter(k => agentStatuses[k].status === 'running');

  // No more mini-preview/expand toggle — this column always spans the full
  // height of the row it shares with AgentsTab (flex `alignItems: 'stretch'`
  // on the parent does that), text fills from the top and scrolls within.
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="log-terminal" ref={logRef} style={{ flex: 1, overflowY: 'auto' }}>
        {terminalLogs.map((line, i) => {
          const isCrit = line.includes('CRIT') || line.includes('✗') || line.includes('ERROR');
          const isWarn = line.includes('WARN') || line.includes('►');
          const isDone = line.includes('✓');
          const color = isCrit ? 'var(--magenta)' : isWarn ? 'var(--amber)' : isDone ? 'var(--emerald)' : 'var(--text-cyan)';
          return (
            <div key={i} className="log-line" style={{ color, fontFamily: 'monospace', fontSize: 9, lineHeight: 1.7 }}>
              {line}
            </div>
          );
        })}
        {terminalLogs.length === 0 && (
          <div className="f9 text-dim" style={{ padding: 8 }}>Awaiting pipeline events...<span className="blink">_</span></div>
        )}
      </div>

      {/* Live "still working" strip — a client-side readout of real WS timestamps
          and step counts, kept visually and structurally separate from the
          backend-sourced transcript above so it's never mistaken for real
          telemetry. Not appended to the log. */}
      {(running.length > 0 || sandboxStep) && (
        <div style={{
          flexShrink: 0, marginTop: 6, padding: '6px 10px',
          border: '1px dashed rgba(var(--amber-rgb), 0.35)', borderRadius: 4,
          background: 'rgba(var(--amber-rgb), 0.04)',
        }}>
          {sandboxStep && (
            <div style={{ marginBottom: running.length > 0 ? 6 : 0 }}>
              <div style={{ fontSize: 9, fontStyle: 'italic', color: 'var(--amber)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.6 }}>
                <span className="blink">●</span> static analysis: {sandboxStep.message} · {sandboxStep.step}/{sandboxStep.total}
              </div>
              <div style={{ height: 3, borderRadius: 2, background: 'rgba(var(--amber-rgb), 0.15)', marginTop: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 2, background: 'var(--amber)',
                  width: `${Math.min(100, (sandboxStep.step / Math.max(sandboxStep.total, 1)) * 100)}%`,
                  transition: 'width 0.3s ease',
                }} />
              </div>
            </div>
          )}
          {running.map(k => (
            <div key={k} style={{ fontSize: 9, fontStyle: 'italic', color: 'var(--amber)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.6 }}>
              <span className="blink">●</span> waiting on {AGENT_LABELS[k] ?? k}
              {typeof agentElapsed[k] === 'number' ? ` · ${agentElapsed[k]}s` : ''}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── REPORTS tab — stage content ───────────────────────────────────────────────

// Ported from the old standalone ThreatReportPanel (now merged here so
// stage-1 data only shows up in one place instead of twice). Keeps the same
// useRef+setTimeout width-animation technique — Stage1Content only ever
// mounts once `s` is available (the accordion item it lives in is itself
// conditionally rendered), so there's no "reset gauge on clear" case to
// handle here the way the original component needed.
function Stage1Content({ s, isNarrow }: { s: Stage1Data; isNarrow?: boolean }) {
  const riskRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      if (riskRef.current) riskRef.current.style.width = `${s.risk_score}%`;
    }, 80);
    return () => clearTimeout(t);
  }, [s.risk_score]);

  if (!s.malware_family && !s.verdict && typeof s.risk_score !== 'number') {
    return <StageEmptyNote s={s} />;
  }

  const severityColor = s.severity === 'CRITICAL' ? 'var(--magenta)' : s.severity === 'HIGH' ? 'var(--amber)' : 'var(--text-cyan)';
  const pct = Math.round((s.confidence ?? 0) <= 1 ? (s.confidence ?? 0) * 100 : (s.confidence ?? 0));

  // Sized up noticeably from the original compact rendering — this now sits
  // in a tall widget with lots of vertical room (the overview fills
  // whatever height Agents/Raw Logs settle the row at), so a small dense
  // banner left most of it blank. Bigger type and more breathing room make
  // it actually use that space instead of floating in it.
  return (
    <div style={{ fontSize: 11 }}>
      {/* Threat identity banner */}
      <div style={{
        padding: '20px 22px', marginBottom: 22,
        background: 'rgba(var(--rose-rgb), 0.08)',
        border: '1px solid rgba(var(--rose-rgb), 0.3)',
        borderRadius: 4,
      }}>
        <div style={{ display: 'flex', flexWrap: isNarrow ? 'wrap' : 'nowrap', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px 18px' }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', letterSpacing: 2 }}>MALWARE FAMILY</div>
            <div style={{ fontSize: 28, fontFamily: "'Orbitron', monospace", color: 'var(--magenta)', marginTop: 4, lineHeight: 1.2, wordBreak: 'break-word' }}>
              {s.malware_family}
            </div>
          </div>
          <div style={{ minWidth: 0, textAlign: isNarrow ? 'left' : 'right' }}>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', letterSpacing: 2 }}>VERDICT</div>
            <div style={{ fontSize: 15, color: severityColor, fontFamily: "'Orbitron', monospace", marginTop: 4, wordBreak: 'break-word' }}>
              {s.verdict}
            </div>
          </div>
        </div>
        <div style={{ marginTop: 14, fontSize: 12, color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.8 }}>
          {s.one_line_summary}
        </div>
      </div>

      {/* Risk gauge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ fontSize: 11, color: 'var(--text-dim)', letterSpacing: 1 }}>RISK SCORE</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 34, fontFamily: "'Orbitron', monospace", color: s.risk_score >= 80 ? 'var(--magenta)' : 'var(--amber)', lineHeight: 1 }}>
            {s.risk_score}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>/100</span>
          <span style={{ fontSize: 9, padding: '3px 9px', border: '1px solid var(--emerald)', borderRadius: 4, color: 'var(--emerald)', fontFamily: "'Orbitron', monospace" }}>
            {pct}% CONF
          </span>
        </div>
      </div>
      <div className="risk-gauge" style={{ height: 12 }}>
        <div className="risk-fill" ref={riskRef} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-dim)', marginTop: 6 }}>
        <span>LOW</span>
        <span style={{ color: severityColor, fontFamily: "'Orbitron', monospace", fontSize: 12 }}>{s.severity}</span>
        <span>CRITICAL</span>
      </div>
    </div>
  );
}

// A Claude/Gemini call that times out or throws comes back as a bare
// `{error, partial: true}` stub instead of real stage fields — without this
// check that stage's whole box used to render as silent empty space (looked
// broken) instead of telling you what actually happened.
function StageEmptyNote({ s }: { s: object }) {
  const failed = 'error' in s;
  return (
    <div style={{ fontSize: 11, color: failed ? 'var(--rose)' : 'var(--text-dim)', fontStyle: 'italic', lineHeight: 1.7 }}>
      {failed
        ? 'This stage failed to generate (the model call timed out or errored) — re-running the analysis may fix it.'
        : 'No significant findings for this stage.'}
    </div>
  );
}

function Stage2Content({ s }: { s: Stage2Data }) {
  if (!s.executive_summary && !s.affected_systems?.length && !s.business_impact) {
    return <StageEmptyNote s={s} />;
  }
  return (
    <div style={{ fontSize: 11 }}>
      {s.executive_summary && (
        <div style={{ color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.8, marginBottom: 14 }}>{s.executive_summary}</div>
      )}
      {s.affected_systems?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: 1, marginBottom: 6 }}>AFFECTED SYSTEMS</div>
          {s.affected_systems.map((sys, i) => (
            <div key={i} style={{ color: 'var(--amber)', padding: '3px 0' }}>▸ {sys}</div>
          ))}
        </>
      )}
      {s.business_impact && (
        <div style={{ marginTop: 14, padding: '10px 12px', background: 'rgba(var(--amber-rgb), 0.04)', border: '1px solid rgba(var(--amber-rgb), 0.2)', borderRadius: 3, fontSize: 11, color: 'var(--amber)', lineHeight: 1.7 }}>
          <span style={{ color: 'var(--text-dim)' }}>IMPACT: </span>{s.business_impact}
        </div>
      )}
    </div>
  );
}

function Stage3Content({ s }: { s: Stage3Data }) {
  const iocs = s.iocs ?? { domains: [], ips: [], files: [], registry_keys: [] };
  const hasMitre = !!s.mitre_techniques?.length;
  const hasIocs = iocs.domains.length > 0 || iocs.ips.length > 0 || iocs.files.length > 0;
  if (!hasMitre && !hasIocs && !s.attack_chain) {
    return <StageEmptyNote s={s} />;
  }
  return (
    <div style={{ fontSize: 11 }}>
      {s.mitre_techniques?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: 1, marginBottom: 6 }}>MITRE ATT&amp;CK</div>
          {s.mitre_techniques.map((t, i) => (
            <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid rgba(var(--cyan-rgb), 0.05)' }}>
              <span style={{ color: 'var(--magenta)', fontFamily: "'Orbitron', monospace", fontSize: 10 }}>{t.id}</span>
              {' '}<span style={{ color: 'var(--text-cyan)' }}>{t.name}</span>
              <span style={{ color: 'var(--text-dim)' }}> · {t.tactic}</span>
              {t.description && <div style={{ fontSize: 10, color: 'var(--text-dim)', paddingLeft: 8, marginTop: 2 }}>{t.description}</div>}
            </div>
          ))}
        </>
      )}
      {(iocs.domains.length > 0 || iocs.ips.length > 0 || iocs.files.length > 0) && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: 1, marginTop: 16, marginBottom: 6 }}>IOCs</div>
          {iocs.domains.map((d, i) => <div key={`d${i}`} style={{ color: 'var(--magenta)', fontSize: 10, padding: '2px 0' }}><span style={{ color: 'var(--text-dim)' }}>DOMAIN </span>{d}</div>)}
          {iocs.ips.map((ip, i)   => <div key={`ip${i}`} style={{ color: 'var(--magenta)', fontSize: 10, padding: '2px 0' }}><span style={{ color: 'var(--text-dim)' }}>IP     </span>{ip}</div>)}
          {iocs.files.slice(0, 4).map((f, i) => <div key={`f${i}`} style={{ color: 'var(--amber)', fontSize: 10, padding: '2px 0', wordBreak: 'break-all' }}><span style={{ color: 'var(--text-dim)' }}>FILE   </span>{f}</div>)}
        </>
      )}
      {s.attack_chain && (
        <div style={{ marginTop: 14, padding: '10px 12px', background: '#010814', fontSize: 10, color: '#7ab8cc', lineHeight: 1.7, border: '1px solid rgba(var(--cyan-rgb), 0.1)', borderRadius: 3 }}>
          <div style={{ color: 'var(--text-dim)', marginBottom: 5 }}>ATTACK CHAIN</div>
          {s.attack_chain}
        </div>
      )}
    </div>
  );
}

function Stage4Content({ s }: { s: Stage4Data }) {
  const CIRCLED = ['①', '②', '③', '④', '⑤', '⑥'];
  const URGENCY_COLOR: Record<string, string> = {
    immediate: 'var(--magenta)', '24h': 'var(--amber)', '72h': 'var(--text-cyan)',
  };
  const [yaraOpen, setYaraOpen] = useState(false);

  if (!s.action_plan?.length && !s.long_term_recommendations?.length && !s.yara_rule) {
    return <StageEmptyNote s={s} />;
  }

  return (
    <div style={{ fontSize: 11 }}>
      {s.action_plan?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: 1, marginBottom: 6 }}>ACTION PLAN</div>
          {s.action_plan.slice().sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99)).map((item, i) => {
            const urgColor = URGENCY_COLOR[item.urgency] ?? 'var(--text-cyan)';
            return (
              <div key={i} style={{ padding: '8px 10px', marginBottom: 6, borderLeft: `3px solid ${urgColor}`, background: 'rgba(var(--cyan-rgb), 0.02)', display: 'flex', gap: 8 }}>
                <span style={{ color: urgColor, fontSize: 13, flexShrink: 0 }}>{CIRCLED[i] ?? `${i+1}.`}</span>
                <div>
                  <div style={{ color: 'var(--text-cyan)' }}>{item.action}</div>
                  <div style={{ fontSize: 9, color: urgColor, letterSpacing: 1, marginTop: 2 }}>{item.urgency?.toUpperCase()}</div>
                </div>
              </div>
            );
          })}
        </>
      )}
      {s.long_term_recommendations?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: 1, marginTop: 14, marginBottom: 6 }}>LONG-TERM</div>
          {s.long_term_recommendations.map((r, i) => (
            <div key={i} style={{ color: '#7ab8cc', padding: '3px 0', fontSize: 10 }}>▸ {r}</div>
          ))}
        </>
      )}
      {s.yara_rule && (
        <div style={{ marginTop: 14 }}>
          <div
            onClick={() => setYaraOpen(v => !v)}
            className="clickable"
            style={{ cursor: 'pointer', fontSize: 10, color: 'var(--text-dim)', display: 'flex', justifyContent: 'space-between' }}
          >
            <span>YARA DETECTION RULE</span><span>{yaraOpen ? '▲' : '▼'}</span>
          </div>
          {yaraOpen && (
            <pre style={{ fontSize: 9, color: 'var(--emerald)', background: '#010814', padding: 12, marginTop: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', border: '1px solid rgba(var(--emerald-rgb), 0.15)', borderRadius: 3 }}>
              {s.yara_rule}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── REPORTS tab ───────────────────────────────────────────────────────────────

const STAGE_META: { key: 1 | 2 | 3 | 4; label: string; accent: string }[] = [
  { key: 1, label: 'Threat Identity', accent: 'rose' },
  { key: 2, label: 'Executive Summary', accent: 'blue' },
  { key: 3, label: 'Technical Analysis', accent: 'violet' },
  { key: 4, label: 'Remediation Plan', accent: 'emerald' },
];

function StageContent({ num, reportStages, isNarrow }: { num: number; reportStages: ReportStages; isNarrow?: boolean }) {
  switch (num) {
    case 1: return reportStages.stage1 ? <Stage1Content s={reportStages.stage1} isNarrow={isNarrow} /> : null;
    case 2: return reportStages.stage2 ? <Stage2Content s={reportStages.stage2} /> : null;
    case 3: return reportStages.stage3 ? <Stage3Content s={reportStages.stage3} /> : null;
    case 4: return reportStages.stage4 ? <Stage4Content s={reportStages.stage4} /> : null;
    default: return null;
  }
}

function EyeIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

// Portal to document.body so the popup escapes every ancestor's
// `overflow: hidden`/Framer-animated containing block (both of which clip or
// mis-position a plain absolutely-positioned child).
function ReportModal({ title, accent, onClose, children }: {
  title: string; accent: string; onClose: () => void; children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (typeof document === 'undefined') return null;

  return createPortal(
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(2, 6, 16, 0.75)', backdropFilter: 'blur(2px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(640px, 100%)', maxHeight: '85vh', overflowY: 'auto',
          background: 'var(--bg-panel)', border: `1px solid var(--${accent})`,
          borderRadius: 10, boxShadow: `0 0 40px rgba(var(--${accent}-rgb), 0.2)`,
          padding: 20,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <span style={{
            fontFamily: "'Orbitron', monospace", fontSize: 11, letterSpacing: 1.5,
            color: `var(--${accent})`, textTransform: 'uppercase',
          }}>
            {title}
          </span>
          <span onClick={onClose} className="clickable" style={{ cursor: 'pointer', color: 'var(--text-dim)', fontSize: 15, padding: '0 4px' }}>✕</span>
        </div>
        {children}
      </div>
    </div>,
    document.body
  );
}

function stageToText(num: number, reportStages: ReportStages): string {
  const divider = '='.repeat(48);
  switch (num) {
    case 1: {
      const s = reportStages.stage1;
      if (!s) return 'Stage 1 data not yet available.';
      return `THREAT IDENTITY\n${divider}\nMalware Family: ${s.malware_family}\nVerdict: ${s.verdict}\nRisk Score: ${s.risk_score}/100\nSeverity: ${s.severity}\nConfidence: ${Math.round(s.confidence * 100)}%\n\nSummary:\n${s.one_line_summary}\n`;
    }
    case 2: {
      const s = reportStages.stage2;
      if (!s) return 'Stage 2 data not yet available.';
      return `EXECUTIVE SUMMARY\n${divider}\n${s.executive_summary}\n\nAffected Systems:\n${(s.affected_systems ?? []).map(x => `  - ${x}`).join('\n')}\n\nBusiness Impact:\n${s.business_impact}\n`;
    }
    case 3: {
      const s = reportStages.stage3;
      if (!s) return 'Stage 3 data not yet available.';
      let t = `TECHNICAL ANALYSIS\n${divider}\nMITRE ATT&CK Techniques:\n`;
      (s.mitre_techniques ?? []).forEach(m => { t += `  ${m.id}  ${m.name}  [${m.tactic}]\n  ${m.description}\n\n`; });
      const iocs = s.iocs ?? { domains: [], ips: [], files: [], registry_keys: [] };
      t += `IOCs:\n  Domains: ${iocs.domains.join(', ')}\n  IPs: ${iocs.ips.join(', ')}\n  Files: ${iocs.files.join(', ')}\n\nAttack Chain:\n${s.attack_chain}\n`;
      return t;
    }
    case 4: {
      const s = reportStages.stage4;
      if (!s) return 'Stage 4 data not yet available.';
      let t = `REMEDIATION PLAN\n${divider}\nAction Plan:\n`;
      (s.action_plan ?? []).forEach((a, i) => { t += `  ${i+1}. [${a.urgency?.toUpperCase()}] ${a.action}\n`; });
      t += `\nLong-term Recommendations:\n${(s.long_term_recommendations ?? []).map(r => `  - ${r}`).join('\n')}\n\nIOCs to Block:\n${(s.iocs_to_block ?? []).map(x => `  - ${x}`).join('\n')}\n\nYARA Rule:\n${s.yara_rule}\n`;
      return t;
    }
    default: return '';
  }
}

async function downloadPDF(filename: string, text: string) {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 40;
  const usable = doc.internal.pageSize.getWidth() - margin * 2;

  doc.setFillColor(1, 8, 20);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), doc.internal.pageSize.getHeight(), 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(0, 245, 255);
  doc.text('MalwareScope Threat Report', margin, 52);

  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 150, 160);
  doc.text(`Generated: ${new Date().toLocaleString()}`, margin, 66);

  doc.setDrawColor(0, 245, 255);
  doc.setLineWidth(0.5);
  doc.line(margin, 72, margin + usable, 72);

  doc.setFontSize(9);
  doc.setTextColor(180, 220, 230);
  const lines = doc.splitTextToSize(text, usable);
  let y = 88;
  for (const line of lines) {
    if (y > doc.internal.pageSize.getHeight() - 40) {
      doc.addPage();
      doc.setFillColor(1, 8, 20);
      doc.rect(0, 0, doc.internal.pageSize.getWidth(), doc.internal.pageSize.getHeight(), 'F');
      y = 40;
    }
    doc.text(line, margin, y);
    y += 13;
  }

  doc.save(filename);
}

function ReportsTab({ reportStages, isNarrow }: { reportStages: ReportStages; isNarrow?: boolean }) {
  const firstAvailable = STAGE_META.find(m => !!reportStages[`stage${m.key}` as keyof ReportStages])?.key ?? 1;
  const [selected, setSelected] = useState<number>(firstAvailable);
  const [modalStage, setModalStage] = useState<number | null>(null);

  // Jump the overview to a newly-arrived stage automatically as long as
  // nothing's been picked yet — keeps it showing something real as stages
  // stream in instead of sitting on "awaiting stage 1" after stage 2 lands.
  useEffect(() => {
    if (reportStages[`stage${selected}` as keyof ReportStages]) return;
    const next = STAGE_META.find(m => !!reportStages[`stage${m.key}` as keyof ReportStages]);
    if (next) setSelected(next.key);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportStages.stage1, reportStages.stage2, reportStages.stage3, reportStages.stage4]);

  const allDone = !!(reportStages.stage1 && reportStages.stage2 && reportStages.stage3 && reportStages.stage4);

  const handleDownloadCurrent = async () => {
    const text = stageToText(selected, reportStages);
    await downloadPDF(`MalwareScope_Stage${selected}.pdf`, text);
  };

  const handleDownloadFull = async () => {
    const full = [1, 2, 3, 4].map(n => stageToText(n, reportStages)).join('\n\n');
    await downloadPDF('MalwareScope_FullReport.pdf', full);
  };

  const selectedMeta = STAGE_META[selected - 1];
  const modalMeta = modalStage != null ? STAGE_META[modalStage - 1] : null;
  const selectedHasData = !!reportStages[`stage${selected}` as keyof ReportStages];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* Download buttons */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexShrink: 0 }}>
        <button
          onClick={handleDownloadCurrent}
          disabled={!selectedHasData}
          style={{
            flex: 1, padding: '4px 6px', fontSize: 8,
            background: 'rgba(var(--cyan-rgb), 0.06)', border: '1px solid rgba(var(--cyan-rgb), 0.25)',
            color: 'var(--text-cyan)', cursor: 'pointer', borderRadius: 2, letterSpacing: 0.5,
          }}
        >
          ↓ THIS STAGE PDF
        </button>
        <button
          onClick={handleDownloadFull}
          disabled={!allDone}
          style={{
            flex: 1, padding: '4px 6px', fontSize: 8,
            background: allDone ? 'rgba(var(--rose-rgb), 0.08)' : 'rgba(0,0,0,0.2)',
            border: `1px solid ${allDone ? 'rgba(var(--rose-rgb), 0.3)' : 'rgba(var(--cyan-rgb), 0.1)'}`,
            color: allDone ? 'var(--magenta)' : 'var(--text-dim)',
            cursor: allDone ? 'pointer' : 'default', borderRadius: 2, letterSpacing: 0.5,
          }}
        >
          ↓ FULL REPORT PDF
        </button>
      </div>

      {/* Overview up top — the actual malware-family/verdict/findings
          content for whichever stage is selected — with the stage-cycling
          pills below it. Content first, controls last. */}
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', marginBottom: 10 }}>
        {!selectedHasData ? (
          <div style={{ fontSize: 9, color: 'var(--text-dim)' }}>
            <span className="blink">▸</span> Awaiting {selectedMeta.label.toLowerCase()}...
          </div>
        ) : (
          <StageContent num={selected} reportStages={reportStages} isNarrow={isNarrow} />
        )}
      </div>

      {/* Stage picker — a horizontal row of distinguishable per-stage pills
          (own accent color each, like the agent nodes) that wraps instead of
          a side column, since this widget is tall and often narrow (it
          shares a row with Agents/Raw Logs) rather than short and wide. Each
          has an eye icon to pop the full report open. */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, flexShrink: 0 }}>
        {STAGE_META.map(meta => {
          const hasData = !!reportStages[`stage${meta.key}` as keyof ReportStages];
          const isSelected = selected === meta.key;
          return (
            <div
              key={meta.key}
              onClick={() => hasData && setSelected(meta.key)}
              className={hasData ? 'clickable' : undefined}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, flex: '1 1 140px',
                padding: '7px 9px', borderRadius: 6, cursor: hasData ? 'pointer' : 'default',
                border: `1px solid ${
                  !hasData ? 'var(--border)'
                    : isSelected ? `var(--${meta.accent})`
                    : `rgba(var(--${meta.accent}-rgb), 0.3)`
                }`,
                background: !hasData ? 'transparent'
                  : isSelected ? `rgba(var(--${meta.accent}-rgb), 0.12)`
                  : `rgba(var(--${meta.accent}-rgb), 0.04)`,
                transition: 'background-color 0.15s ease, border-color 0.15s ease',
              }}
            >
              <span style={{
                flex: 1, minWidth: 0, fontSize: 9, letterSpacing: 0.5, fontFamily: "'Orbitron', monospace",
                color: hasData ? `var(--${meta.accent})` : 'var(--text-dim)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {hasData ? '✓' : '○'} {meta.label.toUpperCase()}
              </span>
              {hasData && (
                <span
                  onClick={e => { e.stopPropagation(); setModalStage(meta.key); }}
                  title="View full report"
                  className="clickable"
                  style={{ color: `var(--${meta.accent})`, cursor: 'pointer', display: 'flex', opacity: 0.85, flexShrink: 0 }}
                >
                  <EyeIcon />
                </span>
              )}
            </div>
          );
        })}
      </div>

      {modalMeta && (
        <ReportModal title={modalMeta.label} accent={modalMeta.accent} onClose={() => setModalStage(null)}>
          <StageContent num={modalStage!} reportStages={reportStages} isNarrow={isNarrow} />
        </ReportModal>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function BehavioralAnalysisPanel({ fileName, currentStage, stageDone, agentStatuses, agentElapsed, sandboxStep, sandboxResult, onSkipVirusTotal, reportStages, terminalLogs, isNarrow }: Props) {
  // Agents, Raw Logs and Reports each default to expanded, sharing one row —
  // any can be individually minimized to a thin strip. Reports just doesn't
  // render until there's data, then rises in and the page scrolls to it.
  const [minimized, setMinimized] = useState<{ agents: boolean; logs: boolean; reports: boolean }>({
    agents: false, logs: false, reports: false,
  });
  const reportsRef = useRef<HTMLDivElement>(null);

  // Agents+Logs set the row's height; Reports conforms to it instead of the
  // other way around. Without this, clicking between report stages (whose
  // content heights differ a lot — a short banner vs. a long MITRE list)
  // would resize the *whole row* every time, snapping Agents/Logs along
  // with it. Measuring the Agents+Logs sub-row and animating Reports' own
  // height to match keeps that resize contained to Reports, and smooth.
  const agentsLogsRef = useRef<HTMLDivElement>(null);
  const [rowHeight, setRowHeight] = useState<number | null>(null);

  useEffect(() => {
    const el = agentsLogsRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const h = entries[0]?.contentRect.height;
      if (h) setRowHeight(h);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (!reportStages.stage1) return;
    const t = setTimeout(() => {
      reportsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
    return () => clearTimeout(t);
  }, [reportStages.stage1]);

  const reportsBadge = reportStages.stage1
    ? `${[1, 2, 3, 4].filter(n => reportStages[`stage${n}` as keyof ReportStages]).length}/4`
    : undefined;

  // Three puzzle pieces sharing one row — minimizing one frees the space
  // the others expand into (want Logs+Reports together? minimize Agents).
  // Any of them can also be minimized all the way down to a thin strip.
  const toggleMinimize = (key: 'agents' | 'logs' | 'reports') =>
    setMinimized(m => ({ ...m, [key]: !m[key] }));

  return (
    <Panel title="BEHAVIORAL ANALYSIS ENGINE">
      {/* The specimen name used to live in a separate File Intake panel that
          stays open the whole run — now that panel collapses away once
          running, this is the one place that info is still shown. */}
      {fileName && (
        <div style={{
          fontSize: 9, color: 'var(--text-dim)', letterSpacing: 1,
          marginTop: -10, marginBottom: 14, wordBreak: 'break-all',
        }}>
          ANALYZING: <span style={{ color: 'var(--text-cyan)' }}>{fileName}</span>
        </div>
      )}

      {/* Agents, Raw Logs and Reports all share one row, like puzzle pieces
          in the same rectangular area — each can be minimized to a thin
          strip (its header's "−") to free room for the other two, which
          grow to fill it via ordinary flex redistribution. Reports doesn't
          exist in the row at all until there's something to show, then
          fades in and auto-scrolls into view. Reports' own height is pinned
          to the measured Agents+Logs height (see rowHeight above) rather
          than contributing its own — see the effect above for why. */}
      <div style={{ display: 'flex', flexDirection: isNarrow ? 'column' : 'row', gap: 14, alignItems: 'stretch', marginTop: 12 }}>
        <div
          ref={agentsLogsRef}
          style={
            isNarrow
              ? { display: 'flex', flexDirection: 'column', gap: 14 }
              : { display: 'flex', gap: 14, alignItems: 'stretch', flex: '6 1 0%', minWidth: 0 }
          }
        >
        <div style={{ flex: minimized.agents ? (isNarrow ? '0 0 44px' : '0 0 34px') : (isNarrow ? '0 0 420px' : '1 1 0%'), minWidth: 0, display: 'flex' }}>
          <Widget
            accent="blue" label="Agents" style={{ flex: 1 }} horizontal={isNarrow}
            minimized={minimized.agents} onToggleMinimize={() => toggleMinimize('agents')}
          >
            {/* Stage pipeline bar — a real progress stepper, each phase
                driven by actual WS/fetch events (see dashboard/page.tsx's
                advanceStage calls), not a fixed timer. AGENTS/REPORT show
                a live x/4 sub-count once reached. */}
            <div className="stages" style={{ margin: '0 0 14px' }}>
              {STAGES.map((s, i) => {
                let suffix = '';
                if (currentStage >= i) {
                  if (i === 1 && sandboxStep) {
                    suffix = ` ${sandboxStep.step}/${sandboxStep.total}`;
                  } else if (i === 2) {
                    const n = CORE_AGENT_KEYS.filter(k => agentStatuses[k].status === 'complete').length;
                    suffix = ` ${n}/4`;
                  } else if (i === 3) {
                    const n = [1, 2, 3, 4].filter(num => !!reportStages[`stage${num}` as keyof ReportStages]).length;
                    suffix = ` ${n}/4`;
                  }
                }
                return (
                  <div key={s} className={stageClass(i, currentStage, stageDone)}>{s}{suffix}</div>
                );
              })}
            </div>

            <AgentsTab
              agentStatuses={agentStatuses}
              agentElapsed={agentElapsed}
              currentStage={currentStage}
              stageDone={stageDone}
              sandboxStep={sandboxStep}
              sandboxResult={sandboxResult}
              onSkipVirusTotal={onSkipVirusTotal}
              isNarrow={isNarrow}
            />
          </Widget>
        </div>

        <div style={{ flex: minimized.logs ? (isNarrow ? '0 0 44px' : '0 0 34px') : (isNarrow ? '0 0 320px' : '1 1 0%'), minWidth: 0, display: 'flex' }}>
          <Widget
            accent="amber" label="Raw Logs" live style={{ flex: 1 }} horizontal={isNarrow}
            minimized={minimized.logs} onToggleMinimize={() => toggleMinimize('logs')}
          >
            <LogsTab
              terminalLogs={terminalLogs}
              agentStatuses={agentStatuses}
              agentElapsed={agentElapsed}
              sandboxStep={sandboxStep}
            />
          </Widget>
        </div>
        </div>

        <AnimatePresence>
          {reportStages.stage1 && (
            <motion.div
              key="reports-section"
              ref={reportsRef}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.4 }}
              style={
                isNarrow
                  ? { flex: minimized.reports ? '0 0 44px' : '0 0 420px', minWidth: 0, display: 'flex' }
                  : {
                    flex: minimized.reports ? '0 0 34px' : '3 1 0%', minWidth: 0, display: 'flex',
                    height: rowHeight ?? undefined,
                    transition: 'height 0.4s cubic-bezier(0.65,0,0.35,1)',
                  }
              }
            >
              <Widget
                accent="emerald" label="Reports" badge={reportsBadge} bgAlpha={0.07} style={{ flex: 1, minHeight: 0 }} horizontal={isNarrow}
                minimized={minimized.reports} onToggleMinimize={() => toggleMinimize('reports')}
              >
                <ReportsTab reportStages={reportStages} isNarrow={isNarrow} />
              </Widget>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Panel>
  );
}
