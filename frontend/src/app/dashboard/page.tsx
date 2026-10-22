'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel, {
  type AgentStatuses,
  type AgentStatus,
} from '@/components/BehavioralAnalysisPanel';
import {
  type ReportStages,
  type Stage1Data,
  type Stage2Data,
  type Stage3Data,
  type Stage4Data,
} from '@/components/ThreatReportPanel';
import { useRunActive } from '@/contexts/RunActiveContext';
import { useIsNarrow } from '@/lib/useIsNarrow';

import dynamic from 'next/dynamic';
const LinuxSandboxPanel = dynamic(() => import('@/components/LinuxSandboxPanel'), { ssr: false });

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// 4 honest phases, each driven by a real WS/fetch event — no fixed timer.
// UPLOAD=0, SANDBOX=1, AGENTS=2, REPORT=3.
const CORE_AGENT_KEYS = ['ingestion', 'static_analysis', 'mitre_mapping', 'remediation'] as const;

// The backend's "complete" events carry structured `data`, not a summary
// string — build a short, real one per agent so the node shows what it
// actually found, not just a generic "complete".
function summarizeAgentComplete(event: string, data: Record<string, unknown>, fallbackMessage: string): string {
  switch (event) {
    case 'ingestion': {
      const flags = (data.suspicious_flags as unknown[] | undefined)?.length ?? 0;
      return `${flags} suspicious flag${flags === 1 ? '' : 's'} found`;
    }
    case 'static_analysis': {
      const type = (data.malware_type as string) || 'unclassified';
      const sev = data.severity ?? '?';
      return `${type} · severity ${sev}/10`;
    }
    case 'mitre_mapping': {
      const n = (data.techniques as unknown[] | undefined)?.length ?? 0;
      return `${n} ATT&CK technique${n === 1 ? '' : 's'} mapped`;
    }
    case 'remediation': {
      const conf = typeof data.confidence === 'number' ? Math.round(data.confidence * 100) : null;
      const steps = (data.containment_steps as unknown[] | undefined)?.length ?? 0;
      return conf != null ? `${steps} containment steps · ${conf}% confidence` : `${steps} containment steps`;
    }
    case 'report': {
      const risk = data.risk_score ?? '?';
      return `4-stage report generated · risk ${risk}/100`;
    }
    default:
      return fallbackMessage;
  }
}


const INITIAL_AGENT_STATUSES: AgentStatuses = {
  ingestion:       { status: 'idle', detail: '' },
  static_analysis: { status: 'idle', detail: '' },
  mitre_mapping:   { status: 'idle', detail: '' },
  remediation:     { status: 'idle', detail: '' },
  report:          { status: 'idle', detail: '' },
  virustotal:      { status: 'idle', detail: '' },
};

// Events that map directly to AgentStatuses keys
const AGENT_KEYS = new Set(['ingestion', 'static_analysis', 'mitre_mapping', 'remediation', 'report', 'virustotal']);

export default function Dashboard() {
  const { setActive: setWiresActive } = useRunActive();
  // .main-grid collapses to a single column below 860px (see globals.css) —
  // the two main children are positioned via inline gridColumn/gridRow
  // below (not CSS classes), so the column collapse needs a matching JS
  // switch here to stack them instead of overlapping in the same cell.
  const isNarrow = useIsNarrow();
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [hasStarted, setHasStarted] = useState(false);
  // Bumped once per run, synchronously with hasStarted/analysisRunning —
  // keyed onto BehavioralAnalysisPanel below so it fully remounts on every
  // new analysis. Without this, a second run in the same session would reset
  // reportStages but leave the panel's own internal accordion state (which
  // section is open) stranded on whatever it was left at after the first run.
  const [runSeq, setRunSeq] = useState(0);
  // Drives the Framer Motion morph below — once a run starts, File Intake
  // isn't needed anymore: it exit-animates (AnimatePresence) while
  // Behavioral Analysis's `layout`-animated wrapper grows into the freed
  // space in the same beat (mode="popLayout"), reading as one panel
  // literally turning into the other rather than two separate animations.
  // Deliberately NOT set in the same render as hasStarted: AnimatePresence
  // can only play an *exit* animation for something that actually rendered
  // first — if intakeCollapsed were already true on .main-grid's very first
  // render, File Intake would never have mounted at all, so there'd be
  // nothing to animate away. This flips a beat later specifically so it
  // mounts expanded first, then exits.
  const [intakeCollapsed, setIntakeCollapsed] = useState(false);
  // Every run is a full run — static analysis, VirusTotal, the AI report
  // agents, and e2b (auto-started alongside the rest, see the
  // LinuxSandboxPanel render below) all happen together.
  // Lifted out of LinuxSandboxPanel so Header's lock can account for e2b
  // still running even after the main pipeline itself has finished — e2b's
  // own patch loop (plus the human-in-the-loop pause) can easily outlast it.
  const [sandboxRunning, setSandboxRunning] = useState(false);
  const [sandboxResult, setSandboxResult] = useState<string | null>(null);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(4).fill(false));
  const [reportStages, setReportStages] = useState<ReportStages>({});
  const [agentStatuses, setAgentStatuses] = useState<AgentStatuses>(INITIAL_AGENT_STATUSES);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[system] MalwareScope initialized — awaiting specimen upload...',
  ]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [nowTick, setNowTick] = useState(0);
  const [sandboxStep, setSandboxStep] = useState<{ message: string; step: number; total: number } | null>(null);
  const staticData = null;
  const apiDoneRef = useRef(false);
  const agentStartedAtRef = useRef<Record<string, number>>({});

  function pushLog(line: string) {
    setTerminalLogs(prev => [...prev, line]);
  }

  // VirusTotal's own upload+poll loop can take minutes — let the user bail
  // out of it early from the AGENTS node instead of being stuck waiting.
  // The backend keeps going without it; everything downstream just runs
  // without VT enrichment.
  function skipVirusTotal() {
    if (!jobId) return;
    pushLog('[WARN] VIRUSTOTAL: skip requested by user...');
    fetch(`${API_URL}/jobs/${jobId}/skip-virustotal`, { method: 'POST' }).catch(() => {});
  }

  // Live elapsed-time ticker for whichever agent(s) are currently running —
  // purely a UI readout of real WS-sourced timestamps, not fabricated data.
  useEffect(() => {
    if (!analysisRunning) return;
    const id = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, [analysisRunning]);

  // Fires once, a beat after .main-grid first mounts with File Intake still
  // expanded (see intakeCollapsed's declaration above for why the delay
  // matters to AnimatePresence).
  useEffect(() => {
    if (!hasStarted) return;
    const t = setTimeout(() => setIntakeCollapsed(true), 60);
    return () => clearTimeout(t);
  }, [hasStarted]);

  const agentElapsed: Record<string, number> = {};
  for (const key of Object.keys(agentStatuses)) {
    if (agentStatuses[key as keyof AgentStatuses].status === 'running') {
      const startedAt = agentStartedAtRef.current[key];
      if (startedAt) agentElapsed[key] = Math.max(0, Math.floor(((nowTick || Date.now()) - startedAt) / 1000));
    }
  }

  function tryFinish() {
    if (apiDoneRef.current) {
      setAnalysisRunning(false);
      setCurrentStage(-1);
    }
  }

  // Monotonic — only ever moves the stepper forward, so a duplicate or
  // out-of-order event (e.g. the same WS event arriving twice) can't un-does
  // progress or double-count a transition.
  function advanceStage(toIndex: number) {
    setCurrentStage(prev => Math.max(prev, toIndex));
    setStageDone(prev => prev.map((done, i) => (i < toIndex ? true : done)));
  }

  const startAnalysis = useCallback(() => {
    if (analysisRunning || !fileInfo) return;

    setHasStarted(true);
    setWiresActive(true); // bring in the circuit-wires overlay now that a run is actually happening
    setRunSeq(n => n + 1);
    setJobId(null);

    setAnalysisRunning(true);
    setReportStages({});
    setAgentStatuses(INITIAL_AGENT_STATUSES);
    setTerminalLogs(['[system] Upload received — initiating analysis pipeline...']);
    setCurrentStage(0);
    setStageDone(Array(4).fill(false));
    setSandboxStep(null);
    setSandboxResult(null);
    apiDoneRef.current = false;
    agentStartedAtRef.current = {};

    if (fileInfo.file) {
      const formData = new FormData();
      formData.append('file', fileInfo.file);
      if (fileInfo.mode) formData.append('mode', fileInfo.mode);

      fetch(`${API_URL}/upload`, { method: 'POST', body: formData })
        .then(r => {
          if (!r.ok) throw new Error(`Upload error ${r.status}`);
          return r.json();
        })
        .then(({ job_id, mode }: { job_id: string; mode: string }) => {
          setJobId(job_id);
          if (mode === 'vt_log') {
            pushLog('[✓] VT behavior log detected — skipping static analysis');
            advanceStage(2); // UPLOAD + SANDBOX done, AGENTS active
          } else {
            advanceStage(1); // UPLOAD done, SANDBOX active
          }
          const wsBase = API_URL.replace(/^https?/, s => (s === 'https' ? 'wss' : 'ws'));
          const ws = new WebSocket(`${wsBase}/ws/${job_id}`);

          ws.onmessage = (ev) => {
            let msg: Record<string, unknown>;
            try {
              msg = JSON.parse(ev.data as string) as Record<string, unknown>;
            } catch (parseErr) {
              console.error('[WS] JSON parse error:', parseErr, 'raw:', ev.data);
              return;
            }

            console.log('[WS event]', msg.event,
              'stage' in msg ? `stage=${msg.stage}` : '',
              'status' in msg ? `status=${msg.status}` : '',
              msg);

            try {
              const event  = msg.event as string;
              const status = msg.status as string;

              // ── Agent status + log updates ──────────────────────────────────

              // Sandbox static analysis events (stage 0 — before AI pipeline).
              // Named "sandbox_static_analysis" specifically so it can never
              // collide with the "static_analysis" AI agent further down.
              if (event === 'sandbox_static_analysis' && status === 'running') {
                pushLog('[►] SANDBOX static analysis starting...');
              }
              // Real per-sub-step progress during static analysis (strings,
              // pefile, exiftool, binwalk, YARA, .NET) — not a fake heartbeat,
              // each one fires exactly when that sub-step actually starts.
              if (event === 'static_analysis_step') {
                const stepNum = Number(msg.step) || 0;
                const total   = Number(msg.total) || 0;
                const message = (msg.message as string) ?? '...';
                pushLog(`[·] (${stepNum}/${total}) ${message}`);
                setSandboxStep({ message, step: stepNum, total });
              }
              if (event === 'sandbox_static_analysis' && status === 'complete' && msg.data) {
                setSandboxStep(null);
                const d = msg.data as Record<string, unknown>;
                const entropy  = typeof d.entropy === 'number' ? d.entropy.toFixed(2) : '?';
                const level    = d.threat_level as string ?? 'UNKNOWN';
                const obf      = d.is_obfuscated ? ' OBFUSCATED' : '';
                setSandboxResult(`entropy ${entropy} · threat ${level}${obf}`);
                pushLog(`[✓] SANDBOX static analysis complete — entropy: ${entropy}  threat: ${level}${obf}`);
                const behaviors = (d.behaviors as string[] | undefined) ?? [];
                if (behaviors.length > 0) {
                  pushLog(`[✓] Behaviors: ${behaviors.slice(0, 4).join(' · ')}`);
                }
                const dangerFns = (d.dangerous_functions as string[] | undefined) ?? [];
                if (dangerFns.length > 0) {
                  pushLog(`[WARN] Dangerous functions: ${dangerFns.slice(0, 4).join(', ')}`);
                }
              }

              // Pipeline start (after sandbox, before agents)
              if (event === 'pipeline_start') {
                setSandboxStep(null);
                pushLog(`[►] ${(msg.message as string) ?? 'AI pipeline starting...'}`);
                advanceStage(2); // SANDBOX done, AGENTS active
              }

              // Agent running/complete/skipped/error events
              if (AGENT_KEYS.has(event) && status === 'running') {
                // Every agent sends a real descriptive message while running
                // (set in agents/pipeline.py) — show it, not just VirusTotal's.
                const detail = (msg.message as string) ?? '';
                agentStartedAtRef.current[event] = Date.now();
                setAgentStatuses(prev => ({
                  ...prev,
                  [event]: { status: 'running' as AgentStatus, detail },
                }));
                if (event === 'virustotal') {
                  pushLog(`[►] VIRUSTOTAL: ${detail || 'querying...'}`);
                } else {
                  pushLog(`[►] ${event.toUpperCase().replace('_', ' ')} agent starting...`);
                }
              }

              if (AGENT_KEYS.has(event) && status === 'complete') {
                // The backend sends structured `data`, not a message, for
                // completion — synthesize a short, real summary per agent
                // instead of leaving the node blank once it's done.
                const d = (msg.data ?? {}) as Record<string, unknown>;
                const detail = summarizeAgentComplete(event, d, (msg.message as string) ?? '');
                setAgentStatuses(prev => {
                  const next = { ...prev, [event]: { status: 'complete' as AgentStatus, detail } };
                  const coreDone = CORE_AGENT_KEYS.every(k => next[k].status === 'complete');
                  if (coreDone) advanceStage(3); // AGENTS done, REPORT active
                  return next;
                });
                if (event === 'virustotal') {
                  pushLog(`[✓] VIRUSTOTAL: ${detail}`);
                } else {
                  pushLog(`[✓] ${event.toUpperCase().replace('_', ' ')} agent complete`);
                }
              }

              if (AGENT_KEYS.has(event) && (status === 'skipped' || status === 'error')) {
                // Keep the real status (skipped vs error) and the real
                // backend message — this used to collapse both into a
                // hardcoded {status:'idle', detail:'skipped'}, which is why
                // the UI always said "not configured" regardless of the
                // actual reason (API error, user skip, or truly unconfigured).
                const detail = (msg.message as string) ?? '';
                setAgentStatuses(prev => ({
                  ...prev,
                  [event]: { status: status as AgentStatus, detail },
                }));
                pushLog(`[WARN] ${event.toUpperCase().replace('_', ' ')}: ${detail}`);
              }

              // Streaming report stages
              if (event === 'report_stage' && msg.data) {
                const stageNum = Number(msg.stage);
                const data = msg.data as Record<string, unknown>;
                console.log('[WS] report_stage received, stageNum=', stageNum, 'data keys:', Object.keys(data));

                // Mark report agent as running once first stage arrives
                if (stageNum === 1) {
                  setAgentStatuses(prev => ({
                    ...prev,
                    report: { status: 'running' as AgentStatus, detail: 'generating report stages...' },
                  }));
                }

                if (stageNum >= 1 && stageNum <= 4) {
                  setReportStages(prev => {
                    const next = { ...prev };
                    if      (stageNum === 1) next.stage1 = data as unknown as Stage1Data;
                    else if (stageNum === 2) next.stage2 = data as unknown as Stage2Data;
                    else if (stageNum === 3) next.stage3 = data as unknown as Stage3Data;
                    else if (stageNum === 4) next.stage4 = data as unknown as Stage4Data;
                    console.log('[WS] setReportStages → stages now:', Object.keys(next).filter(k => next[k as keyof ReportStages]));
                    return next;
                  });

                  const stageNames = ['', 'Threat Identity', 'Executive Summary', 'Technical Analysis', 'Remediation Plan'];
                  pushLog(`[✓] REPORT stage ${stageNum} complete — ${stageNames[stageNum]}`);

                  // Mark report complete after stage 4
                  if (stageNum === 4) {
                    setAgentStatuses(prev => ({
                      ...prev,
                      report: { status: 'complete' as AgentStatus, detail: 'all 4 stages generated' },
                    }));
                  }
                } else {
                  console.warn('[WS] report_stage with unexpected stageNum:', stageNum, msg);
                }
              }

              // Pipeline fully complete — hydrate any missed stages from done payload
              if (event === 'done' && msg.data) {
                const result = msg.data as Record<string, unknown>;
                const report = (result.report ?? {}) as Record<string, unknown>;
                console.log('[WS] done — report keys:', Object.keys(report));

                setReportStages(prev => {
                  const s1 = prev.stage1 ?? (report.stage1 as Stage1Data | undefined);
                  const s2 = prev.stage2 ?? (report.stage2 as Stage2Data | undefined);
                  const s3 = prev.stage3 ?? (report.stage3 as Stage3Data | undefined);
                  const s4 = prev.stage4 ?? (report.stage4 as Stage4Data | undefined);
                  console.log('[WS] done hydration — stage1 present:', !!s1, 's2:', !!s2, 's3:', !!s3, 's4:', !!s4);
                  return { stage1: s1, stage2: s2, stage3: s3, stage4: s4 };
                });

                pushLog('[✓] Pipeline complete — full report available');
                advanceStage(4); // mark all 4 stages done
                apiDoneRef.current = true;
                tryFinish();
              }

              if (event === 'error') {
                console.error('[WS] Analysis error:', msg.message);
                pushLog(`[CRIT] Pipeline error: ${msg.message as string}`);
                apiDoneRef.current = true;
                tryFinish();
              }
            } catch (handlerErr) {
              console.error('[WS] onmessage handler threw:', handlerErr, 'msg was:', msg);
            }
          };

          ws.onerror = () => {
            console.error('WebSocket connection failed');
            pushLog('[CRIT] WebSocket connection failed');
            apiDoneRef.current = true;
            tryFinish();
          };
        })
        .catch(err => {
          console.error('Upload error:', err);
          pushLog(`[CRIT] Upload failed: ${String(err)}`);
          apiDoneRef.current = true;
          tryFinish();
        });
    } else {
      // No real file attached (e.g. called without a selection) — there's no
      // backend run to wait on, so resolve immediately instead of leaving the
      // UI "running" forever with nothing left to drive it forward.
      pushLog('[WARN] No file attached — nothing to analyze.');
      advanceStage(4);
      apiDoneRef.current = true;
      tryFinish();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisRunning, fileInfo]);

  return (
    <>
      <Header locked={analysisRunning || sandboxRunning} showStartOver={hasStarted && !analysisRunning && !sandboxRunning} />
      {/* Pressing START ANALYSIS crossfades the pre-run intake screen into
          the full dashboard instead of snapping straight to it — mode="wait"
          lets the intake screen fully fade out before the grid fades in,
          rather than a jump cut. */}
      <AnimatePresence mode="wait">
        {!hasStarted ? (
          <motion.div
            key="pre-run"
            className="pre-run-wrap"
            initial={false}
            exit={{ opacity: 0, scale: 0.97 }}
            transition={{ duration: 0.4, ease: [0.65, 0, 0.35, 1] }}
          >
            <FileIntakePanel
              fileInfo={fileInfo}
              onFileLoaded={setFileInfo}
              onAnalyze={startAnalysis}
              analysisRunning={analysisRunning}
            />
          </motion.div>
        ) : (
          <motion.div
            key="main-grid"
            className="main-grid"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.45, ease: [0.65, 0, 0.35, 1] }}
          >
            {/* File Intake genuinely morphs into Behavioral Analysis: popLayout
                pulls it out of document flow the instant it starts exiting, so
                the sibling's `layout` animation can grow into the freed space
                in the same beat rather than waiting for the exit to finish. */}
            <AnimatePresence mode="popLayout">
              {!intakeCollapsed && (
                <motion.div
                  key="file-intake"
                  layout
                  style={{ gridColumn: 1, gridRow: 1, minWidth: 0 }}
                  exit={{ opacity: 0, scale: 0.92 }}
                  transition={{ duration: 0.55, ease: [0.65, 0, 0.35, 1] }}
                >
                  <FileIntakePanel
                    fileInfo={fileInfo}
                    onFileLoaded={setFileInfo}
                    onAnalyze={startAnalysis}
                    analysisRunning={analysisRunning}
                  />
                </motion.div>
              )}
            </AnimatePresence>

            <motion.div
              layout
              transition={{ duration: 0.55, ease: [0.65, 0, 0.35, 1] }}
              style={
                isNarrow
                  ? { gridRow: 2, gridColumn: 1, minWidth: 0 }
                  : { gridRow: 1, gridColumn: intakeCollapsed ? '1 / -1' : 2, minWidth: 0 }
              }
            >
              <BehavioralAnalysisPanel
                key={runSeq}
                isNarrow={isNarrow}
                fileName={fileInfo?.name}
                currentStage={currentStage}
                stageDone={stageDone}
                agentStatuses={agentStatuses}
                agentElapsed={agentElapsed}
                sandboxStep={sandboxStep}
                sandboxResult={sandboxResult}
                onSkipVirusTotal={skipVirusTotal}
                reportStages={reportStages}
                terminalLogs={terminalLogs}
              />
            </motion.div>

            {/* Always visible now — not something to dig for behind a toggle.
                LinuxSandboxPanel renders its own Panel heading, so no separate
                label is needed here (that used to duplicate it). Starts
                automatically, in parallel with static analysis. */}
            {/* Explicit gridRow, not left to auto-placement: once File Intake
                unmounts (intakeCollapsed) its row becomes vacant, and an
                auto-placed item greedily fills the first open cell — on the
                narrow single-column layout that would pull this panel above
                Behavioral Analysis instead of staying below it. */}
            <div style={{ gridColumn: '1 / -1', gridRow: isNarrow ? 3 : 2, minWidth: 0 }}>
              <LinuxSandboxPanel
                staticData={staticData}
                jobId={jobId}
                autoStart
                onRunningChange={setSandboxRunning}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
