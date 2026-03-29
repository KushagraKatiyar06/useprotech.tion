'use client';

import { useCallback, useRef, useState } from 'react';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel, {
  type AgentStatuses,
  type AgentStatus,
} from '@/components/BehavioralAnalysisPanel';
import ThreatReportPanel, {
  type ReportStages,
  type Stage1Data,
  type Stage2Data,
  type Stage3Data,
  type Stage4Data,
} from '@/components/ThreatReportPanel';
import SandboxSimulation from '@/components/SandboxSimulation';

const STAGE_DURATIONS = [800, 1500, 2500, 1000, 2000, 800];
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

const INITIAL_AGENT_STATUSES: AgentStatuses = {
  ingestion:       { status: 'idle', detail: '' },
  static_analysis: { status: 'idle', detail: '' },
  mitre_mapping:   { status: 'idle', detail: '' },
  remediation:     { status: 'idle', detail: '' },
  report:          { status: 'idle', detail: '' },
};

// Events that map directly to AgentStatuses keys
const AGENT_KEYS = new Set(['ingestion', 'static_analysis', 'mitre_mapping', 'remediation', 'report']);

export default function Dashboard() {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(6).fill(false));
  const [reportStages, setReportStages] = useState<ReportStages>({});
  const [agentStatuses, setAgentStatuses] = useState<AgentStatuses>(INITIAL_AGENT_STATUSES);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[system] MalwareScope initialized — awaiting specimen upload...',
  ]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const animDoneRef = useRef(false);
  const apiDoneRef = useRef(false);

  function pushLog(line: string) {
    setTerminalLogs(prev => [...prev, line]);
  }

  function tryFinish() {
    if (animDoneRef.current && apiDoneRef.current) {
      setAnalysisRunning(false);
      setCurrentStage(-1);
    }
  }

  const startAnalysis = useCallback(() => {
    if (analysisRunning || !fileInfo) return;

    setAnalysisRunning(true);
    setReportStages({});
    setAgentStatuses(INITIAL_AGENT_STATUSES);
    setTerminalLogs(['[system] Upload received — initiating analysis pipeline...']);
    setCurrentStage(-1);
    setStageDone(Array(6).fill(false));
    animDoneRef.current = false;
    apiDoneRef.current = false;

    if (fileInfo.file) {
      const formData = new FormData();
      formData.append('file', fileInfo.file);

      fetch(`${API_URL}/upload`, { method: 'POST', body: formData })
        .then(r => {
          if (!r.ok) throw new Error(`Upload error ${r.status}`);
          return r.json();
        })
        .then(({ job_id }: { job_id: string }) => {
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

              // Sandbox static analysis events (stage 0 — before AI pipeline)
              if (event === 'static_analysis' && status === 'running') {
                pushLog('[►] SANDBOX static analysis starting...');
              }
              if (event === 'static_analysis' && status === 'complete' && msg.data) {
                const d = msg.data as Record<string, unknown>;
                const entropy  = typeof d.entropy === 'number' ? d.entropy.toFixed(2) : '?';
                const level    = d.threat_level as string ?? 'UNKNOWN';
                const obf      = d.is_obfuscated ? ' OBFUSCATED' : '';
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
                pushLog(`[►] ${(msg.message as string) ?? 'AI pipeline starting...'}`);
              }

              // Agent running/complete events (ingestion, static_analysis agent, mitre_mapping, remediation, report)
              if (AGENT_KEYS.has(event) && status === 'running') {
                setAgentStatuses(prev => ({
                  ...prev,
                  [event]: { status: 'running' as AgentStatus, detail: '' },
                }));
                pushLog(`[►] ${event.toUpperCase().replace('_', ' ')} agent starting...`);
              }

              if (AGENT_KEYS.has(event) && status === 'complete') {
                const detail = (msg.message as string) ?? '';
                setAgentStatuses(prev => ({
                  ...prev,
                  [event]: { status: 'complete' as AgentStatus, detail },
                }));
                pushLog(`[✓] ${event.toUpperCase().replace('_', ' ')} agent complete`);
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
      // Demo mode — no real file, animation runs
      apiDoneRef.current = true;
    }

    // ── Circuit board stage animation (independent of API) ────────────────
    let idx = 0;

    function nextStage() {
      if (idx >= 6) return;

      if (idx > 0) {
        setStageDone(prev => {
          const next = [...prev];
          next[idx - 1] = true;
          return next;
        });
      }

      setCurrentStage(idx);

      if (idx === 5) {
        setTimeout(() => {
          setStageDone(prev => { const n = [...prev]; n[5] = true; return n; });
          animDoneRef.current = true;
          tryFinish();
        }, STAGE_DURATIONS[5]);
        return;
      }

      idx++;
      timerRef.current = setTimeout(nextStage, STAGE_DURATIONS[idx - 1]);
    }

    nextStage();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisRunning, fileInfo]);

  return (
    <>
      <Header />
      <div className="main-grid">
        <FileIntakePanel
          fileInfo={fileInfo}
          onFileLoaded={setFileInfo}
          onAnalyze={startAnalysis}
          analysisRunning={analysisRunning}
        />
        <BehavioralAnalysisPanel
          currentStage={currentStage}
          stageDone={stageDone}
          agentStatuses={agentStatuses}
          reportStages={reportStages}
          terminalLogs={terminalLogs}
        />
        <ThreatReportPanel stage1={reportStages.stage1} />
        <SandboxSimulation />
      </div>
    </>
  );
}
