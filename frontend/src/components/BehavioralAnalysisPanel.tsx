'use client';

import { useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import { DEMO_CONNS, DEMO_LOGS, DEMO_PROCS, type LogEntry, type Connection, type Process } from '@/lib/data';

const STAGES = ['UPLOAD', 'SANDBOX', 'MONITOR', 'PARSE', 'AI ANALYZE', 'REPORT'];

// ── Agent pipeline node definitions ───────────────────────────────────────────
const AGENT_NODES = [
  { id: 'ingestion',       label: 'INGESTION',    desc: 'Triage & structure',    col: 0, row: 0 },
  { id: 'static_analysis', label: 'STATIC',       desc: 'Classify & behaviors',  col: 1, row: 0 },
  { id: 'mitre_mapping',   label: 'MITRE',        desc: 'ATT&CK mapping',        col: 1, row: 1 },
  { id: 'remediation',     label: 'REMEDIATION',  desc: 'YARA + IOC blocking',   col: 2, row: 0 },
  { id: 'report',          label: 'REPORT',       desc: 'Final threat intel',     col: 3, row: 0 },
];

// Stage → which agents are active/done
function agentStatuses(currentStage: number, stageDone: boolean[]): Record<string, 'idle' | 'running' | 'done'> {
  const allDone = stageDone[5];
  if (allDone) return Object.fromEntries(AGENT_NODES.map(n => [n.id, 'done'])) as Record<string, 'idle' | 'running' | 'done'>;

  const s: Record<string, 'idle' | 'running' | 'done'> = {};
  for (const n of AGENT_NODES) s[n.id] = 'idle';

  if (currentStage >= 1) { s['ingestion'] = stageDone[2] ? 'done' : 'running'; }
  if (currentStage >= 3) { s['static_analysis'] = stageDone[3] ? 'done' : 'running'; s['mitre_mapping'] = stageDone[3] ? 'done' : 'running'; }
  if (currentStage >= 4) { s['remediation'] = stageDone[4] ? 'done' : 'running'; }
  if (currentStage >= 5) { s['report'] = 'running'; }
  return s;
}

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

interface Props {
  currentStage: number;
  stageDone: boolean[];
  staticData?: StaticResult | null;
}

// Convert real static analysis into log entries
function buildRealLogs(s: StaticResult): LogEntry[] {
  const logs: LogEntry[] = [];
  let sec = 1;

  logs.push({ sec: sec++, tag: 'info', cat: 'SYS', msg: `File loaded: ${s.file_name ?? 'unknown'} [${s.file_type}]` });
  if (s.sha256) logs.push({ sec: sec++, tag: 'info', cat: 'HASH', msg: `SHA256: ${s.sha256}` });
  if (s.entropy !== undefined) {
    const tag = s.entropy > 7 ? 'crit' : s.entropy > 6 ? 'warn' : 'info';
    logs.push({ sec: sec++, tag, cat: 'ENTR', msg: `Entropy: ${s.entropy} — ${s.entropy > 7 ? 'likely packed/encrypted' : s.entropy > 6 ? 'elevated entropy' : 'normal'}` });
  }
  if (s.is_obfuscated) logs.push({ sec: sec++, tag: 'warn', cat: 'OBFS', msg: 'Obfuscation detected in file content' });
  if (s.yara_matches?.length) {
    s.yara_matches.forEach(m => logs.push({ sec: sec++, tag: 'crit', cat: 'YARA', msg: `YARA match: ${m}` }));
  }

  const HIGH = new Set(['Process injection', 'AMSI bypass - antivirus evasion', 'ETW patching - event log evasion',
    'Shadow copy deletion (ransomware)', 'Reflective .NET assembly loading (fileless)', 'Process memory manipulation']);
  const MED = new Set(['PowerShell execution', 'Cryptographic operations', 'Dynamic code loading',
    'Hardcoded AES key detected', 'Packed or encrypted section (obfuscation)', 'Network C2 communication']);

  (s.behaviors ?? []).forEach(b => {
    const tag: LogEntry['tag'] = HIGH.has(b) ? 'crit' : MED.has(b) ? 'warn' : 'info';
    logs.push({ sec: sec++, tag, cat: 'BEHV', msg: b });
  });
  (s.mitre_techniques ?? []).forEach(t => logs.push({ sec: sec++, tag: 'warn', cat: 'MITR', msg: t }));
  (s.dropped_files ?? []).forEach(f => logs.push({ sec: sec++, tag: 'crit', cat: 'FILE', msg: `DROP: ${f}` }));
  (s.registry_keys ?? []).forEach(r => logs.push({ sec: sec++, tag: 'warn', cat: 'REG', msg: `WRITE: ${r}` }));

  return logs;
}

// Convert suspicious imports / PE sections into process-tree entries
function buildRealProcs(s: StaticResult): Process[] {
  const procs: Process[] = [];
  const HIGH_IMPORTS = ['createremotethread', 'virtualalloc', 'writeprocessmemory', 'ntcreatethreadex',
    'amsiscanbuffer', 'etweventwrite', 'shellex', 'winexec'];

  (s.suspicious_imports ?? s.dangerous_functions ?? []).slice(0, 7).forEach((imp, i) => {
    const low = imp.toLowerCase();
    const isHigh = HIGH_IMPORTS.some(h => low.includes(h));
    procs.push({
      name: imp.split('!')[1] ?? imp,
      pid: 1000 + i * 17,
      parent: imp.includes('!') ? imp.split('!')[0] : s.file_name ?? 'sample',
      color: isHigh ? 'red' : 'yellow',
    });
  });

  return procs;
}

// Convert IPs / URLs into connection entries
function buildRealConns(s: StaticResult): Connection[] {
  const conns: Connection[] = [];
  let ts = 0;

  const fmt = (n: number) => `00:${String(n).padStart(2, '0')}`;

  (s.ips_found ?? []).slice(0, 3).forEach(ip => {
    conns.push({ ts: fmt(ts++), dir: 'OUT', dst: ip, port: 443, size: '?KB', type: 'SUSPECT IP' });
  });
  (s.urls_found ?? []).slice(0, 3).forEach(url => {
    const host = url.replace(/https?:\/\//, '').split('/')[0];
    conns.push({ ts: fmt(ts++), dir: 'OUT', dst: host, port: 80, size: '?KB', type: 'URL' });
  });
  (s.domains_found ?? []).slice(0, 2).forEach(d => {
    conns.push({ ts: fmt(ts++), dir: 'OUT', dst: d, port: 443, size: '?KB', type: 'DOMAIN' });
  });

  return conns;
}

export default function BehavioralAnalysisPanel({ currentStage, stageDone, staticData }: Props) {
  const [activeTab, setActiveTab] = useState('process');
  const [logs, setLogs] = useState<LogEntry[]>([
    { sec: 0, tag: 'info', cat: 'SYS', msg: 'ThreatNet AI v2.4.1 — sandbox initialized' },
    { sec: 0, tag: 'info', cat: 'SYS', msg: 'Awaiting specimen upload...' },
  ]);
  const [procs, setProcs] = useState<Process[]>([]);
  const [conns, setConns] = useState<Connection[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const netAnimRef = useRef<number>(0);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  function addLog(entry: LogEntry) {
    const ts = new Date().toTimeString().slice(0, 8);
    setLogs(prev => [...prev, { ...entry, msg: `[${ts}] ${entry.msg}` }]);
  }

  // When real static data arrives, populate panels
  useEffect(() => {
    if (!staticData) return;

    const realLogs = buildRealLogs(staticData);
    const realProcs = buildRealProcs(staticData);
    const realConns = buildRealConns(staticData);

    // Stream logs with a short delay between each
    realLogs.forEach((entry, i) => {
      setTimeout(() => addLog(entry), i * 120);
    });

    setTimeout(() => setProcs(realProcs), 300);
    setTimeout(() => setConns(realConns), 600);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [staticData]);

  // Stage-driven demo logs (only when no real data yet)
  useEffect(() => {
    if (staticData) return;

    if (currentStage === 1) {
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'Restoring clean snapshot...' }), 0);
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'VM booted — transferring specimen' }), 600);
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'Running static analysis tools...' }), 1200);
    }
    if (currentStage === 2) {
      let delay = 0;
      DEMO_LOGS.forEach(entry => {
        setTimeout(() => addLog(entry), delay);
        delay += 350 + Math.random() * 200;
      });
      setProcs([]);
      let pd = 0;
      DEMO_PROCS.forEach(p => {
        setTimeout(() => setProcs(prev => [...prev, p]), pd);
        pd += 400;
      });
    }
    if (currentStage === 3) {
      setConns([]);
      DEMO_CONNS.forEach((c, i) => {
        setTimeout(() => setConns(prev => [...prev, c]), i * 600);
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentStage]);

  // Network canvas animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || activeTab !== 'network') return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const W = canvas.offsetWidth;
    const H = canvas.offsetHeight;

    type Packet = { x: number; y: number; vx: number; color: string; label: string };
    let packets: Packet[] = [];
    let lastSpawn = 0;

    function frame(ts: number) {
      ctx!.clearRect(0, 0, W, H);
      ctx!.strokeStyle = 'rgba(0,245,255,0.04)';
      ctx!.lineWidth = 0.5;
      for (let y = 0; y < H; y += 16) {
        ctx!.beginPath(); ctx!.moveTo(0, y); ctx!.lineTo(W, y); ctx!.stroke();
      }
      ctx!.fillStyle = 'rgba(0,245,255,0.25)';
      ctx!.font = '8px monospace';
      ctx!.fillText('HOST', 4, H - 4);
      ctx!.fillText('C2 SERVER', W - 58, H - 4);
      ctx!.strokeStyle = 'rgba(0,245,255,0.15)';
      ctx!.lineWidth = 1;
      ctx!.beginPath(); ctx!.moveTo(W - 2, 0); ctx!.lineTo(W - 2, H); ctx!.stroke();

      if (ts - lastSpawn > 600) {
        const types = [
          { color: '#ff2d9e', label: 'C2' },
          { color: '#ff2d9e', label: 'EXFIL' },
          { color: '#ffcc00', label: 'DNS' },
        ];
        const t = types[Math.floor(Math.random() * types.length)];
        packets.push({ x: 0, y: 10 + Math.random() * (H - 20), vx: 1.5 + Math.random() * 2, ...t });
        lastSpawn = ts;
      }

      packets = packets.filter(p => p.x < W);
      packets.forEach(p => {
        p.x += p.vx;
        const trail = 24;
        const grad = ctx!.createLinearGradient(p.x - trail, p.y, p.x, p.y);
        grad.addColorStop(0, 'transparent');
        grad.addColorStop(1, p.color);
        ctx!.strokeStyle = grad;
        ctx!.lineWidth = 2;
        ctx!.beginPath(); ctx!.moveTo(p.x - trail, p.y); ctx!.lineTo(p.x, p.y); ctx!.stroke();
        ctx!.fillStyle = p.color;
        ctx!.font = '7px monospace';
        ctx!.fillText(p.label, p.x + 3, p.y - 3);
      });

      netAnimRef.current = requestAnimationFrame(frame);
    }

    netAnimRef.current = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(netAnimRef.current);
  }, [activeTab]);

  function stageClass(i: number) {
    if (stageDone[i]) return 'stage done';
    if (currentStage === i) return 'stage active';
    return 'stage';
  }

  return (
    <Panel title="// BEHAVIORAL ANALYSIS ENGINE" className="center-panel" style={{ gridRow: 1 }}>
      <div className="stages">
        {STAGES.map((s, i) => (
          <div key={s} className={stageClass(i)}>{s}</div>
        ))}
      </div>

      <div className="tab-row">
        {['process', 'logs', 'network', 'agents', 'tree'].map(tab => (
          <div
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'process' ? 'IMPORTS' : tab === 'network' ? 'NETWORK' : tab === 'logs' ? 'RAW LOGS' : tab === 'agents' ? 'AGENTS' : 'PROC TREE'}
          </div>
        ))}
      </div>

      {activeTab === 'process' && (
        <div className="proc-list">
          {procs.length === 0 ? (
            <div className="f9 text-dim" style={{ padding: 8, textAlign: 'center' }}>
              Awaiting specimen...<span className="blink">_</span>
            </div>
          ) : procs.map(p => {
            const indent = staticData ? '' : (p.parent === 'explorer.exe' || p.parent === 'services.exe') ? '' : '    ';
            const memMb = Math.round(Math.random() * 80 + 10);
            return (
              <div key={`${p.pid}-${p.name}`} className={`proc-item ${p.color === 'red' ? 'danger' : ''}`}>
                <span style={{ color: 'var(--text-dim)', fontSize: 9 }}>{indent}├─</span>
                <span className={`proc-dot ${p.color}`} />
                <span className="proc-name">{p.name}</span>
                <span className="proc-pid">PID:{p.pid}</span>
                {!staticData && <span className="proc-mem">{memMb}MB</span>}
              </div>
            );
          })}
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="log-terminal" ref={logRef}>
          {logs.map((l, i) => (
            <div key={i} className="log-line">
              <span className="log-ts">{new Date().toTimeString().slice(0, 8)}</span>
              <span className={`log-tag ${l.tag}`}>{l.cat}</span>
              <span className="log-msg">{l.msg}</span>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'network' && (
        <>
          <div className="net-traffic">
            <canvas ref={canvasRef} style={{ width: '100%', height: '100%' }} />
          </div>
          <div className="mt8">
            <div className="f9 text-dim">CONNECTION LOG</div>
            <div style={{ fontSize: 10, lineHeight: 1.9, marginTop: 6, height: 120, overflowY: 'auto', background: '#010814', border: '1px solid rgba(0,245,255,0.1)', padding: 8 }}>
              {conns.length === 0 ? (
                <span className="text-dim">No connections observed.</span>
              ) : conns.map((c, i) => {
                const isExfil = c.type.includes('EXFIL') || c.type.includes('C2') || c.type.includes('SUSPECT');
                return (
                  <div key={i} style={{ color: isExfil ? 'var(--magenta)' : '#00ff88' }}>
                    [{c.ts}] {c.dir} → {c.dst}:{c.port} ({c.size}){' '}
                    <span style={{ color: 'var(--text-dim)' }}>{c.type}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {activeTab === 'agents' && (() => {
        const statuses = agentStatuses(currentStage, stageDone);
        const COL_W = 88, ROW_H = 54, PAD_X = 12, PAD_Y = 16;
        const nodeColor = (s: string) => s === 'done' ? '#00ff88' : s === 'running' ? '#ffcc00' : 'rgba(255,255,255,0.18)';
        const nodeBg    = (s: string) => s === 'done' ? 'rgba(0,255,136,0.08)' : s === 'running' ? 'rgba(255,204,0,0.10)' : 'rgba(255,255,255,0.03)';
        const nodeW = 76, nodeH = 36;

        // positions: 4 columns, 2 rows
        const pos = (col: number, row: number) => ({
          x: PAD_X + col * COL_W,
          y: PAD_Y + row * ROW_H,
        });

        // edges: ingestion→static, ingestion→mitre, static→remediation, mitre→remediation, remediation→report
        const edges: [string, string][] = [
          ['ingestion', 'static_analysis'],
          ['ingestion', 'mitre_mapping'],
          ['static_analysis', 'remediation'],
          ['mitre_mapping', 'remediation'],
          ['remediation', 'report'],
        ];

        const nodePos = Object.fromEntries(AGENT_NODES.map(n => {
          const { x, y } = pos(n.col, n.row);
          return [n.id, { x: x + nodeW / 2, y: y + nodeH / 2, px: x, py: y }];
        }));

        const svgW = PAD_X + 4 * COL_W + nodeW;
        const svgH = PAD_Y + 2 * ROW_H + nodeH;

        return (
          <div style={{ padding: '8px 0' }}>
            <div className="f9 text-dim" style={{ marginBottom: 8 }}>CLAUDE AI AGENT PIPELINE — 5 AGENTS</div>
            <svg width="100%" viewBox={`0 0 ${svgW} ${svgH}`} style={{ overflow: 'visible' }}>
              {/* edges */}
              {edges.map(([from, to]) => {
                const f = nodePos[from], t = nodePos[to];
                const color = statuses[from] === 'done' ? '#00ff88' : statuses[from] === 'running' ? '#ffcc00' : 'rgba(255,255,255,0.1)';
                return (
                  <line key={`${from}-${to}`}
                    x1={f.x + nodeW / 2} y1={f.y}
                    x2={t.x - nodeW / 2} y2={t.y}
                    stroke={color} strokeWidth={1.5} strokeDasharray={statuses[from] === 'running' ? '4 3' : undefined}
                  />
                );
              })}
              {/* nodes */}
              {AGENT_NODES.map(n => {
                const s = statuses[n.id];
                const { px, py } = nodePos[n.id];
                return (
                  <g key={n.id}>
                    <rect x={px} y={py} width={nodeW} height={nodeH} rx={6}
                      fill={nodeBg(s)} stroke={nodeColor(s)} strokeWidth={1.2} />
                    <text x={px + nodeW / 2} y={py + 13} textAnchor="middle"
                      fontSize={8} fontFamily="'Orbitron',monospace" fill={nodeColor(s)} letterSpacing={1}>
                      {n.label}
                    </text>
                    <text x={px + nodeW / 2} y={py + 25} textAnchor="middle"
                      fontSize={7} fontFamily="monospace" fill="rgba(255,255,255,0.35)">
                      {n.desc}
                    </text>
                    <text x={px + nodeW / 2} y={py + nodeH - 4} textAnchor="middle"
                      fontSize={7} fontFamily="monospace" fill={nodeColor(s)}>
                      {s === 'running' ? '● ACTIVE' : s === 'done' ? '✓ DONE' : '○ IDLE'}
                    </text>
                  </g>
                );
              })}
            </svg>
            <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 8, lineHeight: 1.7 }}>
              <span style={{ color: '#00ff88', marginRight: 10 }}>● DONE</span>
              <span style={{ color: '#ffcc00', marginRight: 10 }}>● ACTIVE</span>
              <span style={{ color: 'rgba(255,255,255,0.3)' }}>● IDLE</span>
            </div>
          </div>
        );
      })()}

      {activeTab === 'tree' && (
        <div style={{ padding: '8px 0' }}>
          <div className="f9 text-dim" style={{ marginBottom: 8 }}>PROCESS TREE</div>
          {procs.length === 0 ? (
            <div className="f9 text-dim" style={{ textAlign: 'center', padding: 16 }}>
              No process data yet.<span className="blink">_</span>
            </div>
          ) : (() => {
            const roots = procs.filter(p => !procs.some(q => q.name === p.parent));
            const children = procs.filter(p => procs.some(q => q.name === p.parent));
            const nodeW = 160, nodeH = 40, gapX = 12, gapY = 28;

            const nodeColor = (c: string) => c === 'red' ? '#ff4466' : c === 'yellow' ? '#ffcc00' : '#00ff88';
            const nodeBg    = (c: string) => c === 'red' ? 'rgba(255,68,102,0.14)' : c === 'yellow' ? 'rgba(255,204,0,0.10)' : 'rgba(0,255,136,0.06)';

            // Vertical tree: roots at top, children below stacked
            const rootNodes = roots.map((p, i) => ({ ...p, x: i * (nodeW + gapX), y: 0 }));
            const childNodes = children.map((p, i) => ({ ...p, x: i * (nodeW + gapX), y: nodeH + gapY }));
            const allPos = [...rootNodes, ...childNodes];

            const cols = Math.max(roots.length, children.length);
            const totalW = cols * (nodeW + gapX) - gapX;
            const totalH = (roots.length > 0 && children.length > 0) ? nodeH * 2 + gapY : nodeH;

            return (
              <div style={{ overflowX: 'auto', overflowY: 'visible' }}>
                <svg width={Math.max(totalW + 8, 300)} height={totalH + 16} viewBox={`-4 -4 ${totalW + 8} ${totalH + 8}`}>
                  {childNodes.map((c, ci) => {
                    const parentNode = allPos.find(p => p.name === c.parent);
                    if (!parentNode) return null;
                    return (
                      <line key={`edge-${ci}`}
                        x1={parentNode.x + nodeW / 2} y1={parentNode.y + nodeH}
                        x2={c.x + nodeW / 2} y2={c.y}
                        stroke="rgba(0,245,255,0.25)" strokeWidth={1.5} strokeDasharray="4 3" />
                    );
                  })}
                  {allPos.map((p, pi) => (
                    <g key={`proc-${pi}`}>
                      <rect x={p.x} y={p.y} width={nodeW} height={nodeH} rx={6}
                        fill={nodeBg(p.color)} stroke={nodeColor(p.color)} strokeWidth={1.5} />
                      <text x={p.x + 10} y={p.y + 16} fontSize={10} fontFamily="'JetBrains Mono',monospace" fill={nodeColor(p.color)} fontWeight="500">
                        {p.name.length > 20 ? p.name.slice(0, 19) + '…' : p.name}
                      </text>
                      <text x={p.x + 10} y={p.y + 30} fontSize={9} fontFamily="monospace" fill="rgba(255,255,255,0.35)">
                        PID: {p.pid}  ·  {p.parent !== p.name ? p.parent : 'root'}
                      </text>
                    </g>
                  ))}
                </svg>
              </div>
            );
          })()}
        </div>
      )}

    </Panel>
  );
}
