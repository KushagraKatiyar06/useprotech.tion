'use client';

import { useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import { DEMO_CONNS, DEMO_LOGS, DEMO_PROCS, type LogEntry, type Connection, type Process } from '@/lib/data';

const STAGES = ['UPLOAD', 'SANDBOX', 'MONITOR', 'PARSE', 'AI ANALYZE', 'REPORT'];

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
        {['process', 'logs', 'network'].map(tab => (
          <div
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'process' ? 'IMPORTS' : tab === 'network' ? 'NETWORK' : 'RAW LOGS'}
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

    </Panel>
  );
}
