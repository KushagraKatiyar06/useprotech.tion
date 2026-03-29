'use client';

import { useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import { ARCH_DETAILS, DEMO_CONNS, DEMO_LOGS, DEMO_PROCS, type LogEntry, type Connection, type Process } from '@/lib/data';

const STAGES = ['UPLOAD', 'SANDBOX', 'MONITOR', 'PARSE', 'AI ANALYZE', 'REPORT'];

interface Props {
  currentStage: number; // -1 = idle, 0-5 = stage index
  stageDone: boolean[];
}

export default function BehavioralAnalysisPanel({ currentStage, stageDone }: Props) {
  const [activeTab, setActiveTab] = useState('process');
  const [logs, setLogs] = useState<LogEntry[]>([
    { sec: 0, tag: 'info', cat: 'SYS', msg: 'ThreatNet AI v2.4.1 — sandbox initialized' },
    { sec: 0, tag: 'info', cat: 'SYS', msg: 'VirtualBox instance ready — WIN10_CLEAN_SNAPSHOT' },
    { sec: 0, tag: 'info', cat: 'SYS', msg: 'Awaiting specimen upload...' },
  ]);
  const [procs, setProcs] = useState<Process[]>([]);
  const [conns, setConns] = useState<Connection[]>([]);
  const [archHighlight, setArchHighlight] = useState<number | null>(null);
  const [archDetail, setArchDetail] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const netAnimRef = useRef<number>(0);

  // Auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  function addLog(entry: LogEntry) {
    const ts = new Date().toTimeString().slice(0, 8);
    setLogs(prev => [...prev, { ...entry, msg: `[${ts}] ${entry.msg}` }]);
  }

  // React to stage changes
  useEffect(() => {
    if (currentStage === 1) {
      // Sandbox start
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'Restoring WIN10_CLEAN_SNAPSHOT...' }), 0);
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'VM booted — transferring specimen via guestcontrol' }), 600);
      setTimeout(() => addLog({ sec: 0, tag: 'info', cat: 'SYS', msg: 'Executing invoice_q4.exe in isolated environment' }), 1200);
    }
    if (currentStage === 2) {
      // Stream logs
      let delay = 0;
      DEMO_LOGS.forEach(entry => {
        setTimeout(() => addLog(entry), delay);
        delay += 350 + Math.random() * 200;
      });
      // Stream procs
      setProcs([]);
      let pd = 0;
      DEMO_PROCS.forEach(p => {
        setTimeout(() => setProcs(prev => [...prev, p]), pd);
        pd += 400;
      });
    }
    if (currentStage === 3) {
      // Stream connections
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

  function showArchDetail(i: number) {
    setArchHighlight(i);
    setArchDetail(ARCH_DETAILS[i]);
  }

  function stageClass(i: number) {
    if (stageDone[i]) return 'stage done';
    if (currentStage === i) return 'stage active';
    return 'stage';
  }

  return (
    <Panel title="// BEHAVIORAL ANALYSIS ENGINE" className="center-panel" style={{ gridRow: 1 }}>
      {/* Stage indicators */}
      <div className="stages">
        {STAGES.map((s, i) => (
          <div key={s} className={stageClass(i)}>{s}</div>
        ))}
      </div>

      {/* Tabs */}
      <div className="tab-row">
        {['process', 'logs', 'network', 'arch'].map(tab => (
          <div
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'process' ? 'PROCESS TREE' : tab === 'arch' ? 'ARCHITECTURE' : tab === 'network' ? 'NETWORK' : 'RAW LOGS'}
          </div>
        ))}
      </div>

      {/* PROCESS TREE */}
      {activeTab === 'process' && (
        <div className="proc-list">
          {procs.length === 0 ? (
            <div className="f9 text-dim" style={{ padding: 8, textAlign: 'center' }}>
              Awaiting specimen...<span className="blink">_</span>
            </div>
          ) : procs.map(p => {
            const indent = (p.parent === 'explorer.exe' || p.parent === 'services.exe') ? '' : '    ';
            const memMb = Math.round(Math.random() * 80 + 10);
            return (
              <div key={`${p.pid}-${p.name}`} className={`proc-item ${p.color === 'red' ? 'danger' : ''}`}>
                <span style={{ color: 'var(--text-dim)', fontSize: 9 }}>{indent}├─</span>
                <span className={`proc-dot ${p.color}`} />
                <span className="proc-name">{p.name}</span>
                <span className="proc-pid">PID:{p.pid}</span>
                <span className="proc-mem">{memMb}MB</span>
              </div>
            );
          })}
        </div>
      )}

      {/* LOGS */}
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

      {/* NETWORK */}
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
                const isExfil = c.type.includes('EXFIL') || c.type.includes('C2');
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

      {/* ARCHITECTURE */}
      {activeTab === 'arch' && (
        <>
          <div style={{ marginBottom: 10 }}>
            <div className="f9 text-dim">END-TO-END PIPELINE ARCHITECTURE</div>
          </div>
          <div className="arch-grid">
            {[
              { icon: '🌐', lbl: 'REACT FRONTEND',  sub: 'File upload · HUD UI' },
              null,
              { icon: '⚙️', lbl: 'FASTAPI BACKEND',  sub: 'REST API · Orchestration' },
              null,
              { icon: '📦', lbl: 'SANDBOX VM',        sub: 'VirtualBox · Isolated' },
            ].map((node, i) =>
              node ? (
                <div
                  key={i}
                  className={`arch-node ${archHighlight === Math.floor(i / 2) ? 'highlight' : ''}`}
                  onClick={() => showArchDetail(Math.floor(i / 2))}
                >
                  <span className="arch-icon">{node.icon}</span>
                  <div className="arch-lbl">{node.lbl}</div>
                  <div style={{ fontSize: 8, color: 'var(--text-dim)', marginTop: 3 }}>{node.sub}</div>
                </div>
              ) : (
                <div key={i} className="arch-arrow">→</div>
              )
            )}
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', margin: '2px 0' }}>
            <span style={{ color: 'rgba(0,245,255,0.3)' }}>↓</span>
          </div>
          <div className="arch-grid">
            {[
              { icon: '📊', lbl: 'LOG COLLECTOR',  sub: 'Process · File · Net' },
              null,
              { icon: '🔄', lbl: 'PARSER/STRUCT',   sub: 'JSON normalization' },
              null,
              { icon: '🤖', lbl: 'CLAUDE AI',        sub: 'Analysis · Report gen' },
            ].map((node, i) =>
              node ? (
                <div
                  key={i}
                  className={`arch-node ${archHighlight === 3 + Math.floor(i / 2) ? 'highlight' : ''}`}
                  onClick={() => showArchDetail(3 + Math.floor(i / 2))}
                >
                  <span className="arch-icon">{node.icon}</span>
                  <div className="arch-lbl">{node.lbl}</div>
                  <div style={{ fontSize: 8, color: 'var(--text-dim)', marginTop: 3 }}>{node.sub}</div>
                </div>
              ) : (
                <div key={i} className="arch-arrow">→</div>
              )
            )}
          </div>

          {archDetail && (
            <div
              style={{ marginTop: 14, padding: 10, border: '1px solid rgba(0,245,255,0.2)', background: '#010814', fontSize: 11, lineHeight: 1.7 }}
              dangerouslySetInnerHTML={{ __html: archDetail }}
            />
          )}

          <div className="section-divider" style={{ marginTop: 14 }} />
          <div className="f9 text-dim">API CONTRACT EXAMPLE</div>
          <pre style={{ fontSize: 10, color: 'var(--text-cyan)', background: '#010814', border: '1px solid rgba(0,245,255,0.1)', padding: 10, marginTop: 6, overflowX: 'auto', lineHeight: 1.6 }}>
{`{
  "file_id": "a3f8-...",
  "behaviors": {
    "processes": [{"name":"cmd.exe","pid":4821,"parent":"malware.exe"}],
    "file_ops": [{"op":"CREATE","path":"C:\\\\temp\\\\payload.dll"}],
    "network":  [{"dst":"185.220.101.x","port":443,"bytes":2048}]
  },
  "ai_report": {
    "type": "RANSOMWARE",
    "risk": 0.94,
    "confidence": "HIGH",
    "mitigations": ["Isolate host","Block C2 IP","Restore backup"]
  }
}`}
          </pre>
        </>
      )}
    </Panel>
  );
}
