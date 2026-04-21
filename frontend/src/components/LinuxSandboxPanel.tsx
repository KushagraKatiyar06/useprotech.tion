'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import Panel from './Panel';
import Tooltip from './Tooltip';
import { type StaticResult } from './BehavioralAnalysisPanel';

// ── Node colours matching e2b_adaptive_sandbox.py TAG_RULES ──────────────────
const NODE_COLORS: Record<string, string> = {
  PROCESS:  '#FA8072',
  EXEC:     '#FF4500',
  NETWORK:  '#FF6B6B',
  REGISTRY: '#DA70D6',
  WMI:      '#90EE90',
  FILE:     '#00BFFF',
  STREAM:   '#87CEEB',
  ACTIVEX:  '#FFD700',
  SLEEP:    '#A0A0A0',
  WSCRIPT:  '#FF8C00',
};

const LEGEND_ITEMS: { type: string; desc: string }[] = [
  { type: 'PROCESS',  desc: 'Root process' },
  { type: 'EXEC',     desc: 'Shell execution' },
  { type: 'NETWORK',  desc: 'HTTP/network call' },
  { type: 'REGISTRY', desc: 'Registry access' },
  { type: 'WMI',      desc: 'WMI query' },
  { type: 'FILE',     desc: 'File system op' },
  { type: 'STREAM',   desc: 'ADODB stream' },
  { type: 'ACTIVEX',  desc: 'ActiveX object' },
  { type: 'WSCRIPT',  desc: 'WScript call' },
  { type: 'SLEEP',    desc: 'Sleep / delay' },
];

const TYPE_ANGLE: Record<string, number> = {
  EXEC:     0,
  NETWORK:  Math.PI * 0.30,
  REGISTRY: Math.PI * 0.58,
  WMI:      Math.PI * 0.86,
  FILE:     Math.PI * 1.14,
  STREAM:   Math.PI * 1.42,
  ACTIVEX:  Math.PI * 1.70,
  WSCRIPT:  Math.PI * 1.88,
  SLEEP:    Math.PI * 0.12,
};

interface GNode {
  id: string;
  type: string;
  label: string;
  x: number;
  y: number;
  color: string;
}

function getPos(type: string, idx: number, cx: number, cy: number): { x: number; y: number } {
  const angle = TYPE_ANGLE[type] ?? (idx * (Math.PI / 5));
  const r = 110 + idx * 70;
  return { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
}

function classifyLine(line: string): { tag: 'info' | 'warn' | 'crit' | 'sys'; node?: { type: string; label: string } } {
  const u = line.toUpperCase();
  const label = line.replace(/^\[MOCK[^\]]*\]\s*/, '').slice(0, 30);

  if (u.includes('EXECQUERY') || u.includes('[MOCK WMI]') || u.includes('WMI') || u.includes('WINMGMTS') || u.includes('GETOBJECT'))
    return { tag: 'warn', node: { type: 'WMI', label } };
  if (u.includes('HTTP') || u.includes('XMLHTTP') || u.includes('WINHTTP'))
    return { tag: 'crit', node: { type: 'NETWORK', label } };
  if (u.includes('REGWRITE') || u.includes('REGREAD') || u.includes('REGDELETE') || u.includes('[MOCK REG]'))
    return { tag: u.includes('WRITE') ? 'crit' : 'warn', node: { type: 'REGISTRY', label } };
  if (u.includes('SHELL.RUN') || u.includes('SHELL.EXEC') || u.includes('-ENC') || u.includes('POWERSHELL'))
    return { tag: 'crit', node: { type: 'EXEC', label } };
  if (u.includes('FSO.') || u.includes('FILEEXISTS') || u.includes('DELETEFILE') || u.includes('CREATETEXTFILE') || u.includes('[MOCK FS]') || u.includes('FILESYSTEMOBJECT'))
    return { tag: u.includes('DELETE') ? 'crit' : 'warn', node: { type: 'FILE', label } };
  if (u.includes('ADODB') || u.includes('STREAM'))
    return { tag: u.includes('WRITE') || u.includes('SAVE') ? 'crit' : 'warn', node: { type: 'STREAM', label } };
  if (u.includes('ACTIVEXOBJECT') || u.includes('NEW ACTIVEX') || u.includes('CREATEOBJECT'))
    return { tag: 'warn', node: { type: 'ACTIVEX', label } };
  if (u.includes('WSCRIPT'))
    return { tag: 'warn', node: { type: 'WSCRIPT', label } };

  return { tag: 'info' };
}

// ── SVG graph with pan + zoom ─────────────────────────────────────────────────
interface GraphViewProps {
  gnodes: GNode[];
}

function GraphView({ gnodes }: GraphViewProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const dragRef = useRef<{ startX: number; startY: number; tx: number; ty: number } | null>(null);

  const nodesEmpty = gnodes.length === 0;
  useEffect(() => {
    if (nodesEmpty) setTransform({ x: 0, y: 0, scale: 1 });
  }, [nodesEmpty]);

  function onWheel(e: React.WheelEvent) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform(t => {
      const newScale = Math.min(4, Math.max(0.2, t.scale * delta));
      const svg = svgRef.current;
      if (!svg) return { ...t, scale: newScale };
      const rect = svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const nx = mx - (mx - t.x) * (newScale / t.scale);
      const ny = my - (my - t.y) * (newScale / t.scale);
      return { x: nx, y: ny, scale: newScale };
    });
  }

  function onMouseDown(e: React.MouseEvent) {
    if (e.button !== 0) return;
    dragRef.current = { startX: e.clientX, startY: e.clientY, tx: transform.x, ty: transform.y };
  }

  function onMouseMove(e: React.MouseEvent) {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    setTransform(t => ({ ...t, x: dragRef.current!.tx + dx, y: dragRef.current!.ty + dy }));
  }

  function onMouseUp() { dragRef.current = null; }

  const root = gnodes[0];

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <svg
        ref={svgRef}
        width="100%" height="100%"
        style={{ display: 'block', background: '#060c1a', cursor: dragRef.current ? 'grabbing' : 'grab', userSelect: 'none' }}
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      >
        <defs>
          <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
            <circle cx="0" cy="0" r="0.7" fill="rgba(0,245,255,0.06)" />
          </pattern>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-strong">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <marker key={type} id={`arrow-${type}`} markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L6,3 z" fill={color + '88'} />
            </marker>
          ))}
        </defs>

        <rect width="100%" height="100%" fill="url(#grid)" />

        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
          {root && gnodes.slice(1).map((n) => (
            <line
              key={`edge-${n.id}`}
              x1={root.x} y1={root.y} x2={n.x} y2={n.y}
              stroke={n.color + '55'}
              strokeWidth={1.5 / transform.scale}
              strokeDasharray="4,6"
              markerEnd={`url(#arrow-${n.type})`}
            />
          ))}
          {gnodes.map((n) => {
            const isRoot = n.id === 'root';
            const W = isRoot ? 120 : 100;
            const H = isRoot ? 44 : 36;
            return (
              <g key={n.id} transform={`translate(${n.x - W / 2},${n.y - H / 2})`} filter={isRoot ? 'url(#glow-strong)' : 'url(#glow)'}>
                <rect width={W} height={H} rx={5} ry={5} fill="#060c1a" stroke={n.color} strokeWidth={isRoot ? 2 : 1.5} opacity={0.95} />
                <text x={W / 2} y={isRoot ? 15 : 13} textAnchor="middle" fill={n.color} fontSize={isRoot ? 10 : 9} fontFamily="JetBrains Mono, monospace" fontWeight="bold">
                  [{n.type}]
                </text>
                <text x={W / 2} y={isRoot ? 30 : 26} textAnchor="middle" fill="rgba(226,232,240,0.8)" fontSize={isRoot ? 9 : 8} fontFamily="JetBrains Mono, monospace">
                  {n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {nodesEmpty && (
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#1e293b', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, pointerEvents: 'none',
        }}>
          behavioral graph will render here
        </div>
      )}

      {/* Zoom controls */}
      <div style={{ position: 'absolute', bottom: 8, right: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <button onClick={() => setTransform(t => ({ ...t, scale: Math.min(4, t.scale * 1.2) }))} style={zoomBtnStyle} title="Zoom in">+</button>
        <button onClick={() => setTransform(t => ({ ...t, scale: Math.max(0.2, t.scale / 1.2) }))} style={zoomBtnStyle} title="Zoom out">−</button>
        <button onClick={() => setTransform({ x: 0, y: 0, scale: 1 })} style={{ ...zoomBtnStyle, fontSize: 8 }} title="Reset view">⌂</button>
      </div>
      <div style={{ position: 'absolute', bottom: 8, left: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#334155', pointerEvents: 'none' }}>
        {Math.round(transform.scale * 100)}%
      </div>
    </div>
  );
}

const zoomBtnStyle: React.CSSProperties = {
  width: 22, height: 22,
  background: 'rgba(0,0,0,0.7)',
  border: '1px solid rgba(0,245,255,0.2)',
  color: '#00f5ff',
  borderRadius: 4,
  cursor: 'pointer',
  fontFamily: 'monospace',
  fontSize: 14,
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  padding: 0,
};

// ── Legend ────────────────────────────────────────────────────────────────────
function Legend() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 1,
          padding: '4px 10px',
          background: open ? 'rgba(0,245,255,0.1)' : 'rgba(0,0,0,0.4)',
          border: '1px solid rgba(0,245,255,0.2)',
          color: '#00f5ff', borderRadius: 4, cursor: 'pointer', textTransform: 'uppercase',
        }}
      >
        LEGEND {open ? '▴' : '▾'}
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', marginTop: 4,
          background: '#010814', border: '1px solid rgba(0,245,255,0.15)',
          borderRadius: 6, padding: '10px 12px', zIndex: 10, minWidth: 210,
          boxShadow: '0 4px 24px rgba(0,0,0,0.6)',
        }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', marginBottom: 8, letterSpacing: 1, textTransform: 'uppercase' }}>
            Node Types
          </div>
          {LEGEND_ITEMS.map(({ type, desc }) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <div style={{ width: 10, height: 10, borderRadius: 2, background: NODE_COLORS[type], flexShrink: 0, boxShadow: `0 0 4px ${NODE_COLORS[type]}` }} />
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: NODE_COLORS[type], minWidth: 70 }}>[{type}]</span>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#475569' }}>{desc}</span>
            </div>
          ))}
          <div style={{ borderTop: '1px solid rgba(0,245,255,0.08)', marginTop: 8, paddingTop: 8 }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>Severity</div>
            {[
              { color: '#f43f5e', label: 'Critical' },
              { color: '#f59e0b', label: 'Warning' },
              { color: '#00f5ff', label: 'Info' },
              { color: '#64748b', label: 'System' },
            ].map(({ color, label }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <div style={{ width: 20, height: 2, background: color, borderRadius: 1 }} />
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#64748b' }}>{label}</span>
              </div>
            ))}
          </div>
          <div style={{ borderTop: '1px solid rgba(0,245,255,0.08)', marginTop: 8, paddingTop: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#334155' }}>
            Scroll to zoom · Drag to pan · ⌂ to reset
          </div>
        </div>
      )}
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
interface Props {
  staticData?: StaticResult | null;
  /** jobId from a completed analysis run — if provided, sandbox uses it directly */
  jobId?: string | null;
}

const TAG_COLOR: Record<string, string> = {
  sys:  '#64748b',
  info: '#00f5ff',
  warn: '#f59e0b',
  crit: '#f43f5e',
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export default function LinuxSandboxPanel({ staticData, jobId }: Props) {
  const [running, setRunning]   = useState(false);
  const [done, setDone]         = useState(false);
  const [logs, setLogs]         = useState<Array<{ line: string; tag: string }>>([]);
  const [gnodes, setGnodes]     = useState<GNode[]>([]);

  // jobId from a direct sandbox-only upload (no analysis)
  const [localJobId, setLocalJobId]   = useState<string | null>(null);
  const [localFileName, setLocalFileName] = useState<string | null>(null);
  const [uploading, setUploading]     = useState(false);

  // The effective job id — prefer the analysis one, fall back to local
  const effectiveJobId = jobId ?? localJobId;

  const [patchFile, setPatchFile] = useState<File | null>(null);
  const sandboxFileInputRef = useRef<HTMLInputElement>(null);
  const patchFileInputRef   = useRef<HTMLInputElement>(null);
  const logRef              = useRef<HTMLDivElement>(null);
  const typeIdxRef          = useRef<Record<string, number>>({});

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // ── Direct sandbox file upload (no analysis) ────────────────────────────
  function handleSandboxFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);
    fetch(`${API_URL}/sandbox/upload`, { method: 'POST', body: formData })
      .then(r => {
        if (!r.ok) throw new Error(`Upload failed: ${r.status}`);
        return r.json();
      })
      .then(({ job_id, filename }: { job_id: string; filename: string }) => {
        setLocalJobId(job_id);
        setLocalFileName(filename);
        setUploading(false);
      })
      .catch(err => {
        console.error('[sandbox upload]', err);
        setUploading(false);
      });
  }

  function clearLocalFile() {
    setLocalJobId(null);
    setLocalFileName(null);
  }

  // ── Patch file ────────────────────────────────────────────────────────────
  function handlePatchFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setPatchFile(file);
    e.target.value = '';
  }

  function clearPatch() { setPatchFile(null); }

  // ── Graph helpers ─────────────────────────────────────────────────────────
  function initGraph(fileName: string) {
    const cx = 400;
    const cy = 180;
    const rootNode: GNode = {
      id: 'root', type: 'PROCESS',
      label: fileName,
      x: cx, y: cy,
      color: NODE_COLORS.PROCESS,
    };
    setGnodes([rootNode]);
    return { cx, cy };
  }

  function addLogNode(line: string, tag: string, cx: number, cy: number, nodeData?: { type: string; label: string } | null) {
    setLogs(prev => [...prev, { line, tag }]);
    const nd = nodeData ?? classifyLine(line).node;
    if (nd) {
      const { type, label } = nd;
      const idx = typeIdxRef.current[type] ?? 0;
      typeIdxRef.current[type] = idx + 1;
      const pos = getPos(type, idx, cx, cy);
      setGnodes(prev => [
        ...prev,
        { id: `${type}-${idx}`, type, label, x: pos.x, y: pos.y, color: NODE_COLORS[type] ?? '#ffffff' },
      ]);
    }
  }

  function connectSandboxWS(sandbox_job_id: string, cx: number, cy: number) {
    const wsBase = API_URL.replace(/^https?/, s => (s === 'https' ? 'wss' : 'ws'));
    const ws = new WebSocket(`${wsBase}/ws/sandbox/${sandbox_job_id}`);

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string, unknown>;
        if (msg.event === 'sandbox_log') {
          addLogNode(msg.line as string, (msg.tag as string) ?? 'info', cx, cy,
            msg.node as { type: string; label: string } | null ?? undefined);
        }
        if (msg.event === 'sandbox_patch') {
          addLogNode(msg.line as string, 'info', cx, cy);
        }
        if (msg.event === 'sandbox_done' || msg.event === 'sandbox_error') {
          if (msg.event === 'sandbox_done') {
            const pf = msg.patch_file as string | null;
            if (pf) addLogNode(`[SYSTEM] Patches saved → testing/patches/${pf}`, 'info', cx, cy);
          }
          setRunning(false);
          setDone(msg.event === 'sandbox_done');
        }
      } catch (e) { console.error('[sandbox WS] parse error:', e); }
    };

    ws.onerror = () => {
      addLogNode('[ERROR] Sandbox WebSocket connection failed.', 'crit', cx, cy);
      setRunning(false);
    };
  }

  function runPatchSandbox(jid: string, cx: number, cy: number) {
    if (!patchFile) return;
    const formData = new FormData();
    formData.append('patch', patchFile);
    fetch(`${API_URL}/sandbox/run-patch/${jid}`, { method: 'POST', body: formData })
      .then(r => { if (!r.ok) throw new Error(`Patch run failed: ${r.status}`); return r.json(); })
      .then(({ sandbox_job_id }: { sandbox_job_id: string }) => connectSandboxWS(sandbox_job_id, cx, cy))
      .catch(err => { addLogNode(`[ERROR] ${err.message}`, 'crit', cx, cy); setRunning(false); });
  }

  function runAdaptiveSandbox(jid: string, cx: number, cy: number) {
    fetch(`${API_URL}/sandbox/start/${jid}`, { method: 'POST' })
      .then(r => { if (!r.ok) throw new Error(`Sandbox start failed: ${r.status}`); return r.json(); })
      .then(({ sandbox_job_id }: { sandbox_job_id: string }) => connectSandboxWS(sandbox_job_id, cx, cy))
      .catch(err => { addLogNode(`[ERROR] ${err.message}`, 'crit', cx, cy); setRunning(false); });
  }

  const runSim = useCallback(() => {
    if (running || !effectiveJobId) return;
    setRunning(true);
    setDone(false);
    setLogs([]);
    setGnodes([]);
    typeIdxRef.current = {};

    const displayName = staticData?.file_name ?? localFileName ?? 'malware.js';
    const { cx, cy } = initGraph(displayName);

    if (patchFile) {
      runPatchSandbox(effectiveJobId, cx, cy);
    } else {
      runAdaptiveSandbox(effectiveJobId, cx, cy);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, effectiveJobId, patchFile, staticData, localFileName]);

  const nodeCount  = gnodes.length > 0 ? gnodes.length - 1 : 0;
  const patchMode  = !!patchFile && !!effectiveJobId;
  const adaptiveMode = !patchFile && !!effectiveJobId;
  const canRun     = !!effectiveJobId && !running;
  const hasPatch   = !!patchFile;

  // Derive the displayed file name (from analysis or direct upload)
  const displayedFile = staticData?.file_name ?? (jobId ? '(analysis file)' : localFileName);

  return (
    <Panel title="// LINUX ADAPTIVE SANDBOX — e2b isolation" style={{ gridColumn: '1 / -1' }}>

      {/* ── File source bar (shown when no analysis job is present) ── */}
      {!jobId && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          marginBottom: 10, padding: '8px 12px',
          background: 'rgba(0,0,0,0.4)',
          border: `1px solid ${localJobId ? 'rgba(0,245,255,0.2)' : 'rgba(0,245,255,0.06)'}`,
          borderRadius: 6,
        }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', flexShrink: 0 }}>
            SANDBOX FILE
          </span>

          {localJobId ? (
            <>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                color: '#00f5ff', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                ✓ {localFileName}
              </span>
              <button
                onClick={clearLocalFile}
                disabled={running}
                style={{
                  fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                  padding: '3px 8px', background: 'rgba(244,63,94,0.1)',
                  border: '1px solid rgba(244,63,94,0.3)', color: '#f43f5e',
                  borderRadius: 4, cursor: running ? 'not-allowed' : 'pointer',
                }}
              >
                ✕ CLEAR
              </button>
            </>
          ) : (
            <>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#334155', flex: 1 }}>
                {uploading ? 'uploading…' : 'No file — upload a malware file or run analysis first'}
              </span>
              <button
                onClick={() => sandboxFileInputRef.current?.click()}
                disabled={uploading || running}
                style={{
                  fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                  padding: '4px 12px',
                  background: uploading ? 'rgba(0,245,255,0.03)' : 'rgba(0,245,255,0.08)',
                  border: '1px solid rgba(0,245,255,0.25)', color: uploading ? '#334155' : '#00f5ff',
                  borderRadius: 4, cursor: uploading ? 'not-allowed' : 'pointer',
                  textTransform: 'uppercase', transition: 'all 0.2s',
                }}
              >
                {uploading ? 'UPLOADING…' : 'LOAD FILE'}
              </button>
            </>
          )}

          <input
            ref={sandboxFileInputRef}
            type="file"
            style={{ display: 'none' }}
            onChange={handleSandboxFileChange}
          />
        </div>
      )}

      {/* ── System info bar + controls ── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 12, padding: '6px 10px',
        background: 'rgba(0,0,0,0.35)',
        border: '1px solid rgba(0,245,255,0.08)',
        borderRadius: 6,
      }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#90EE90' }}>
            ubuntu@e2b-sandbox:~$
          </span>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569' }}>
            Linux 5.15.0-91-generic x86_64 GNU/Linux
          </span>
          <span style={{
            padding: '2px 7px', border: '1px solid rgba(144,238,144,0.3)',
            borderRadius: 3, fontSize: 8, color: '#90EE90',
            fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1,
          }}>ISOLATED</span>
          {patchMode && (
            <span style={{
              padding: '2px 7px', border: '1px solid rgba(255,215,0,0.4)',
              borderRadius: 3, fontSize: 8, color: '#FFD700',
              fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1,
            }}>PATCH RUN</span>
          )}
          {adaptiveMode && (
            <span style={{
              padding: '2px 7px', border: '1px solid rgba(139,92,246,0.5)',
              borderRadius: 3, fontSize: 8, color: '#a78bfa',
              fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1,
            }}>LIVE E2B</span>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {done && (
            <span style={{ fontSize: 9, color: '#10b981', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1 }}>
              ● COMPLETE
            </span>
          )}
          <span style={{ fontSize: 9, color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>
            {nodeCount} node{nodeCount !== 1 ? 's' : ''}
          </span>

          {/* Legend */}
          <Legend />

          {/* Hidden patch file input */}
          <input ref={patchFileInputRef} type="file" accept=".js" style={{ display: 'none' }} onChange={handlePatchFile} />

          {/* Patch file button */}
          <Tooltip
            text={!effectiveJobId ? 'Load a malware file first' : 'Upload a .js patch to test against'}
            disabled={!effectiveJobId}
          >
            {patchFile ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{
                  fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#FFD700',
                  padding: '4px 8px', background: 'rgba(255,215,0,0.08)',
                  border: '1px solid rgba(255,215,0,0.3)', borderRadius: 4,
                  maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>✓ {patchFile.name}</span>
                <button
                  onClick={clearPatch}
                  disabled={running}
                  style={{
                    fontFamily: 'JetBrains Mono, monospace', fontSize: 9, padding: '4px 7px',
                    background: 'rgba(244,63,94,0.1)', border: '1px solid rgba(244,63,94,0.3)',
                    color: '#f43f5e', borderRadius: 4, cursor: running ? 'not-allowed' : 'pointer',
                  }}
                >✕</button>
              </div>
            ) : (
              <button
                onClick={() => { if (effectiveJobId) patchFileInputRef.current?.click(); }}
                disabled={!effectiveJobId || running}
                style={{
                  fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                  padding: '5px 12px',
                  background: !effectiveJobId ? 'rgba(255,215,0,0.02)' : 'rgba(255,215,0,0.07)',
                  border: `1px solid ${!effectiveJobId ? 'rgba(255,215,0,0.1)' : 'rgba(255,215,0,0.3)'}`,
                  color: !effectiveJobId ? '#3d3010' : '#b8941f',
                  borderRadius: 4, cursor: (!effectiveJobId || running) ? 'not-allowed' : 'pointer',
                  textTransform: 'uppercase', transition: 'all 0.2s',
                }}
              >UPLOAD PATCH</button>
            )}
          </Tooltip>

          {/* Run button */}
          <Tooltip
            text={
              !effectiveJobId
                ? 'Load a malware file using "LOAD FILE" above'
                : running
                  ? 'Sandbox is running…'
                  : ''
            }
            disabled={!canRun}
          >
            <button
              onClick={runSim}
              disabled={!canRun}
              style={{
                fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 2,
                padding: '5px 14px',
                background: !canRun ? 'rgba(139,92,246,0.05)' : 'rgba(139,92,246,0.18)',
                border: `1px solid ${!canRun ? 'rgba(139,92,246,0.15)' : 'rgba(139,92,246,0.65)'}`,
                color: !canRun ? '#4a3880' : '#a78bfa',
                borderRadius: 4, cursor: !canRun ? 'not-allowed' : 'pointer',
                textTransform: 'uppercase', transition: 'all 0.2s',
              }}
            >
              {running ? 'RUNNING...' : done ? 'RE-RUN' : 'RUN SANDBOX'}
            </button>
          </Tooltip>
        </div>
      </div>

      {/* Mode hints */}
      {patchMode && !running && !done && (
        <div style={{
          marginBottom: 8, padding: '5px 10px',
          background: 'rgba(255,215,0,0.04)', border: '1px solid rgba(255,215,0,0.15)',
          borderRadius: 4, fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#78716c',
        }}>
          Patch loaded — will run <span style={{ color: '#00f5ff' }}>{displayedFile}</span> against{' '}
          <span style={{ color: '#FFD700' }}>{patchFile?.name}</span> in a real e2b sandbox.
        </div>
      )}
      {adaptiveMode && !running && !done && (
        <div style={{
          marginBottom: 8, padding: '5px 10px',
          background: 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.15)',
          borderRadius: 4, fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#78716c',
        }}>
          Adaptive mode — Gemini patches crashes iteratively for{' '}
          <span style={{ color: '#00f5ff' }}>{displayedFile}</span>.
          Patches saved to <span style={{ color: '#a78bfa' }}>testing/patches/</span>.
        </div>
      )}

      {/* ── Console | Graph ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '38% 1fr', gap: 12, height: 340 }}>

        {/* Terminal console */}
        <div
          ref={logRef}
          style={{
            background: '#010814', border: '1px solid rgba(0,245,255,0.08)',
            borderRadius: 6, padding: '8px 10px', overflowY: 'auto',
            fontFamily: 'JetBrains Mono, monospace', fontSize: 10, lineHeight: 1.75,
          }}
        >
          {logs.length === 0 ? (
            <span style={{ color: '#1e293b' }}>
              {effectiveJobId ? 'Press RUN SANDBOX to begin' : 'Load a file to enable the sandbox…'}<span className="blink">_</span>
            </span>
          ) : (
            logs.map((l, i) => (
              <div key={i} style={{ color: TAG_COLOR[l.tag] ?? '#94a3b8' }}>{l.line}</div>
            ))
          )}
        </div>

        {/* Interactive graph */}
        <div style={{
          position: 'relative', background: '#060c1a',
          border: '1px solid rgba(0,245,255,0.08)', borderRadius: 6, overflow: 'hidden',
        }}>
          <GraphView gnodes={gnodes} />
        </div>
      </div>
    </Panel>
  );
}
