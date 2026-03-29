'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import Panel from './Panel';
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

// Each type gets its own angular cluster around the root node
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

interface SimStep {
  delay: number;
  line: string;
  tag: 'info' | 'warn' | 'crit' | 'sys';
  node?: { type: string; label: string };
}

// ── Position helper ───────────────────────────────────────────────────────────
function getPos(
  type: string,
  idx: number,
  cx: number,
  cy: number,
): { x: number; y: number } {
  const angle = TYPE_ANGLE[type] ?? (idx * (Math.PI / 5));
  const r = 92 + idx * 58;
  return { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
}

// ── Build simulation steps (uses real IOCs if available) ──────────────────────
function buildSteps(data: StaticResult | null): SimStep[] {
  const steps: SimStep[] = [];
  let t = 0;
  const s = (
    line: string,
    tag: SimStep['tag'],
    node?: SimStep['node'],
    gap = 390,
  ) => {
    steps.push({ delay: t, line, tag, node });
    t += gap;
  };

  s('[SYSTEM] e2b sandbox — Ubuntu 22.04 LTS x86_64', 'sys', undefined, 240);
  s('[SYSTEM] Mounting specimen → /home/user/malware.js', 'sys', undefined, 240);
  s('[SYSTEM] Loading adaptive Windows API mock layer...', 'sys', undefined, 420);
  s('[SYSTEM] node --require mock.js malware.js 2>&1', 'sys', undefined, 720);
  s('[SYSTEM] Adaptive Simulation Layer Active.', 'info', undefined, 780);

  s('[MOCK WMI] Querying: winmgmts:\\\\.\\root\\cimv2', 'warn',
    { type: 'WMI', label: 'WMI open' });
  s('[MOCK PATCH] WMI ExecQuery: SELECT * FROM Win32_Processor', 'warn',
    { type: 'WMI', label: 'Win32_Processor' }, 340);
  s('[MOCK PATCH] WMI ExecQuery: SELECT * FROM Win32_VideoController', 'warn',
    { type: 'WMI', label: 'Win32_VideoController' }, 340);
  s('[MOCK PATCH] WMI ExecQuery: SELECT * FROM Win32_NetworkAdapterConfiguration', 'warn',
    { type: 'WMI', label: 'NetworkAdapter MAC' });

  s('[MOCK ACTIVEX] Created: WinHttp.WinHttpRequest.5.1', 'warn',
    { type: 'ACTIVEX', label: 'WinHttp.WinHttpRequest' });
  s('[MOCK PATCH] HTTP open: GET http://ip-api.com/?fields=hosting', 'crit',
    { type: 'NETWORK', label: 'ip-api.com (VM detect)' });
  s('[MOCK PATCH] HTTP send — probing if host is VM/sandbox', 'crit',
    { type: 'NETWORK', label: 'HTTP_SEND → ip-api' }, 340);

  s('[MOCK PATCH] WScript.Shell.RegRead: HKCU\\Software\\Aerofox\\Foxmail\\V3.1', 'crit',
    { type: 'REGISTRY', label: 'Foxmail credentials' });
  s('[MOCK PATCH] WScript.Shell.RegRead: HKCU\\Software\\Comodo\\IceDragon', 'warn',
    { type: 'REGISTRY', label: 'IceDragon AV check' }, 340);
  s('[MOCK REG] Reading: HKLM\\SOFTWARE\\VMware Inc.', 'warn',
    { type: 'REGISTRY', label: 'VMware detection key' }, 340);

  s('[MOCK FS] Checking: C:\\Users\\Public\\Mands.png', 'warn',
    { type: 'FILE', label: 'Mands.png check' });
  s('[MOCK FS] Self-Deletion Attempt: C:\\Users\\Public\\Mands.png', 'crit',
    { type: 'FILE', label: 'Mands.png delete' }, 340);
  s('[MOCK FS] Checking: C:\\Users\\Public\\Vile.png', 'warn',
    { type: 'FILE', label: 'Vile.png check' }, 340);

  // Real IOCs from static analysis
  if (data) {
    (data.ips_found ?? []).slice(0, 2).forEach(ip =>
      s(`[MOCK NET] Connecting to: ${ip}`, 'crit',
        { type: 'NETWORK', label: `C2: ${ip.slice(0, 22)}` })
    );
    (data.registry_keys ?? []).slice(0, 2).forEach(k =>
      s(`[MOCK PATCH] WScript.Shell.RegWrite: ${k.slice(0, 55)}`, 'crit',
        { type: 'REGISTRY', label: k.slice(0, 30) })
    );
    (data.dropped_files ?? []).slice(0, 2).forEach(f =>
      s(`[MOCK FS] Creating: ${f.slice(0, 55)}`, 'crit',
        { type: 'FILE', label: f.slice(0, 28) })
    );
  }

  s('[MOCK ACTIVEX] Created: ADODB.Stream', 'warn',
    { type: 'ACTIVEX', label: 'ADODB.Stream' });
  s('[MOCK PATCH] ADODB.Stream.Open', 'warn',
    { type: 'STREAM', label: 'Stream.Open' }, 300);
  s('[MOCK PATCH] ADODB.Stream.Write: 4096 bytes', 'crit',
    { type: 'STREAM', label: 'Stream.Write 4096b' }, 350);
  s('[MOCK PATCH] ADODB.Stream.SaveToFile: C:\\Users\\Public\\payload.exe', 'crit',
    { type: 'STREAM', label: 'SaveToFile payload.exe' });

  s('[MOCK PATCH] WScript.Shell.Run: powershell -enc JABzAHQA...', 'crit',
    { type: 'EXEC', label: 'PS -enc (reflective load)' }, 560);
  s('[MOCK PATCH] WScript.Shell.Run: powershell -ExecutionPolicy Bypass', 'crit',
    { type: 'EXEC', label: 'PS -ExecPol Bypass' }, 400);
  s('[MOCK NET] Connecting to: account.dyn.com', 'crit',
    { type: 'NETWORK', label: 'DynDNS C2' });
  s('[MOCK PATCH] WScript.Echo: agent-tesla payload delivered', 'warn',
    { type: 'WSCRIPT', label: 'payload delivered' });
  s('[MOCK TIME] Skipping sleep: 5000ms', 'info',
    { type: 'SLEEP', label: 'Sleep 5000ms' }, 300);

  s('[SYSTEM] ── simulation complete — exit code 0 ──', 'info', undefined, 400);
  return steps;
}

// ── Canvas helpers ────────────────────────────────────────────────────────────
function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number, r: number,
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.arcTo(x + w, y, x + w, y + r, r);
  ctx.lineTo(x + w, y + h - r);
  ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h);
  ctx.arcTo(x, y + h, x, y + h - r, r);
  ctx.lineTo(x, y + r);
  ctx.arcTo(x, y, x + r, y, r);
  ctx.closePath();
}

function drawGraph(canvas: HTMLCanvasElement, gnodes: GNode[]) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth;
  const H = canvas.offsetHeight;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  ctx.fillStyle = '#060c1a';
  ctx.fillRect(0, 0, W, H);

  // Subtle dot grid
  ctx.fillStyle = 'rgba(0,245,255,0.03)';
  for (let x = 0; x < W; x += 24)
    for (let y = 0; y < H; y += 24)
      ctx.fillRect(x, y, 1, 1);

  if (gnodes.length === 0) return;

  const root = gnodes[0];

  // Draw dashed edges from root to each child
  for (let i = 1; i < gnodes.length; i++) {
    const n = gnodes[i];
    ctx.strokeStyle = n.color + '44';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 5]);
    ctx.beginPath();
    ctx.moveTo(root.x, root.y);
    ctx.lineTo(n.x, n.y);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Draw nodes
  for (const n of gnodes) {
    const isRoot = n.id === 'root';
    const typeLabel = `[${n.type}]`;
    const detail = n.label.length > 20 ? n.label.slice(0, 19) + '\u2026' : n.label;

    ctx.font = `bold ${isRoot ? 10 : 9}px monospace`;
    const tw = ctx.measureText(typeLabel).width;
    ctx.font = `${isRoot ? 9 : 8}px monospace`;
    const dw = ctx.measureText(detail).width;
    const w = Math.max(tw, dw) + 18;
    const h = isRoot ? 36 : 30;
    const bx = n.x - w / 2;
    const by = n.y - h / 2;

    ctx.shadowColor = n.color;
    ctx.shadowBlur = isRoot ? 14 : 7;
    ctx.fillStyle = '#060c1a';
    ctx.strokeStyle = n.color;
    ctx.lineWidth = isRoot ? 2 : 1.5;
    roundRect(ctx, bx, by, w, h, 4);
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    ctx.textAlign = 'center';
    ctx.fillStyle = n.color;
    ctx.font = `bold ${isRoot ? 10 : 9}px monospace`;
    ctx.fillText(typeLabel, n.x, n.y - 4);
    ctx.fillStyle = 'rgba(226,232,240,0.85)';
    ctx.font = `${isRoot ? 9 : 8}px monospace`;
    ctx.fillText(detail, n.x, n.y + 9);
    ctx.textAlign = 'left';
  }
}

// ── Component ─────────────────────────────────────────────────────────────────
interface Props {
  staticData?: StaticResult | null;
}

const TAG_COLOR: Record<string, string> = {
  sys:  '#64748b',
  info: '#00f5ff',
  warn: '#f59e0b',
  crit: '#f43f5e',
};

export default function LinuxSandboxPanel({ staticData }: Props) {
  const [running, setRunning] = useState(false);
  const [done, setDone]       = useState(false);
  const [logs, setLogs]       = useState<Array<{ line: string; tag: string }>>([]);
  const [gnodes, setGnodes]   = useState<GNode[]>([]);

  const canvasRef  = useRef<HTMLCanvasElement>(null);
  const logRef     = useRef<HTMLDivElement>(null);
  const timersRef  = useRef<ReturnType<typeof setTimeout>[]>([]);
  const typeIdxRef = useRef<Record<string, number>>({});

  // Auto-scroll console
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // Redraw graph whenever nodes change
  useEffect(() => {
    if (canvasRef.current) drawGraph(canvasRef.current, gnodes);
  }, [gnodes]);

  const runSim = useCallback(() => {
    if (running) return;
    setRunning(true);
    setDone(false);
    setLogs([]);
    setGnodes([]);
    typeIdxRef.current = {};
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];

    const canvas = canvasRef.current;
    const W  = canvas?.offsetWidth  ?? 500;
    const H  = canvas?.offsetHeight ?? 300;
    const cx = W / 2;
    const cy = H / 2;

    // Seed root node
    const rootNode: GNode = {
      id:    'root',
      type:  'PROCESS',
      label: staticData?.file_name ?? 'malware.js',
      x:     cx,
      y:     cy,
      color: NODE_COLORS.PROCESS,
    };
    setGnodes([rootNode]);

    const steps = buildSteps(staticData ?? null);

    steps.forEach((step, i) => {
      const timer = setTimeout(() => {
        setLogs(prev => [...prev, { line: step.line, tag: step.tag }]);

        if (step.node) {
          const { type, label } = step.node;
          const idx = typeIdxRef.current[type] ?? 0;
          typeIdxRef.current[type] = idx + 1;
          const pos = getPos(type, idx, cx, cy);
          setGnodes(prev => [
            ...prev,
            { id: `${type}-${idx}`, type, label, x: pos.x, y: pos.y, color: NODE_COLORS[type] ?? '#ffffff' },
          ]);
        }

        if (i === steps.length - 1) {
          setRunning(false);
          setDone(true);
        }
      }, step.delay);

      timersRef.current.push(timer);
    });
  }, [running, staticData]);

  const nodeCount = gnodes.length > 0 ? gnodes.length - 1 : 0;

  return (
    <Panel title="// LINUX ADAPTIVE SANDBOX — e2b isolation" style={{ gridColumn: '1 / -1' }}>

      {/* ── System info bar + button ── */}
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
            padding: '2px 7px',
            border: '1px solid rgba(144,238,144,0.3)',
            borderRadius: 3,
            fontSize: 8,
            color: '#90EE90',
            fontFamily: 'JetBrains Mono, monospace',
            letterSpacing: 1,
          }}>
            ISOLATED
          </span>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {done && (
            <span style={{ fontSize: 9, color: '#10b981', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1 }}>
              ● COMPLETE
            </span>
          )}
          <span style={{ fontSize: 9, color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>
            {nodeCount} node{nodeCount !== 1 ? 's' : ''}
          </span>
          <button
            onClick={runSim}
            disabled={running}
            style={{
              fontFamily: 'Orbitron, monospace',
              fontSize: 9,
              letterSpacing: 2,
              padding: '5px 14px',
              background: running ? 'rgba(139,92,246,0.08)' : 'rgba(139,92,246,0.18)',
              border: `1px solid ${running ? 'rgba(139,92,246,0.25)' : 'rgba(139,92,246,0.65)'}`,
              color: running ? '#6b46c1' : '#a78bfa',
              borderRadius: 4,
              cursor: running ? 'not-allowed' : 'pointer',
              textTransform: 'uppercase',
              transition: 'all 0.2s',
            }}
          >
            {running ? 'RUNNING...' : done ? 'RE-RUN LINUX SIMULATION' : 'RUN LINUX SIMULATION'}
          </button>
        </div>
      </div>

      {/* ── Console  |  Graph ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '38% 1fr', gap: 12, height: 300 }}>

        {/* Terminal console */}
        <div
          ref={logRef}
          style={{
            background: '#010814',
            border: '1px solid rgba(0,245,255,0.08)',
            borderRadius: 6,
            padding: '8px 10px',
            overflowY: 'auto',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 10,
            lineHeight: 1.75,
          }}
        >
          {logs.length === 0 ? (
            <span style={{ color: '#1e293b' }}>
              Press RUN LINUX SIMULATION to begin<span className="blink">_</span>
            </span>
          ) : (
            logs.map((l, i) => (
              <div key={i} style={{ color: TAG_COLOR[l.tag] ?? '#94a3b8' }}>
                {l.line}
              </div>
            ))
          )}
        </div>

        {/* Behavioral graph canvas */}
        <div style={{
          position: 'relative',
          background: '#060c1a',
          border: '1px solid rgba(0,245,255,0.08)',
          borderRadius: 6,
          overflow: 'hidden',
        }}>
          <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />
          {gnodes.length === 0 && (
            <div style={{
              position: 'absolute', inset: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#1e293b',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 10,
              pointerEvents: 'none',
            }}>
              behavioral graph will render here
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}
