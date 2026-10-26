'use client';

import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { createPortal } from 'react-dom';
import Panel from './Panel';
import Tooltip from './Tooltip';
import WidgetWires from './WidgetWires';
import { useRunActive } from '@/contexts/RunActiveContext';
import { type StaticResult, Widget } from './BehavioralAnalysisPanel';
import { useIsNarrow } from '@/lib/useIsNarrow';

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

// ── Tree layout ───────────────────────────────────────────────────────────────
// Root process → one branch per event type that's actually occurred → each
// individual traced event as a leaf under its branch. Built fresh from the
// raw event stream on every update (cheap at this scale) rather than
// incrementally patching positions, since adding a new category reflows
// every sibling's x position anyway.

interface SandboxEvent {
  id: string;
  type: string;
  label: string;
  fullLine: string;
  tag: string;
}

interface GNode {
  id: string;
  type: string;
  label: string;
  fullLine: string;
  tag: string;
  parentId: string | null;
  x: number;
  y: number;
  color: string;
  isRoot?: boolean;
  isCategory?: boolean;
  count?: number;
}

interface GEdge {
  id: string;
  x1: number; y1: number; x2: number; y2: number;
  color: string;
  type: string;
}

const CANVAS_W = 860;
const ROOT_Y = 36;
const CAT_Y = 118;
const LEAF_Y_START = 182;
const LEAF_Y_STEP = 42;

function buildTree(events: SandboxEvent[], rootLabel: string): { nodes: GNode[]; edges: GEdge[]; height: number } {
  const rootX = CANVAS_W / 2;
  const nodes: GNode[] = [{
    id: 'root', type: 'PROCESS', label: rootLabel, fullLine: rootLabel, tag: 'sys',
    parentId: null, x: rootX, y: ROOT_Y, color: NODE_COLORS.PROCESS, isRoot: true,
  }];
  const edges: GEdge[] = [];

  if (events.length === 0) {
    return { nodes, edges, height: 300 };
  }

  const order: string[] = [];
  const byType = new Map<string, SandboxEvent[]>();
  for (const ev of events) {
    if (!byType.has(ev.type)) { byType.set(ev.type, []); order.push(ev.type); }
    byType.get(ev.type)!.push(ev);
  }

  const slot = CANVAS_W / (order.length + 1);
  let maxLeaves = 0;

  order.forEach((type, i) => {
    const group = byType.get(type)!;
    maxLeaves = Math.max(maxLeaves, group.length);
    const catX = slot * (i + 1);
    const catId = `cat-${type}`;
    const color = NODE_COLORS[type] ?? '#ffffff';

    nodes.push({
      id: catId, type, label: type, fullLine: '', tag: 'sys',
      parentId: 'root', x: catX, y: CAT_Y, color, isCategory: true, count: group.length,
    });
    edges.push({ id: `e-root-${catId}`, x1: rootX, y1: ROOT_Y, x2: catX, y2: CAT_Y, color, type });

    group.forEach((ev, j) => {
      const leafY = LEAF_Y_START + j * LEAF_Y_STEP;
      nodes.push({ id: ev.id, type: ev.type, label: ev.label, fullLine: ev.fullLine, tag: ev.tag, parentId: catId, x: catX, y: leafY, color });
      edges.push({ id: `e-${catId}-${ev.id}`, x1: catX, y1: CAT_Y, x2: catX, y2: leafY, color, type });
    });
  });

  return { nodes, edges, height: LEAF_Y_START + maxLeaves * LEAF_Y_STEP + 40 };
}

// ── SVG tree view with pan + zoom + click-to-inspect ──────────────────────────
function GraphView({ nodes, edges, canvasHeight, running, onNodeClick, onBackgroundClick }: {
  nodes: GNode[]; edges: GEdge[]; canvasHeight: number; running: boolean;
  onNodeClick: (n: GNode) => void;
  /** Fires on a genuine click on empty canvas (not a node, not the tail end
   *  of a pan-drag) — used to toggle the free-look expanded overlay. */
  onBackgroundClick?: () => void;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const dragRef = useRef<{ startX: number; startY: number; tx: number; ty: number } | null>(null);
  const draggedRef = useRef(false);

  const nodesEmpty = nodes.length <= 1;
  useEffect(() => {
    if (nodesEmpty) setTransform({ x: 0, y: 0, scale: 1 });
  }, [nodesEmpty]);

  // React attaches onWheel as a *passive* listener, so calling
  // preventDefault() inside a React synthetic handler silently does nothing
  // — the page scrolls right along with the zoom regardless. Only a real,
  // non-passive native listener can actually block it.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      setTransform(t => {
        const newScale = Math.min(4, Math.max(0.2, t.scale * delta));
        const rect = el.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const nx = mx - (mx - t.x) * (newScale / t.scale);
        const ny = my - (my - t.y) * (newScale / t.scale);
        return { x: nx, y: ny, scale: newScale };
      });
    };
    el.addEventListener('wheel', handler, { passive: false });
    return () => el.removeEventListener('wheel', handler);
  }, []);

  function onMouseDown(e: React.MouseEvent) {
    if (e.button !== 0) return;
    draggedRef.current = false;
    dragRef.current = { startX: e.clientX, startY: e.clientY, tx: transform.x, ty: transform.y };
  }

  function onMouseMove(e: React.MouseEvent) {
    const drag = dragRef.current;
    if (!drag) return;
    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;
    // A few px of wobble shouldn't cancel a click-to-expand, only an actual pan.
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) draggedRef.current = true;
    setTransform(t => ({ ...t, x: drag.tx + dx, y: drag.ty + dy }));
  }

  function onMouseUp() { dragRef.current = null; }

  // Touch equivalent of the mouse pan above — drag-to-pan has no native
  // touch fallback (unlike a tap, which browsers already synthesize into
  // a click), so without this the graph would be mouse-only on phones.
  // Pinch-zoom is intentionally not implemented here: the +/−/⌂ buttons
  // already give full tap-reachable zoom control, so the one truly
  // missing interaction is the drag itself.
  function onTouchStart(e: React.TouchEvent) {
    if (e.touches.length !== 1) return;
    draggedRef.current = false;
    const t = e.touches[0];
    dragRef.current = { startX: t.clientX, startY: t.clientY, tx: transform.x, ty: transform.y };
  }

  function onTouchMove(e: React.TouchEvent) {
    const drag = dragRef.current;
    if (!drag || e.touches.length !== 1) return;
    const t = e.touches[0];
    const dx = t.clientX - drag.startX;
    const dy = t.clientY - drag.startY;
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) draggedRef.current = true;
    setTransform(tr => ({ ...tr, x: drag.tx + dx, y: drag.ty + dy }));
  }

  function onTouchEnd() { dragRef.current = null; }

  function onBackgroundClickInternal() {
    if (draggedRef.current) return; // was a pan, not a click
    onBackgroundClick?.();
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <svg
        ref={svgRef}
        width="100%" height="100%"
        viewBox={`0 0 ${CANVAS_W} ${Math.max(canvasHeight, 300)}`}
        preserveAspectRatio="xMidYMin meet"
        style={{ display: 'block', background: '#060c1a', cursor: dragRef.current ? 'grabbing' : 'grab', userSelect: 'none', touchAction: 'none' }}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onTouchStart={onTouchStart}
        onTouchMove={onTouchMove}
        onTouchEnd={onTouchEnd}
        onClick={onBackgroundClickInternal}
      >
        <defs>
          <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
            <circle cx="0" cy="0" r="0.7" fill="rgba(var(--violet-rgb),0.06)" />
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
          {edges.map(e => (
            <line
              key={e.id}
              x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
              stroke={e.color + '55'}
              strokeWidth={1.5 / transform.scale}
              strokeDasharray="4,6"
              markerEnd={`url(#arrow-${e.type})`}
            />
          ))}
          {nodes.map(n => {
            const W = n.isRoot ? 130 : n.isCategory ? 112 : 150;
            const H = n.isRoot ? 44 : n.isCategory ? 32 : 32;
            const runningRoot = n.isRoot && running;
            return (
              <g
                key={n.id}
                className="sandbox-node-in"
                transform={`translate(${n.x - W / 2},${n.y - H / 2})`}
                filter={n.isRoot ? 'url(#glow-strong)' : 'url(#glow)'}
                style={{ cursor: 'pointer', transition: 'transform 0.4s cubic-bezier(0.65,0,0.35,1)' }}
                onClick={e => { e.stopPropagation(); onNodeClick(n); }}
              >
                <title>{n.fullLine || n.label}</title>
                <rect
                  width={W} height={H} rx={5} ry={5} fill="#060c1a"
                  stroke={n.color} strokeWidth={n.isRoot ? 2 : n.isCategory ? 1.8 : 1.4}
                  strokeDasharray={n.isCategory ? '3,2' : undefined}
                  opacity={0.95}
                  style={runningRoot ? { animation: 'pulse-border 1.4s ease-in-out infinite' } : undefined}
                />
                <text x={W / 2} y={n.isRoot ? 16 : n.isCategory ? 14 : 13} textAnchor="middle" fill={n.color} fontSize={n.isRoot ? 10 : 9} fontFamily="JetBrains Mono, monospace" fontWeight="bold">
                  {n.isCategory ? `[${n.type}] ×${n.count}` : `[${n.type}]`}
                </text>
                {!n.isCategory && (
                  <text x={W / 2} y={n.isRoot ? 31 : 26} textAnchor="middle" fill="rgba(226,232,240,0.8)" fontSize={n.isRoot ? 9 : 8} fontFamily="JetBrains Mono, monospace">
                    {n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {nodesEmpty && (
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#1e293b', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, pointerEvents: 'none', textAlign: 'center', padding: 20,
        }}>
          behavior tree will render here as the trace streams in — click any node once it appears
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
  border: '1px solid rgba(var(--violet-rgb),0.2)',
  color: 'var(--violet)',
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
          background: open ? 'rgba(var(--violet-rgb),0.1)' : 'rgba(0,0,0,0.4)',
          border: '1px solid rgba(var(--violet-rgb),0.2)',
          color: 'var(--violet)', borderRadius: 4, cursor: 'pointer', textTransform: 'uppercase',
        }}
      >
        LEGEND {open ? '▴' : '▾'}
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', marginTop: 4,
          background: '#010814', border: '1px solid rgba(var(--violet-rgb),0.15)',
          borderRadius: 6, padding: '10px 12px', zIndex: 10, minWidth: 220,
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
          <div style={{ borderTop: '1px solid rgba(var(--violet-rgb),0.08)', marginTop: 8, paddingTop: 8 }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>Shapes</div>
            <div style={{ fontSize: 8, color: '#64748b', fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>Solid box — root process</div>
            <div style={{ fontSize: 8, color: '#64748b', fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>Dashed box — event category (click for the list)</div>
            <div style={{ fontSize: 8, color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>Thin box — one traced event (click for its log line)</div>
          </div>
          <div style={{ borderTop: '1px solid rgba(var(--violet-rgb),0.08)', marginTop: 8, paddingTop: 8 }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', marginBottom: 6, letterSpacing: 1, textTransform: 'uppercase' }}>Severity</div>
            {[
              { color: '#f43f5e', label: 'Critical' },
              { color: '#f59e0b', label: 'Warning' },
              { color: 'var(--violet)', label: 'Info' },
              { color: '#64748b', label: 'System' },
            ].map(({ color, label }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <div style={{ width: 20, height: 2, background: color, borderRadius: 1 }} />
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#64748b' }}>{label}</span>
              </div>
            ))}
          </div>
          <div style={{ borderTop: '1px solid rgba(var(--violet-rgb),0.08)', marginTop: 8, paddingTop: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#334155' }}>
            Scroll to zoom · Drag to pan · ⌂ to reset
          </div>
        </div>
      )}
    </div>
  );
}

// ── Node detail popup — the actual log line a node came from ─────────────────
function NodeDetailModal({ node, childNodes, onSelectChild, onClose }: {
  node: GNode; childNodes: GNode[]; onSelectChild: (n: GNode) => void; onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (typeof document === 'undefined') return null;

  const severityLabel = node.tag === 'crit' ? 'CRITICAL' : node.tag === 'warn' ? 'WARNING' : node.tag === 'sys' ? 'SYSTEM' : 'INFO';
  const severityColor = node.tag === 'crit' ? '#f43f5e' : node.tag === 'warn' ? '#f59e0b' : node.tag === 'sys' ? '#64748b' : 'var(--violet)';

  return createPortal(
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(2,6,16,0.75)', backdropFilter: 'blur(2px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(560px, 100%)', maxHeight: '80vh', overflowY: 'auto',
          background: '#0c1628', border: `1px solid ${node.color}`,
          borderRadius: 10, boxShadow: `0 0 40px ${node.color}40`,
          padding: 20,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
          <span style={{ fontFamily: "'Orbitron', monospace", fontSize: 12, letterSpacing: 1.5, color: node.color, textTransform: 'uppercase' }}>
            [{node.type}]{node.isCategory ? ` · ${node.count} events` : node.isRoot ? ' · root process' : ''}
          </span>
          <span onClick={onClose} className="clickable" style={{ cursor: 'pointer', color: '#475569', fontSize: 16, padding: '0 4px' }}>✕</span>
        </div>

        {!node.isCategory && (
          <span style={{
            display: 'inline-block', fontSize: 8, padding: '2px 7px', borderRadius: 3,
            border: `1px solid ${severityColor}`, color: severityColor,
            fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1, marginBottom: 10,
          }}>
            {severityLabel}
          </span>
        )}

        {node.isCategory ? (
          <div>
            <div style={{ fontSize: 10, color: '#94a3b8', lineHeight: 1.6, marginBottom: 10 }}>
              {node.count} {node.type.toLowerCase()} event{node.count !== 1 ? 's' : ''} grouped under this branch. Click one to see its exact log line.
            </div>
            {childNodes.map(c => (
              <div
                key={c.id}
                onClick={() => onSelectChild(c)}
                className="clickable"
                style={{
                  cursor: 'pointer', padding: '7px 9px', marginBottom: 4,
                  border: '1px solid rgba(255,255,255,0.07)', borderRadius: 4,
                  fontSize: 10, color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace",
                  transition: 'background-color 0.15s ease',
                }}
              >
                ▸ {c.label}
              </div>
            ))}
          </div>
        ) : (
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#e2e8f0',
            background: '#010814', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6,
            padding: 12, lineHeight: 1.7, wordBreak: 'break-word', whiteSpace: 'pre-wrap',
          }}>
            {node.fullLine || node.label}
          </div>
        )}
      </div>
    </div>,
    document.body
  );
}

// ── Patch viewer popup ─────────────────────────────────────────────────────────
function PatchViewModal({ filename, content, loading, error, onClose }: {
  filename: string; content: string; loading: boolean; error: string | null; onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (typeof document === 'undefined') return null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard permission denied — no-op */ }
  }

  return createPortal(
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(2,6,16,0.75)', backdropFilter: 'blur(2px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(720px, 100%)', maxHeight: '85vh', overflowY: 'auto',
          background: '#0c1628', border: '1px solid var(--emerald)',
          borderRadius: 10, boxShadow: '0 0 40px rgba(var(--emerald-rgb), 0.2)',
          padding: 20,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <span style={{ fontFamily: "'Orbitron', monospace", fontSize: 11, letterSpacing: 1.5, color: 'var(--emerald)', textTransform: 'uppercase', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {filename}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            {!loading && !error && (
              <span
                onClick={copy}
                className="clickable"
                style={{
                  cursor: 'pointer', fontSize: 9, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1,
                  color: copied ? 'var(--emerald)' : '#94a3b8', padding: '3px 8px',
                  border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4,
                }}
              >
                {copied ? '✓ COPIED' : 'COPY'}
              </span>
            )}
            <span onClick={onClose} className="clickable" style={{ cursor: 'pointer', color: '#475569', fontSize: 16 }}>✕</span>
          </div>
        </div>

        {loading && (
          <div style={{ fontSize: 10, color: '#475569', fontFamily: "'JetBrains Mono', monospace" }}>
            <span className="blink">▸</span> loading patch…
          </div>
        )}
        {error && (
          <div style={{ fontSize: 10, color: '#f43f5e', fontFamily: "'JetBrains Mono', monospace" }}>
            [ERROR] {error}
          </div>
        )}
        {!loading && !error && (
          <pre style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--emerald)',
            background: '#010814', border: '1px solid rgba(var(--emerald-rgb), 0.15)', borderRadius: 6,
            padding: 14, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.7,
          }}>
            {content}
          </pre>
        )}
      </div>
    </div>,
    document.body
  );
}

// ── Free-look graph overlay — click empty canvas to expand, click again
// (or the background) to collapse. Full-viewport room for panning/zooming
// a tree that's cramped in the normal 340px-tall row. ─────────────────────
function GraphExpandedOverlay({ nodes, edges, canvasHeight, running, onNodeClick, onClose }: {
  nodes: GNode[]; edges: GEdge[]; canvasHeight: number; running: boolean;
  onNodeClick: (n: GNode) => void; onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (typeof document === 'undefined') return null;

  return createPortal(
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(2,6,16,0.85)', backdropFilter: 'blur(2px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 28,
      }}
    >
      <div style={{
        position: 'relative', width: '92vw', height: '88vh',
        background: '#060c1a', border: '1px solid rgba(var(--violet-rgb),0.3)',
        borderRadius: 10, boxShadow: '0 0 60px rgba(var(--violet-rgb),0.15)', overflow: 'hidden',
      }}>
        <div style={{
          position: 'absolute', top: 10, left: 14, zIndex: 2,
          fontFamily: 'JetBrains Mono, monospace', fontSize: 10, letterSpacing: 1.5,
          color: 'var(--violet)', textTransform: 'uppercase', pointerEvents: 'none',
        }}>
          Behavior Tree — free look
        </div>
        <span
          onClick={onClose}
          className="clickable"
          title="Collapse (Esc)"
          style={{
            position: 'absolute', top: 8, right: 10, zIndex: 2, cursor: 'pointer',
            color: '#94a3b8', fontSize: 18, padding: '2px 6px',
          }}
        >
          ✕
        </span>
        <GraphView
          nodes={nodes} edges={edges} canvasHeight={canvasHeight} running={running}
          onNodeClick={onNodeClick} onBackgroundClick={onClose}
        />
      </div>
    </div>,
    document.body
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
interface Props {
  staticData?: StaticResult | null;
  /** jobId from a completed analysis run — if provided, sandbox uses it directly */
  jobId?: string | null;
  /** Start the adaptive run the moment a jobId is available, instead of
   *  waiting for the user to click RUN SANDBOX — static analysis and e2b
   *  run in parallel on every analysis now. */
  autoStart?: boolean;
  /** Mirrors the `running` state up to the parent — e2b's own patch loop
   *  (plus a human-in-the-loop pause) can easily outlast the main pipeline,
   *  so the dashboard needs this to keep Header's nav lock engaged for the
   *  full duration, not just while the main pipeline is active. */
  onRunningChange?: (running: boolean) => void;
}

const TAG_COLOR: Record<string, string> = {
  sys:  '#64748b',
  info: 'var(--violet)',
  warn: '#f59e0b',
  crit: '#f43f5e',
};

// Empty string = relative/same-origin, which is correct for the production
// static export (served by the same FastAPI app on Railway). Local dev sets
// NEXT_PUBLIC_API_URL via frontend/.env.local to point at :8000 instead.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

export default function LinuxSandboxPanel({ staticData, jobId, autoStart, onRunningChange }: Props) {
  const { active: wiresActive } = useRunActive();
  const isNarrow = useIsNarrow();
  const [running, setRunning]       = useState(false);
  const [done, setDone]             = useState(false);
  const [hasRunStarted, setHasRunStarted] = useState(false);
  const [logs, setLogs]             = useState<Array<{ line: string; tag: string }>>([]);
  const [rawEvents, setRawEvents]   = useState<SandboxEvent[]>([]);
  const [savedPatchFile, setSavedPatchFile] = useState<string | null>(null);

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
  const patchPulseTimerRef  = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Node click → detail popup
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);

  // Console/Tree/Live-code row — same minimize/expand puzzle mechanics as
  // the Agents/Raw Logs/Reports widgets above (reusing the actual Widget
  // component, not a reimplementation). Plus a separate "free look" overlay
  // just for the graph, toggled by clicking empty canvas.
  const [panelMin, setPanelMin] = useState<{ console: boolean; graph: boolean; code: boolean }>({
    console: false, graph: false, code: false,
  });
  const toggleMin = (key: 'console' | 'graph' | 'code') =>
    setPanelMin(m => ({ ...m, [key]: !m[key] }));
  const [graphExpanded, setGraphExpanded] = useState(false);

  // "Gemini is patching" live banner — a separate, clearly-techy pulse on top
  // of the ordinary log line, cleared a couple seconds after the last patch
  // event so back-to-back iterations keep it alive without flickering.
  const [patchPulse, setPatchPulse] = useState<number | null>(null);

  // Live mock.js — each successful iteration now sends back the COMPLETE
  // file (see app.py/ask_gemini_for_patch), so this always shows the real
  // current state of the script, not a reconstructed diff.
  const [liveCode, setLiveCode] = useState<{ code: string; iteration: number } | null>(null);
  const [liveCodeFlash, setLiveCodeFlash] = useState(false);
  const liveCodeRef = useRef<HTMLDivElement>(null);
  const liveCodeFlashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Patch viewer popup
  const [patchView, setPatchView] = useState<{ filename: string; content: string; loading: boolean; error: string | null } | null>(null);

  // Human-in-the-loop — adaptive mode only. The run forces a pause after 3x
  // the same error either way; controlArmed lets you jump in on the *next*
  // failure instead of waiting for that, one-shot per click.
  const [currentSandboxJobId, setCurrentSandboxJobId] = useState<string | null>(null);
  const [controlArmed, setControlArmed] = useState(false);
  const [awaitingInput, setAwaitingInput] = useState<{
    reason: string; error: string; diagnosis: string; iteration: number;
    snippet: { file: string; line: number; start_line: number; snippet: string } | null;
  } | null>(null);
  const [guidanceText, setGuidanceText] = useState('');

  function requestControl() {
    if (!currentSandboxJobId) return;
    setControlArmed(true);
    fetch(`${API_URL}/sandbox/${currentSandboxJobId}/request-control`, { method: 'POST' })
      .catch(() => setControlArmed(false));
  }

  function endRun() {
    if (!currentSandboxJobId) return;
    fetch(`${API_URL}/sandbox/${currentSandboxJobId}/end`, { method: 'POST' }).catch(() => {});
  }

  function continueRun() {
    if (!currentSandboxJobId) return;
    const url = `${API_URL}/sandbox/${currentSandboxJobId}/continue`
      + (guidanceText.trim() ? `?guidance=${encodeURIComponent(guidanceText.trim())}` : '');
    fetch(url, { method: 'POST' }).catch(() => {});
    setGuidanceText('');
  }

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => {
    if (liveCodeRef.current) liveCodeRef.current.scrollTop = liveCodeRef.current.scrollHeight;
  }, [liveCode]);

  useEffect(() => {
    onRunningChange?.(running);
  }, [running, onRunningChange]);

  useEffect(() => () => {
    if (patchPulseTimerRef.current) clearTimeout(patchPulseTimerRef.current);
    if (liveCodeFlashTimerRef.current) clearTimeout(liveCodeFlashTimerRef.current);
  }, []);

  const displayedRootLabel = staticData?.file_name ?? localFileName ?? 'malware.js';
  const { nodes, edges, height: treeHeight } = useMemo(
    () => (hasRunStarted ? buildTree(rawEvents, displayedRootLabel) : { nodes: [] as GNode[], edges: [] as GEdge[], height: 300 }),
    [hasRunStarted, rawEvents, displayedRootLabel],
  );
  const selectedChildren = selectedNode?.isCategory ? nodes.filter(n => n.parentId === selectedNode.id) : [];

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

  async function viewPatch() {
    if (!savedPatchFile) return;
    setPatchView({ filename: savedPatchFile, content: '', loading: true, error: null });
    try {
      const res = await fetch(`${API_URL}/sandbox/patches/${encodeURIComponent(savedPatchFile)}`);
      if (!res.ok) throw new Error(`Failed to load patch: ${res.status}`);
      const text = await res.text();
      setPatchView({ filename: savedPatchFile, content: text, loading: false, error: null });
    } catch (err) {
      setPatchView({
        filename: savedPatchFile, content: '', loading: false,
        error: err instanceof Error ? err.message : 'Failed to load patch',
      });
    }
  }

  // ── Event stream helpers ──────────────────────────────────────────────────
  function addLogNode(line: string, tag: string, nodeData?: { type: string; label: string } | null) {
    setLogs(prev => [...prev, { line, tag }]);
    const nd = nodeData ?? classifyLine(line).node;
    if (nd) {
      const { type, label } = nd;
      const idx = typeIdxRef.current[type] ?? 0;
      typeIdxRef.current[type] = idx + 1;
      setRawEvents(prev => [...prev, { id: `${type}-${idx}`, type, label, fullLine: line, tag }]);
    }
  }

  function connectSandboxWS(sandbox_job_id: string) {
    setCurrentSandboxJobId(sandbox_job_id);
    const wsBase = API_URL
      ? API_URL.replace(/^https?/, s => (s === 'https' ? 'wss' : 'ws'))
      : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`;
    const ws = new WebSocket(`${wsBase}/ws/sandbox/${sandbox_job_id}`);

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string, unknown>;
        if (msg.event === 'sandbox_log') {
          addLogNode(msg.line as string, (msg.tag as string) ?? 'info',
            msg.node as { type: string; label: string } | null ?? undefined);
        }
        if (msg.event === 'sandbox_patch') {
          addLogNode(msg.line as string, 'info');
          const iteration = typeof msg.iteration === 'number' ? msg.iteration : 0;
          setPatchPulse(iteration);
          if (patchPulseTimerRef.current) clearTimeout(patchPulseTimerRef.current);
          patchPulseTimerRef.current = setTimeout(() => setPatchPulse(null), 2600);

          if (typeof msg.mock_js === 'string') {
            setLiveCode({ code: msg.mock_js, iteration });
            setLiveCodeFlash(true);
            if (liveCodeFlashTimerRef.current) clearTimeout(liveCodeFlashTimerRef.current);
            liveCodeFlashTimerRef.current = setTimeout(() => setLiveCodeFlash(false), 700);
          }
        }
        if (msg.event === 'sandbox_awaiting_input') {
          setControlArmed(false); // consumed server-side, whichever way it triggered
          setAwaitingInput({
            reason: (msg.reason as string) ?? 'stuck',
            error: (msg.error as string) ?? '',
            diagnosis: (msg.diagnosis as string) ?? '',
            iteration: typeof msg.iteration === 'number' ? msg.iteration : 0,
            snippet: msg.snippet as { file: string; line: number; start_line: number; snippet: string } | null ?? null,
          });
          addLogNode('[ADAPTIVE] Paused — waiting for your input.', 'warn');
        }
        if (msg.event === 'sandbox_resumed') {
          setAwaitingInput(null);
        }
        if (msg.event === 'sandbox_done' || msg.event === 'sandbox_error') {
          if (msg.event === 'sandbox_done') {
            const pf = msg.patch_file as string | null;
            if (pf) {
              addLogNode(`[SYSTEM] Patches saved → testing/patches/${pf}`, 'info');
              setSavedPatchFile(pf);
            }
          }
          setRunning(false);
          setDone(msg.event === 'sandbox_done');
          setAwaitingInput(null);
          setControlArmed(false);
        }
      } catch (e) { console.error('[sandbox WS] parse error:', e); }
    };

    ws.onerror = () => {
      addLogNode('[ERROR] Sandbox WebSocket connection failed.', 'crit');
      setRunning(false);
    };
  }

  function runPatchSandbox(jid: string) {
    if (!patchFile) return;
    const formData = new FormData();
    formData.append('patch', patchFile);
    fetch(`${API_URL}/sandbox/run-patch/${jid}`, { method: 'POST', body: formData })
      .then(r => { if (!r.ok) throw new Error(`Patch run failed: ${r.status}`); return r.json(); })
      .then(({ sandbox_job_id }: { sandbox_job_id: string }) => connectSandboxWS(sandbox_job_id))
      .catch(err => { addLogNode(`[ERROR] ${err.message}`, 'crit'); setRunning(false); });
  }

  function runAdaptiveSandbox(jid: string) {
    fetch(`${API_URL}/sandbox/start/${jid}`, { method: 'POST' })
      .then(r => { if (!r.ok) throw new Error(`Sandbox start failed: ${r.status}`); return r.json(); })
      .then(({ sandbox_job_id }: { sandbox_job_id: string }) => connectSandboxWS(sandbox_job_id))
      .catch(err => { addLogNode(`[ERROR] ${err.message}`, 'crit'); setRunning(false); });
  }

  const runSim = useCallback(() => {
    if (running || !effectiveJobId) return;
    setRunning(true);
    setDone(false);
    setHasRunStarted(true);
    setLogs([]);
    setRawEvents([]);
    setSavedPatchFile(null);
    setPatchPulse(null);
    setCurrentSandboxJobId(null);
    setControlArmed(false);
    setAwaitingInput(null);
    setGuidanceText('');
    setLiveCode(null);
    setLiveCodeFlash(false);
    typeIdxRef.current = {};

    if (patchFile) {
      runPatchSandbox(effectiveJobId);
    } else {
      runAdaptiveSandbox(effectiveJobId);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, effectiveJobId, patchFile]);

  // Fire once per jobId when autoStart is set — "Full Run" wants static
  // analysis and e2b running at the same time, not e2b waiting on a manual
  // click after the fact.
  const autoStartedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (!autoStart || !effectiveJobId) return;
    if (autoStartedForRef.current === effectiveJobId) return;
    autoStartedForRef.current = effectiveJobId;
    runSim();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart, effectiveJobId]);

  const nodeCount  = rawEvents.length;
  const patchMode  = !!patchFile && !!effectiveJobId;
  const adaptiveMode = !patchFile && !!effectiveJobId;
  const canRun     = !!effectiveJobId && !running;

  // Derive the displayed file name (from analysis or direct upload)
  const displayedFile = staticData?.file_name ?? (jobId ? '(analysis file)' : localFileName);

  return (
    <Panel title="LINUX ADAPTIVE SANDBOX" style={{ gridColumn: '1 / -1' }}>
      {/* .panel is already position:relative + overflow:hidden (globals.css),
          so this just needs its own stacking layer — an absolutely-positioned
          child with no z-index actually paints *above* normal-flow siblings
          in CSS, not below, regardless of DOM order, so the real content
          below is wrapped in its own relative/z-index:1 layer to guarantee
          it stays on top of the wires rather than relying on paint order. */}
      <div className={`widget-wires-wrap${wiresActive ? ' active' : ''}`}>
        <WidgetWires accent="violet" />
      </div>
      <div style={{ position: 'relative', zIndex: 1 }}>

      {/* ── File source bar (shown when no analysis job is present) ── */}
      {!jobId && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          marginBottom: 10, padding: '8px 12px',
          background: 'rgba(0,0,0,0.4)',
          border: `1px solid ${localJobId ? 'rgba(var(--violet-rgb),0.2)' : 'rgba(var(--violet-rgb),0.06)'}`,
          borderRadius: 6,
        }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', flexShrink: 0 }}>
            SANDBOX FILE
          </span>

          {localJobId ? (
            <>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                color: 'var(--violet)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
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
                  background: uploading ? 'rgba(var(--violet-rgb),0.03)' : 'rgba(var(--violet-rgb),0.08)',
                  border: '1px solid rgba(var(--violet-rgb),0.25)', color: uploading ? '#334155' : 'var(--violet)',
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

      {/* ── System info bar + controls ──
          This bar packs a lot in (status badges, VIEW/SAVE/UPLOAD PATCH,
          legend, RUN) — on a phone-width viewport there's no room for all
          of it on one line, so it wraps instead of overflowing off-screen
          (the page clips horizontal overflow, which would otherwise make
          some of these controls permanently unreachable). */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        flexWrap: 'wrap', gap: 8,
        marginBottom: 12, padding: '6px 10px',
        background: 'rgba(0,0,0,0.35)',
        border: '1px solid rgba(var(--violet-rgb),0.08)',
        borderRadius: 6,
      }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
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

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {done && (
            <span style={{ fontSize: 9, color: '#10b981', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1 }}>
              ● COMPLETE
            </span>
          )}
          {savedPatchFile && (
            <>
              <span
                onClick={viewPatch}
                className="clickable"
                style={{
                  fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                  padding: '4px 10px',
                  background: 'rgba(16,185,129,0.06)',
                  border: '1px solid rgba(16,185,129,0.25)',
                  color: '#10b981',
                  borderRadius: 4, cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                ⊙ VIEW PATCH
              </span>
              <a
                href={`${API_URL}/sandbox/patches/${encodeURIComponent(savedPatchFile)}`}
                download={savedPatchFile}
                style={{
                  fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                  padding: '4px 10px',
                  background: 'rgba(16,185,129,0.1)',
                  border: '1px solid rgba(16,185,129,0.35)',
                  color: '#10b981',
                  borderRadius: 4, cursor: 'pointer',
                  textTransform: 'uppercase',
                  textDecoration: 'none',
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                }}
              >
                ↓ SAVE PATCH
              </a>
            </>
          )}
          <span style={{ fontSize: 9, color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>
            {nodeCount} event{nodeCount !== 1 ? 's' : ''}
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
                animation: running ? 'pulse-border 1.6s ease-in-out infinite' : 'none',
              }}
            >
              {running ? 'RUNNING...' : done ? 'RE-RUN' : 'RUN SANDBOX'}
            </button>
          </Tooltip>

          {/* Human-in-the-loop controls — adaptive mode only (patch mode is
              a single one-shot run, nothing iterative to steer or end). The
              run already force-pauses on 3x the same error; this button
              lets you jump in on the very next failure instead of waiting
              for that. END is right next to it per how these get used
              together — "let me take over, or just stop it." */}
          {adaptiveMode && running && (
            <>
              <Tooltip text={controlArmed ? 'Will pause on the next failure' : 'Pause and steer the next patch yourself'} disabled={false} onlyWhenDisabled={false}>
                <button
                  onClick={requestControl}
                  disabled={controlArmed || !!awaitingInput}
                  style={{
                    fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                    padding: '5px 10px',
                    background: controlArmed ? 'rgba(245,158,11,0.18)' : 'rgba(245,158,11,0.07)',
                    border: `1px solid ${controlArmed ? 'var(--amber)' : 'rgba(245,158,11,0.3)'}`,
                    color: 'var(--amber)',
                    borderRadius: 4, cursor: (controlArmed || !!awaitingInput) ? 'default' : 'pointer',
                    textTransform: 'uppercase', transition: 'all 0.2s',
                  }}
                >
                  {controlArmed ? '⏸ ARMED' : 'TAKE CONTROL NEXT FAILURE'}
                </button>
              </Tooltip>
              <button
                onClick={endRun}
                style={{
                  fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                  padding: '5px 10px',
                  background: 'rgba(244,63,94,0.08)',
                  border: '1px solid rgba(244,63,94,0.35)',
                  color: '#f43f5e',
                  borderRadius: 4, cursor: 'pointer',
                  textTransform: 'uppercase', transition: 'all 0.2s',
                }}
              >
                ⏹ END RUN
              </button>
            </>
          )}
        </div>
      </div>

      {/* Paused for human input — forced at 3x the same error, or whenever
          "take control" was armed and the next failure hit. Gemini's own
          plain-English diagnosis sits above a free-text box so you're
          steering the next patch with context, not guessing blind. */}
      {awaitingInput && (
        <div style={{
          marginBottom: 12, padding: '12px 14px',
          background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.3)',
          borderRadius: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span className="blink" style={{ color: 'var(--amber)', fontSize: 10 }}>●</span>
            <span style={{ fontFamily: 'Orbitron, monospace', fontSize: 10, letterSpacing: 1, color: 'var(--amber)', textTransform: 'uppercase' }}>
              Paused — iteration {awaitingInput.iteration} ({awaitingInput.reason === 'stuck' ? 'stuck on same error ×3' : 'you took control'})
            </span>
          </div>
          <div style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#f43f5e',
            marginBottom: 8, wordBreak: 'break-word',
          }}>
            {awaitingInput.error}
          </div>

          {awaitingInput.snippet && (
            <div style={{
              marginBottom: 10, border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4,
              overflow: 'hidden', fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
            }}>
              <div style={{
                padding: '4px 10px', background: 'rgba(0,0,0,0.3)', color: '#64748b',
                letterSpacing: 0.5,
              }}>
                {awaitingInput.snippet.file}:{awaitingInput.snippet.line}
              </div>
              <div style={{ background: '#010814' }}>
                {awaitingInput.snippet.snippet.replace(/\n$/, '').split('\n').map((lineText, i) => {
                  const lineNum = awaitingInput.snippet!.start_line + i;
                  const isFailing = lineNum === awaitingInput.snippet!.line;
                  return (
                    <div
                      key={i}
                      style={{
                        display: 'flex', background: isFailing ? 'rgba(244,63,94,0.12)' : 'transparent',
                        borderLeft: isFailing ? '2px solid #f43f5e' : '2px solid transparent',
                      }}
                    >
                      <span style={{
                        flexShrink: 0, width: 42, textAlign: 'right', padding: '1px 8px',
                        color: isFailing ? '#f43f5e' : '#334155', userSelect: 'none',
                      }}>
                        {lineNum}
                      </span>
                      <span style={{
                        padding: '1px 8px', color: isFailing ? '#fca5a5' : '#94a3b8',
                        whiteSpace: 'pre', overflowX: 'auto',
                      }}>
                        {lineText || ' '}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{
            fontFamily: "'Inter', sans-serif", fontSize: 11, color: '#cbd5e1',
            lineHeight: 1.6, marginBottom: 10, fontStyle: 'italic',
          }}>
            {awaitingInput.diagnosis}
          </div>
          <textarea
            value={guidanceText}
            onChange={e => setGuidanceText(e.target.value)}
            placeholder="Optional — steer the next patch (e.g. 'stub RegQueryValueEx too, it's calling that right after')"
            rows={3}
            style={{
              width: '100%', resize: 'vertical', padding: '8px 10px', marginBottom: 8,
              background: '#010814', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 4,
              color: '#e2e8f0', fontFamily: 'JetBrains Mono, monospace', fontSize: 10,
            }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={continueRun}
              style={{
                fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                padding: '6px 14px', flex: 1,
                background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.4)',
                color: '#10b981', borderRadius: 4, cursor: 'pointer', textTransform: 'uppercase',
              }}
            >
              ▶ {guidanceText.trim() ? 'Send Guidance & Continue' : 'Continue'}
            </button>
            <button
              onClick={endRun}
              style={{
                fontFamily: 'Orbitron, monospace', fontSize: 9, letterSpacing: 1,
                padding: '6px 14px',
                background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.35)',
                color: '#f43f5e', borderRadius: 4, cursor: 'pointer', textTransform: 'uppercase',
              }}
            >
              ⏹ End Run
            </button>
          </div>
        </div>
      )}

      {/* Mode hints */}
      {patchMode && !running && !done && (
        <div style={{
          marginBottom: 8, padding: '5px 10px',
          background: 'rgba(255,215,0,0.04)', border: '1px solid rgba(255,215,0,0.15)',
          borderRadius: 4, fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#78716c',
        }}>
          Patch loaded — will run <span style={{ color: 'var(--violet)' }}>{displayedFile}</span> against{' '}
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
          <span style={{ color: 'var(--violet)' }}>{displayedFile}</span>.
          Patches saved to <span style={{ color: '#a78bfa' }}>testing/patches/</span>.
        </div>
      )}

      {/* "Gemini is patching" — a distinct, animated beat on top of the
          ordinary log line, so a patch iteration actually feels like
          something is happening rather than just another console row. */}
      {patchPulse !== null && (
        <div className="gemini-patch-banner">
          <span className="spark">⚡</span> GEMINI PATCHING — iteration {patchPulse}
        </div>
      )}

      {/* ── Console | Tree | Live mock.js — same minimize/expand puzzle as
          the Agents/Raw Logs/Reports widgets above (reusing the real Widget
          component), each piece free to shrink to a thin strip so the
          others can grow into the freed space. ── */}
      <div style={isNarrow
        ? { display: 'flex', flexDirection: 'column', gap: 12 }
        : { display: 'flex', gap: 12, alignItems: 'stretch', height: 340 }
      }>

        {/* Terminal console */}
        <div style={{ flex: panelMin.console ? (isNarrow ? '0 0 44px' : '0 0 34px') : (isNarrow ? '0 0 300px' : '1 1 0%'), minWidth: 0, display: 'flex' }}>
          <Widget accent="violet" label="Console" live={running} style={{ flex: 1 }} horizontal={isNarrow}
            minimized={panelMin.console} onToggleMinimize={() => toggleMin('console')}>
            <div
              ref={logRef}
              style={{
                height: '100%', overflowY: 'auto',
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
          </Widget>
        </div>

        {/* Interactive behavior tree — click empty canvas to pop it into a
            free-look overlay (see GraphExpandedOverlay); click a node for
            its detail popup instead, same as before. */}
        <div style={{ flex: panelMin.graph ? (isNarrow ? '0 0 44px' : '0 0 34px') : (isNarrow ? '0 0 360px' : '1.3 1 0%'), minWidth: 0, display: 'flex' }}>
          <Widget accent="violet" label="Behavior Tree" style={{ flex: 1 }} horizontal={isNarrow}
            minimized={panelMin.graph} onToggleMinimize={() => toggleMin('graph')}>
            <div style={{ position: 'relative', height: '100%', background: '#060c1a', borderRadius: 4, overflow: 'hidden' }}>
              <GraphView
                nodes={nodes} edges={edges} canvasHeight={treeHeight} running={running}
                onNodeClick={setSelectedNode} onBackgroundClick={() => setGraphExpanded(true)}
              />
            </div>
          </Widget>
        </div>

        {/* Live mock.js — each successful patch now IS the complete file
            (see app.py), so this just shows it and auto-scrolls to the
            bottom, the way a terminal does, instead of trying to fake a
            typing animation on top of data that actually arrives in whole
            chunks per iteration. */}
        {adaptiveMode && (
          <div style={{ flex: panelMin.code ? (isNarrow ? '0 0 44px' : '0 0 34px') : (isNarrow ? '0 0 300px' : '1.6 1 0%'), minWidth: 0, display: 'flex' }}>
            <Widget
              accent="emerald" label="mock.js — live"
              badge={liveCode ? `iter ${liveCode.iteration}` : undefined}
              style={{ flex: 1, borderColor: liveCodeFlash ? 'var(--emerald)' : undefined, transition: 'border-color 0.3s ease' }}
              horizontal={isNarrow}
              minimized={panelMin.code} onToggleMinimize={() => toggleMin('code')}
            >
              <div ref={liveCodeRef} style={{ height: '100%', overflowY: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, lineHeight: 1.6 }}>
                {liveCode ? (
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: '#86e0b8' }}>
                    {liveCode.code}
                  </pre>
                ) : (
                  <span style={{ color: '#1e293b' }}>Waiting for the first successful patch…</span>
                )}
              </div>
            </Widget>
          </div>
        )}
      </div>

      {graphExpanded && (
        <GraphExpandedOverlay
          nodes={nodes} edges={edges} canvasHeight={treeHeight} running={running}
          onNodeClick={setSelectedNode} onClose={() => setGraphExpanded(false)}
        />
      )}

      {selectedNode && (
        <NodeDetailModal
          node={selectedNode}
          childNodes={selectedChildren}
          onSelectChild={setSelectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}

      {patchView && (
        <PatchViewModal
          filename={patchView.filename}
          content={patchView.content}
          loading={patchView.loading}
          error={patchView.error}
          onClose={() => setPatchView(null)}
        />
      )}
      </div>
    </Panel>
  );
}
