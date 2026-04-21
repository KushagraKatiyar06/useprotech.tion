'use client';

import { useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import Tooltip from './Tooltip';

export interface FileInfo {
  name: string;
  sizeKb: number;
  ext: string;
  file?: File;
  mode?: 'malware' | 'vt_log';   // explicit mode chosen by the user
}

interface Props {
  onFileLoaded: (info: FileInfo) => void;
  onAnalyze: () => void;
  analysisRunning: boolean;
  fileInfo: FileInfo | null;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

const MODE_STYLE = {
  tab: (active: boolean, accent: string) => ({
    flex: 1,
    padding: '5px 0',
    fontSize: 9,
    fontFamily: 'Orbitron, monospace',
    letterSpacing: 1,
    textAlign: 'center' as const,
    cursor: 'pointer',
    border: `1px solid ${active ? accent : 'rgba(0,245,255,0.1)'}`,
    background: active ? `${accent}18` : 'transparent',
    color: active ? accent : '#475569',
    borderRadius: 3,
    transition: 'all 0.2s',
  }),
};

export default function FileIntakePanel({ onFileLoaded, onAnalyze, analysisRunning, fileInfo }: Props) {
  const [mode, setMode] = useState<'malware' | 'vt_log'>('malware');
  const [dragOver, setDragOver] = useState(false);
  const [samples, setSamples] = useState<string[]>([]);
  const [samplesOpen, setSamplesOpen] = useState(false);
  const [results, setResults] = useState<string[]>([]);
  const [resultsOpen, setResultsOpen] = useState(false);
  const malwareInputRef = useRef<HTMLInputElement>(null);
  const vtInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetch(`${API_URL}/samples`)
      .then(r => r.json())
      .then(({ samples }: { samples: string[] }) => setSamples(samples))
      .catch(() => setSamples([]));
    fetch(`${API_URL}/results`)
      .then(r => r.json())
      .then(({ results }: { results: string[] }) => setResults(results))
      .catch(() => setResults([]));
  }, []);

  function processFile(f: File, overrideMode?: 'malware' | 'vt_log') {
    const ext = f.name.split('.').pop()?.toUpperCase() ?? 'UNK';
    const sizeKb = Math.round(f.size / 1024) || 1;
    onFileLoaded({ name: f.name, sizeKb, ext, file: f, mode: overrideMode ?? mode });
  }

  function handleDrop(ev: React.DragEvent) {
    ev.preventDefault();
    setDragOver(false);
    const f = ev.dataTransfer.files[0];
    if (f) processFile(f);
  }

  function handleMalwareChange(ev: React.ChangeEvent<HTMLInputElement>) {
    const f = ev.target.files?.[0];
    if (f) processFile(f, 'malware');
    ev.target.value = '';
  }

  function handleVtChange(ev: React.ChangeEvent<HTMLInputElement>) {
    const f = ev.target.files?.[0];
    if (f) processFile(f, 'vt_log');
    ev.target.value = '';
  }

  async function loadSample(name: string) {
    setSamplesOpen(false);
    const res = await fetch(`${API_URL}/samples/${encodeURIComponent(name)}`);
    const blob = await res.blob();
    const file = new File([blob], name, { type: blob.type || 'application/octet-stream' });
    processFile(file, 'malware');
  }

  async function loadResult(name: string) {
    setResultsOpen(false);
    const res = await fetch(`${API_URL}/results/${encodeURIComponent(name)}`);
    const blob = await res.blob();
    const file = new File([blob], name, { type: 'application/json' });
    processFile(file, 'vt_log');
  }

  function switchMode(next: 'malware' | 'vt_log') {
    setMode(next);
    // Clear loaded file if mode changes so there's no mismatch
    if (fileInfo?.mode !== next) onFileLoaded(null as unknown as FileInfo);
  }

  const isMalware = mode === 'malware';

  return (
    <Panel title="// FILE INTAKE" style={{ gridColumn: 1, gridRow: 1 }}>

      {/* ── Mode selector ── */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        <div style={MODE_STYLE.tab(isMalware, '#ff2d9e')} onClick={() => switchMode('malware')}>
          MALWARE FILE
        </div>
        <div style={MODE_STYLE.tab(!isMalware, '#a78bfa')} onClick={() => switchMode('vt_log')}>
          VT LOG
        </div>
      </div>

      {/* ── Upload zone ── */}
      {isMalware ? (
        <>
          <div
            className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
            onClick={() => malwareInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
          >
            <div className="upload-icon">
              <svg viewBox="0 0 40 40" fill="none">
                <rect x="4" y="8" width="24" height="28" rx="2" stroke="#00f5ff" strokeWidth="1" fill="none" opacity="0.4" />
                <rect x="8" y="4" width="24" height="28" rx="2" stroke="#00f5ff" strokeWidth="1.5" fill="rgba(0,245,255,0.06)" />
                <path d="M16 16 L20 12 L24 16" stroke="#ff2d9e" strokeWidth="1.5" strokeLinecap="round" fill="none" />
                <line x1="20" y1="12" x2="20" y2="22" stroke="#ff2d9e" strokeWidth="1.5" strokeLinecap="round" />
                <line x1="14" y1="24" x2="26" y2="24" stroke="#00f5ff" strokeWidth="1" opacity="0.5" />
                <line x1="14" y1="27" x2="26" y2="27" stroke="#00f5ff" strokeWidth="1" opacity="0.3" />
              </svg>
            </div>
            <div className="upload-text">DROP MALWARE OR CLICK TO UPLOAD</div>
            <div className="upload-subtext">.EXE · .DLL · .JS · .PS1 · .BAT · .MSI</div>
          </div>
          <input ref={malwareInputRef} type="file" style={{ display: 'none' }} onChange={handleMalwareChange} />
        </>
      ) : (
        <>
          <div
            className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
            style={{ borderColor: 'rgba(167,139,250,0.35)' }}
            onClick={() => vtInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
          >
            <div className="upload-icon">
              <svg viewBox="0 0 40 40" fill="none">
                <rect x="8" y="4" width="24" height="32" rx="2" stroke="#a78bfa" strokeWidth="1.5" fill="rgba(167,139,250,0.05)" />
                <line x1="13" y1="14" x2="27" y2="14" stroke="#a78bfa" strokeWidth="1" opacity="0.6" />
                <line x1="13" y1="19" x2="27" y2="19" stroke="#a78bfa" strokeWidth="1" opacity="0.4" />
                <line x1="13" y1="24" x2="22" y2="24" stroke="#a78bfa" strokeWidth="1" opacity="0.3" />
              </svg>
            </div>
            <div className="upload-text" style={{ color: '#a78bfa' }}>DROP VT LOG OR CLICK TO UPLOAD</div>
            <div className="upload-subtext">VirusTotal behaviour_summary .JSON</div>
            <div className="upload-subtext" style={{ marginTop: 2, color: '#475569', fontSize: 8 }}>
              skips static analysis &amp; API call
            </div>
          </div>
          <input ref={vtInputRef} type="file" accept=".json,application/json" style={{ display: 'none' }} onChange={handleVtChange} />
        </>
      )}

      {/* ── Loaded file info ── */}
      {fileInfo && (
        <>
          <div className="section-divider" />
          <div className="f9 text-dim">
            {fileInfo.mode === 'vt_log' ? 'VT LOG LOADED' : 'SPECIMEN LOADED'}
          </div>
          <div className="f10 mt4" style={{ wordBreak: 'break-all', color: fileInfo.mode === 'vt_log' ? '#a78bfa' : 'var(--text-cyan)' }}>
            {fileInfo.name}
          </div>
          <div className="stat-row mt8">
            <div className="mini-stat">
              <div className="mini-stat-val">{fileInfo.sizeKb}</div>
              <div className="mini-stat-lbl">SIZE KB</div>
            </div>
            <div className="mini-stat">
              <div className="mini-stat-val" style={{ color: fileInfo.mode === 'vt_log' ? '#a78bfa' : undefined }}>
                {fileInfo.mode === 'vt_log' ? 'JSON' : fileInfo.ext}
              </div>
              <div className="mini-stat-lbl">TYPE</div>
            </div>
          </div>
        </>
      )}

      <Tooltip
        text={!fileInfo ? 'Drop or select a file above first' : 'Analysis already running…'}
        disabled={!fileInfo || analysisRunning}
      >
        <button
          className="hud-btn"
          onClick={onAnalyze}
          disabled={!fileInfo || analysisRunning}
          style={{
            width: '100%',
            ...(fileInfo?.mode === 'vt_log' ? { borderColor: 'rgba(167,139,250,0.5)', color: '#a78bfa' } : {}),
          }}
        >
          {fileInfo?.mode === 'vt_log' ? '▶ ANALYSE VT LOG' : '▶ INITIATE ANALYSIS'}
        </button>
      </Tooltip>

      {/* ── Pre-saved VT logs (vt_log mode only) ── */}
      {!isMalware && results.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <button
            className="hud-btn cyan-btn"
            style={{ borderColor: 'rgba(167,139,250,0.4)', color: '#a78bfa' }}
            onClick={() => setResultsOpen(o => !o)}
          >
            {resultsOpen ? '▲ HIDE EXAMPLE LOGS' : '▼ LOAD EXAMPLE LOG'}
          </button>

          {resultsOpen && (
            <div style={{
              marginTop: 6,
              border: '1px solid rgba(167,139,250,0.2)',
              borderRadius: 4,
              overflow: 'hidden',
            }}>
              {results.map(name => (
                <button
                  key={name}
                  onClick={() => loadResult(name)}
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: '6px 10px',
                    background: 'rgba(167,139,250,0.03)',
                    border: 'none',
                    borderBottom: '1px solid rgba(167,139,250,0.08)',
                    color: '#94a3b8',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 10,
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(167,139,250,0.09)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'rgba(167,139,250,0.03)')}
                >
                  <span style={{ color: '#a78bfa', marginRight: 6 }}>›</span>
                  {name}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Sample malware library (malware mode only) ── */}
      {isMalware && samples.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <button
            className="hud-btn cyan-btn"
            onClick={() => setSamplesOpen(o => !o)}
          >
            {samplesOpen ? '▲ HIDE EXAMPLES' : '▼ LOAD EXAMPLE MALWARE'}
          </button>

          {samplesOpen && (
            <div style={{
              marginTop: 6,
              border: '1px solid rgba(0,245,255,0.15)',
              borderRadius: 4,
              overflow: 'hidden',
            }}>
              {samples.map(name => (
                <button
                  key={name}
                  onClick={() => loadSample(name)}
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: '6px 10px',
                    background: 'rgba(0,245,255,0.03)',
                    border: 'none',
                    borderBottom: '1px solid rgba(0,245,255,0.08)',
                    color: '#94a3b8',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 10,
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,245,255,0.09)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'rgba(0,245,255,0.03)')}
                >
                  <span style={{ color: '#ff2d9e', marginRight: 6 }}>›</span>
                  {name}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
