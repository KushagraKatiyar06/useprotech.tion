'use client';

import { useRef, useState } from 'react';
import Panel from './Panel';

export interface FileInfo {
  name: string;
  sizeKb: number;
  ext: string;
  threatLevel: number;
}

interface Props {
  onFileLoaded: (info: FileInfo) => void;
  onAnalyze: () => void;
  analysisRunning: boolean;
  fileInfo: FileInfo | null;
}

export default function FileIntakePanel({ onFileLoaded, onAnalyze, analysisRunning, fileInfo }: Props) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function processFile(f: File) {
    const ext = f.name.split('.').pop()?.toUpperCase() ?? 'UNK';
    const sizeKb = Math.round(f.size / 1024) || 1;
    const threatLevel = Math.floor(Math.random() * 6) + 4;
    onFileLoaded({ name: f.name, sizeKb, ext, threatLevel });
  }

  function handleDrop(ev: React.DragEvent) {
    ev.preventDefault();
    setDragOver(false);
    const f = ev.dataTransfer.files[0];
    if (f) processFile(f);
  }

  function handleChange(ev: React.ChangeEvent<HTMLInputElement>) {
    const f = ev.target.files?.[0];
    if (f) processFile(f);
  }

  function loadDemo() {
    onFileLoaded({
      name: 'invoice_q4.exe',
      sizeKb: 278,
      ext: 'EXE',
      threatLevel: 7,
    });
  }

  return (
    <Panel title="// FILE INTAKE" style={{ gridColumn: 1, gridRow: 1 }}>
      <div
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onClick={() => inputRef.current?.click()}
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
        <div className="upload-text">DROP SUSPICIOUS FILE<br />OR CLICK TO UPLOAD</div>
        <div className="upload-subtext">.EXE · .DLL · .BAT · .PS1 · .MSI</div>
      </div>
      <input ref={inputRef} type="file" style={{ display: 'none' }} onChange={handleChange} />

      {fileInfo && (
        <>
          <div className="section-divider" />
          <div className="f9 text-dim">SPECIMEN LOADED</div>
          <div className="f10 text-cyan mt4" style={{ wordBreak: 'break-all' }}>{fileInfo.name}</div>
          <div className="stat-row mt8">
            <div className="mini-stat">
              <div className="mini-stat-val">{fileInfo.sizeKb}</div>
              <div className="mini-stat-lbl">SIZE KB</div>
            </div>
            <div className="mini-stat">
              <div className="mini-stat-val">{fileInfo.ext}</div>
              <div className="mini-stat-lbl">TYPE</div>
            </div>
          </div>
          <div className="section-divider" />
          <div className="f9 text-dim">THREAT LEVEL PRE-SCAN</div>
          <div className="threat-level-display" style={{ marginTop: 6 }}>
            {Array.from({ length: 10 }, (_, i) => (
              <div key={i} className={`threat-bar ${i < fileInfo.threatLevel ? 'filled' : ''}`} />
            ))}
            <span className="threat-label">{fileInfo.threatLevel * 10}%</span>
          </div>
        </>
      )}

      <button
        className="hud-btn"
        onClick={onAnalyze}
        disabled={!fileInfo || analysisRunning}
      >
        ▶ INITIATE ANALYSIS
      </button>
      <button className="hud-btn cyan-btn mt4" onClick={loadDemo}>
        ⚡ LOAD DEMO SPECIMEN
      </button>

      <div className="section-divider" style={{ marginTop: 14 }} />
      <div className="f9 text-dim">SYSTEM STATUS</div>
      <div className="hex-row mt4">
        {Array.from({ length: 9 }, (_, i) => (
          <div key={i} className={`hex ${i < 3 ? 'active' : ''}`} />
        ))}
      </div>
      <div className="f9 text-dim mt4">
        SANDBOX CORES: <span className="text-cyan">3/9 IDLE</span>
      </div>
    </Panel>
  );
}
