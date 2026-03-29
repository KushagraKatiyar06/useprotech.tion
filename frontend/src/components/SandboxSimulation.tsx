'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import { SIM_EXFILS, SIM_FILES, SIM_PHASES } from '@/lib/data';

type FileState = 'normal' | 'infected' | 'encrypted';

const PHASE_PCTS = [16, 14, 20, 20, 10, 20];

export default function SandboxSimulation() {
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState(-1);
  const [phaseLabel, setPhaseLabel] = useState('IDLE');
  const [fileStates, setFileStates] = useState<Record<string, FileState>>({
    f1: 'normal', f2: 'normal', f3: 'normal', f4: 'normal',
    f5: 'normal', f6: 'normal', f7: 'normal',
  });
  const [fileOpLog, setFileOpLog] = useState<Array<{ msg: string; color: string }>>([]);
  const [exfilLog, setExfilLog] = useState<Array<{ msg: string; color: string }>>([]);
  const [taskbarProc, setTaskbarProc] = useState('');
  const [ransomVisible, setRansomVisible] = useState(false);
  const [ransomBg, setRansomBg] = useState('rgba(0,0,0,0)');

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const runningRef = useRef(false);
  const progressRef = useRef(0);
  const phaseRef = useRef(-1);

  function addFileOp(msg: string, color: string) {
    setFileOpLog(prev => [...prev, { msg, color }]);
  }

  function addExfil(msg: string, color: string) {
    setExfilLog(prev => [...prev, { msg, color }]);
  }

  const advanceProgress = useCallback((pct: number, next: () => void) => {
    const target = progressRef.current + pct;
    const step = () => {
      if (!runningRef.current) return;
      progressRef.current = Math.min(progressRef.current + 1, target);
      setProgress(progressRef.current);
      if (progressRef.current < target) setTimeout(step, 30);
      else {
        phaseRef.current++;
        setTimeout(next, 400);
      }
    };
    step();
  }, []);

  const runPhase = useCallback(() => {
    const p = phaseRef.current;
    if (!runningRef.current || p >= SIM_PHASES.length) {
      runningRef.current = false;
      setRunning(false);
      setPhaseLabel(p >= SIM_PHASES.length ? 'COMPLETE' : 'STOPPED');
      return;
    }
    setPhaseLabel(SIM_PHASES[p]);

    if (p === 0) {
      // Payload deploy
      setTaskbarProc('invoice_q4.exe');
      setFileStates(prev => ({ ...prev, f5: 'infected' }));
      addFileOp('CREATE: C:\\Temp\\payload.dll', 'var(--magenta)');
      setTimeout(() => {
        if (!runningRef.current) return;
        setFileStates(prev => ({ ...prev, f6: 'infected' }));
        addFileOp('CREATE: svchost_fake.exe', 'var(--magenta)');
        advanceProgress(PHASE_PCTS[0], runPhase);
      }, 900);
    } else if (p === 1) {
      // Process inject
      addFileOp('INJECT: svchost.exe (PID 1240)', '#ffcc00');
      setTaskbarProc('svchost_fake [injected]');
      advanceProgress(PHASE_PCTS[1], runPhase);
    } else if (p === 2) {
      // File encryption
      let idx = 0;
      const encryptNext = () => {
        if (!runningRef.current || idx >= SIM_FILES.length) {
          advanceProgress(PHASE_PCTS[2], runPhase);
          return;
        }
        const { id, path } = SIM_FILES[idx];
        setFileStates(prev => ({ ...prev, [id]: 'encrypted' }));
        addFileOp(`ENCRYPT: ${path.split('\\').pop()}`, '#ff8888');
        idx++;
        setTimeout(encryptNext, 700);
      };
      encryptNext();
    } else if (p === 3) {
      // C2 exfil
      setExfilLog([]);
      SIM_EXFILS.forEach((e, i) => {
        setTimeout(() => {
          if (!runningRef.current) return;
          addExfil(e.msg, e.color);
        }, i * 600);
      });
      advanceProgress(PHASE_PCTS[3], runPhase);
    } else if (p === 4) {
      // Persistence
      setFileStates(prev => ({ ...prev, f7: 'infected' }));
      addFileOp('WRITE REG: ...\\Run\\WindowsDefender32', 'var(--magenta)');
      advanceProgress(PHASE_PCTS[4], runPhase);
    } else if (p === 5) {
      // Ransom drop
      setRansomBg('rgba(0,0,0,0.75)');
      setTimeout(() => setRansomVisible(true), 300);
      setTaskbarProc('⚠ ENCRYPTED');
      advanceProgress(PHASE_PCTS[5], runPhase);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [advanceProgress]);

  function startSim() {
    runningRef.current = true;
    progressRef.current = 0;
    phaseRef.current = 0;
    setRunning(true);
    setProgress(0);
    setPhase(0);
    setRansomVisible(false);
    setRansomBg('rgba(0,0,0,0)');
    setFileStates({ f1: 'normal', f2: 'normal', f3: 'normal', f4: 'normal', f5: 'normal', f6: 'normal', f7: 'normal' });
    setFileOpLog([]);
    setExfilLog([{ msg: 'Monitoring...', color: 'var(--text-dim)' }]);
    setTaskbarProc('');
    drawSimNet();
    runPhase();
  }

  function stopSim() {
    runningRef.current = false;
    setRunning(false);
    setPhaseLabel('STOPPED');
    cancelAnimationFrame(animRef.current);
  }

  function drawSimNet() {
    const canvas = canvasRef.current;
    if (!canvas) return;
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
      if (!runningRef.current) { ctx!.clearRect(0, 0, W, H); return; }
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

      if (ts - lastSpawn > 500) {
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

      animRef.current = requestAnimationFrame(frame);
    }
    animRef.current = requestAnimationFrame(frame);
  }

  useEffect(() => () => cancelAnimationFrame(animRef.current), []);

  return (
    <Panel
      title="// LIVE SANDBOX SIMULATION — WHAT THIS MALWARE DOES TO YOUR SYSTEM"
      className="sim-panel"
      style={{ gridRow: 2, gridColumn: '1 / -1' }}
    >
      <div className="sim-screen">
        {/* Pane 1: Desktop */}
        <div className="sim-pane">
          <div className="f9 text-dim" style={{ marginBottom: 6 }}>► SYSTEM DISPLAY</div>
          <div className="fake-desktop">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: 8 }}>
              {[['📁','Docs'],['💻','PC'],['🗑️','Trash']].map(([icon, label]) => (
                <div key={label} style={{ width: 36, textAlign: 'center', fontSize: 8, color: 'rgba(255,255,255,0.7)' }}>
                  <div style={{ fontSize: 18 }}>{icon}</div>
                  <div>{label}</div>
                </div>
              ))}
            </div>
            <div className="ransomware-overlay" style={{ background: ransomBg }}>
              <div className={`ransom-msg ${ransomVisible ? 'show' : ''}`}>
                <div className="ransom-title">⚠ YOUR FILES<br />ARE ENCRYPTED</div>
                <div className="ransom-body">All data locked.<br />Pay 0.5 BTC to<br />1A2B...9Z<br />within 72 hours.</div>
              </div>
            </div>
            <div className="fake-taskbar">
              <div className="fake-start">START</div>
              <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.5)', marginLeft: 8 }}>{taskbarProc}</div>
              <div className="fake-clock">10:24 AM</div>
            </div>
          </div>
        </div>

        {/* Pane 2: File system */}
        <div className="sim-pane">
          <div className="f9 text-dim" style={{ marginBottom: 6 }}>► FILE SYSTEM IMPACT</div>
          <div className="fs-tree">
            <div className="fs-dir">C:\Users\victim\</div>
            <div className={`fs-file ${fileStates.f1 === 'encrypted' ? 'encrypted' : ''}`}>
              &nbsp;&nbsp;Documents\budget.xlsx{fileStates.f1 === 'encrypted' ? '.locked' : ''}
            </div>
            <div className={`fs-file ${fileStates.f2 === 'encrypted' ? 'encrypted' : ''}`}>
              &nbsp;&nbsp;Documents\passwords.txt{fileStates.f2 === 'encrypted' ? '.locked' : ''}
            </div>
            <div className={`fs-file ${fileStates.f3 === 'encrypted' ? 'encrypted' : ''}`}>
              &nbsp;&nbsp;Pictures\family.jpg{fileStates.f3 === 'encrypted' ? '.locked' : ''}
            </div>
            <div className={`fs-file ${fileStates.f4 === 'encrypted' ? 'encrypted' : ''}`}>
              &nbsp;&nbsp;Desktop\work.docx{fileStates.f4 === 'encrypted' ? '.locked' : ''}
            </div>
            <div className="fs-dir" style={{ marginTop: 6 }}>C:\Windows\Temp\</div>
            <div className={`fs-file ${fileStates.f5 === 'infected' ? 'infected' : ''}`}>
              &nbsp;&nbsp;payload.dll
            </div>
            <div className={`fs-file ${fileStates.f6 === 'infected' ? 'infected' : ''}`}>
              &nbsp;&nbsp;svchost_fake.exe
            </div>
            <div className="fs-dir" style={{ marginTop: 6 }}>C:\ProgramData\</div>
            <div className={`fs-file ${fileStates.f7 === 'infected' ? 'infected' : ''}`}>
              &nbsp;&nbsp;startup_inject.bat
            </div>
          </div>
          <div className="section-divider" />
          <div className="f9 text-dim">FILE OPERATIONS</div>
          <div style={{ fontSize: 9, lineHeight: 1.7, marginTop: 4, height: 50, overflow: 'hidden' }}>
            {fileOpLog.map((op, i) => (
              <div key={i} style={{ color: op.color }}>{op.msg}</div>
            ))}
          </div>
        </div>

        {/* Pane 3: Network exfil */}
        <div className="sim-pane">
          <div className="f9 text-dim" style={{ marginBottom: 6 }}>► NETWORK EXFILTRATION</div>
          <canvas
            ref={canvasRef}
            style={{ width: '100%', height: 130, display: 'block', background: '#00060f', border: '1px solid rgba(0,245,255,0.1)', marginBottom: 6 }}
          />
          <div style={{ fontSize: 9, lineHeight: 1.8 }}>
            {exfilLog.map((e, i) => (
              <div key={i} style={{ color: e.color }}>{e.msg}</div>
            ))}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="sim-controls">
        <button
          className="hud-btn"
          style={{ width: 'auto', padding: '8px 16px', fontSize: 9 }}
          onClick={running ? stopSim : startSim}
        >
          {running ? '■ STOP SIMULATION' : '▶ RUN SIMULATION'}
        </button>
        <div className="sim-label">SIMULATION PROGRESS</div>
        <div className="sim-progress-outer">
          <div className="sim-progress-inner" style={{ width: `${progress}%` }} />
        </div>
        <div className="sim-label">{phaseLabel}</div>
      </div>
    </Panel>
  );
}
