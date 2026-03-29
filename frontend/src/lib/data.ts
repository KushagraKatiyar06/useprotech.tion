export interface Process {
  name: string;
  pid: number;
  parent: string;
  color: 'green' | 'yellow' | 'red';
}

export interface LogEntry {
  sec: number;
  tag: 'info' | 'warn' | 'crit';
  cat: string;
  msg: string;
}

export interface Connection {
  ts: string;
  dir: 'IN' | 'OUT';
  dst: string;
  port: number;
  size: string;
  type: string;
}

export interface Finding {
  type: 'critical' | 'warn' | 'ok';
  label: string;
  text: string;
}

export const DEMO_PROCS: Process[] = [
  { name: 'invoice_q4.exe',        pid: 3822, parent: 'explorer.exe',    color: 'yellow' },
  { name: 'cmd.exe',               pid: 4120, parent: 'invoice_q4.exe',  color: 'red'    },
  { name: 'powershell.exe',        pid: 4821, parent: 'cmd.exe',         color: 'red'    },
  { name: 'svchost.exe',           pid: 1240, parent: 'services.exe',    color: 'green'  },
  { name: 'payload.dll (inject)',  pid: 4821, parent: 'svchost.exe',     color: 'red'    },
  { name: 'net.exe',               pid: 5003, parent: 'powershell.exe',  color: 'red'    },
  { name: 'vssadmin.exe',          pid: 5120, parent: 'powershell.exe',  color: 'red'    },
];

export const DEMO_LOGS: LogEntry[] = [
  { sec: 1,  tag: 'warn', cat: 'PROC', msg: 'invoice_q4.exe spawned cmd.exe (PID 4120) — suspicious child process' },
  { sec: 2,  tag: 'crit', cat: 'PROC', msg: 'cmd.exe spawned powershell.exe with -enc flag — obfuscated command' },
  { sec: 3,  tag: 'warn', cat: 'FILE', msg: 'WRITE: C:\\Windows\\Temp\\payload.dll (248KB)' },
  { sec: 4,  tag: 'crit', cat: 'FILE', msg: 'INJECT: payload.dll injected into svchost.exe (PID 1240)' },
  { sec: 5,  tag: 'crit', cat: 'NET',  msg: 'DNS query: c2-malnet-relay.ru — known C2 domain' },
  { sec: 6,  tag: 'crit', cat: 'NET',  msg: 'CONNECT: 185.220.101.47:443 (encrypted) — 14KB outbound' },
  { sec: 7,  tag: 'warn', cat: 'REG',  msg: 'WRITE: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — persistence' },
  { sec: 8,  tag: 'crit', cat: 'FILE', msg: 'CRYPTO: bulk file encryption starting (*.docx *.xlsx *.jpg)' },
  { sec: 9,  tag: 'crit', cat: 'PROC', msg: 'vssadmin.exe delete shadows /all — shadow copy deletion' },
  { sec: 10, tag: 'crit', cat: 'FILE', msg: 'DROP: C:\\Users\\victim\\Desktop\\RANSOM_NOTE.txt' },
];

export const DEMO_CONNS: Connection[] = [
  { ts: '00:12', dir: 'OUT', dst: '185.220.101.47',     port: 443, size: '14.2KB', type: 'C2 EXFIL'   },
  { ts: '00:13', dir: 'OUT', dst: '94.102.49.191',      port: 80,  size: '0.4KB',  type: 'C2 BEACON'  },
  { ts: '00:14', dir: 'OUT', dst: 'c2-malnet-relay.ru', port: 443, size: '8.1KB',  type: 'EXFIL DNS'  },
  { ts: '00:15', dir: 'IN',  dst: '185.220.101.47',     port: 443, size: '2.0KB',  type: 'PAYLOAD DL' },
];

export const ARCH_DETAILS: string[] = [
  '<span class="text-cyan">React Frontend</span><br/>File upload via drag-drop. Live WebSocket feed for logs. HUD-themed dashboard renders process tree, network graph, and AI report in real-time.<br/><br/><span class="text-dim">Stack: React 18 · Next.js · TailwindCSS · Socket.io-client</span>',
  '<span class="text-cyan">FastAPI Backend</span><br/>POST /analyze accepts multipart file. Writes to /tmp/sandbox/. Triggers VBoxManage to restore snapshot and start VM. Polls log collector. Calls Claude API with structured behavior JSON.<br/><br/><span class="text-dim">Stack: Python 3.11 · FastAPI · Celery · Redis</span>',
  '<span class="text-cyan">VirtualBox Sandbox</span><br/>Pre-configured Win10 snapshot. File copied via VBoxManage guestcontrol. Process Monitor (procmon) + Wireshark + inotifywait capture all activity. Snapshot restored after each run.<br/><br/><span class="text-dim">Stack: VirtualBox 7 · Procmon · WinPcap · Python agent</span>',
  '<span class="text-cyan">Log Collector</span><br/>Python agent inside VM exports JSON: {processes[], file_ops[], registry_ops[], network_conns[]}. Streamed to backend via host-only network adapter every 500ms.<br/><br/><span class="text-dim">Stack: Python psutil · scapy · watchdog · JSON streaming</span>',
  '<span class="text-cyan">Parser / Structurer</span><br/>Normalizes raw procmon CSV + pcap into unified BehaviorReport schema. Deduplicates, scores severity per operation, tags known-bad IOCs from local hash DB.<br/><br/><span class="text-dim">Stack: Python · pandas · pyshark · MITRE ATT&CK mapping</span>',
  '<span class="text-cyan">Claude AI Module</span><br/>Sends structured BehaviorReport + system prompt to Claude API. Prompt instructs: classify malware type, score risk 0–1, list key behaviors, explain reasoning, recommend mitigations. Returns JSON report.<br/><br/><span class="text-dim">Stack: Anthropic Python SDK · claude-sonnet-4-20250514 · Pydantic validation</span>',
];

export const DEMO_FINDINGS: Finding[] = [
  { type: 'critical', label: 'CRITICAL', text: 'vssadmin shadow deletion confirms ransomware behavior pattern' },
  { type: 'critical', label: 'CRITICAL', text: 'C2 connection to known malicious IP 185.220.101.47' },
  { type: 'warn',     label: 'WARNING',  text: 'Registry persistence via Run key — survives reboot' },
  { type: 'ok',       label: 'INFO',     text: 'No kernel-mode rootkit behavior detected' },
];

export const DEMO_MITIGATIONS: string[] = [
  '① Immediately isolate host from network',
  '② Block IP 185.220.101.47 at firewall',
  '③ Do NOT pay ransom — restore from backup',
  '④ Wipe & reinstall OS — do not trust remediation',
  '⑤ Hunt laterally for C2 beacons across fleet',
];

export const DEMO_REASONING =
  'The specimen exhibits a classic ransomware kill chain: initial execution → child process spawning with obfuscated PowerShell → DLL injection for stealth → shadow copy deletion to prevent recovery → mass encryption of user files → ransom note drop. C2 IP matches ThreatIntel feeds for LockBit 3.0 variant. Risk score 0.94 reflects confirmed destructive payload with active exfiltration.';

export const SIM_PHASES = [
  'PAYLOAD DEPLOY',
  'PROCESS INJECT',
  'FILE ENCRYPTION',
  'C2 EXFIL',
  'PERSISTENCE',
  'RANSOM DROP',
];

export const SIM_FILES = [
  { id: 'f1', path: 'Documents\\budget.xlsx' },
  { id: 'f2', path: 'Documents\\passwords.txt' },
  { id: 'f3', path: 'Pictures\\family.jpg' },
  { id: 'f4', path: 'Desktop\\work.docx' },
];

export const SIM_EXFILS = [
  { msg: '→ DNS exfil: victim_id.c2-malnet-relay.ru', color: 'var(--magenta)' },
  { msg: '→ HTTPS POST: 185.220.101.47:443 (passwords.txt)', color: 'var(--magenta)' },
  { msg: '→ Heartbeat beacon: 94.102.49.191:80', color: '#ffcc00' },
  { msg: '← Receive: encryption_key.bin (2KB)', color: '#00ff88' },
];
