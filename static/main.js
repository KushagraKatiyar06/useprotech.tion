/* MalwareScope — frontend WebSocket client */
'use strict';

// ── DOM refs ────────────────────────────────────────────────────────────────
const dropZone     = document.getElementById('drop-zone');
const fileInput    = document.getElementById('file-input');
const filePreview  = document.getElementById('file-preview');
const fileNameEl   = document.getElementById('file-name');
const fileSizeEl   = document.getElementById('file-size');
const clearBtn     = document.getElementById('clear-btn');
const analyzeBtn   = document.getElementById('analyze-btn');
const uploadPanel  = document.getElementById('upload-panel');
const progressPanel = document.getElementById('progress-panel');
const reportPanel  = document.getElementById('report-panel');
const resetBtn     = document.getElementById('reset-btn');

let selectedFile = null;

// ── File selection ──────────────────────────────────────────────────────────
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});

function setFile(file) {
  selectedFile = file;
  fileNameEl.textContent = file.name;
  fileSizeEl.textContent = formatBytes(file.size);
  filePreview.classList.remove('hidden');
  dropZone.classList.add('hidden');
  analyzeBtn.disabled = false;
}

clearBtn.addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  filePreview.classList.add('hidden');
  dropZone.classList.remove('hidden');
  analyzeBtn.disabled = true;
});

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

// ── Analyze ─────────────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', startAnalysis);

async function startAnalysis() {
  if (!selectedFile) return;
  analyzeBtn.disabled = true;

  // Show progress panel
  uploadPanel.classList.add('hidden');
  progressPanel.classList.remove('hidden');
  reportPanel.classList.add('hidden');

  // Upload file
  const formData = new FormData();
  formData.append('file', selectedFile);

  let jobId;
  try {
    const res = await fetch('/upload', { method: 'POST', body: formData });
    if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
    const json = await res.json();
    jobId = json.job_id;
  } catch (err) {
    showError(`Upload error: ${err.message}`);
    return;
  }

  // Connect WebSocket
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/${jobId}`);

  ws.onmessage = e => {
    const event = JSON.parse(e.data);
    handleEvent(event);
  };

  ws.onerror = () => showError('WebSocket connection error.');
  ws.onclose = () => { /* normal close after done/error */ };
}

// ── Event handler ────────────────────────────────────────────────────────────
function handleEvent(ev) {
  const { event, status, message, data } = ev;

  switch (event) {

    case 'static_analysis':
      if (status === 'running') {
        setStage('static_analysis', 'running', message);
      } else if (status === 'complete') {
        setStage('static_analysis', 'complete', `Threat level: ${data.threat_level}`);
        showThreatBadge('static_analysis', data.threat_level);
        showStaticBody(data);
      }
      break;

    case 'pipeline_start':
      setStage('pipeline_start', 'complete', 'Metadata structured — starting AI agents');
      break;

    case 'ingestion':
      if (status === 'running') {
        setStage('ingestion', 'running', message);
      } else if (status === 'complete') {
        const flags = (data.suspicious_flags || []).length;
        setStage('ingestion', 'complete', `${flags} suspicious flags identified`);
        showIngestionBody(data);
      }
      break;

    case 'static_analysis_ai':   // reuse the parallel stage cards
    case 'static_analysis':
      if (status === 'running' && event === 'static_analysis') break; // already handled above
      if (status === 'running') {
        setParallelStage('static_analysis_ai', 'running', message);
      } else if (status === 'complete') {
        setParallelStage('static_analysis_ai', 'complete',
          `${data.malware_type} — severity ${data.severity}/10`);
        showAiStaticBody('static_analysis_ai', data);
      }
      break;

    case 'mitre_mapping':
      if (status === 'running') {
        setParallelStage('mitre_mapping_ai', 'running', message);
      } else if (status === 'complete') {
        const n = (data.techniques || []).length;
        setParallelStage('mitre_mapping_ai', 'complete', `${n} techniques mapped`);
        showMitreBody('mitre_mapping_ai', data);
      }
      break;

    case 'remediation':
      if (status === 'running') {
        setStage('remediation', 'running', message);
      } else if (status === 'complete') {
        const iocCount = (data.iocs_to_block || []).length;
        setStage('remediation', 'complete', `${iocCount} IOCs — confidence ${pct(data.confidence)}`);
        showRemediationBody(data);
      }
      break;

    case 'report':
      if (status === 'running') {
        setStage('report', 'running', message);
      } else if (status === 'complete') {
        setStage('report', 'complete', `Risk score: ${data.risk_score}/100`);
      }
      break;

    case 'done':
      renderReport(data);
      break;

    case 'error':
      showError(message || 'Unknown error');
      break;
  }
}

// ── Stage helpers ────────────────────────────────────────────────────────────
function setStage(stageId, status, msg) {
  const el   = document.getElementById(`stage-${stageId}`);
  const icon = document.getElementById(`icon-${stageId}`);
  const msgEl = document.getElementById(`msg-${stageId}`);
  if (!el) return;

  el.className = `stage ${status}`;
  if (icon) icon.textContent = status === 'running' ? '◌' : status === 'complete' ? '✓' : '✕';
  if (msgEl && msg) msgEl.textContent = msg;
}

function setParallelStage(stageId, status, msg) {
  // Parallel stages live inside .parallel-row; use same helper but correct IDs
  const el   = document.getElementById(`stage-${stageId}`);
  const msgEl = document.getElementById(`msg-${stageId}`);
  if (!el) return;
  el.className = `stage ${status}`;
  // icon IDs differ for parallel stages
  const iconKey = stageId === 'static_analysis_ai' ? 'static_analysis' : 'mitre_mapping';
  const icon = document.getElementById(`icon-${iconKey}`);
  if (icon) icon.textContent = status === 'running' ? '◌' : status === 'complete' ? '✓' : '✕';
  if (msgEl && msg) msgEl.textContent = msg;
}

function showThreatBadge(stageId, level) {
  const badge = document.getElementById(`badge-${stageId}`);
  if (!badge) return;
  badge.textContent = level;
  badge.className = `stage-badge badge-${level}`;
  badge.classList.remove('hidden');
}

function showBody(bodyId, html) {
  const el = document.getElementById(`body-${bodyId}`);
  if (!el) return;
  el.innerHTML = html;
  el.classList.remove('hidden');
}

// ── Stage body renderers ─────────────────────────────────────────────────────
function showStaticBody(d) {
  const behaviors = (d.behaviors || []).map(b => `<span class="tag">${esc(b)}</span>`).join('');
  const funcs     = (d.dangerous_functions || []).map(f => `<span class="tag ioc">${esc(f)}</span>`).join('');
  const mitre     = (d.mitre_techniques || []).map(m => `<span class="tag mitre">${esc(m)}</span>`).join('');
  showBody('static_analysis', `
    <div>Entropy: <strong>${d.entropy}</strong> &nbsp;|&nbsp; Obfuscated: <strong>${d.is_obfuscated ? 'Yes' : 'No'}</strong></div>
    ${behaviors ? `<div style="margin-top:.5rem;color:#5a6e88;font-size:.75rem">BEHAVIORS</div><div class="tag-list">${behaviors}</div>` : ''}
    ${funcs     ? `<div style="margin-top:.5rem;color:#5a6e88;font-size:.75rem">DANGEROUS FUNCTIONS</div><div class="tag-list">${funcs}</div>` : ''}
    ${mitre     ? `<div style="margin-top:.5rem;color:#5a6e88;font-size:.75rem">MITRE (static)</div><div class="tag-list">${mitre}</div>` : ''}
  `);
}

function showIngestionBody(d) {
  const flags = (d.suspicious_flags || []).map(f => `<span class="tag ioc">${esc(f)}</span>`).join('');
  showBody('ingestion', `
    <div>File: <strong>${esc(d.file_name || '—')}</strong> &nbsp;|&nbsp; SHA256: <code style="font-size:.72rem;color:#5a6e88">${esc((d.sha256 || '').slice(0, 16))}…</code></div>
    ${flags ? `<div class="tag-list" style="margin-top:.5rem">${flags}</div>` : ''}
  `);
}

function showAiStaticBody(bodyId, d) {
  showBody(bodyId, `
    <div><strong>${esc(d.malware_type || '—')}</strong></div>
    <div style="margin-top:.3rem;color:#5a6e88">${esc(d.likely_behavior || '')}</div>
    ${(d.obfuscation_techniques || []).length
      ? `<div class="tag-list" style="margin-top:.4rem">${d.obfuscation_techniques.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>`
      : ''}
  `);
}

function showMitreBody(bodyId, d) {
  const rows = (d.techniques || []).map(t =>
    `<div style="margin-bottom:.3rem"><span class="tag mitre">${esc(t.id)}</span> <span style="color:#d0daea">${esc(t.name)}</span> <span style="color:#5a6e88;font-size:.75rem">${esc(t.tactic)}</span></div>`
  ).join('');
  showBody(bodyId, rows || '<div>No techniques mapped</div>');
}

function showRemediationBody(d) {
  const iocs  = (d.iocs_to_block || []).map(i => `<span class="tag ioc">${esc(i)}</span>`).join('');
  const steps = (d.containment_steps || []).map((s, i) => `<div style="margin-bottom:.25rem"><span style="color:var(--accent);margin-right:.4rem">${i+1}.</span>${esc(s)}</div>`).join('');
  showBody('remediation', `
    ${iocs  ? `<div style="color:#5a6e88;font-size:.75rem;margin-bottom:.3rem">IOCs TO BLOCK</div><div class="tag-list">${iocs}</div>` : ''}
    ${steps ? `<div style="color:#5a6e88;font-size:.75rem;margin:0.5rem 0 .3rem">CONTAINMENT STEPS</div>${steps}` : ''}
  `);
}

// ── Final report ─────────────────────────────────────────────────────────────
function renderReport(full) {
  const r = full.report || {};

  // Risk score
  const score = r.risk_score || 0;
  document.getElementById('risk-score').textContent = score;
  document.getElementById('risk-score').style.color = riskColor(score);
  document.getElementById('risk-bar').style.width = score + '%';
  document.getElementById('risk-bar').style.background = riskColor(score);

  document.getElementById('exec-summary').textContent = r.executive_summary || '—';
  document.getElementById('val-malware-type').textContent = r.malware_type || '—';
  document.getElementById('val-confidence').textContent = r.confidence != null ? pct(r.confidence) : '—';

  // MITRE table
  const tbody = document.getElementById('mitre-tbody');
  tbody.innerHTML = (r.mitre_techniques || []).map(t => `
    <tr>
      <td><span class="mitre-id">${esc(t.id)}</span></td>
      <td>${esc(t.name)}</td>
      <td style="color:var(--muted)">${esc(t.tactic)}</td>
    </tr>`).join('') || '<tr><td colspan="3" style="color:var(--muted)">None identified</td></tr>';

  // IOCs
  document.getElementById('ioc-list').innerHTML =
    (r.iocs || []).map(i => `<li>${esc(i)}</li>`).join('') || '<li style="color:var(--muted)">None</li>';

  // YARA
  document.getElementById('yara-rule').textContent = r.yara_rule || '// No YARA rule generated';

  // Action plan
  document.getElementById('action-list').innerHTML =
    (r.action_plan || []).map(a => `
      <li>
        <div class="action-num">${a.priority || '•'}</div>
        <div class="action-text">${esc(a.action)}</div>
        <div class="urgency-tag urgency-${(a.urgency || 'medium').toLowerCase()}">${esc(a.urgency || 'medium')}</div>
      </li>`).join('') || '<li style="color:var(--muted);padding:.4rem">No actions defined</li>';

  progressPanel.classList.add('hidden');
  reportPanel.classList.remove('hidden');
}

// ── Utilities ────────────────────────────────────────────────────────────────
function showError(msg) {
  const el = document.createElement('div');
  el.style.cssText = 'background:rgba(232,80,58,.12);border:1px solid rgba(232,80,58,.4);color:#e8856a;border-radius:6px;padding:.8rem 1rem;margin-top:.8rem;font-size:.85rem;';
  el.textContent = '⚠ ' + msg;
  progressPanel.appendChild(el);
  analyzeBtn.disabled = false;
}

function riskColor(score) {
  if (score >= 80) return 'var(--red)';
  if (score >= 60) return 'var(--accent2)';
  if (score >= 40) return 'var(--yellow)';
  return 'var(--green)';
}

function pct(v) { return v != null ? (v * 100).toFixed(0) + '%' : '—'; }

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Reset ────────────────────────────────────────────────────────────────────
resetBtn.addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  filePreview.classList.add('hidden');
  dropZone.classList.remove('hidden');
  analyzeBtn.disabled = true;

  // Reset all stage classes + messages
  ['static_analysis','pipeline_start','ingestion','remediation','report'].forEach(id => {
    const el = document.getElementById(`stage-${id}`);
    if (el) el.className = 'stage';
    const icon = document.getElementById(`icon-${id}`);
    if (icon) icon.textContent = '○';
    const msg = document.getElementById(`msg-${id}`);
    if (msg) msg.textContent = 'Waiting...';
    const body = document.getElementById(`body-${id}`);
    if (body) { body.innerHTML = ''; body.classList.add('hidden'); }
    const badge = document.getElementById(`badge-${id}`);
    if (badge) { badge.className = 'stage-badge hidden'; badge.textContent = ''; }
  });

  ['static_analysis_ai','mitre_mapping_ai'].forEach(id => {
    const el = document.getElementById(`stage-${id}`);
    if (el) el.className = 'stage';
    const msg = document.getElementById(`msg-${id}`);
    if (msg) msg.textContent = 'Waiting...';
    const body = document.getElementById(`body-${id}`);
    if (body) { body.innerHTML = ''; body.classList.add('hidden'); }
  });

  reportPanel.classList.add('hidden');
  progressPanel.classList.add('hidden');
  uploadPanel.classList.remove('hidden');
});
