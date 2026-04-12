/**
 * SecureVault — Application Logic
 * Handles UI, state, and orchestrates crypto operations
 */

"use strict";

// ── State ────────────────────────────────────────────────────────────────────

const state = {
  mode: 'encrypt',   // 'encrypt' | 'decrypt'
  selectedFile: null,        // File object
  resultBlob: null,        // Blob of processed output
  outputName: '',          // Output filename
  processing: false
};

// ── Mode Switching ────────────────────────────────────────────────────────────

function switchMode(mode) {
  if (state.processing) return;
  state.mode = mode;

  const encBtn = document.getElementById('encryptModeBtn');
  const decBtn = document.getElementById('decryptModeBtn');
  const slider = document.getElementById('modeSlider');
  const confirmW = document.getElementById('confirmWrap');
  const btnText = document.getElementById('btnText');
  const btnIcon = document.getElementById('btnIcon');
  const stepName3 = document.getElementById('stepName3');
  const stepName4 = document.getElementById('stepName4');
  const stepDesc4 = document.getElementById('stepDesc4');

  if (mode === 'encrypt') {
    encBtn.classList.add('active');
    decBtn.classList.remove('active');
    slider.classList.remove('right');
    confirmW.classList.remove('hidden');
    btnText.textContent = 'Encrypt File';
    btnIcon.innerHTML = `<rect x="3" y="11" width="18" height="11" rx="2" stroke="currentColor" stroke-width="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`;
    stepName3.textContent = 'Key Derivation';
    stepName4.textContent = 'AES-256-GCM Encrypt';
    stepDesc4.textContent = 'Encrypt file data';
  } else {
    decBtn.classList.add('active');
    encBtn.classList.remove('active');
    slider.classList.add('right');
    confirmW.classList.add('hidden');
    btnText.textContent = 'Decrypt File';
    btnIcon.innerHTML = `<rect x="3" y="11" width="18" height="11" rx="2" stroke="currentColor" stroke-width="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`;
    stepName3.textContent = 'Key Derivation';
    stepName4.textContent = 'AES-256-GCM Decrypt';
    stepDesc4.textContent = 'Decrypt & verify auth tag';
  }

  // Reset steps & result
  resetSteps();
  hideResult();
}

// ── File Handling ─────────────────────────────────────────────────────────────

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('folderTrigger').classList.add('drag-over');
}

function handleDragLeave(e) {
  document.getElementById('folderTrigger').classList.remove('drag-over');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('folderTrigger').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) loadFile(file);
  // Reset so same file can be reselected
  e.target.value = '';
}

function loadFile(file) {
  state.selectedFile = file;

  const folderTrigger = document.getElementById('folderTrigger');
  const fileSelected  = document.getElementById('fileSelected');
  const fileName      = document.getElementById('fileName');
  const fileMeta      = document.getElementById('fileMeta');

  fileName.textContent = file.name;
  fileMeta.textContent = `${formatBytes(file.size)} · ${file.type || 'application/octet-stream'}`;

  folderTrigger.classList.add('hidden');
  fileSelected.classList.remove('hidden');

  markStepDone(1);
  hideResult();
}

function removeFile(e) {
  if (e) e.stopPropagation();
  state.selectedFile = null;

  const folderTrigger = document.getElementById('folderTrigger');
  const fileSelected  = document.getElementById('fileSelected');

  folderTrigger.classList.remove('hidden');
  fileSelected.classList.add('hidden');

  resetStep(1);
  hideResult();
}

// ── Password Strength ─────────────────────────────────────────────────────────

function updatePasswordStrength() {
  const pw = document.getElementById('passwordInput').value;
  const bar = document.getElementById('strengthFill');
  const lbl = document.getElementById('strengthLabel');

  // Check requirements
  const reqs = {
    len: pw.length >= 8,
    upper: /[A-Z]/.test(pw),
    num: /[0-9]/.test(pw),
    sym: /[^A-Za-z0-9]/.test(pw)
  };

  updateReq('req-len', reqs.len);
  updateReq('req-upper', reqs.upper);
  updateReq('req-num', reqs.num);
  updateReq('req-sym', reqs.sym);

  const score = Object.values(reqs).filter(Boolean).length;

  bar.className = 'strength-fill';
  if (pw.length === 0) { lbl.textContent = 'Enter password'; return; }

  const levels = ['', 'weak', 'fair', 'good', 'strong'];
  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  bar.classList.add(levels[score]);
  lbl.textContent = labels[score];

  // Mark step 2 done when at least "fair"
  if (score >= 2) markStepDone(2);
  else resetStep(2);

  checkConfirm();
}

function updateReq(id, met) {
  const el = document.getElementById(id);
  if (met) el.classList.add('met');
  else el.classList.remove('met');
}

function checkConfirm() {
  if (state.mode !== 'encrypt') return;
  const pw = document.getElementById('passwordInput').value;
  const cpw = document.getElementById('confirmInput').value;
  const ind = document.getElementById('confirmIndicator');
  const msg = document.getElementById('confirmMsg');

  if (cpw.length === 0) {
    ind.className = 'confirm-indicator';
    msg.classList.add('hidden');
    return;
  }
  if (pw === cpw) {
    ind.className = 'confirm-indicator match';
    msg.classList.add('hidden');
  } else {
    ind.className = 'confirm-indicator mismatch';
    msg.classList.remove('hidden');
  }
}

function togglePassword() {
  const input = document.getElementById('passwordInput');
  input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Steps UI ──────────────────────────────────────────────────────────────────

function setStepState(n, state) {
  // state: 'pending' | 'active' | 'processing' | 'done'
  const el = document.getElementById(`step-${n}`);
  const wait = el.querySelector('.step-icon-wait');
  const done = el.querySelector('.step-icon-done');
  const spinner = el.querySelector('.step-spinner');

  el.className = 'step-item';
  wait.classList.add('hidden');
  done.classList.add('hidden');
  spinner.classList.add('hidden');

  if (state === 'active') {
    el.classList.add('active');
    wait.classList.remove('hidden');
  } else if (state === 'processing') {
    el.classList.add('active');
    spinner.classList.remove('hidden');
  } else if (state === 'done') {
    el.classList.add('done');
    done.classList.remove('hidden');
  } else {
    // pending
    wait.classList.remove('hidden');
  }
}

function markStepDone(n) { setStepState(n, 'done'); }
function markStepProcessing(n) { setStepState(n, 'processing'); }
function markStepActive(n) { setStepState(n, 'active'); }

function resetStep(n) {
  const el = document.getElementById(`step-${n}`);
  const wait = el.querySelector('.step-icon-wait');
  const done = el.querySelector('.step-icon-done');
  const spinner = el.querySelector('.step-spinner');

  el.className = 'step-item';
  wait.classList.remove('hidden');
  done.classList.add('hidden');
  spinner.classList.add('hidden');

  if (n === 1) el.classList.add('active');
}

function resetSteps() {
  for (let i = 1; i <= 5; i++) resetStep(i);
  document.getElementById('step-1').classList.add('active');
}

// ── Log Entries ───────────────────────────────────────────────────────────────

const logColors = { info: 'info', success: 'success', error: 'error' };

function addLog(msg, type = 'info') {
  const entries = document.getElementById('logEntries');
  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(now.getMilliseconds()).padStart(3, '0')}`;

  const dots = { info: '→', success: '✓', error: '✗' };

  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.innerHTML = `
    <span class="log-time">${ts}</span>
    <span class="log-dot">${dots[type]}</span>
    <span class="log-msg">${msg}</span>
  `;
  entries.appendChild(entry);
  entries.scrollTop = entries.scrollHeight;
}

function clearLog() {
  document.getElementById('logEntries').innerHTML = '';
}

// ── Result Panel ──────────────────────────────────────────────────────────────

function showResultProcessing() {
  const panel = document.getElementById('resultPanel');
  const spinner = document.getElementById('resultSpinner');
  const check = document.getElementById('resultCheck');
  const errIcon = document.getElementById('resultErrorIcon');
  const title = document.getElementById('resultTitle');
  const sub = document.getElementById('resultSub');
  const dlSec = document.getElementById('downloadSection');
  const icon = document.getElementById('resultIcon');

  panel.className = 'result-panel';
  icon.style.background = 'rgba(99,102,241,0.1)';
  icon.style.borderColor = 'rgba(99,102,241,0.25)';
  spinner.classList.remove('hidden');
  check.classList.add('hidden');
  errIcon.classList.add('hidden');
  dlSec.classList.add('hidden');
  panel.classList.remove('hidden');

  title.textContent = state.mode === 'encrypt' ? 'Encrypting file...' : 'Decrypting file...';
  sub.textContent = 'Processing — please wait';

  clearLog();
}

function showResultSuccess(outputName, inputSize, outputSize) {
  const spinner = document.getElementById('resultSpinner');
  const check = document.getElementById('resultCheck');
  const title = document.getElementById('resultTitle');
  const sub = document.getElementById('resultSub');
  const dlSec = document.getElementById('downloadSection');
  const dlBtn = document.getElementById('downloadFileName');
  const resultStats = document.getElementById('resultStats');
  const panel = document.getElementById('resultPanel');
  const icon = document.getElementById('resultIcon');

  spinner.classList.add('hidden');
  check.classList.remove('hidden');
  panel.classList.add('success');
  icon.style.background = 'rgba(45,212,191,0.1)';
  icon.style.borderColor = 'rgba(45,212,191,0.3)';

  title.textContent = state.mode === 'encrypt' ? '🔒 File Encrypted Successfully!' : '🔓 File Decrypted Successfully!';
  sub.textContent = `Your file is ready for download`;

  dlBtn.textContent = `Download: ${outputName}`;

  resultStats.innerHTML = `
    <div class="stat-item"><div class="stat-label">Input Size</div><div class="stat-value">${formatBytes(inputSize)}</div></div>
    <div class="stat-item"><div class="stat-label">Output Size</div><div class="stat-value">${formatBytes(outputSize)}</div></div>
    <div class="stat-item"><div class="stat-label">Algorithm</div><div class="stat-value">AES-256-GCM</div></div>
    <div class="stat-item"><div class="stat-label">Key Derivation</div><div class="stat-value">PBKDF2·310k</div></div>
  `;

  dlSec.classList.remove('hidden');
}

function showResultError(errMsg) {
  const spinner = document.getElementById('resultSpinner');
  const errIcon = document.getElementById('resultErrorIcon');
  const title = document.getElementById('resultTitle');
  const sub = document.getElementById('resultSub');
  const panel = document.getElementById('resultPanel');
  const icon = document.getElementById('resultIcon');

  spinner.classList.add('hidden');
  errIcon.classList.remove('hidden');
  panel.classList.add('error');
  icon.style.background = 'rgba(255,80,80,0.1)';
  icon.style.borderColor = 'rgba(255,80,80,0.3)';

  title.textContent = '❌ Operation Failed';
  sub.textContent = errMsg;

  addLog(errMsg, 'error');
}

function hideResult() {
  document.getElementById('resultPanel').classList.add('hidden');
}

// ── Main Process ───────────────────────────────────────────────────────────────

async function processFile() {
  if (state.processing) return;

  const file = state.selectedFile;
  const password = document.getElementById('passwordInput').value;
  const confirm = document.getElementById('confirmInput').value;

  // Validation
  if (!file) {
    shakeElement('dropZone');
    addLog('No file selected', 'error');
    return;
  }
  if (!password) {
    shakeElement('passwordInput');
    document.getElementById('passwordInput').focus();
    return;
  }
  if (state.mode === 'encrypt' && password !== confirm) {
    shakeElement('confirmInput');
    document.getElementById('confirmMsg').classList.remove('hidden');
    return;
  }

  // UI → processing state
  state.processing = true;
  setActionBtnState(true);
  showResultProcessing();

  try {
    const fileBuffer = await file.arrayBuffer();
    const outputName = getOutputFilename(file.name, state.mode);

    if (state.mode === 'encrypt') {
      await runEncrypt(fileBuffer, password, file, outputName);
    } else {
      await runDecrypt(fileBuffer, password, file, outputName);
    }

  } catch (err) {
    showResultError(err.message || 'Unknown error');
    resetStepsOnError();
  } finally {
    state.processing = false;
    setActionBtnState(false);
  }
}

async function runEncrypt(fileBuffer, password, file, outputName) {
  // Steps 3 & 4: Key derivation + encrypt
  markStepProcessing(3);

  let stepPhase = 'keyDerive';

  const result = await encryptFile(fileBuffer, password, (phase, msg) => {
    if (phase !== stepPhase) {
      if (stepPhase === 'keyDerive' || stepPhase === 'saltGen') {
        // key derivation done, move to step 4
        if (phase === 'ivGen' || phase === 'encrypt') {
          markStepDone(3);
          markStepProcessing(4);
          stepPhase = 'encrypt';
        }
      } else if (stepPhase === 'encrypt') {
        stepPhase = phase;
      }
    }

    const type = phase === 'encrypt' ? 'info' : (phase === 'package' ? 'success' : 'info');
    addLog(`[${phase.toUpperCase()}] ${msg}`, type);
  });

  markStepDone(3);
  markStepDone(4);

  // Finalize
  addLog(`Output ready: ${outputName} (${formatBytes(result.encrypted.byteLength)})`, 'success');
  markStepDone(5);

  // Store result
  state.resultBlob = new Blob([result.encrypted], { type: 'application/octet-stream' });
  state.outputName = outputName;

  showResultSuccess(outputName, fileBuffer.byteLength, result.encrypted.byteLength);
}

async function runDecrypt(fileBuffer, password, file, outputName) {
  markStepProcessing(3);
  let stepPhase = 'validate';

  const result = await decryptFile(fileBuffer, password, (phase, msg) => {
    if (phase === 'keyDerive' && stepPhase !== 'keyDerive') {
      markStepDone(3);
      markStepProcessing(4);
      stepPhase = 'decrypt';
    } else if (phase === 'decrypt' && stepPhase !== 'decrypt') {
      stepPhase = 'decrypt';
    }

    const type = phase === 'decrypt' ? 'success' : 'info';
    addLog(`[${phase.toUpperCase()}] ${msg}`, type);
  });

  markStepDone(3);
  markStepDone(4);

  addLog(`Output ready: ${outputName} (${formatBytes(result.decrypted.byteLength)})`, 'success');
  markStepDone(5);

  state.resultBlob = new Blob([result.decrypted], { type: 'application/octet-stream' });
  state.outputName = outputName;

  showResultSuccess(outputName, fileBuffer.byteLength, result.decrypted.byteLength);
}

// ── Download ──────────────────────────────────────────────────────────────────

function downloadResult() {
  if (!state.resultBlob) return;
  const url = URL.createObjectURL(state.resultBlob);
  const a = document.createElement('a');
  a.href = url;
  a.download = state.outputName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);

  addLog(`File download initiated: ${state.outputName}`, 'success');
}

// ── Reset ─────────────────────────────────────────────────────────────────────

function resetAll() {
  state.selectedFile = null;
  state.resultBlob = null;
  state.outputName = '';

  // Reset file zone
  document.getElementById('folderTrigger').classList.remove('hidden');
  document.getElementById('fileSelected').classList.add('hidden');

  // Reset passwords
  document.getElementById('passwordInput').value = '';
  document.getElementById('confirmInput').value = '';
  document.getElementById('strengthFill').className = 'strength-fill';
  document.getElementById('strengthLabel').textContent = 'Enter password';
  document.getElementById('confirmIndicator').className = 'confirm-indicator';
  document.getElementById('confirmMsg').classList.add('hidden');
  ['req-len', 'req-upper', 'req-num', 'req-sym'].forEach(id => {
    document.getElementById(id).classList.remove('met');
  });

  resetSteps();
  hideResult();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function setActionBtnState(disabled) {
  const btn = document.getElementById('actionBtn');
  const content = document.getElementById('btnContent');
  const spinner = document.getElementById('btnSpinner');

  btn.disabled = disabled;
  if (disabled) {
    content.classList.add('hidden');
    spinner.classList.remove('hidden');
  } else {
    content.classList.remove('hidden');
    spinner.classList.add('hidden');
  }
}

function resetStepsOnError() {
  // Keep step 1 and 2 as done if they were
  for (let i = 3; i <= 5; i++) resetStep(i);
}

function shakeElement(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.animation = 'none';
  el.offsetHeight; // reflow
  el.style.animation = 'shake 0.4s cubic-bezier(0.4,0,0.2,1)';
  setTimeout(() => el.style.animation = '', 500);
}

// Add shake keyframes dynamically
(function addShakeKeyframe() {
  const style = document.createElement('style');
  style.textContent = `
    @keyframes shake {
      0%,100% { transform: translateX(0); }
      20%      { transform: translateX(-8px); }
      40%      { transform: translateX(8px); }
      60%      { transform: translateX(-6px); }
      80%      { transform: translateX(6px); }
    }
  `;
  document.head.appendChild(style);
})();

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Keyboard shortcut: Enter to process when not in textarea
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      processFile();
    }
  });

  // Prevent default drag on body
  document.body.addEventListener('dragover', e => e.preventDefault());
  document.body.addEventListener('drop', e => e.preventDefault());

  console.log('%c SecureVault Ready ', 'background:#6366f1;color:white;font-weight:bold;font-size:14px;padding:4px 8px;border-radius:4px;');
  console.log('%c AES-256-GCM + PBKDF2(310k) + SHA-256 ', 'color:#6ee7f7;font-family:monospace;');

  // PWA Service Worker Registration
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js')
      .then(reg => console.log('Service Worker registered', reg))
      .catch(err => console.error('Service Worker registration failed', err));
  }
});

// ══════════════════════════════════════════════════════════════════
//  FOLDER WINDOW MODULE
// ══════════════════════════════════════════════════════════════════

const fwState = {
  view: 'grid',            // 'grid' | 'list'
  currentPath: 'Desktop',
  selectedFile: null,      // virtual or real File object
  pendingRealFile: null,   // real File from drop inside window
  history: ['Desktop'],
  historyIdx: 0
};

// Virtual file system for demo purposes
const virtualFS = {
  Desktop: [
    { name: 'Documents', type: 'folder', size: null, date: '4/10/2026' },
    { name: 'report_Q1.pdf', type: 'pdf', size: 2457600, date: '4/11/2026' },
    { name: 'backup.zip',    type: 'zip', size: 18340000, date: '4/8/2026' },
    { name: 'photo.jpg',     type: 'image', size: 3145728, date: '4/12/2026' },
    { name: 'notes.txt',     type: 'text', size: 4096, date: '4/9/2026' },
    { name: 'project.docx',  type: 'word', size: 512000, date: '3/28/2026' },
    { name: 'data.xlsx',     type: 'excel', size: 256000, date: '4/1/2026' },
    { name: 'archive.tar',   type: 'zip', size: 9437184, date: '3/22/2026' },
    { name: 'script.py',     type: 'code', size: 8192, date: '4/5/2026' },
    { name: 'video.mp4',     type: 'video', size: 157286400, date: '4/3/2026' },
  ],
  Documents: [
    { name: 'contract.pdf', type: 'pdf', size: 1048576, date: '3/15/2026' },
    { name: 'resume.docx',  type: 'word', size: 77824, date: '4/2/2026' },
    { name: 'taxes.xlsx',   type: 'excel', size: 204800, date: '3/31/2026' },
    { name: 'notes.txt',    type: 'text', size: 2048, date: '4/10/2026' },
  ],
  Downloads: [
    { name: 'installer.exe', type: 'exe', size: 67108864, date: '4/7/2026' },
    { name: 'ebook.pdf',     type: 'pdf', size: 5242880, date: '4/6/2026' },
    { name: 'music.mp3',     type: 'audio', size: 8388608, date: '4/4/2026' },
  ],
  Pictures: [
    { name: 'vacation.jpg',  type: 'image', size: 4194304, date: '3/20/2026' },
    { name: 'portrait.png',  type: 'image', size: 2097152, date: '4/1/2026' },
    { name: 'wallpaper.jpg', type: 'image', size: 6291456, date: '3/25/2026' },
  ],
  LocalDisk: [
    { name: 'Users',   type: 'folder', size: null, date: '1/1/2026' },
    { name: 'Windows', type: 'folder', size: null, date: '1/1/2026' },
    { name: 'Program Files', type: 'folder', size: null, date: '1/1/2026' },
  ]
};

const fileTypeColors = {
  pdf:   { fill: 'rgba(239,68,68,0.3)',   stroke: 'rgba(239,68,68,0.8)',   label: '#ef4444' },
  zip:   { fill: 'rgba(245,158,11,0.3)',  stroke: 'rgba(245,158,11,0.8)',  label: '#f59e0b' },
  image: { fill: 'rgba(16,185,129,0.3)',  stroke: 'rgba(16,185,129,0.8)',  label: '#10b981' },
  text:  { fill: 'rgba(99,102,241,0.3)',  stroke: 'rgba(99,102,241,0.8)',  label: '#6366f1' },
  word:  { fill: 'rgba(37,99,235,0.3)',   stroke: 'rgba(37,99,235,0.8)',   label: '#2563eb' },
  excel: { fill: 'rgba(34,197,94,0.3)',   stroke: 'rgba(34,197,94,0.8)',   label: '#22c55e' },
  code:  { fill: 'rgba(168,85,247,0.3)',  stroke: 'rgba(168,85,247,0.8)',  label: '#a855f7' },
  video: { fill: 'rgba(236,72,153,0.3)',  stroke: 'rgba(236,72,153,0.8)',  label: '#ec4899' },
  audio: { fill: 'rgba(251,146,60,0.3)',  stroke: 'rgba(251,146,60,0.8)',  label: '#fb923c' },
  exe:   { fill: 'rgba(156,163,175,0.3)', stroke: 'rgba(156,163,175,0.8)', label: '#9ca3af' },
  folder:{ fill: 'rgba(99,102,241,0.25)', stroke: 'rgba(99,102,241,0.6)',  label: '#6366f1' },
};

function getFileExt(name) {
  const dot = name.lastIndexOf('.');
  return dot !== -1 ? name.slice(dot + 1).toLowerCase() : '';
}

function inferType(entry) {
  if (entry.type === 'folder') return 'folder';
  const ext = getFileExt(entry.name);
  if (['jpg','jpeg','png','gif','webp','svg'].includes(ext)) return 'image';
  if (['mp4','mov','avi','mkv'].includes(ext)) return 'video';
  if (['mp3','wav','flac','aac'].includes(ext)) return 'audio';
  if (['zip','tar','gz','rar','7z'].includes(ext)) return 'zip';
  if (['pdf'].includes(ext)) return 'pdf';
  if (['doc','docx'].includes(ext)) return 'word';
  if (['xls','xlsx'].includes(ext)) return 'excel';
  if (['py','js','ts','html','css','json','sh'].includes(ext)) return 'code';
  if (['exe','msi'].includes(ext)) return 'exe';
  if (['txt','md','log'].includes(ext)) return 'text';
  return 'text';
}

function makeFileSVG(type, size = 44) {
  if (type === 'folder') {
    const c = fileTypeColors.folder;
    return `<svg width="${size}" height="${size * 0.8}" viewBox="0 0 56 44" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M4 10a3 3 0 0 1 3-3h12l5 5h25a3 3 0 0 1 3 3v22a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3V10z" fill="${c.fill}" stroke="${c.stroke}" stroke-width="2"/>
      <path d="M4 14h48" stroke="${c.stroke}" stroke-width="1.5" opacity="0.5"/>
    </svg>`;
  }
  const c = fileTypeColors[type] || fileTypeColors.text;
  const hs = size * 0.9;
  return `<svg width="${hs * 0.7}" height="${hs}" viewBox="0 0 28 36" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M18 2H6C4.3 2 3 3.3 3 5v26c0 1.7 1.3 3 3 3h16c1.7 0 3-1.3 3-3V10L18 2z" fill="${c.fill}" stroke="${c.stroke}" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M18 2v8h8" stroke="${c.stroke}" stroke-width="1.5" stroke-linejoin="round"/>
    <text x="14" y="26" text-anchor="middle" fill="${c.label}" font-size="7" font-weight="800" font-family="monospace">${getFileExt(type === 'text' ? '.txt' : type.toUpperCase()) || type.slice(0,3).toUpperCase()}</text>
  </svg>`;
}

function makeFileSVGFromExt(name, size = 44) {
  const t = inferType({ name, type: 'file' });
  if (t === 'folder') return makeFileSVG('folder', size);
  const c = fileTypeColors[t] || fileTypeColors.text;
  const ext = getFileExt(name).toUpperCase().slice(0, 4) || t.slice(0,3).toUpperCase();
  const hs = size * 0.9;
  return `<svg width="${hs * 0.7}" height="${hs}" viewBox="0 0 28 36" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M18 2H6C4.3 2 3 3.3 3 5v26c0 1.7 1.3 3 3 3h16c1.7 0 3-1.3 3-3V10L18 2z" fill="${c.fill}" stroke="${c.stroke}" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M18 2v8h8" stroke="${c.stroke}" stroke-width="1.5" stroke-linejoin="round"/>
    <text x="14" y="26" text-anchor="middle" fill="${c.label}" font-size="7" font-weight="800" font-family="monospace">${ext}</text>
  </svg>`;
}

function openFolderWindow() {
  const overlay = document.getElementById('folderWindowOverlay');
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
  fwState.selectedFile = null;
  fwState.pendingRealFile = null;
  fwRenderFiles();
  fwUpdateStatus();
  document.getElementById('fwSearch').value = '';
}

function closeFolderWindow() {
  document.getElementById('folderWindowOverlay').classList.remove('open');
  document.body.style.overflow = '';
}

function closeFolderWindowOnBackdrop(e) {
  if (e.target === document.getElementById('folderWindowOverlay')) {
    closeFolderWindow();
  }
}

function fwNavTo(path) {
  if (!virtualFS[path]) return;
  // Trim future history if navigated back
  fwState.history = fwState.history.slice(0, fwState.historyIdx + 1);
  fwState.history.push(path);
  fwState.historyIdx = fwState.history.length - 1;
  fwState.currentPath = path;
  fwState.selectedFile = null;
  fwState.pendingRealFile = null;
  document.getElementById('fwSearch').value = '';

  // Sidebar highlight
  document.querySelectorAll('.fw-sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.path === path);
  });

  // Breadcrumb
  fwUpdateBreadcrumb(path);
  fwRenderFiles();
  fwUpdateStatus();
  fwUpdateNavBtns();
}

function fwUpdateBreadcrumb(path) {
  const crumb = document.querySelector('.fw-crumb.active');
  if (crumb) {
    crumb.textContent = path === 'LocalDisk' ? 'Local Disk (C:)' : path;
    crumb.dataset.path = path;
  }
}

function fwUpdateNavBtns() {
  document.getElementById('fwBackBtn').disabled = fwState.historyIdx <= 0;
  document.getElementById('fwFwdBtn').disabled = fwState.historyIdx >= fwState.history.length - 1;
}

document.getElementById('fwBackBtn').addEventListener('click', () => {
  if (fwState.historyIdx > 0) {
    fwState.historyIdx--;
    const path = fwState.history[fwState.historyIdx];
    fwState.currentPath = path;
    fwState.selectedFile = null;
    fwUpdateBreadcrumb(path);
    fwRenderFiles();
    fwUpdateStatus();
    fwUpdateNavBtns();
  }
});

document.getElementById('fwFwdBtn').addEventListener('click', () => {
  if (fwState.historyIdx < fwState.history.length - 1) {
    fwState.historyIdx++;
    const path = fwState.history[fwState.historyIdx];
    fwState.currentPath = path;
    fwState.selectedFile = null;
    fwUpdateBreadcrumb(path);
    fwRenderFiles();
    fwUpdateStatus();
    fwUpdateNavBtns();
  }
});

function fwRenderFiles(filter = '') {
  const container = document.getElementById('fwFilesContainer');
  const entries = virtualFS[fwState.currentPath] || [];
  const q = filter.toLowerCase();
  const filtered = q ? entries.filter(e => e.name.toLowerCase().includes(q)) : entries;

  container.className = `fw-files-container ${fwState.view}-view`;
  container.innerHTML = '';

  if (filtered.length === 0) {
    container.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--text-subtle);font-size:13px;">No files found</div>`;
    return;
  }

  filtered.forEach(entry => {
    const t = entry.type === 'folder' ? 'folder' : inferType(entry);
    const isFolder = t === 'folder';
    const el = document.createElement('div');
    el.className = `fw-file-item${isFolder ? ' fw-folder-item' : ''}`;
    el.dataset.name = entry.name;

    const iconHtml = makeFileSVG(t, fwState.view === 'grid' ? 44 : 22);

    if (fwState.view === 'grid') {
      el.innerHTML = `
        <div class="fw-file-icon">${iconHtml}</div>
        <div class="fw-file-name">${entry.name}</div>
      `;
    } else {
      el.innerHTML = `
        <div class="fw-file-icon">${iconHtml}</div>
        <div class="fw-file-name">${entry.name}</div>
        <div class="fw-file-type">${t.charAt(0).toUpperCase()+t.slice(1)}</div>
        <div class="fw-file-size">${isFolder ? '—' : formatBytes(entry.size)}</div>
        <div class="fw-file-date">${entry.date}</div>
      `;
    }

    el.addEventListener('click', () => {
      if (isFolder) {
        fwNavTo(entry.name);
        return;
      }
      container.querySelectorAll('.fw-file-item').forEach(i => i.classList.remove('selected'));
      el.classList.add('selected');
      fwState.selectedFile = entry;
      fwState.pendingRealFile = null;
      fwUpdateStatus(entry, false);
    });

    el.addEventListener('dblclick', () => {
      if (!isFolder) confirmFolderSelection();
    });

    container.appendChild(el);
  });
}

function filterFolderFiles() {
  fwRenderFiles(document.getElementById('fwSearch').value);
}

function setFwView(view) {
  fwState.view = view;
  document.getElementById('fwGridViewBtn').classList.toggle('active', view === 'grid');
  document.getElementById('fwListViewBtn').classList.toggle('active', view === 'list');
  fwRenderFiles(document.getElementById('fwSearch').value);
}

function fwUpdateStatus(entry = null, isReal = false) {
  const statusEl = document.getElementById('fwStatusLeft');
  const openBtn  = document.getElementById('fwOpenBtn');

  if (fwState.pendingRealFile) {
    statusEl.textContent = `🗂 Dropped: ${fwState.pendingRealFile.name} (${formatBytes(fwState.pendingRealFile.size)})`;
    openBtn.disabled = false;
  } else if (entry) {
    statusEl.textContent = `📄 ${entry.name} — ${formatBytes(entry.size)} · ${entry.date}`;
    openBtn.disabled = false;
  } else {
    statusEl.textContent = 'No item selected';
    openBtn.disabled = true;
  }
}

function confirmFolderSelection() {
  if (fwState.pendingRealFile) {
    loadFile(fwState.pendingRealFile);
    closeFolderWindow();
    return;
  }
  if (fwState.selectedFile) {
    // For virtual files: trigger the real file picker as a fallback
    // (browsers can't load virtual files)
    triggerRealFilePicker();
  }
}

function triggerRealFilePicker() {
  // Show a hint and trigger the actual picker
  closeFolderWindow();
  document.getElementById('fileInput').click();
}

// Drag-and-drop inside the folder window
function handleFwDragOver(e) {
  e.preventDefault();
  document.getElementById('fwDropzone').classList.add('fw-drag-active');
}
function handleFwDragLeave(e) {
  document.getElementById('fwDropzone').classList.remove('fw-drag-active');
}
function handleFwDrop(e) {
  e.preventDefault();
  document.getElementById('fwDropzone').classList.remove('fw-drag-active');
  const file = e.dataTransfer.files[0];
  if (file) {
    fwState.pendingRealFile = file;
    fwState.selectedFile = null;
    // Deselect any previously selected virtual file
    document.querySelectorAll('.fw-file-item').forEach(i => i.classList.remove('selected'));
    fwUpdateStatus(null, true);
  }
}

// Escape key closes window
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('folderWindowOverlay');
    if (overlay.classList.contains('open')) closeFolderWindow();
  }
});
