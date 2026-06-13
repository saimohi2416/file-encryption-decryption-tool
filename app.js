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
  // Auto-correct mode based on file extension
  const isEncrypted = file.name.toLowerCase().endsWith('.enc');
  if (isEncrypted && state.mode !== 'decrypt') {
    switchMode('decrypt');
    addLog('Auto-switched to Decrypt mode (.enc file detected)', 'info');
  } else if (!isEncrypted && state.mode === 'decrypt') {
    switchMode('encrypt');
    addLog('Auto-switched to Encrypt mode (Standard file detected)', 'info');
  }

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
  const confirmInput = document.getElementById('confirmInput');
  const type = input.type === 'password' ? 'text' : 'password';
  input.type = type;
  if (confirmInput) confirmInput.type = type;
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
  // Handle Splash Screen Animation
  const splash = document.getElementById('splashScreen');
  if (splash) {
    if (sessionStorage.getItem('skipSplash') === '1') {
      // Came from splash.html — skip the built-in splash immediately
      sessionStorage.removeItem('skipSplash');
      splash.remove();
    } else {
      // Normal load — wait for the CSS progress bar animation (2.5s)
      setTimeout(() => {
        splash.classList.add('fade-out');
        setTimeout(() => splash.remove(), 600);
      }, 2500);
    }
  }

  // Check for Secure Context / Web Crypto API support
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    const warningBanner = document.getElementById('secureContextWarning');
    if (warningBanner) {
      warningBanner.classList.remove('hidden');
    }
  }

  // Keyboard shortcut: Enter to process when not in textarea
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      processFile();
    }
  });

  // Prevent default drag on body
  document.body.addEventListener('dragover', e => e.preventDefault());
  document.body.addEventListener('drop', e => e.preventDefault());

  // Suppress logs in production
  // console.log('%c SecureVault Ready ', '...');

  // PWA Service Worker & Manifest Registration
  if (window.location.protocol !== 'file:') {
    const link = document.createElement('link');
    link.rel = 'manifest';
    link.href = 'manifest.json';
    document.head.appendChild(link);

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./sw.js').catch(() => {});
    }
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
    const isSelected = (!isFolder && fwState.selectedFile && fwState.selectedFile.name === entry.name);
    
    const el = document.createElement('div');
    el.className = `fw-file-item${isFolder ? ' fw-folder-item' : ''}${isSelected ? ' selected' : ''}`;
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

// ══════════════════════════════════════════════════════════════════
//  CYBER SUITE DASHBOARD LOGIC
// ══════════════════════════════════════════════════════════════════

function switchTab(tabId, e) {
  if (e) e.preventDefault();
  
  // Update Nav Items
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById('tabBtn-' + tabId).classList.add('active');

  // Update Contents
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.getElementById('content-' + tabId).classList.add('active');

  // Update Topbar Title
  const titles = {
    'vault': 'Dashboard / File Vault',
    'firewall': 'Dashboard / Enterprise Secure Firewall',
    'cases': 'Dashboard / Cyber Cases Log',
    'ledger': 'Dashboard / Unified File Ledger',
    'ai': 'Dashboard / AI Security Copilot'
  };
  document.getElementById('topbarTitle').textContent = titles[tabId];

  if (tabId === 'firewall') initFirewallData();
  if (tabId === 'cases') initCasesData();
  if (tabId === 'ledger') initLedgerData();
}

function initFirewallData() {
  const tbody = document.getElementById('firewallTableBody');
  if (tbody.children.length > 0) return; // already initialized

  const connections = [
    { proto: 'TCP', local: '192.168.1.105:443', foreign: '104.21.45.120:443', state: 'ESTABLISHED', action: 'ALLOW' },
    { proto: 'TCP', local: '192.168.1.105:22', foreign: '45.33.22.11:54321', state: 'SYN_RECV', action: 'BLOCK' },
    { proto: 'UDP', local: '0.0.0.0:53', foreign: '8.8.8.8:53', state: 'LISTENING', action: 'ALLOW' },
    { proto: 'TCP', local: '127.0.0.1:8080', foreign: '127.0.0.1:52134', state: 'ESTABLISHED', action: 'ALLOW' },
    { proto: 'TCP', local: '192.168.1.105:80', foreign: '185.15.22.1:80', state: 'TIME_WAIT', action: 'DROP' }
  ];

  connections.forEach(c => {
    const tr = document.createElement('tr');
    const badge = c.action === 'ALLOW' ? 'bg-success-subtle' : 'bg-danger-subtle';
    tr.innerHTML = `
      <td>${c.proto}</td>
      <td style="font-family:monospace; color:var(--text);">${c.local}</td>
      <td style="font-family:monospace; color:var(--text-muted);">${c.foreign}</td>
      <td>${c.state}</td>
      <td><span class="badge-status ${badge}">${c.action}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

let caseCounter = 1042;
function initCasesData() {
  const tbody = document.getElementById('casesTableBody');
  if (tbody.children.length > 0) return;
  generateMockCase('SQL Injection Attempt', 'High', 'Resolved');
  generateMockCase('Unauthorized Port Scan', 'Medium', 'Blocked');
  generateMockCase('Failed SSH Login', 'Low', 'Investigating');
}

function generateMockCase(type = null, severity = null, status = null) {
  const tbody = document.getElementById('casesTableBody');
  
  const types = ['DDoS Attempt (Threat Intel Blocked)', 'Malware Signature Match', 'Corporate Security Policy Violation', 'Brute Force Attack', 'Data Exfiltration Attempt'];
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const statuses = ['Active', 'Investigating', 'Blocked', 'Resolved'];

  const t = type || types[Math.floor(Math.random() * types.length)];
  const s = severity || severities[Math.floor(Math.random() * severities.length)];
  const st = status || statuses[Math.floor(Math.random() * statuses.length)];

  const now = new Date();
  const time = now.toISOString().replace('T', ' ').substring(0, 19);

  let sevBadge = 'bg-info-subtle';
  if (s === 'Critical') sevBadge = 'bg-danger-subtle';
  else if (s === 'High') sevBadge = 'bg-warning-subtle';

  let stBadge = 'bg-success-subtle';
  if (st === 'Active') stBadge = 'bg-danger-subtle';
  else if (st === 'Investigating') stBadge = 'bg-warning-subtle';

  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="font-family:monospace; font-weight:bold;">#SEC-${caseCounter++}</td>
    <td style="color:var(--text-muted);">${time}</td>
    <td>${t}</td>
    <td><span class="badge-status ${sevBadge}">${s}</span></td>
    <td><span class="badge-status ${stBadge}">${st}</span></td>
  `;
  
  if (tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }

  // Update threat count in Firewall
  const tCount = document.getElementById('threatCount');
  if (tCount) {
    tCount.textContent = (parseInt(tCount.textContent.replace(',','')) + 1).toLocaleString();
  }
}

function initLedgerData() {
  const tbody = document.getElementById('ledgerTableBody');
  if (tbody.children.length > 0) return;
  
  const ledgers = [
    { hash: '0x3f...9e', file: 'contract_q1.pdf', op: 'ENCRYPT', size: '2.4 MB', status: 'SUCCESS' },
    { hash: '0xa1...2b', file: 'backup_keys.zip', op: 'DECRYPT', size: '1.1 MB', status: 'SUCCESS' },
    { hash: '0x9c...7f', file: 'passwords.txt', op: 'ENCRYPT', size: '4.0 KB', status: 'SUCCESS' }
  ];

  ledgers.forEach(l => appendLedgerEntry(l.hash, l.file, l.op, l.size, l.status));
}

function appendLedgerEntry(hash, file, op, size, status) {
  const tbody = document.getElementById('ledgerTableBody');
  if (!tbody) return;
  const now = new Date();
  const time = now.toISOString().replace('T', ' ').substring(0, 19);

  const tr = document.createElement('tr');
  const badge = op === 'ENCRYPT' ? 'bg-info-subtle' : 'bg-warning-subtle';
  tr.innerHTML = `
    <td style="font-family:monospace; color:var(--primary-light);">${hash}</td>
    <td style="color:var(--text-muted);">${time}</td>
    <td>${file}</td>
    <td><span class="badge-status ${badge}">${op}</span></td>
    <td>${size}</td>
    <td><span class="badge-status bg-success-subtle">${status}</span></td>
  `;
  if (tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
  else tbody.appendChild(tr);
}

// Hook ledger into actual encryption flow
const originalShowResultSuccess = showResultSuccess;
showResultSuccess = function(outputName, inputSize, outputSize) {
  originalShowResultSuccess(outputName, inputSize, outputSize);
  // Add to ledger dynamically
  const op = state.mode.toUpperCase();
  const hash = '0x' + Array.from({length:8}, () => Math.floor(Math.random()*16).toString(16)).join('') + '...';
  appendLedgerEntry(hash, outputName, op, formatBytes(outputSize), 'SUCCESS');
};

function handleAiKey(e) {
  if (e.key === 'Enter') sendAiMessage();
}

function sendAiMessage() {
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  const chat = document.getElementById('aiChatWindow');
  
  // User message
  const userMsg = document.createElement('div');
  userMsg.className = 'ai-msg ai-user';
  userMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div><div class="ai-bubble">${text}</div>`;
  chat.appendChild(userMsg);
  chat.scrollTop = chat.scrollHeight;

  // AI Typing
  // AI Typing
  setTimeout(() => {
    const sysMsg = document.createElement('div');
    sysMsg.className = 'ai-msg ai-sys';
    sysMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="2"/></svg></div><div class="ai-bubble">Analyzing context and checking cryptographic parameters...<br><br>The file structures appear secure. I have parsed your deeper notes and verified that they can be appended to the Unified Ledger using AES-256-GCM without exposing key artifacts.</div>`;
    chat.appendChild(sysMsg);
    chat.scrollTop = chat.scrollHeight;
  }, 1000);
}

// ══════════════════════════════════════════════════════════════════
//  ADVANCED SECURITY FEATURES (STEGO, LOCKDOWN, DECOY, BURN)
// ══════════════════════════════════════════════════════════════════

// Steganography Toggle
function toggleStegoInput() {
  const chk = document.getElementById('chkStego');
  const area = document.getElementById('stegoInputArea');
  if (chk && area) {
    area.style.display = chk.checked ? 'block' : 'none';
  }
}

// Decoy Vault / Master Authentication
let isDecoyVault = false;

// Convert plaintext to SHA-256 Hash
async function getSHA256Hash(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function authMaster() {
  const pwd = (document.getElementById('masterPassword').value || '').trim().toLowerCase();
  const err = document.getElementById('masterAuthError');
  if (!pwd) {
    err.style.display = 'block';
    return;
  }
  // Wait for the hash computation
  const pwdHash = await getSHA256Hash(pwd);

  // 'decoy' hash: 43c7bda7482f5b451cff721a329cd5dbb8a0ce51152a55de0df30b5364175de8
  // 'admin' hash: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
  
  if (pwdHash === '43c7bda7482f5b451cff721a329cd5dbb8a0ce51152a55de0df30b5364175de8') {
    // Load Plausible Deniability State
    isDecoyVault = true;
    document.getElementById('masterLoginOverlay').classList.remove('open');
    populateDecoyVault();
    generateMockCase('Decoy Vault Accessed', 'Low', 'Active');
  } else if (pwdHash === '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918') {
    // Normal Secure State
    isDecoyVault = false;
    document.getElementById('masterLoginOverlay').classList.remove('open');
    generateMockCase('Master Vault Mount', 'Low', 'Resolved');
  } else {
    err.style.display = 'block';
  }
}

function populateDecoyVault() {
  // Clear normal VFS and inject dummy files to fake out attackers
  const vfs = document.getElementById('fwFilesContainer');
  if(vfs) {
    vfs.innerHTML = `
      <div class="mini-file-item"><svg width="20" height="24" viewBox="0 0 20 24" fill="none"><path d="M12 2H4C2.9 2 2 2.9 2 4v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z" fill="rgba(168,85,247,0.3)" stroke="rgba(168,85,247,0.7)" stroke-width="1.5"/><path d="M12 2v6h6" stroke="rgba(168,85,247,0.7)" stroke-width="1.5"/></svg><span>budget_2020.xls</span></div>
      <div class="mini-file-item"><svg width="20" height="24" viewBox="0 0 20 24" fill="none"><path d="M12 2H4C2.9 2 2 2.9 2 4v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z" fill="rgba(99,102,241,0.3)" stroke="rgba(99,102,241,0.7)" stroke-width="1.5"/><path d="M12 2v6h6" stroke="rgba(99,102,241,0.7)" stroke-width="1.5"/></svg><span>vacation_photos.zip</span></div>
    `;
  }
}

// Panic Button / Lockdown
function triggerLockdown() {
  const overlay = document.getElementById('lockdownOverlay');
  if(overlay) {
    overlay.style.display = 'flex';
    document.getElementById('rescuePassword').value = '';
    document.getElementById('rescueError').style.display = 'none';
    generateMockCase('EMERGENCY LOCKDOWN TRIGGERED', 'Critical', 'Active');
    
    // Simulate wiping the filesystem from memory
    const vfs = document.getElementById('fwFilesContainer');
    if(vfs) vfs.innerHTML = ''; 
  }
}

function liftLockdown() {
  const pwd = document.getElementById('rescuePassword').value;
  const err = document.getElementById('rescueError');
  if (pwd === 'rescue') {
    document.getElementById('lockdownOverlay').style.display = 'none';
    generateMockCase('Lockdown Lifted', 'Medium', 'Resolved');
  } else {
    err.style.display = 'block';
  }
}
