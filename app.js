/**
 * SecureVault — Application Logic
 * Handles UI, state, IndexedDB profiles, and orchestrates crypto/batch operations
 */

"use strict";

// ── Word Dictionary for Passphrase Generator ───────────────────────────────
const WORD_LIST = [
  "cyber", "vault", "secure", "crypto", "quantum", "matrix", "shield", "carbon",
  "silicon", "network", "node", "nexus", "pulse", "beacon", "vector", "binary",
  "cipher", "plasma", "galaxy", "orbit", "comet", "nebula", "stellar", "aurora",
  "vortex", "shadow", "ghost", "phantom", "specter", "wraith", "blade", "laser",
  "photon", "electron", "proton", "neutron", "atom", "molecule", "quartz", "crystal",
  "diamond", "sapphire", "emerald", "ruby", "gold", "silver", "bronze", "copper",
  "iron", "steel", "cobalt", "nickel", "titanium", "helium", "neon", "argon",
  "krypton", "xenon", "radon", "sodium", "potassium", "calcium", "silica", "basalt",
  "granite", "marble", "ocean", "river", "glacier", "canyon", "desert", "forest",
  "jungle", "tundra", "meadow", "savanna", "monsoon", "typhoon", "cyclone", "hurricane",
  "tornado", "blizzard", "thunder", "lightning", "eclipse", "solstice", "equinox", "horizon",
  "zenith", "nadir", "apex", "vertex", "summit", "abyss", "chasm", "fissure",
  "trench", "rift", "crater", "caldera", "geyser", "oasis", "mirage", "dune",
  "glade", "grove", "delta", "estuary", "lagoon", "reef", "atoll", "archipelago",
  "peninsula", "isthmus", "strait", "channel", "cove", "fjord", "iceberg", "steppe",
  "plateau", "mesa", "butte", "ravine", "gorge", "pass", "ridge", "peak",
  "dome", "spire", "obelisk", "monolith", "dolmen", "cairn", "pillar", "column",
  "arch", "turret", "tower", "castle", "fortress", "citadel", "bastion", "rampart",
  "moat", "bridge", "gate", "portal", "threshold", "corridor", "gallery", "chamber",
  "crypt", "catacomb", "labyrinth", "maze", "grid", "mesh", "web", "lattice",
  "array", "tensor", "scalar", "spiral", "helix", "whirlpool", "tempest", "gale",
  "zephyr", "breeze", "mist", "fog", "haze", "vapor", "steam", "cloud",
  "cumulus", "stratus", "cirrus", "nimbus", "rain", "shower", "drizzle", "storm",
  "bolt", "flash", "spark", "ember", "flame", "blaze", "fire", "smoke",
  "ash", "dust", "sand", "soil", "clay", "mud", "rock", "stone",
  "pebble", "gravel", "silt", "loam", "peat", "coal", "amber", "fossil",
  "relic", "token", "token", "symbol", "sign", "signal", "flare", "lantern",
  "torch", "candle", "lamp", "beam", "ray", "glow", "gleam", "glimmer",
  "shimmer", "sparkle", "glitter", "sheen", "luster", "gloss", "finish", "texture",
  "pattern", "design", "motif", "theme", "style", "mode", "phase", "state",
  "status", "stage", "step", "pace", "stride", "march", "journey", "voyage",
  "flight", "trajectory", "path", "route", "track", "trail", "course", "drift",
  "tide", "current", "flow", "stream", "brook", "creek", "spring", "fountain",
  "well", "source", "origin", "beginning", "start", "launch", "initiation", "creation",
  "genesis", "birth", "dawn", "sunrise", "morning", "noon", "afternoon", "dusk",
  "sunset", "evening", "night", "midnight", "twilight", "gloaming", "darkness", "shade",
  "canopy", "ceiling", "roof", "rafter", "post", "foundation", "base", "pedestal",
  "plinth", "platform", "dais", "theater", "arena", "stadium", "zone", "sector"
];

// ── State ────────────────────────────────────────────────────────────────────

const state = {
  mode: 'encrypt',           // 'encrypt' | 'decrypt'
  fileMode: 'single',        // 'single' | 'batch'
  keyType: 'symmetric',      // 'symmetric' | 'asymmetric'
  selectedFile: null,        // Single File object
  batchFiles: [],            // Array of File objects (batch mode)
  resultBlob: null,          // Blob of processed output
  outputName: '',            // Output filename
  processing: false,
  currentUser: null,         // Logged-in username
  keyFileHash: null,         // ArrayBuffer of keyfile hash
  db: null                   // IndexedDB instance
};

// ── IndexedDB Configuration ──────────────────────────────────────────────────

function initDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('securevault_db', 1);

    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      
      // Users object store
      if (!db.objectStoreNames.contains('users')) {
        db.createObjectStore('users', { keyPath: 'username' });
      }
      
      // Ledger / Transaction logs store
      if (!db.objectStoreNames.contains('ledger')) {
        db.createObjectStore('ledger', { keyPath: 'id', autoIncrement: true });
      }
      
      // User Virtual Filesystem store
      if (!db.objectStoreNames.contains('virtual_files')) {
        db.createObjectStore('virtual_files', { keyPath: 'id', autoIncrement: true });
      }
    };

    request.onsuccess = (e) => {
      state.db = e.target.result;
      resolve(state.db);
    };

    request.onerror = (e) => {
      reject(e.target.error);
    };
  });
}

// ── Authentication System ────────────────────────────────────────────────────

let currentAuthTab = 'signin';

function switchAuthTab(tab) {
  currentAuthTab = tab;
  const btnSignin = document.getElementById('authTab-signin');
  const btnSignup = document.getElementById('authTab-signup');
  const confirmWrap = document.getElementById('authConfirmWrap');
  const submitBtn = document.getElementById('authSubmitBtn');
  const errEl = document.getElementById('authErrorMsg');

  errEl.classList.add('hidden');

  if (tab === 'signin') {
    btnSignin.classList.add('active');
    btnSignup.classList.remove('active');
    confirmWrap.classList.add('hidden');
    submitBtn.textContent = 'Sign In';
  } else {
    btnSignup.classList.add('active');
    btnSignin.classList.remove('active');
    confirmWrap.classList.remove('hidden');
    submitBtn.textContent = 'Sign Up';
  }
}

async function handleAuthentication() {
  const username = document.getElementById('authUsername').value.trim().toLowerCase();
  const password = document.getElementById('authPassword').value;
  const confirmPassword = document.getElementById('authConfirmPassword').value;
  const errEl = document.getElementById('authErrorMsg');

  if (!username) {
    showAuthError('Username is required.');
    return;
  }
  if (!password) {
    showAuthError('Password is required.');
    return;
  }

  const encoder = new TextEncoder();
  const pwdBuffer = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', pwdBuffer);
  const passwordHash = bufToHex(hashBuffer);

  const tx = state.db.transaction('users', currentAuthTab === 'signin' ? 'readonly' : 'readwrite');
  const store = tx.objectStore('users');

  if (currentAuthTab === 'signin') {
    const getReq = store.get(username);
    getReq.onsuccess = () => {
      const user = getReq.result;
      if (user && user.passwordHash === passwordHash) {
        loginUser(username);
      } else {
        showAuthError('Incorrect username or password.');
      }
    };
    getReq.onerror = () => showAuthError('Authentication error.');
  } else {
    // Sign Up
    if (password !== confirmPassword) {
      showAuthError('Passwords do not match.');
      return;
    }
    if (password.length < 8) {
      showAuthError('Password must be at least 8 characters.');
      return;
    }

    const checkReq = store.get(username);
    checkReq.onsuccess = () => {
      if (checkReq.result) {
        showAuthError('Username already exists.');
      } else {
        const addReq = store.add({ username, passwordHash });
        addReq.onsuccess = () => {
          loginUser(username);
        };
        addReq.onerror = () => showAuthError('Failed to register user.');
      }
    };
  }
}

function showAuthError(msg) {
  const errEl = document.getElementById('authErrorMsg');
  errEl.textContent = msg;
  errEl.classList.remove('hidden');
}

function loginUser(username) {
  state.currentUser = username;
  sessionStorage.setItem('currentUser', username);
  
  // Hide Auth screen
  document.getElementById('masterLoginOverlay').classList.remove('open');
  document.getElementById('masterLoginOverlay').style.display = 'none';

  // Show user profile in sidebar
  document.getElementById('userDisplayCard').classList.remove('hidden');
  document.getElementById('logoutBtnWrap').classList.remove('hidden');
  document.getElementById('userNameDisplay').textContent = username;
  document.getElementById('userAvatar').textContent = username.slice(0, 2).toUpperCase();

  addLog(`User session opened: ${username}`, 'success');
  generateMockCase(`User ${username} Logged In`, 'Low', 'Resolved');

  // Load custom user files & ledger logs
  fwRenderFiles();
  initLedgerData();
}

function logoutUser() {
  state.currentUser = null;
  sessionStorage.removeItem('currentUser');

  // Show Auth screen
  document.getElementById('masterLoginOverlay').classList.add('open');
  document.getElementById('masterLoginOverlay').style.display = 'flex';

  // Hide user info
  document.getElementById('userDisplayCard').classList.add('hidden');
  document.getElementById('logoutBtnWrap').classList.add('hidden');
  
  // Clear inputs
  document.getElementById('authUsername').value = '';
  document.getElementById('authPassword').value = '';
  document.getElementById('authConfirmPassword').value = '';

  resetAll();
  addLog('User logged out. Session secured.', 'info');
}

// ── File Management Toggles & Handlers ───────────────────────────────────────

function switchFileMode(mode) {
  if (state.processing) return;
  state.fileMode = mode;
  
  const singleBtn = document.getElementById('fileMode-single');
  const batchBtn = document.getElementById('fileMode-batch');
  const batchList = document.getElementById('batchFilesList');
  const openFolderBtn = document.getElementById('openFolderBtn');

  if (mode === 'single') {
    singleBtn.classList.add('active');
    batchBtn.classList.remove('active');
    batchList.classList.add('hidden');
    openFolderBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="2" stroke-linejoin="round" /></svg> Open Folder`;
  } else {
    batchBtn.classList.add('active');
    singleBtn.classList.remove('active');
    batchList.classList.remove('hidden');
    openFolderBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" /></svg> Select Folder`;
  }
  removeFile();
}

function handleFileSelect(e) {
  const files = e.target.files;
  if (files.length > 0) {
    if (state.fileMode === 'single') {
      loadFile(files[0]);
    } else {
      loadBatchFiles(Array.from(files));
    }
  }
  e.target.value = '';
}

function handleFolderSelect(e) {
  const files = e.target.files;
  if (files.length > 0) {
    loadBatchFiles(Array.from(files));
  }
  e.target.value = '';
}

function loadFile(file) {
  state.selectedFile = file;
  state.batchFiles = [];

  // Metadata check for .enc files
  const isEncrypted = file.name.toLowerCase().endsWith('.enc');
  
  if (isEncrypted && state.mode !== 'decrypt') {
    switchMode('decrypt');
    addLog('Auto-switched to Decrypt mode (.enc file detected)', 'info');
  } else if (!isEncrypted && state.mode === 'decrypt') {
    switchMode('encrypt');
    addLog('Auto-switched to Encrypt mode (Standard file detected)', 'info');
  }

  const folderTrigger = document.getElementById('folderTrigger');
  const fileSelected  = document.getElementById('fileSelected');
  const fileName      = document.getElementById('fileName');
  const fileMeta      = document.getElementById('fileMeta');

  fileName.textContent = file.name;
  fileMeta.textContent = `${formatBytes(file.size)} · ${file.type || 'application/octet-stream'}`;

  folderTrigger.classList.add('hidden');
  fileSelected.classList.remove('hidden');
  document.getElementById('batchFilesList').classList.add('hidden');

  markStepDone(1);
  hideResult();

  if (state.mode === 'decrypt') {
    checkFileMetadata(file);
  }
}

function loadBatchFiles(files) {
  state.selectedFile = null;
  state.batchFiles = state.batchFiles.concat(files);

  const folderTrigger = document.getElementById('folderTrigger');
  const fileSelected  = document.getElementById('fileSelected');
  const fileName      = document.getElementById('fileName');
  const fileMeta      = document.getElementById('fileMeta');

  fileName.textContent = `Batch of ${state.batchFiles.length} files`;
  
  const totalSize = state.batchFiles.reduce((sum, f) => sum + f.size, 0);
  fileMeta.textContent = `Total Size: ${formatBytes(totalSize)}`;

  folderTrigger.classList.add('hidden');
  fileSelected.classList.remove('hidden');
  document.getElementById('batchFilesList').classList.remove('hidden');

  renderBatchFilesList();
  markStepDone(1);
  hideResult();
}

function renderBatchFilesList() {
  const listEl = document.getElementById('batchFilesList');
  listEl.innerHTML = '';
  
  state.batchFiles.forEach((file, idx) => {
    const row = document.createElement('div');
    row.className = 'batch-file-row';
    
    // Icon
    const type = inferType(file);
    const iconHtml = makeFileSVG(type, 18);

    row.innerHTML = `
      <div class="batch-file-icon">${iconHtml}</div>
      <div class="batch-file-name" title="${file.name}">${file.name}</div>
      <div class="batch-file-size">${formatBytes(file.size)}</div>
      <button class="batch-file-remove" onclick="removeBatchFile(${idx}, event)">&times;</button>
    `;
    listEl.appendChild(row);
  });
}

function removeBatchFile(idx, e) {
  if (e) e.stopPropagation();
  state.batchFiles.splice(idx, 1);
  if (state.batchFiles.length === 0) {
    removeFile();
  } else {
    loadBatchFiles([]); // Trigger reload
  }
}

function removeFile(e) {
  if (e) e.stopPropagation();
  state.selectedFile = null;
  state.batchFiles = [];
  state.keyFileHash = null;
  if (document.getElementById('keyFileInput')) document.getElementById('keyFileInput').value = '';

  const folderTrigger = document.getElementById('folderTrigger');
  const fileSelected  = document.getElementById('fileSelected');

  folderTrigger.classList.remove('hidden');
  fileSelected.classList.add('hidden');
  
  document.getElementById('metadataPreviewCard').classList.add('hidden');

  resetStep(1);
  hideResult();
}

// ── 2FA Key File ─────────────────────────────────────────────────────────────

function toggle2FAInput() {
  const chk = document.getElementById('chk2FA');
  const inputArea = document.getElementById('keyFileInputArea');
  if (chk.checked) {
    inputArea.classList.remove('hidden');
  } else {
    inputArea.classList.add('hidden');
    state.keyFileHash = null;
    document.getElementById('keyFileInput').value = '';
  }
}

async function handleKeyFileSelect(e) {
  const file = e.target.files[0];
  if (!file) return;
  
  addLog(`Reading 2FA key file: ${file.name}...`, 'info');
  const buffer = await file.arrayBuffer();
  state.keyFileHash = await computeSHA256(buffer);
  addLog('2FA key file digest calculated successfully.', 'success');
}

// ── Asymmetric RSA Key Management ────────────────────────────────────────────

function switchKeyType(type) {
  state.keyType = type;
  const symBtn = document.getElementById('keyType-symmetric');
  const asymBtn = document.getElementById('keyType-asymmetric');
  const symFields = document.getElementById('symmetricFields');
  const asymFields = document.getElementById('asymmetricFields');

  if (type === 'symmetric') {
    symBtn.classList.add('active');
    asymBtn.classList.remove('active');
    symFields.classList.remove('hidden');
    asymFields.classList.add('hidden');
  } else {
    asymBtn.classList.add('active');
    symBtn.classList.remove('active');
    symFields.classList.add('hidden');
    asymFields.classList.remove('hidden');
    
    // Toggle recipient key fields based on encrypt/decrypt mode
    toggleAsymmetricKeyFields();
  }
}

function toggleAsymmetricKeyFields() {
  const encFields = document.getElementById('asymmetricEncryptFields');
  const decFields = document.getElementById('asymmetricDecryptFields');
  if (state.mode === 'encrypt') {
    encFields.classList.remove('hidden');
    decFields.classList.add('hidden');
  } else {
    decFields.classList.remove('hidden');
    encFields.classList.add('hidden');
  }
}

async function generateAsymmetricKeys() {
  addLog('Generating secure RSA-2048 keypair client-side. Please wait...', 'info');
  try {
    const keys = await generateRSAKeypair();
    
    // Prompt download of public key
    const pubBlob = new Blob([keys.publicKeyPem], { type: 'text/plain' });
    const pubUrl = URL.createObjectURL(pubBlob);
    const pubLink = document.createElement('a');
    pubLink.href = pubUrl;
    pubLink.download = 'securevault_public_key.pem';
    pubLink.click();
    
    // Prompt download of private key
    const privBlob = new Blob([keys.privateKeyPem], { type: 'text/plain' });
    const privUrl = URL.createObjectURL(privBlob);
    const privLink = document.createElement('a');
    privLink.href = privUrl;
    privLink.download = 'securevault_private_key.pem';
    privLink.click();

    // Populate keyareas
    document.getElementById('recipientPublicKey').value = keys.publicKeyPem;
    document.getElementById('recipientPrivateKey').value = keys.privateKeyPem;

    addLog('Asymmetric RSA-2048 keypair generated successfully. PEM keys downloaded.', 'success');
  } catch (err) {
    addLog(`Key generation failed: ${err.message}`, 'error');
  }
}

// ── Passphrase Generator & QR Code ───────────────────────────────────────────

function generateSecurePassphrase() {
  const words = [];
  for (let i = 0; i < 4; i++) {
    const idx = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] % WORD_LIST.length);
    words.push(WORD_LIST[idx]);
  }
  const passphrase = words.join('-');

  document.getElementById('passwordInput').value = passphrase;
  document.getElementById('confirmInput').value = passphrase;
  
  // Force show cleartext password temporarily so user can see it
  const pwInput = document.getElementById('passwordInput');
  const confInput = document.getElementById('confirmInput');
  const oldType = pwInput.type;
  
  pwInput.type = 'text';
  confInput.type = 'text';
  
  setTimeout(() => {
    pwInput.type = oldType;
    confInput.type = oldType;
  }, 10_000);

  updatePasswordStrength();
  checkConfirm();
  addLog('Secure 4-word passphrase generated successfully.', 'success');
}

function showPassphraseQrCode() {
  const pwd = document.getElementById('passwordInput').value;
  if (!pwd) {
    shakeElement('passwordInput');
    return;
  }

  const modal = document.getElementById('qrModal');
  const textEl = document.getElementById('qrText');
  textEl.textContent = pwd;

  // Clear canvas
  const canvas = document.getElementById('qrCanvas');
  canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);

  // Render QR
  new QRious({
    element: canvas,
    value: pwd,
    size: 200,
    background: 'white',
    foreground: 'black',
    level: 'H'
  });

  modal.classList.add('open');
}

function closeQrModal() {
  document.getElementById('qrModal').classList.remove('open');
}

// ── Password Strength and Entropy ────────────────────────────────────────────

function calculateEntropy(pwd) {
  if (!pwd) return { bits: 0, time: 'Instant' };
  
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;

  const bits = Math.round(pwd.length * Math.log2(pool || 1));
  
  // Cracking estimates assuming 10,000 attempts per second (slow due to PBKDF2 iterations)
  const attemptsPerSec = 10000;
  const searchSpace = Math.pow(pool, pwd.length);
  const timeSecs = searchSpace / (2 * attemptsPerSec);

  let timeStr = 'Instant';
  if (timeSecs >= 31536000 * 1000) {
    timeStr = 'Centuries';
  } else if (timeSecs >= 31536000) {
    timeStr = `${Math.round(timeSecs / 31536000)} years`;
  } else if (timeSecs >= 86400) {
    timeStr = `${Math.round(timeSecs / 86400)} days`;
  } else if (timeSecs >= 3600) {
    timeStr = `${Math.round(timeSecs / 3600)} hours`;
  } else if (timeSecs >= 60) {
    timeStr = `${Math.round(timeSecs / 60)} minutes`;
  } else if (timeSecs > 0) {
    timeStr = `${Math.round(timeSecs)} seconds`;
  }

  return { bits, time: timeStr };
}

function updatePasswordStrength() {
  const pw = document.getElementById('passwordInput').value;
  const bar = document.getElementById('strengthFill');
  const lbl = document.getElementById('strengthLabel');

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
  const entropy = calculateEntropy(pw);

  bar.className = 'strength-fill';
  if (pw.length === 0) {
    lbl.textContent = 'Enter password';
    resetStep(2);
    return;
  }

  const levels = ['', 'weak', 'fair', 'good', 'strong'];
  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  bar.classList.add(levels[score]);
  lbl.textContent = `${labels[score]} (Entropy: ${entropy.bits} bits, Crack time: ~${entropy.time})`;

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

// ── Metadata Header Parser ──────────────────────────────────────────────────

async function checkFileMetadata(file) {
  try {
    const slice = file.slice(0, 310);
    const buffer = await slice.arrayBuffer();
    const meta = parseEncryptedHeader(buffer);
    
    const card = document.getElementById('metadataPreviewCard');
    if (!meta) {
      card.classList.add('hidden');
      return;
    }

    document.getElementById('metaVersion').textContent = `v${meta.version}`;
    document.getElementById('metaType').textContent = meta.asymmetric ? 'Asymmetric (RSA)' : 'Symmetric (Password)';
    document.getElementById('metaSalt').textContent = meta.salt ? `0x${bufToHex(meta.salt.slice(0, 6))}...` : 'N/A';
    document.getElementById('metaIv').textContent = `0x${bufToHex(meta.iv.slice(0, 6))}...`;
    document.getElementById('metaHash').textContent = meta.integrityHash ? `0x${bufToHex(meta.integrityHash.slice(0, 16))}...` : 'N/A';
    
    card.classList.remove('hidden');
    addLog(`Parsed file metadata: Format v${meta.version}, ${meta.asymmetric ? 'Asymmetric' : 'Symmetric'} mode.`, 'info');
  } catch (err) {
    console.error('Metadata parsing error', err);
  }
}

// ── Main Process ─────────────────────────────────────────────────────────────

async function processFile() {
  if (state.processing) return;

  const file = state.selectedFile;
  const batchList = state.batchFiles;
  const password = document.getElementById('passwordInput').value;
  const confirm = document.getElementById('confirmInput').value;
  const rsaPubKey = document.getElementById('recipientPublicKey').value;
  const rsaPrivKey = document.getElementById('recipientPrivateKey').value;
  
  const isStreaming = document.getElementById('chkStreaming').checked;

  // Validation
  if (!file && batchList.length === 0) {
    shakeElement('dropZone');
    addLog('No file or folder batch selected', 'error');
    return;
  }

  if (state.keyType === 'symmetric') {
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
  } else {
    // Asymmetric
    if (state.mode === 'encrypt' && !rsaPubKey) {
      shakeElement('recipientPublicKey');
      return;
    }
    if (state.mode === 'decrypt' && !rsaPrivKey) {
      shakeElement('recipientPrivateKey');
      return;
    }
  }

  // UI → processing state
  state.processing = true;
  setActionBtnState(true);
  showResultProcessing();

  try {
    let sourceFile = file;

    // Batch mode: Zip all files in-memory before encrypting
    if (state.fileMode === 'batch') {
      addLog(`[ZIP] Compressing ${batchList.length} files with JSZip...`, 'info');
      const zip = new JSZip();
      for (const f of batchList) {
        zip.file(f.name, f);
      }
      const zipBuffer = await zip.generateAsync({ type: 'arraybuffer' });
      sourceFile = new File([zipBuffer], 'secured_batch.zip', { type: 'application/zip' });
      addLog(`[ZIP] Compression successful. Zipped file size: ${formatBytes(sourceFile.size)}`, 'success');
    }

    const outputName = getOutputFilename(sourceFile.name, state.mode);

    if (state.mode === 'encrypt') {
      if (isStreaming) {
        // Version 3 Streaming
        markStepProcessing(3);
        const result = await encryptFileStream(sourceFile, {
          password,
          keyFileHash: state.keyFileHash,
          chunkSize: 1024 * 1024
        }, (phase, msg) => {
          if (phase === 'encrypt') {
            markStepDone(3);
            markStepProcessing(4);
          }
          addLog(`[STREAM] ${msg}`);
        }, (pct, detail) => {
          updateProgressBar(pct, detail);
        });

        markStepDone(3);
        markStepDone(4);
        markStepDone(5);
        
        state.resultBlob = result.encryptedBlob;
        state.outputName = outputName;
        showResultSuccess(outputName, sourceFile.size, result.encryptedBlob.size, result.sha256);
      } else {
        // Standard (V2 or V4 Asymmetric)
        const fileBuffer = await sourceFile.arrayBuffer();
        markStepProcessing(3);
        
        let stepPhase = 'keyDerive';
        const result = await encryptFile(fileBuffer, {
          password,
          keyFileHash: state.keyFileHash,
          recipientPublicKeyPem: state.keyType === 'asymmetric' ? rsaPubKey : null
        }, (phase, msg) => {
          if (phase !== stepPhase) {
            if (phase === 'encrypt') {
              markStepDone(3);
              markStepProcessing(4);
            }
            stepPhase = phase;
          }
          addLog(`[CRYPT] ${msg}`);
        });

        markStepDone(3);
        markStepDone(4);
        markStepDone(5);

        state.resultBlob = new Blob([result.encrypted], { type: 'application/octet-stream' });
        state.outputName = outputName;
        showResultSuccess(outputName, fileBuffer.byteLength, result.encrypted.byteLength, result.sha256);
      }
    } else {
      // Decrypt
      if (isStreaming || sourceFile.name.toLowerCase().endsWith('.enc')) {
        // Determine version from header before choosing flow
        const headSlice = sourceFile.slice(0, 5);
        const headBuf = await headSlice.arrayBuffer();
        const headBytes = new Uint8Array(headBuf);
        const isStreamVer = (headBytes.length >= 5 && headBytes[4] === 3);

        if (isStreamVer) {
          markStepProcessing(3);
          const result = await decryptFileStream(sourceFile, {
            password,
            keyFileHash: state.keyFileHash
          }, (phase, msg) => {
            if (phase === 'decrypt') {
              markStepDone(3);
              markStepProcessing(4);
            }
            addLog(`[STREAM] ${msg}`);
          }, (pct, detail) => {
            updateProgressBar(pct, detail);
          });

          markStepDone(3);
          markStepDone(4);
          markStepDone(5);

          state.resultBlob = result.decryptedBlob;
          state.outputName = outputName;
          showResultSuccess(outputName, sourceFile.size, result.decryptedBlob.size, result.sha256);
          return;
        }
      }

      // Standard Decryption
      const fileBuffer = await sourceFile.arrayBuffer();
      markStepProcessing(3);
      let stepPhase = 'validate';
      
      const result = await decryptFile(fileBuffer, {
        password,
        keyFileHash: state.keyFileHash,
        recipientPrivateKeyPem: state.keyType === 'asymmetric' ? rsaPrivKey : null
      }, (phase, msg) => {
        if (phase === 'decrypt') {
          markStepDone(3);
          markStepProcessing(4);
        }
        stepPhase = phase;
        addLog(`[CRYPT] ${msg}`);
      });

      markStepDone(3);
      markStepDone(4);
      markStepDone(5);

      state.resultBlob = new Blob([result.decrypted], { type: 'application/octet-stream' });
      state.outputName = outputName;
      showResultSuccess(outputName, fileBuffer.byteLength, result.decrypted.byteLength, result.sha256);
    }

  } catch (err) {
    showResultError(err.message || 'Unknown error');
    resetStepsOnError();
  } finally {
    state.processing = false;
    setActionBtnState(false);
  }
}

function updateProgressBar(pct, detail) {
  const sub = document.getElementById('resultSub');
  sub.textContent = `${detail}...`;
  
  // Update UI step description dynamically to show progress percentage
  const stepDesc4 = document.getElementById('stepDesc4');
  if (stepDesc4) stepDesc4.textContent = `Progress: ${pct}%`;
}

// ── History logs / Local Ledger in IndexedDB ──────────────────────────────────

function appendLedgerEntry(hash, file, op, size, status, integrityHash) {
  if (!state.currentUser) return;

  const now = new Date();
  const time = now.toISOString().replace('T', ' ').substring(0, 19);

  const tx = state.db.transaction('ledger', 'readwrite');
  const store = tx.objectStore('ledger');
  
  store.add({
    username: state.currentUser,
    txHash: hash,
    timestamp: time,
    fileName: file,
    operation: op,
    size: size,
    status: status,
    sha256: integrityHash || 'N/A'
  });
}

function initLedgerData() {
  const tbody = document.getElementById('ledgerTableBody');
  if (!tbody || !state.currentUser) return;
  tbody.innerHTML = '';

  const tx = state.db.transaction('ledger', 'readonly');
  const store = tx.objectStore('ledger');

  const cursorReq = store.openCursor();
  cursorReq.onsuccess = (e) => {
    const cursor = e.target.result;
    if (cursor) {
      const log = cursor.value;
      if (log.username === state.currentUser) {
        const tr = document.createElement('tr');
        const badge = log.operation === 'ENCRYPT' ? 'bg-info-subtle' : 'bg-warning-subtle';
        tr.innerHTML = `
          <td style="font-family:monospace; color:var(--primary-light);" title="SHA-256: ${log.sha256}">${log.txHash}</td>
          <td style="color:var(--text-muted);">${log.timestamp}</td>
          <td title="${log.fileName}">${log.fileName}</td>
          <td><span class="badge-status ${badge}">${log.operation}</span></td>
          <td>${log.size}</td>
          <td><span class="badge-status bg-success-subtle">${log.status}</span></td>
        `;
        tbody.appendChild(tr);
      }
      cursor.continue();
    }
  };
}

function clearLedgerHistory() {
  if (!state.currentUser) return;
  
  addLog('Clearing IndexedDB Ledger logs...', 'info');
  const tx = state.db.transaction('ledger', 'readwrite');
  const store = tx.objectStore('ledger');
  
  const cursorReq = store.openCursor();
  cursorReq.onsuccess = (e) => {
    const cursor = e.target.result;
    if (cursor) {
      if (cursor.value.username === state.currentUser) {
        cursor.delete();
      }
      cursor.continue();
    } else {
      initLedgerData();
      addLog('Ledger history cleared successfully.', 'success');
    }
  };
}

// ── Download & UI Actions ───────────────────────────────────────────────────

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

function resetAll() {
  state.selectedFile = null;
  state.batchFiles = [];
  state.resultBlob = null;
  state.outputName = '';
  state.keyFileHash = null;

  document.getElementById('folderTrigger').classList.remove('hidden');
  document.getElementById('fileSelected').classList.add('hidden');
  document.getElementById('batchFilesList').classList.add('hidden');

  // Reset passwords
  document.getElementById('passwordInput').value = '';
  document.getElementById('confirmInput').value = '';
  document.getElementById('strengthFill').className = 'strength-fill';
  document.getElementById('strengthLabel').textContent = 'Enter password';
  document.getElementById('confirmIndicator').className = 'confirm-indicator';
  document.getElementById('confirmMsg').classList.add('hidden');
  
  if (document.getElementById('keyFileInput')) document.getElementById('keyFileInput').value = '';
  if (document.getElementById('chk2FA')) document.getElementById('chk2FA').checked = false;
  if (document.getElementById('keyFileInputArea')) document.getElementById('keyFileInputArea').classList.add('hidden');
  if (document.getElementById('chkStreaming')) document.getElementById('chkStreaming').checked = false;

  ['req-len', 'req-upper', 'req-num', 'req-sym'].forEach(id => {
    document.getElementById(id).classList.remove('met');
  });

  resetSteps();
  hideResult();
}

// ── Steps UI Helpers ─────────────────────────────────────────────────────────

function setStepState(n, s) {
  const el = document.getElementById(`step-${n}`);
  if (!el) return;
  const wait = el.querySelector('.step-icon-wait');
  const done = el.querySelector('.step-icon-done');
  const spinner = el.querySelector('.step-spinner');

  el.className = 'step-item';
  wait.classList.add('hidden');
  done.classList.add('hidden');
  spinner.classList.add('hidden');

  if (s === 'active') {
    el.classList.add('active');
    wait.classList.remove('hidden');
  } else if (s === 'processing') {
    el.classList.add('active');
    spinner.classList.remove('hidden');
  } else if (s === 'done') {
    el.classList.add('done');
    done.classList.remove('hidden');
  } else {
    wait.classList.remove('hidden');
  }
}

function markStepDone(n) { setStepState(n, 'done'); }
function markStepProcessing(n) { setStepState(n, 'processing'); }
function markStepActive(n) { setStepState(n, 'active'); }

function resetStep(n) {
  const el = document.getElementById(`step-${n}`);
  if (!el) return;
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

// ── Log entries ──────────────────────────────────────────────────────────────

function addLog(msg, type = 'info') {
  const entries = document.getElementById('logEntries');
  if (!entries) return;
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
  const entries = document.getElementById('logEntries');
  if (entries) entries.innerHTML = '';
}

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

  // Switch RSA key fields as well
  if (state.keyType === 'asymmetric') {
    toggleAsymmetricKeyFields();
  }

  resetSteps();
  hideResult();
  
  if (state.selectedFile) {
    loadFile(state.selectedFile);
  }
}

// ── Result Panels ────────────────────────────────────────────────────────────

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

function showResultSuccess(outputName, inputSize, outputSize, integrityHash) {
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
    <div class="stat-item"><div class="stat-label">Key Derivation</div><div class="stat-value">${state.keyType === 'asymmetric' ? 'RSA Hybrid' : 'PBKDF2·600k'}</div></div>
  `;

  dlSec.classList.remove('hidden');

  // Add event to ledger history
  const op = state.mode.toUpperCase();
  const txHash = '0x' + (integrityHash ? integrityHash.slice(0, 10) : Array.from({length:8}, () => Math.floor(Math.random()*16).toString(16)).join('')) + '...';
  appendLedgerEntry(txHash, outputName, op, formatBytes(outputSize), 'SUCCESS', integrityHash);
  initLedgerData();
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
  resetStepsOnError();
}

function hideResult() {
  const el = document.getElementById('resultPanel');
  if (el) el.classList.add('hidden');
}

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

// Add shake keyframes
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

// ── Drag & Drop Handlers ─────────────────────────────────────────────────────

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
  const files = e.dataTransfer.files;
  if (files.length > 0) {
    if (state.fileMode === 'single') {
      loadFile(files[0]);
    } else {
      loadBatchFiles(Array.from(files));
    }
  }
}

// ── DOM Init ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Initialize DB
  initDatabase().then(() => {
    // Check session
    const savedUser = sessionStorage.getItem('currentUser');
    if (savedUser) {
      loginUser(savedUser);
    } else {
      // Force Login Overlay
      const overlay = document.getElementById('masterLoginOverlay');
      overlay.classList.add('open');
      overlay.style.display = 'flex';
      switchAuthTab('signin');
    }
  });

  const splash = document.getElementById('splashScreen');
  if (splash) {
    if (sessionStorage.getItem('skipSplash') === '1') {
      sessionStorage.removeItem('skipSplash');
      splash.remove();
    } else {
      setTimeout(() => {
        splash.classList.add('fade-out');
        setTimeout(() => splash.remove(), 600);
      }, 2500);
    }
  }

  // Keyboard shortcut: Enter to process
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      processFile();
    }
  });

  document.body.addEventListener('dragover', e => e.preventDefault());
  document.body.addEventListener('drop', e => e.preventDefault());

  // Register PWA service worker
  if (window.location.protocol !== 'file:') {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./sw.js').catch(() => {});
    }
  }
});


// ══════════════════════════════════════════════════════════════════
//  FOLDER WINDOW / VIRTUAL DESKTOP MODULE (IndexedDB Backed)
// ══════════════════════════════════════════════════════════════════

const fwState = {
  view: 'grid',
  currentPath: 'Desktop',
  selectedFile: null,      // Virtual File object
  pendingRealFile: null,   // Real File from drop inside window
  history: ['Desktop'],
  historyIdx: 0
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

function openFolderWindow() {
  const overlay = document.getElementById('folderWindowOverlay');
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
  fwState.selectedFile = null;
  fwState.pendingRealFile = null;
  fwRenderFiles();
  fwUpdateStatus();
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
  fwState.history = fwState.history.slice(0, fwState.historyIdx + 1);
  fwState.history.push(path);
  fwState.historyIdx = fwState.history.length - 1;
  fwState.currentPath = path;
  fwState.selectedFile = null;
  fwState.pendingRealFile = null;
  document.getElementById('fwSearch').value = '';

  document.querySelectorAll('.fw-sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.path === path);
  });

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
  if (!container || !state.currentUser) return;
  container.className = `fw-files-container ${fwState.view}-view`;
  container.innerHTML = '';

  const q = filter.toLowerCase();

  // Load custom user files from IndexedDB
  const tx = state.db.transaction('virtual_files', 'readonly');
  const store = tx.objectStore('virtual_files');

  const files = [];
  const cursorReq = store.openCursor();
  cursorReq.onsuccess = (e) => {
    const cursor = e.target.result;
    if (cursor) {
      const fileVal = cursor.value;
      if (fileVal.username === state.currentUser && fileVal.path === fwState.currentPath) {
        files.push(fileVal);
      }
      cursor.continue();
    } else {
      // Finished loading files, now render
      renderVirtualList(files);
    }
  };

  function renderVirtualList(virtualFiles) {
    // Add default virtual folders/files for Desktop if empty
    if (virtualFiles.length === 0 && fwState.currentPath === 'Desktop') {
      const defaultDocs = [
        { name: 'Documents', type: 'folder', size: 0, date: '4/10/2026', path: 'Desktop', username: state.currentUser },
        { name: 'notes.txt', type: 'text', size: 24, date: '4/12/2026', path: 'Desktop', username: state.currentUser, content: new TextEncoder().encode("SecureVault User Notes.") },
      ];
      // Save default
      const wrTx = state.db.transaction('virtual_files', 'readwrite');
      const wrStore = wrTx.objectStore('virtual_files');
      defaultDocs.forEach(d => wrStore.add(d));
      
      wrTx.oncomplete = () => {
        fwRenderFiles(filter);
      };
      return;
    }

    const filtered = q ? virtualFiles.filter(e => e.name.toLowerCase().includes(q)) : virtualFiles;

    if (filtered.length === 0) {
      container.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--text-subtle);font-size:13px;">No files found in ${fwState.currentPath}</div>`;
      return;
    }

    filtered.forEach(entry => {
      const t = entry.type === 'folder' ? 'folder' : inferType(entry);
      const isFolder = t === 'folder';
      const isSelected = (!isFolder && fwState.selectedFile && fwState.selectedFile.id === entry.id);

      const el = document.createElement('div');
      el.className = `fw-file-item${isFolder ? ' fw-folder-item' : ''}${isSelected ? ' selected' : ''}`;

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
          <div class="fw-file-type">${t.charAt(0).toUpperCase() + t.slice(1)}</div>
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
    // Import real file to database Virtual Filesystem, then load it
    saveFileToVirtualFS(fwState.pendingRealFile);
    return;
  }
  if (fwState.selectedFile) {
    // Convert Virtual File to real File object and load it
    const virtualFile = fwState.selectedFile;
    const fileObj = new File([virtualFile.content], virtualFile.name, { type: virtualFile.mimeType || 'application/octet-stream' });
    loadFile(fileObj);
    closeFolderWindow();
  }
}

function triggerRealFilePicker() {
  closeFolderWindow();
  document.getElementById('fileInput').click();
}

function triggerRealFolderPicker() {
  closeFolderWindow();
  document.getElementById('folderInput').click();
}

function saveFileToVirtualFS(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const arrayBuffer = reader.result;
    
    const tx = state.db.transaction('virtual_files', 'readwrite');
    const store = tx.objectStore('virtual_files');

    const entry = {
      username: state.currentUser,
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      date: new Date().toLocaleDateString(),
      path: fwState.currentPath,
      content: arrayBuffer,
      mimeType: file.type
    };

    store.add(entry).onsuccess = () => {
      addLog(`Imported file to Virtual Workspace: ${file.name}`, 'success');
      fwRenderFiles();
      fwState.pendingRealFile = null;
      fwUpdateStatus();
    };
  };
  reader.readAsArrayBuffer(file);
}

// Drag-and-drop inside folder window
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
    document.querySelectorAll('.fw-file-item').forEach(i => i.classList.remove('selected'));
    fwUpdateStatus(null, true);
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('folderWindowOverlay');
    if (overlay && overlay.classList.contains('open')) closeFolderWindow();
  }
});


// ══════════════════════════════════════════════════════════════════
//  CYBER SUITE DASHBOARD LOGIC
// ══════════════════════════════════════════════════════════════════

function switchTab(tabId, e) {
  if (e) e.preventDefault();
  
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const btn = document.getElementById('tabBtn-' + tabId);
  if (btn) btn.classList.add('active');

  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  const content = document.getElementById('content-' + tabId);
  if (content) content.classList.add('active');

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
  if (!tbody || tbody.children.length > 0) return;

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
  if (!tbody || tbody.children.length > 0) return;
  generateMockCase('SQL Injection Attempt', 'High', 'Resolved');
  generateMockCase('Unauthorized Port Scan', 'Medium', 'Blocked');
  generateMockCase('Failed SSH Login', 'Low', 'Investigating');
}

function generateMockCase(type = null, severity = null, status = null) {
  const tbody = document.getElementById('casesTableBody');
  if (!tbody) return;
  
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

  const tCount = document.getElementById('threatCount');
  if (tCount) {
    tCount.textContent = (parseInt(tCount.textContent.replace(',','')) + 1).toLocaleString();
  }
}

let copilotHistory = [
  {
    role: 'system',
    content: "You are SecureVault's AI Security Copilot. You are an expert cryptographer and cybersecurity analyst. You help users analyze files, detect anomalies, and understand cryptographic details of SecureVault. Keep your answers brief, professional, and technically precise."
  }
];

function handleAiKey(e) {
  if (e.key === 'Enter') sendAiMessage();
}

async function sendAiMessage() {
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  const chat = document.getElementById('aiChatWindow');
  
  const userMsg = document.createElement('div');
  userMsg.className = 'ai-msg ai-user';
  userMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div><div class="ai-bubble">${text}</div>`;
  chat.appendChild(userMsg);
  chat.scrollTop = chat.scrollHeight;

  copilotHistory.push({ role: 'user', content: text });

  const typingMsg = document.createElement('div');
  typingMsg.className = 'ai-msg ai-sys';
  typingMsg.id = 'copilot-typing';
  typingMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="2"/></svg></div><div class="ai-bubble" style="display:flex; gap:4px; align-items:center; padding:4px 8px;"><span style="animation: sv-typing 1.4s infinite ease-in-out both; width:6px; height:6px; background:#94a3b8; border-radius:50%; -webkit-animation-delay:-0.32s; animation-delay:-0.32s;"></span><span style="animation: sv-typing 1.4s infinite ease-in-out both; width:6px; height:6px; background:#94a3b8; border-radius:50%; -webkit-animation-delay:-0.16s; animation-delay:-0.16s;"></span><span style="animation: sv-typing 1.4s infinite ease-in-out both; width:6px; height:6px; background:#94a3b8; border-radius:50%;"></span></div>`;
  chat.appendChild(typingMsg);
  chat.scrollTop = chat.scrollHeight;

  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messages: copilotHistory
      })
    });

    typingMsg.remove();

    if (!response.ok) {
      throw new Error('API error: ' + response.status);
    }

    const data = await response.json();
    const replyText = data.choices?.[0]?.message?.content || 'Error generating AI response.';
    
    copilotHistory.push({ role: 'assistant', content: replyText });

    const sysMsg = document.createElement('div');
    sysMsg.className = 'ai-msg ai-sys';
    const parsedText = window.parseChatMarkdown ? window.parseChatMarkdown(replyText) : replyText;
    sysMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="2"/></svg></div><div class="ai-bubble">${parsedText}</div>`;
    chat.appendChild(sysMsg);
    chat.scrollTop = chat.scrollHeight;
  } catch (error) {
    typingMsg.remove();
    const errorMsg = document.createElement('div');
    errorMsg.className = 'ai-msg ai-sys';
    errorMsg.innerHTML = `<div class="ai-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="2"/></svg></div><div class="ai-bubble">⚠️ <strong>Error connecting to AI Copilot</strong>: ${error.message}</div>`;
    chat.appendChild(errorMsg);
    chat.scrollTop = chat.scrollHeight;
    console.error('AI Security Copilot Error:', error);
  }
}

// Steganography Toggle
function toggleStegoInput() {
  const chk = document.getElementById('chkStego');
  const area = document.getElementById('stegoInputArea');
  if (chk && area) {
    area.style.display = chk.checked ? 'block' : 'none';
  }
}

// Panic Button / Lockdown
function triggerLockdown() {
  const overlay = document.getElementById('lockdownOverlay');
  if (overlay) {
    overlay.style.display = 'flex';
    document.getElementById('rescuePassword').value = '';
    document.getElementById('rescueError').style.display = 'none';
    generateMockCase('EMERGENCY LOCKDOWN TRIGGERED', 'Critical', 'Active');
    
    // Wipe files from virtual explorer view
    const container = document.getElementById('fwFilesContainer');
    if (container) container.innerHTML = '';
  }
}

function liftLockdown() {
  const pwd = document.getElementById('rescuePassword').value;
  const err = document.getElementById('rescueError');
  if (pwd === 'rescue') {
    document.getElementById('lockdownOverlay').style.display = 'none';
    generateMockCase('Lockdown Lifted', 'Medium', 'Resolved');
    fwRenderFiles();
  } else {
    err.style.display = 'block';
  }
}
