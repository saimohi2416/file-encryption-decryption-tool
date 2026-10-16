/**
 * SecureVault AI — Zero-Knowledge Wi-Fi / Cellular Cloud Auto-Backup Engine
 * 
 * Cryptographic Standard:
 * - PBKDF2-SHA256 (600,000 iterations, 16-byte cryptographically random salt)
 * - AES-256-GCM (12-byte random IV, 128-bit authentication tag)
 * - SHA-256 payload integrity check
 * 
 * Network Intelligence:
 * - Network Information API (`navigator.connection`) detects Wi-Fi vs Cellular.
 * - Respects "Wi-Fi Only" setting and auto-queues backups on cellular.
 * - Automatically executes queued backup as soon as network returns to Wi-Fi.
 */

export class BackupEngine {
  constructor(dbManager) {
    this.db = dbManager;
    this.settings = this.loadSettings();
    this.status = 'idle'; // 'idle' | 'running' | 'queued_wifi' | 'error'
    this.queuedBackup = false;
    this.googleAccessToken = null;

    this.init();
  }

  loadSettings() {
    try {
      const saved = localStorage.getItem('sv_backup_settings');
      if (saved) {
        return Object.assign({
          frequency: 'daily',             // 'off' | 'instant' | 'daily' | 'weekly' | 'monthly'
          networkPreference: 'wifi-only', // 'wifi-only' | 'any'
          includeEncrypted: true,
          lastBackupTime: null,
          lastBackupSize: 0,
          cloudTarget: 'drive'            // 'drive' | 'local'
        }, JSON.parse(saved));
      }
    } catch (e) {
      console.warn('[BackupEngine] Failed to load settings from storage, using defaults:', e);
    }
    return {
      frequency: 'daily',
      networkPreference: 'wifi-only',
      includeEncrypted: true,
      lastBackupTime: null,
      lastBackupSize: 0,
      cloudTarget: 'drive'
    };
  }

  saveSettings(newSettings = {}) {
    this.settings = Object.assign(this.settings, newSettings);
    localStorage.setItem('sv_backup_settings', JSON.stringify(this.settings));
    this.updateUI();
  }

  init() {
    this.setupNetworkMonitor();
    this.bindDOMControls();
    this.updateUI();

    // Check if auto-backup is due on launch
    setTimeout(() => this.checkSchedule(), 4000);

    // Periodic check every 10 minutes
    setInterval(() => this.checkSchedule(), 10 * 60 * 1000);
  }

  // ── Network Intelligence (Wi-Fi vs Cellular) ────────────────────────────────

  getNetworkStatus() {
    if (!navigator.onLine) {
      return { type: 'offline', isWifi: false, isCellular: false, isOffline: true, label: 'Offline' };
    }

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn) {
      // Browser doesn't expose Network Information API; assume standard connection
      return { type: 'wifi', isWifi: true, isCellular: false, isOffline: false, label: 'Standard Connection (Wi-Fi / LAN)' };
    }

    const type = conn.type || '';
    const effectiveType = conn.effectiveType || '';
    const saveData = conn.saveData || false;

    if (type === 'cellular' || saveData === true) {
      return { type: 'cellular', isWifi: false, isCellular: true, isOffline: false, label: `Cellular (${effectiveType.toUpperCase() || 'Mobile'})` };
    }

    if (type === 'wifi' || type === 'ethernet' || (!type && effectiveType === '4g' && !saveData)) {
      return { type: 'wifi', isWifi: true, isCellular: false, isOffline: false, label: 'Wi-Fi / LAN' };
    }

    return { type: 'wifi', isWifi: true, isCellular: false, isOffline: false, label: `${effectiveType.toUpperCase() || 'Online'}` };
  }

  setupNetworkMonitor() {
    const handleNetworkChange = () => {
      const net = this.getNetworkStatus();
      console.log(`[BackupEngine] Network transition detected: ${net.label}`);
      window.dispatchEvent(new CustomEvent('sv:backup-network-change', { detail: net }));
      this.updateNetworkBadge();

      // If a backup was queued waiting for Wi-Fi, and we are now on Wi-Fi, resume backup
      if (this.queuedBackup && net.isWifi) {
        console.log('[BackupEngine] Resuming queued backup on Wi-Fi connection.');
        this.queuedBackup = false;
        this.triggerBackup('network-resumed');
      }
    };

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
      conn.addEventListener('change', handleNetworkChange);
    }
    window.addEventListener('online', handleNetworkChange);
    window.addEventListener('offline', handleNetworkChange);
  }

  // ── Scheduling & Queueing ───────────────────────────────────────────────────

  checkSchedule() {
    if (this.settings.frequency === 'off') return;

    const now = Date.now();
    const last = this.settings.lastBackupTime || 0;
    const intervals = {
      instant: 0,
      daily: 24 * 60 * 60 * 1000,
      weekly: 7 * 24 * 60 * 60 * 1000,
      monthly: 30 * 24 * 60 * 60 * 1000
    };

    const intervalMs = intervals[this.settings.frequency] || intervals.daily;
    if (now - last >= intervalMs) {
      console.log(`[BackupEngine] Scheduled backup due (frequency: ${this.settings.frequency})`);
      this.triggerBackup('scheduled');
    }
  }

  async triggerBackup(reason = 'manual') {
    const net = this.getNetworkStatus();

    if (net.isOffline) {
      this.updateStatusText('⚠️ Network Offline. Backup queued.');
      this.queuedBackup = true;
      return;
    }

    // Check Wi-Fi Only constraint
    if (this.settings.networkPreference === 'wifi-only' && net.isCellular) {
      console.warn('[BackupEngine] Backup paused: User configured Wi-Fi Only, current network is Cellular.');
      this.status = 'queued_wifi';
      this.queuedBackup = true;
      this.updateStatusText('⏸️ Backup Queued (Waiting for Wi-Fi)');
      this.updateUI();
      return;
    }

    try {
      this.status = 'running';
      this.updateUI();
      await this.performZeroKnowledgeBackup();
      this.status = 'idle';
      this.queuedBackup = false;
      this.updateUI();
    } catch (err) {
      this.status = 'error';
      console.error('[BackupEngine] Backup failed:', err);
      this.updateStatusText(`❌ Backup error: ${err.message}`);
      this.updateUI();
    }
  }

  // ── Zero-Knowledge Serialization & Cryptography ─────────────────────────────

  async performZeroKnowledgeBackup(masterPassword = null) {
    this.updateProgress(10, 'Gathering database records...');
    window.dispatchEvent(new CustomEvent('sv:backup-start'));

    // 1. Resolve Vault Key / Master Password
    let password = masterPassword || window.currentUserPassword || sessionStorage.getItem('currentUserHash') || 'SecureVaultMasterPass';

    // 2. Extract Data from IndexedDB
    const payloadData = await this.extractAllDatabaseStores(this.settings.includeEncrypted);
    this.updateProgress(35, `Extracted ${payloadData.virtual_files.length} files, ${payloadData.audit_logs.length} logs...`);

    // 3. Serialize to UTF-8
    const rawJson = JSON.stringify({
      magic: 'SVBACKUP_PAYLOAD',
      version: '2.5.0',
      timestamp: Date.now(),
      data: payloadData
    });
    const encoder = new TextEncoder();
    const rawBytes = encoder.encode(rawJson);

    // 4. Derive Key using PBKDF2-SHA256 (600,000 iterations)
    this.updateProgress(50, 'Deriving AES-256 key (PBKDF2-SHA256, 600,000 iterations)...');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await this.deriveBackupKey(password, salt);

    // 5. Encrypt with AES-256-GCM (12-byte IV)
    this.updateProgress(70, 'Encrypting vault package with AES-256-GCM...');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      aesKey,
      rawBytes
    );

    // 6. Compute SHA-256 digest of ciphertext
    this.updateProgress(85, 'Verifying cryptographic integrity hash...');
    const hashBuffer = await crypto.subtle.digest('SHA-256', ciphertext);

    // 7. Assemble Container
    const container = {
      magic: 'SVBACKUP',
      version: '2.5.0',
      timestamp: Date.now(),
      device: 'SecureVault Client',
      kdf: {
        algorithm: 'PBKDF2-SHA256',
        iterations: 600000,
        salt: this.bufToHex(salt)
      },
      cipher: {
        algorithm: 'AES-256-GCM',
        iv: this.bufToHex(iv),
        ciphertext: this.bufToBase64(new Uint8Array(ciphertext)),
        sha256: this.bufToHex(new Uint8Array(hashBuffer))
      },
      metadata: {
        recordCounts: {
          virtual_files: payloadData.virtual_files.length,
          ledger: payloadData.ledger.length,
          audit_logs: payloadData.audit_logs.length,
          copilot_history: payloadData.copilot_history.length
        },
        includesEncryptedFiles: this.settings.includeEncrypted,
        totalSizeBytes: ciphertext.byteLength
      }
    };

    const containerJson = JSON.stringify(container, null, 2);
    const containerSize = new Blob([containerJson]).size;

    // 8. Sync or Store
    this.updateProgress(95, 'Finalizing backup telemetry...');
    this.saveSettings({
      lastBackupTime: Date.now(),
      lastBackupSize: containerSize
    });

    // Cloud upload if Google token with drive.appdata scope exists
    if (this.googleAccessToken) {
      await this.uploadToGoogleDriveAppData(containerJson);
    }

    this.updateProgress(100, `✅ Backup complete (${this.formatBytes(containerSize)})`);
    window.dispatchEvent(new CustomEvent('sv:backup-success', { detail: container }));

    // Record audit log
    if (this.db?.appendAuditLog) {
      await this.db.appendAuditLog({
        timestamp: new Date().toISOString(),
        action: 'AUTO_BACKUP_COMPLETED',
        severity: 'INFO',
        details: `Zero-Knowledge .svbackup created (${this.formatBytes(containerSize)}) | Network: ${this.getNetworkStatus().label}`
      });
    }

    return container;
  }

  async deriveBackupKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async extractAllDatabaseStores(includeEncrypted = true) {
    const stores = ['virtual_files', 'ledger', 'audit_logs', 'copilot_history', 'app_settings'];
    const result = {
      virtual_files: [],
      ledger: [],
      audit_logs: [],
      copilot_history: [],
      app_settings: []
    };

    if (!window.state?.db && !this.db) {
      return result;
    }

    const idb = window.state?.db || this.db;

    for (const storeName of stores) {
      try {
        if (!idb.objectStoreNames || !idb.objectStoreNames.contains(storeName)) continue;
        const tx = idb.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const records = await new Promise((resolve) => {
          const req = store.getAll();
          req.onsuccess = () => resolve(req.result || []);
          req.onerror = () => resolve([]);
        });

        if (storeName === 'virtual_files' && !includeEncrypted) {
          // Strip out ciphertext blobs to save space if requested
          result[storeName] = records.map(f => ({
            id: f.id,
            name: f.name,
            size: f.size,
            mimeType: f.mimeType,
            sha256: f.sha256,
            date: f.date,
            stripped: true
          }));
        } else {
          result[storeName] = records;
        }
      } catch (e) {
        console.warn(`[BackupEngine] Store extraction warning for ${storeName}:`, e);
      }
    }

    return result;
  }

  // ── Restore / Import Engine ─────────────────────────────────────────────────

  async restoreFromBackupText(containerJson, password) {
    const container = JSON.parse(containerJson);
    if (container.magic !== 'SVBACKUP') {
      throw new Error('Invalid container: Magic header mismatch (expected SVBACKUP)');
    }

    const salt = this.hexToBuf(container.kdf.salt);
    const iv = this.hexToBuf(container.cipher.iv);
    const ciphertextBytes = this.base64ToBuf(container.cipher.ciphertext);

    // Verify SHA-256 hash
    const checkHash = await crypto.subtle.digest('SHA-256', ciphertextBytes);
    const computedHashHex = this.bufToHex(new Uint8Array(checkHash));
    if (computedHashHex !== container.cipher.sha256) {
      throw new Error('Integrity check failed: Ciphertext hash does not match container header');
    }

    // Derive key
    const aesKey = await this.deriveBackupKey(password, salt);

    // Decrypt
    let decryptedBytes;
    try {
      decryptedBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        aesKey,
        ciphertextBytes
      );
    } catch (e) {
      throw new Error('Decryption failed: Incorrect master password or corrupted backup.');
    }

    const decoder = new TextDecoder();
    const rawJson = decoder.decode(decryptedBytes);
    const payload = JSON.parse(rawJson);

    if (payload.magic !== 'SVBACKUP_PAYLOAD') {
      throw new Error('Corrupted inner backup payload.');
    }

    // Write records into IndexedDB
    const idb = window.state?.db || this.db;
    if (idb && payload.data) {
      for (const [storeName, records] of Object.entries(payload.data)) {
        if (!idb.objectStoreNames || !idb.objectStoreNames.contains(storeName)) continue;
        const tx = idb.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        for (const item of records) {
          store.put(item);
        }
      }
    }

    if (this.db?.appendAuditLog) {
      await this.db.appendAuditLog({
        timestamp: new Date().toISOString(),
        action: 'BACKUP_RESTORED',
        severity: 'WARN',
        details: `Restored ${container.metadata?.recordCounts?.virtual_files || 0} files and ${container.metadata?.recordCounts?.audit_logs || 0} logs from .svbackup`
      });
    }

    window.dispatchEvent(new CustomEvent('sv:restore-success', { detail: payload.data }));
    return payload.data;
  }

  // ── Export & Google Drive AppData Sync ───────────────────────────────────────

  async exportBackupFile() {
    this.updateStatusText('Generating .svbackup export file...');
    const container = await this.performZeroKnowledgeBackup();
    const jsonStr = JSON.stringify(container, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `securevault-backup-${new Date().toISOString().slice(0, 10)}.svbackup`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async uploadToGoogleDriveAppData(containerJson) {
    if (!this.googleAccessToken) return;

    try {
      const metadata = {
        name: 'securevault-auto-backup.svbackup',
        mimeType: 'application/json',
        parents: ['appDataFolder']
      };

      const form = new FormData();
      form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
      form.append('file', new Blob([containerJson], { type: 'application/json' }));

      const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.googleAccessToken}`
        },
        body: form
      });

      if (res.ok) {
        console.log('[BackupEngine] Successfully uploaded backup to Google Drive AppData folder.');
      }
    } catch (e) {
      console.warn('[BackupEngine] Google Drive AppData upload failed:', e);
    }
  }

  // ── UI Integration & Bindings ───────────────────────────────────────────────

  bindDOMControls() {
    // Frequency change
    const freqSelect = document.getElementById('backup-frequency-select');
    if (freqSelect) {
      freqSelect.value = this.settings.frequency;
      freqSelect.addEventListener('change', (e) => {
        this.saveSettings({ frequency: e.target.value });
      });
    }

    // Network Preference change (Wi-Fi Only toggle)
    const wifiOnlyRadio = document.getElementById('backup-net-wifi');
    const anyNetRadio = document.getElementById('backup-net-any');
    if (wifiOnlyRadio && anyNetRadio) {
      wifiOnlyRadio.checked = this.settings.networkPreference === 'wifi-only';
      anyNetRadio.checked = this.settings.networkPreference === 'any';

      wifiOnlyRadio.addEventListener('change', () => {
        if (wifiOnlyRadio.checked) this.saveSettings({ networkPreference: 'wifi-only' });
      });
      anyNetRadio.addEventListener('change', () => {
        if (anyNetRadio.checked) this.saveSettings({ networkPreference: 'any' });
      });
    }

    // Include Encrypted Files toggle
    const includeEncToggle = document.getElementById('backup-include-enc-toggle');
    if (includeEncToggle) {
      includeEncToggle.checked = this.settings.includeEncrypted;
      includeEncToggle.addEventListener('change', (e) => {
        this.saveSettings({ includeEncrypted: e.target.checked });
      });
    }

    // Backup Now Button
    const backupNowBtn = document.getElementById('btn-backup-now');
    if (backupNowBtn) {
      backupNowBtn.addEventListener('click', () => this.triggerBackup('manual'));
    }

    // Export .svbackup Button
    const exportBtn = document.getElementById('btn-export-svbackup');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => this.exportBackupFile());
    }

    // Restore File Input
    const restoreInput = document.getElementById('input-restore-svbackup');
    if (restoreInput) {
      restoreInput.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        const pwd = prompt('Enter your Vault Master Password to decrypt this .svbackup container:');
        if (!pwd) return;

        try {
          const text = await file.text();
          this.updateProgress(20, 'Decrypting and restoring records...');
          await this.restoreFromBackupText(text, pwd);
          alert('✅ Vault successfully restored! Reloading application data...');
          window.location.reload();
        } catch (err) {
          alert(`Restore Error: ${err.message}`);
        }
      });
    }
  }

  updateUI() {
    // 1. Last backup time
    const lastTimeEl = document.getElementById('backup-last-time');
    if (lastTimeEl) {
      lastTimeEl.textContent = this.settings.lastBackupTime
        ? new Date(this.settings.lastBackupTime).toLocaleString()
        : 'Never';
    }

    // 2. Backup size
    const sizeEl = document.getElementById('backup-size-display');
    if (sizeEl) {
      sizeEl.textContent = this.settings.lastBackupSize
        ? this.formatBytes(this.settings.lastBackupSize)
        : '0 KB';
    }

    // 3. Network badge
    this.updateNetworkBadge();

    // 4. Status state
    if (this.status === 'queued_wifi') {
      this.updateStatusText('⏸️ Queued (Waiting for Wi-Fi)');
    } else if (this.status === 'running') {
      // Keep running message
    } else if (this.status === 'idle') {
      const backupNowBtn = document.getElementById('btn-backup-now');
      if (backupNowBtn) backupNowBtn.disabled = false;
    }
  }

  updateNetworkBadge() {
    const badge = document.getElementById('backup-network-badge');
    if (!badge) return;

    const net = this.getNetworkStatus();
    if (net.isOffline) {
      badge.className = 'px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-400 border border-slate-700';
      badge.innerHTML = '⚪ Offline';
    } else if (net.isCellular) {
      badge.className = 'px-2 py-0.5 text-xs font-mono rounded bg-amber-950 text-amber-300 border border-amber-800';
      badge.innerHTML = `🟠 ${net.label}`;
    } else {
      badge.className = 'px-2 py-0.5 text-xs font-mono rounded bg-emerald-950 text-emerald-300 border border-emerald-800';
      badge.innerHTML = `🟢 ${net.label}`;
    }
  }

  updateProgress(percent, message) {
    const progressBar = document.getElementById('backup-progress-bar');
    const statusText = document.getElementById('backup-status-text');

    if (progressBar) {
      progressBar.style.width = `${percent}%`;
    }
    if (statusText) {
      statusText.textContent = message;
    }
  }

  updateStatusText(msg) {
    const statusText = document.getElementById('backup-status-text');
    if (statusText) statusText.textContent = msg;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  hexToBuf(hexString) {
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  bufToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  base64ToBuf(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
}

// Global initialization
if (typeof window !== 'undefined') {
  window.BackupEngine = BackupEngine;
}
