/**
 * SecureVault AI — Auto-Updater & Version Guard
 * Polls for new releases, respects active cryptographic operations,
 * and seamlessly reloads when safe.
 */

export class VersionUpdater {
  constructor(options = {}) {
    this.currentVersion = options.currentVersion || '2.5.0';
    this.pollIntervalMs = options.pollIntervalMs || 15 * 60 * 1000; // 15 minutes
    this.waitingWorker = null;
    this.updatePending = false;
    this.bannerEl = null;

    this.init();
  }

  async init() {
    this.registerServiceWorker();
    this.setupListeners();
    // Initial check after 3 seconds
    setTimeout(() => this.checkForUpdates(), 3000);
    // Recurring poll
    setInterval(() => this.checkForUpdates(), this.pollIntervalMs);
  }

  registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;

    navigator.serviceWorker.register('/sw.js').then((registration) => {
      console.log('[VersionGuard] Service Worker registered with scope:', registration.scope);

      // 1. Worker already waiting
      if (registration.waiting) {
        this.waitingWorker = registration.waiting;
        this.handleNewVersionDetected({ version: 'Latest' });
      }

      // 2. New worker installing
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        if (!newWorker) return;

        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            this.waitingWorker = newWorker;
            this.handleNewVersionDetected({ version: 'Latest' });
          }
        });
      });
    }).catch((err) => {
      console.warn('[VersionGuard] Service Worker registration failed:', err);
    });

    // Reload when new worker takes control
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (this.updatePending) {
        window.location.reload();
      }
    });
  }

  setupListeners() {
    // Check when user refocuses the tab
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        this.checkForUpdates();
      }
    });

    // Check when internet returns
    window.addEventListener('online', () => {
      this.checkForUpdates();
    });
  }

  async checkForUpdates() {
    try {
      const response = await fetch(`/version.json?_t=${Date.now()}`, {
        cache: 'no-store',
        headers: { 'Cache-Control': 'no-cache' }
      });
      if (!response.ok) return;

      const remoteData = await response.json();
      if (this.isNewerVersion(remoteData.version, this.currentVersion)) {
        console.log(`[VersionGuard] New version discovered: ${remoteData.version} (current: ${this.currentVersion})`);
        this.handleNewVersionDetected(remoteData);
      }
    } catch (e) {
      // Offline or network error
    }
  }

  isNewerVersion(remote, current) {
    if (!remote || !current) return false;
    const rParts = remote.split('.').map(n => parseInt(n, 10) || 0);
    const cParts = current.split('.').map(n => parseInt(n, 10) || 0);

    for (let i = 0; i < Math.max(rParts.length, cParts.length); i++) {
      const r = rParts[i] || 0;
      const c = cParts[i] || 0;
      if (r > c) return true;
      if (r < c) return false;
    }
    return false;
  }

  handleNewVersionDetected(versionInfo) {
    // Crypto Worker Safety Guard: Check if cryptographic operations are active
    if (window.isCryptoWorkerBusy === true) {
      console.warn('[VersionGuard] Cryptographic operation busy. Deferring reload prompt.');
      this.renderDeferredBanner(versionInfo);

      // Listen for safe idle event
      window.addEventListener('sv:crypto-idle', () => {
        console.log('[VersionGuard] Crypto worker returned to idle. Showing update banner.');
        this.renderUpdateBanner(versionInfo);
      }, { once: true });
      return;
    }

    this.renderUpdateBanner(versionInfo);
  }

  renderDeferredBanner(versionInfo) {
    let banner = document.getElementById('sv-update-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'sv-update-banner';
      document.body.prepend(banner);
    }

    banner.className = 'sv-update-banner sv-update-banner-deferred';
    banner.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; max-width:1200px; margin:0 auto; font-size:12px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#f59e0b; animation:pulse 1.5s infinite;"></span>
          <span>⏳ <strong>Update Ready (v${versionInfo.version || '2.5.0'})</strong> — Update deferred until current file encryption/decryption finishes.</span>
        </div>
        <span style="font-size:11px; opacity:0.8; font-mono;">Safe Guard Active</span>
      </div>
    `;
    banner.style.display = 'block';
  }

  renderUpdateBanner(versionInfo) {
    let banner = document.getElementById('sv-update-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'sv-update-banner';
      document.body.prepend(banner);
    }

    banner.className = 'sv-update-banner sv-update-banner-ready';
    banner.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; max-width:1200px; margin:0 auto; font-size:13px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <span style="font-size:16px;">🚀</span>
          <span><strong>SecureVault AI Update (v${versionInfo.version || '2.5.0'}) Available!</strong> Zero-Knowledge auto-backup & security patches ready.</span>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <button id="sv-btn-dismiss-update" style="background:transparent; border:1px solid rgba(255,255,255,0.2); color:#cbd5e1; padding:4px 10px; border-radius:6px; font-size:12px; cursor:pointer;">
            Later
          </button>
          <button id="sv-btn-apply-update" style="background:#06b6d4; border:none; color:black; font-weight:700; padding:6px 14px; border-radius:6px; font-size:12px; cursor:pointer; box-shadow:0 0 10px rgba(6,182,212,0.5);">
            Update Now
          </button>
        </div>
      </div>
    `;
    banner.style.display = 'block';

    document.getElementById('sv-btn-dismiss-update')?.addEventListener('click', () => {
      banner.style.display = 'none';
    });

    document.getElementById('sv-btn-apply-update')?.addEventListener('click', () => {
      this.applyUpdate();
    });
  }

  applyUpdate() {
    this.updatePending = true;
    const btn = document.getElementById('sv-btn-apply-update');
    if (btn) {
      btn.textContent = 'Updating...';
      btn.disabled = true;
    }

    if (this.waitingWorker) {
      this.waitingWorker.postMessage({ action: 'SKIP_WAITING' });
    }

    // Give service worker 500ms to activate, then reload
    setTimeout(() => {
      window.location.reload();
    }, 500);
  }
}

// Global initialization
if (typeof window !== 'undefined') {
  window.versionUpdater = new VersionUpdater();
}
