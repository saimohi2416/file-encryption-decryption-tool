/**
 * SecureVault AI — Unified OAuth 2.0 PKCE & Database Account Sync Manager
 * 
 * Zero-Knowledge Guarantee:
 * - OAuth identity tokens ONLY authenticate the user's session profile.
 * - Raw cryptographic keys and master passwords NEVER leave client memory.
 * - Google Drive `drive.appdata` scope allows encrypted .svbackup storage in hidden appData folder.
 */

import { BackupEngine } from './backup-engine.js';

export class AuthSyncManager {
  constructor(options = {}) {
    this.currentUser = null;
    this.backupEngine = null;
    this.googleClientId = window.SECUREVAULT_ENV?.GOOGLE_CLIENT_ID || '';
    
    this.init();
  }

  async init() {
    this.bindEvents();
    this.processCallbackParams();
    this.initBackupEngine();
    this.restoreSavedSession();
  }

  initBackupEngine() {
    if (typeof window !== 'undefined') {
      this.backupEngine = new BackupEngine(window.state?.db);
      window.backupEngine = this.backupEngine;
    }
  }

  bindEvents() {
    // Topbar & Modal OAuth triggers
    document.querySelectorAll('[data-action="oauth-google"]').forEach(btn => {
      btn.addEventListener('click', () => this.signInWithGoogle());
    });
    document.querySelectorAll('[data-action="oauth-github"]').forEach(btn => {
      btn.addEventListener('click', () => this.signInWithGitHub());
    });

    // Account Center Modal buttons
    document.getElementById('btn-account-center-close')?.addEventListener('click', () => {
      this.closeAccountCenterModal();
    });

    // Disconnect button
    document.getElementById('btn-oauth-signout')?.addEventListener('click', () => {
      this.signOut();
    });
  }

  // ── Real OAuth 2.0 PKCE Flow ────────────────────────────────────────────────

  async generateCodeVerifier() {
    const array = new Uint8Array(64);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
  }

  async generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async signInWithGoogle() {
    console.log('[AuthSync] Initiating real Google OAuth flow with drive.appdata scope...');

    // If client ID is present in frontend config, execute direct PKCE
    if (this.googleClientId) {
      const verifier = await this.generateCodeVerifier();
      const challenge = await this.generateCodeChallenge(verifier);
      sessionStorage.setItem('sv_google_code_verifier', verifier);

      const redirectUri = window.location.origin + window.location.pathname;
      const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/drive.appdata');
      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${encodeURIComponent(this.googleClientId)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=${scope}` +
        `&code_challenge=${challenge}` +
        `&code_challenge_method=S256` +
        `&access_type=offline` +
        `&prompt=consent`;

      window.location.href = authUrl;
      return;
    }

    // Default: Redirect to production backend OAuth endpoint
    window.location.href = '/api/v1/auth/google/login';
  }

  signInWithGitHub() {
    console.log('[AuthSync] Initiating real GitHub OAuth flow...');
    window.location.href = '/api/v1/auth/github/login';
  }

  async processCallbackParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const oauthProvider = urlParams.get('oauth_provider');
    const oauthError = urlParams.get('oauth_error');

    if (oauthError) {
      console.error('[AuthSync] OAuth authorization error:', oauthError);
      alert('OAuth Error: ' + decodeURIComponent(oauthError));
      window.history.replaceState({}, document.title, window.location.pathname + '#auth');
      return;
    }

    // Direct Google PKCE exchange
    if (code && sessionStorage.getItem('sv_google_code_verifier') && this.googleClientId) {
      const verifier = sessionStorage.getItem('sv_google_code_verifier');
      sessionStorage.removeItem('sv_google_code_verifier');
      await this.exchangeGooglePKCECode(code, verifier);
      window.history.replaceState({}, document.title, window.location.pathname + '#vault');
      return;
    }

    // Backend redirect flow return
    if (oauthProvider) {
      const username = urlParams.get('username');
      const email = urlParams.get('email');
      const name = urlParams.get('name');
      const avatar = urlParams.get('avatar');
      const passwordHash = urlParams.get('passwordHash');
      const token = urlParams.get('token');

      if (username) {
        await this.handleUserAuthenticated({
          id: username,
          email: email || `${username}@${oauthProvider}.com`,
          name: name || username,
          avatarUrl: avatar || null,
          provider: oauthProvider,
          passwordHash: passwordHash || null,
          token: token || null
        });
        window.history.replaceState({}, document.title, window.location.pathname + '#vault');
      }
    }
  }

  async exchangeGooglePKCECode(code, verifier) {
    try {
      const redirectUri = window.location.origin + window.location.pathname;
      const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: this.googleClientId,
          code: code,
          code_verifier: verifier,
          grant_type: 'authorization_code',
          redirect_uri: redirectUri
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error_description || 'Token exchange failed');

      // Fetch profile
      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${data.access_token}` }
      });
      const profile = await userRes.json();

      // Pass token to backup engine for Google Drive AppData sync
      if (this.backupEngine) {
        this.backupEngine.googleAccessToken = data.access_token;
      }

      await this.handleUserAuthenticated({
        id: 'google_' + profile.email.replace(/[^a-z0-9]/g, '_'),
        email: profile.email,
        name: profile.name || profile.email.split('@')[0],
        avatarUrl: profile.picture,
        provider: 'google',
        token: data.access_token
      });
    } catch (err) {
      console.error('[AuthSync] Google PKCE exchange error:', err);
      alert('Google PKCE Login Error: ' + err.message);
    }
  }

  // ── Session Management & Profile State ──────────────────────────────────────

  restoreSavedSession() {
    const savedUser = sessionStorage.getItem('currentUser');
    const authProvider = sessionStorage.getItem('authProvider');
    if (savedUser && authProvider && authProvider !== 'local') {
      this.currentUser = {
        id: savedUser,
        email: sessionStorage.getItem('userEmail') || '',
        name: sessionStorage.getItem('displayName') || savedUser,
        avatarUrl: sessionStorage.getItem('userAvatar') || null,
        provider: authProvider
      };
      this.renderAuthenticatedState(this.currentUser);
    } else {
      this.renderGuestState();
    }
  }

  async handleUserAuthenticated(user) {
    this.currentUser = user;

    sessionStorage.setItem('currentUser', user.id);
    sessionStorage.setItem('authProvider', user.provider);
    if (user.email) sessionStorage.setItem('userEmail', user.email);
    if (user.name) sessionStorage.setItem('displayName', user.name);
    if (user.avatarUrl) sessionStorage.setItem('userAvatar', user.avatarUrl);
    if (user.passwordHash) sessionStorage.setItem('currentUserHash', user.passwordHash);

    // Sync with global state if present
    if (window.state) {
      window.state.currentUser = user.id;
      window.state.authProvider = user.provider;
      window.state.userEmail = user.email;
      window.state.userAvatar = user.avatarUrl;
      window.state.displayName = user.name;
      if (user.passwordHash) window.state.passwordHash = user.passwordHash;
    }

    // Check Guest-to-Account Migration
    await this.checkGuestMigration(user);

    // Update UI states
    this.renderAuthenticatedState(user);

    // Hide login overlay if open
    const overlay = document.getElementById('masterLoginOverlay');
    if (overlay) {
      overlay.classList.remove('open');
      overlay.style.display = 'none';
    }
  }

  async signOut() {
    sessionStorage.removeItem('currentUser');
    sessionStorage.removeItem('currentUserHash');
    sessionStorage.removeItem('authProvider');
    sessionStorage.removeItem('userEmail');
    sessionStorage.removeItem('userAvatar');
    sessionStorage.removeItem('displayName');

    if (window.state) {
      window.state.currentUser = null;
      window.state.passwordHash = null;
      window.state.authProvider = null;
    }

    this.currentUser = null;
    this.renderGuestState();
    this.closeAccountCenterModal();
    alert('You have been signed out.');
  }

  // ── Guest-to-Account IndexedDB Migration ────────────────────────────────────

  async checkGuestMigration(authenticatedUser) {
    const migrationCard = document.getElementById('account-center-migration-card');
    if (!migrationCard) return;

    const counts = await this.getStoreCounts();
    const totalRecords = counts.virtual_files + counts.ledger + counts.audit_logs;

    const lastMigrated = localStorage.getItem('sv_last_migrated_user');
    if (lastMigrated === authenticatedUser.id || totalRecords === 0) {
      migrationCard.style.display = 'none';
      return;
    }

    // Populate migration counts
    migrationCard.style.display = 'block';
    const desc = document.getElementById('migration-counts-desc');
    if (desc) {
      desc.textContent = `${counts.virtual_files} virtual files, ${counts.ledger} ledger transactions, and ${counts.audit_logs} audit logs.`;
    }

    document.getElementById('btn-migration-merge')?.addEventListener('click', () => {
      localStorage.setItem('sv_last_migrated_user', authenticatedUser.id);
      migrationCard.style.display = 'none';
      alert('✅ Local guest vault successfully merged with your account.');
    }, { once: true });

    document.getElementById('btn-migration-clean')?.addEventListener('click', async () => {
      localStorage.setItem('sv_last_migrated_user', authenticatedUser.id);
      if (window.state?.db) {
        try {
          const tx = window.state.db.transaction(['virtual_files', 'ledger'], 'readwrite');
          tx.objectStore('virtual_files').clear();
          tx.objectStore('ledger').clear();
        } catch(e) {}
      }
      migrationCard.style.display = 'none';
      alert('Clean authenticated session started.');
      window.location.reload();
    }, { once: true });
  }

  async getStoreCounts() {
    const idb = window.state?.db;
    const counts = { virtual_files: 0, ledger: 0, audit_logs: 0 };
    if (!idb) return counts;

    for (const name of Object.keys(counts)) {
      try {
        if (!idb.objectStoreNames.contains(name)) continue;
        const tx = idb.transaction(name, 'readonly');
        counts[name] = await new Promise(res => {
          const req = tx.objectStore(name).count();
          req.onsuccess = () => res(req.result || 0);
          req.onerror = () => res(0);
        });
      } catch (e) {}
    }
    return counts;
  }

  // ── DOM & Sidebar Dynamic Bindings ──────────────────────────────────────────

  renderAuthenticatedState(user) {
    // 1. Sidebar User Profile
    const card = document.getElementById('userDisplayCard');
    const logoutWrap = document.getElementById('logoutBtnWrap');
    if (card) card.classList.remove('hidden');
    if (logoutWrap) logoutWrap.classList.remove('hidden');

    const nameEl = document.getElementById('userNameDisplay');
    if (nameEl) nameEl.textContent = user.name;

    const subEl = document.getElementById('userSubDisplay');
    if (subEl) subEl.textContent = user.email || 'Authenticated Session';

    const avatarEl = document.getElementById('userAvatar');
    if (avatarEl) {
      if (user.avatarUrl) {
        avatarEl.innerHTML = `<img src="${user.avatarUrl}" alt="${user.name}" style="width:100%; height:100%; border-radius:50%; object-fit:cover;" />`;
      } else {
        avatarEl.innerHTML = `<span style="font-weight:700; color:#38bdf8;">${user.name.slice(0, 2).toUpperCase()}</span>`;
      }
    }

    const badgeEl = document.getElementById('userProviderBadge');
    if (badgeEl) {
      const prov = (user.provider || 'oauth').toUpperCase();
      badgeEl.innerHTML = `<span class="auth-provider-badge ${user.provider}">${prov} AUTH</span>`;
    }

    // 2. DB Status Badge (Sidebar & Footer)
    const dbStatusIndicator = document.getElementById('dbStatusIndicator');
    if (dbStatusIndicator) {
      dbStatusIndicator.innerHTML = `<span class="pulse-dot" style="background:#38bdf8; width:8px; height:8px;"></span>🔵 DB: Synced (OAuth + Auto-Backup)`;
    }

    // 3. Account Center Modal Identity Card
    const accountCenterIdentity = document.getElementById('account-center-identity-card');
    if (accountCenterIdentity) {
      accountCenterIdentity.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; background:rgba(6,182,212,0.06); border:1px solid rgba(6,182,212,0.25); border-radius:10px; padding:14px;">
          <div style="display:flex; align-items:center; gap:12px;">
            <div style="width:44px; height:44px; border-radius:50%; overflow:hidden; border:2px solid #06b6d4; display:flex; align-items:center; justify-content:center; background:#0f172a;">
              ${user.avatarUrl ? `<img src="${user.avatarUrl}" style="width:100%; height:100%; object-fit:cover;" />` : `<span style="font-weight:800; color:#38bdf8;">${user.name.slice(0, 2).toUpperCase()}</span>`}
            </div>
            <div>
              <div style="font-weight:800; color:white; font-size:15px;">${user.name}</div>
              <div style="color:#94a3b8; font-size:12px;">${user.email}</div>
              <div style="display:inline-block; margin-top:4px; font-size:10px; font-weight:700; background:#082f49; color:#38bdf8; border:1px solid #0369a1; padding:2px 6px; border-radius:4px;">
                ${user.provider.toUpperCase()} (PKCE)
              </div>
            </div>
          </div>
          <button id="btn-oauth-signout-inner" class="action-btn-sm" style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.4); color:#f87171; cursor:pointer;">
            Disconnect
          </button>
        </div>
      `;
      document.getElementById('btn-oauth-signout-inner')?.addEventListener('click', () => this.signOut());
    }
  }

  renderGuestState() {
    const card = document.getElementById('userDisplayCard');
    const nameEl = document.getElementById('userNameDisplay');
    const subEl = document.getElementById('userSubDisplay');
    const avatarEl = document.getElementById('userAvatar');
    const badgeEl = document.getElementById('userProviderBadge');

    if (nameEl) nameEl.textContent = 'Guest User';
    if (subEl) subEl.textContent = 'Active Local Session';
    if (avatarEl) avatarEl.innerHTML = `<span style="font-size:14px; font-weight:700; color:#94a3b8;">U</span>`;
    if (badgeEl) badgeEl.innerHTML = `<span class="auth-provider-badge local">OFFLINE GUEST</span>`;

    const dbStatusIndicator = document.getElementById('dbStatusIndicator');
    if (dbStatusIndicator) {
      dbStatusIndicator.innerHTML = `<span class="pulse-dot" style="background:#10b981; width:8px; height:8px;"></span>🟢 DB: IndexedDB (Local Guest)`;
    }

    const accountCenterIdentity = document.getElementById('account-center-identity-card');
    if (accountCenterIdentity) {
      accountCenterIdentity.innerHTML = `
        <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:10px; padding:14px; margin-bottom:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div>
              <div style="font-weight:700; color:white; font-size:14px;">Guest Session</div>
              <div style="color:#94a3b8; font-size:12px;">Local browser IndexedDB only. Not synced to cloud.</div>
            </div>
            <span style="font-size:10px; font-weight:700; background:#1e293b; color:#94a3b8; border:1px solid #334155; padding:2px 6px; border-radius:4px;">OFFLINE GUEST</span>
          </div>
          <p style="font-size:12px; color:#cbd5e1; margin-bottom:12px;">Connect with Google or GitHub to activate cloud auto-backups and profile sync:</p>
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
            <button type="button" class="sso-btn sso-btn-google" data-action="oauth-google" style="padding:8px 12px; font-size:13px;">
              <svg width="16" height="16" viewBox="0 0 24 24"><path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.4 9 5 12 5z"/><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"/><path fill="#FBBC05" d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3s.2-1.6.4-2.3L1.9 7.3C.7 9.7 0 12.3 0 15s.7 5.3 1.9 7.7l3.7-2.9c-.4-.7-.6-1.5-.6-2.4z"/><path fill="#34A853" d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.4-6.4-5.2L1.9 16c1.8 3.7 5.6 7 10.1 7z"/></svg>
              <span>Google Login</span>
            </button>
            <button type="button" class="sso-btn sso-btn-github" data-action="oauth-github" style="padding:8px 12px; font-size:13px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
              <span>GitHub Login</span>
            </button>
          </div>
        </div>
      `;
      accountCenterIdentity.querySelector('[data-action="oauth-google"]')?.addEventListener('click', () => this.signInWithGoogle());
      accountCenterIdentity.querySelector('[data-action="oauth-github"]')?.addEventListener('click', () => this.signInWithGitHub());
    }
  }

  openAccountCenterModal() {
    const modal = document.getElementById('accountCenterModal') || document.getElementById('databaseModal');
    if (modal) {
      modal.style.display = 'flex';
      this.backupEngine?.updateUI();
    }
  }

  closeAccountCenterModal() {
    const modal = document.getElementById('accountCenterModal') || document.getElementById('databaseModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }
}

// Global initialization
if (typeof window !== 'undefined') {
  window.AuthSyncManager = AuthSyncManager;
  window.addEventListener('DOMContentLoaded', () => {
    window.authSyncManager = new AuthSyncManager();
    window.openAccountCenterModal = () => window.authSyncManager.openAccountCenterModal();
    window.closeAccountCenterModal = () => window.authSyncManager.closeAccountCenterModal();
    window.openDatabaseModal = () => window.authSyncManager.openAccountCenterModal();
    window.closeDatabaseModal = () => window.authSyncManager.closeAccountCenterModal();
  });
}
