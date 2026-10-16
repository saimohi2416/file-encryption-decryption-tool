/**
 * SecureVault AI — OAuth 2.0 PKCE & Dynamic Session Manager
 * Zero-Knowledge Guarantee: OAuth tokens & profiles manage identity ONLY.
 * Encryption keys never leave the client or tie to remote auth tokens.
 */

// Initialize Supabase Auth client (replace with your Vercel/Supabase public keys or config)
const SUPABASE_URL = window.SECUREVAULT_ENV?.SUPABASE_URL || 'https://YOUR_PROJECT_ID.supabase.co';
const SUPABASE_ANON_KEY = window.SECUREVAULT_ENV?.SUPABASE_ANON_KEY || 'YOUR_ANON_PUBLIC_KEY';

export class AuthManager {
  constructor(dbManager, migrationManager) {
    this.db = dbManager;
    this.migration = migrationManager;
    this.currentUser = null;
    this.supabase = null;
    this.initSupabase();
  }

  initSupabase() {
    if (window.supabase && window.supabase.createClient) {
      this.supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    } else {
      console.warn('[AuthManager] Supabase JS SDK not detected on window. Loading dynamically...');
    }
  }

  async initSession() {
    if (!this.supabase) return this.renderGuestState();

    // 1. Check existing active session
    const { data: { session }, error } = await this.supabase.auth.getSession();
    if (error) {
      console.error('[AuthManager] Session fetch error:', error);
      return this.renderGuestState();
    }

    if (session?.user) {
      await this.handleUserAuthenticated(session.user);
    } else {
      this.renderGuestState();
    }

    // 2. Listen for auth state transitions (Sign-in, Sign-out, Token Refresh)
    this.supabase.auth.onAuthStateChange(async (event, session) => {
      if (event === 'SIGNED_IN' && session?.user) {
        await this.handleUserAuthenticated(session.user);
      } else if (event === 'SIGNED_OUT') {
        this.renderGuestState();
      }
    });
  }

  /**
   * Triggers real PKCE OAuth redirect with Google or GitHub
   * @param {'google' | 'github'} provider 
   */
  async signInWithOAuth(provider) {
    if (!this.supabase) {
      // Direct redirect fallback to backend OAuth endpoint if Supabase is not configured
      window.location.href = `/api/v1/auth/${provider}/login`;
      return;
    }

    const { error } = await this.supabase.auth.signInWithOAuth({
      provider: provider,
      options: {
        redirectTo: window.location.origin + window.location.pathname,
        queryParams: {
          access_type: 'offline',
          prompt: 'consent',
        }
      }
    });

    if (error) {
      console.error(`[AuthManager] ${provider} OAuth error:`, error.message);
      if (this.db?.logAudit) {
        this.db.logAudit('OAUTH_LOGIN_FAILED', 'WARN', `${provider}: ${error.message}`);
      }
      alert(`OAuth Login Failed: ${error.message}`);
    }
  }

  async signOut() {
    if (this.supabase) {
      await this.supabase.auth.signOut();
    }
    this.currentUser = null;
    this.renderGuestState();
    if (this.db?.logAudit) {
      this.db.logAudit('OAUTH_LOGOUT', 'INFO', 'User signed out from OAuth identity layer');
    }
  }

  async handleUserAuthenticated(user) {
    this.currentUser = {
      id: user.id,
      email: user.email,
      name: user.user_metadata?.full_name || user.user_metadata?.name || user.email.split('@')[0],
      avatar_url: user.user_metadata?.avatar_url || null,
      provider: user.app_metadata?.provider || 'oauth'
    };

    // Trigger Guest-to-Account Migration Prompt if local guest records exist
    if (this.migration) {
      await this.migration.checkAndPromptMigration(this.currentUser);
    }

    this.renderAuthenticatedState(this.currentUser);
  }

  renderAuthenticatedState(user) {
    // 1. Sidebar Profile Card Update
    const userAvatarEl = document.getElementById('sidebar-user-avatar') || document.getElementById('userAvatar');
    const userNameEl = document.getElementById('sidebar-user-name') || document.getElementById('userNameDisplay');
    const userEmailEl = document.getElementById('sidebar-user-email') || document.getElementById('userSubDisplay');
    const userBadgeEl = document.getElementById('sidebar-user-badge') || document.getElementById('userProviderBadge');

    if (userAvatarEl) {
      if (user.avatar_url) {
        userAvatarEl.innerHTML = `<img src="${user.avatar_url}" alt="${user.name}" class="w-full h-full rounded-full object-cover border border-cyan-500/50" />`;
      } else {
        userAvatarEl.innerHTML = `<span class="text-xs font-bold text-cyan-300">${user.name.substring(0, 2).toUpperCase()}</span>`;
      }
    }

    if (userNameEl) userNameEl.textContent = user.name;
    if (userEmailEl) userEmailEl.textContent = user.email;
    if (userBadgeEl) {
      userBadgeEl.className = 'px-2 py-0.5 text-[10px] font-semibold rounded bg-cyan-950 text-cyan-400 border border-cyan-800';
      userBadgeEl.textContent = `${user.provider.toUpperCase()} AUTH`;
    }

    // 2. Database & Account Center Modal Update
    const accountCenterStatus = document.getElementById('account-center-status');
    if (accountCenterStatus) {
      accountCenterStatus.innerHTML = `
        <div class="flex items-center justify-between p-3 bg-slate-900 border border-cyan-800/60 rounded-lg">
          <div class="flex items-center space-x-3">
            <span class="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-glow-cyan"></span>
            <div>
              <p class="text-sm font-medium text-white">${user.email}</p>
              <p class="text-xs text-slate-400">Authenticated via ${user.provider.toUpperCase()} (PKCE)</p>
            </div>
          </div>
          <button id="btn-oauth-signout" class="px-3 py-1 text-xs text-rose-400 border border-rose-800 hover:bg-rose-950 rounded transition">
            Disconnect
          </button>
        </div>
      `;
      document.getElementById('btn-oauth-signout')?.addEventListener('click', () => this.signOut());
    }

    // 3. Resolve bottom-left DB badge
    const dbStatusBadge = document.getElementById('db-status-badge') || document.getElementById('dbStatusIndicator');
    if (dbStatusBadge) {
      dbStatusBadge.innerHTML = `<span class="inline-block w-2 h-2 rounded-full bg-cyan-400 mr-1.5 animate-pulse"></span>🔵 DB: Synced (OAuth + IndexedDB)`;
      dbStatusBadge.className = 'text-xs px-2.5 py-1 rounded bg-slate-900 border border-cyan-800 text-cyan-300 font-mono flex items-center';
    }
  }

  renderGuestState() {
    const userAvatarEl = document.getElementById('sidebar-user-avatar') || document.getElementById('userAvatar');
    const userNameEl = document.getElementById('sidebar-user-name') || document.getElementById('userNameDisplay');
    const userEmailEl = document.getElementById('sidebar-user-email') || document.getElementById('userSubDisplay');
    const userBadgeEl = document.getElementById('sidebar-user-badge') || document.getElementById('userProviderBadge');

    if (userAvatarEl) userAvatarEl.innerHTML = `<span class="text-sm font-bold text-slate-400">U</span>`;
    if (userNameEl) userNameEl.textContent = 'Guest User';
    if (userEmailEl) userEmailEl.textContent = 'Active Local Session';
    if (userBadgeEl) {
      userBadgeEl.className = 'px-2 py-0.5 text-[10px] font-semibold rounded bg-slate-800 text-slate-400 border border-slate-700';
      userBadgeEl.textContent = 'OFFLINE GUEST';
    }

    const accountCenterStatus = document.getElementById('account-center-status');
    if (accountCenterStatus) {
      accountCenterStatus.innerHTML = `
        <div class="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <p class="text-xs text-slate-400">Current Account: <strong class="text-white">Guest User</strong></p>
          <p class="text-[11px] text-slate-500 mt-1">Connect your Google or GitHub account to sync settings and audit logs.</p>
        </div>
      `;
    }

    const dbStatusBadge = document.getElementById('db-status-badge') || document.getElementById('dbStatusIndicator');
    if (dbStatusBadge) {
      dbStatusBadge.innerHTML = `<span class="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-1.5"></span>🟢 DB: IndexedDB (Local Guest)`;
      dbStatusBadge.className = 'text-xs px-2.5 py-1 rounded bg-slate-900 border border-emerald-800 text-emerald-300 font-mono flex items-center';
    }
  }
}
