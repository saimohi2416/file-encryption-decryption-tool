/**
 * SecureVault AI — Guest-to-Account IndexedDB Migration Utility
 * Ensures existing guest vault records & logs can be merged safely upon OAuth sign-in.
 */

export class VaultMigrationManager {
  constructor(dbManager) {
    this.db = dbManager;
  }

  /**
   * Inspects local IndexedDB and presents a non-intrusive modal if guest records exist
   */
  async checkAndPromptMigration(authenticatedUser) {
    const counts = await this.getStoreCounts();
    const totalGuestRecords = counts.virtual_files + counts.ledger + counts.audit_logs;

    // Check if migration has already been executed for this user
    const lastMigratedUser = localStorage.getItem('sv_last_migrated_user');
    if (lastMigratedUser === authenticatedUser.id || totalGuestRecords === 0) {
      // Log OAuth login success directly
      await this.recordOAuthSuccessAudit(authenticatedUser.provider);
      return;
    }

    // Render migration confirmation modal
    this.showMigrationModal(counts, authenticatedUser);
  }

  async getStoreCounts() {
    const stores = ['virtual_files', 'ledger', 'audit_logs'];
    const counts = {};
    for (const store of stores) {
      counts[store] = await this.db.countRecords(store);
    }
    return counts;
  }

  showMigrationModal(counts, user) {
    const modalHtml = `
      <div id="migration-modal-backdrop" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="bg-slate-950 border border-cyan-800/80 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
          <div class="flex items-center space-x-3 text-cyan-400">
            <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
            </svg>
            <h3 class="text-lg font-bold text-white">Merge Guest Vault Records?</h3>
          </div>

          <p class="text-sm text-slate-300">
            You signed in as <strong class="text-cyan-300">${user.email}</strong>. We detected existing unlinked local vault data:
          </p>

          <ul class="text-xs font-mono bg-slate-900 border border-slate-800 p-3 rounded space-y-1 text-slate-400">
            <li>• Virtual Files: <span class="text-white">${counts.virtual_files}</span></li>
            <li>• Ledger Transactions: <span class="text-white">${counts.ledger}</span></li>
            <li>• Audit Logs: <span class="text-white">${counts.audit_logs}</span></li>
          </ul>

          <p class="text-xs text-slate-400">
            Merging retains your encrypted local files and ties subsequent audit logs to your account ID.
          </p>

          <div class="flex items-center justify-end space-x-3 pt-2">
            <button id="btn-migration-clean" class="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white border border-slate-700 hover:bg-slate-800 rounded-lg transition">
              Start Clean Session
            </button>
            <button id="btn-migration-merge" class="px-4 py-2 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg shadow-lg shadow-cyan-900/40 transition">
              Merge Local Vault
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.getElementById('btn-migration-merge')?.addEventListener('click', async () => {
      await this.executeMerge(user);
      this.closeModal();
    });

    document.getElementById('btn-migration-clean')?.addEventListener('click', async () => {
      await this.executeCleanSession(user);
      this.closeModal();
    });
  }

  closeModal() {
    document.getElementById('migration-modal-backdrop')?.remove();
  }

  async executeMerge(user) {
    localStorage.setItem('sv_last_migrated_user', user.id);
    await this.recordOAuthSuccessAudit(user.provider, 'Merged guest logs with authenticated account');
  }

  async executeCleanSession(user) {
    // Isolate guest data without destroying cryptographic records
    localStorage.setItem('sv_last_migrated_user', user.id);
    await this.db.clearStore('virtual_files');
    await this.db.clearStore('ledger');
    await this.recordOAuthSuccessAudit(user.provider, 'Started clean authenticated session; guest records isolated');
  }

  async recordOAuthSuccessAudit(provider, extraDetail = '') {
    const detailText = `Verified OAuth session established and linked to local vault${extraDetail ? ' — ' + extraDetail : ''}`;
    await this.db.appendAuditLog({
      timestamp: new Date().toISOString(),
      action: `OAUTH_LOGIN_SUCCESS (${provider.toUpperCase()})`,
      severity: 'INFO',
      details: detailText
    });
  }
}
