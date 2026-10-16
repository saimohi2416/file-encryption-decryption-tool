/**
 * SecureVault AI — AI Security Copilot Frontend Module
 * - SSE Streaming Consumer
 * - Sanitized Zero-Knowledge RAG Context Harvester
 * - 4 Clickable Quick Prompt Chips
 * - DOMPurify + Markdown Sanitization with Copy Buttons
 * - [🔒 Encrypt Note to Vault] & [+ Apply to Enterprise Firewall] Action Handlers
 * - Encrypted IndexedDB Chat History (`copilot_history`) with Purge Action
 */

export class SecurityCopilot {
  constructor(dbManager, cryptoManager) {
    this.db = dbManager;
    this.crypto = cryptoManager;
    this.chatContainer = document.getElementById('copilot-chat-container');
    this.chatInput = document.getElementById('copilot-chat-input');
    this.sendBtn = document.getElementById('copilot-send-btn');
    this.contextToggle = document.getElementById('copilot-context-toggle');
    this.quotaBadge = document.getElementById('copilot-quota-badge');
    this.purgeBtn = document.getElementById('copilot-purge-btn');

    this.isGenerating = false;
    this.init();
  }

  async init() {
    this.bindEvents();
    this.renderPromptChips();
    await this.loadChatHistory();
  }

  bindEvents() {
    this.sendBtn?.addEventListener('click', () => this.handleSendMessage());
    this.chatInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.handleSendMessage();
      }
    });

    this.purgeBtn?.addEventListener('click', () => this.purgeChatMemory());
  }

  renderPromptChips() {
    const chipsContainer = document.getElementById('copilot-prompt-chips');
    if (!chipsContainer) return;

    const chips = [
      { label: '🔍 Analyze Loaded File Metadata', query: 'Analyze the cryptographic parameters, entropy, and SHA-256 hash of the loaded file.' },
      { label: '🛡️ Audit Recent Security Logs', query: 'Perform an audit of the last 10 security logs. Flag any anomalies or repeated failures.' },
      { label: '🧱 Suggest Firewall IP Rule', query: 'Based on the most recent incident logs, recommend a custom IP firewall ALLOW or BLOCK rule.' },
      { label: '🔐 Verify AES-256-GCM Compliance', query: 'Verify how our PBKDF2 (600,000 iterations) + AES-256-GCM pipeline complies with modern OWASP/NIST standards.' }
    ];

    chipsContainer.innerHTML = chips.map((c, i) => `
      <button class="copilot-chip px-3 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-900/60 rounded-full transition whitespace-nowrap" data-query="${encodeURIComponent(c.query)}">
        ${c.label}
      </button>
    `).join('');

    chipsContainer.querySelectorAll('.copilot-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        const query = decodeURIComponent(btn.getAttribute('data-query'));
        if (this.chatInput) {
          this.chatInput.value = query;
          this.handleSendMessage();
        }
      });
    });
  }

  /**
   * Harvests telemetry strictly adhering to Zero-Knowledge principles.
   * NEVER extracts plaintext content, decryption passwords, or raw keys.
   */
  async getSanitizedDashboardContext() {
    if (!this.contextToggle || !this.contextToggle.checked) return null;

    // 1. File Metadata only (hash, size, encryption format)
    const activeFile = window.activeVaultFile || null;
    const fileMetadata = activeFile ? {
      formatVersion: activeFile.formatVersion || 'SV-AES256-v2',
      mimeType: activeFile.mimeType || 'application/octet-stream',
      fileSize: activeFile.size || 0,
      sha256: activeFile.sha256 || 'N/A',
      pbkdf2Iterations: 600000,
      saltLength: 16,
      ivLength: 12
    } : null;

    // 2. Last 10 Audit Logs
    const auditLogs = this.db?.getLastAuditLogs ? await this.db.getLastAuditLogs(10) : [];

    // 3. Active Firewall Rules
    const firewallRules = Array.from(document.querySelectorAll('#firewall-rules-table tbody tr, #firewallRulesTable tbody tr')).map(tr => {
      const cols = tr.querySelectorAll('td');
      return cols.length >= 3 ? {
        ip: cols[0]?.innerText.trim(),
        policy: cols[1]?.innerText.trim(),
        comment: cols[2]?.innerText.trim()
      } : null;
    }).filter(Boolean);

    return { fileMetadata, auditLogs, firewallRules };
  }

  async handleSendMessage() {
    if (!this.chatInput) return;
    const message = this.chatInput.value.trim();
    if (!message || this.isGenerating) return;

    this.chatInput.value = '';
    this.isGenerating = true;
    if (this.sendBtn) this.sendBtn.disabled = true;

    // 1. Append User Message to UI & Memory
    this.appendMessage('user', message);
    await this.saveMessageToDB('user', message);

    // 2. Harvest Sanitized Context
    const dashboardContext = await this.getSanitizedDashboardContext();

    // 3. Prepare AI Assistant Message Placeholder
    const assistantBubble = this.createMessageBubble('assistant');
    const contentSpan = assistantBubble.querySelector('.message-content');
    const actionsContainer = assistantBubble.querySelector('.message-actions');

    let fullResponseText = '';

    try {
      // Use /api/v1/copilot/chat/stream or fallback /api/copilot
      const endpoint = '/api/v1/copilot/chat/stream';
      let response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, dashboardContext })
      });

      if (!response.ok && response.status === 404) {
        response = await fetch('/api/copilot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message, dashboardContext })
        });
      }

      // Update remaining quota badge from header
      const remainingQuota = response.headers.get('X-RateLimit-Remaining');
      if (remainingQuota && this.quotaBadge) {
        this.quotaBadge.textContent = `${remainingQuota}/20 queries remaining`;
      }

      if (!response.ok) {
        const errorJson = await response.json().catch(() => ({}));
        throw new Error(errorJson.detail || errorJson.error || 'Copilot API request failed');
      }

      // 4. Consume SSE stream
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6).trim();
            if (dataStr === '[DONE]') continue;

            try {
              const data = JSON.parse(dataStr);
              if (data.error) throw new Error(data.error);
              if (data.text) {
                fullResponseText += data.text;
                contentSpan.innerHTML = this.renderSanitizedMarkdown(fullResponseText);
                this.scrollToBottom();
              }
            } catch (e) {
              // Non-JSON SSE line or chunk
            }
          }
        }
      }

      // 5. Finalize UI and render contextual action buttons
      this.attachMessageActions(actionsContainer, fullResponseText);
      await this.saveMessageToDB('assistant', fullResponseText);

    } catch (err) {
      if (contentSpan) {
        contentSpan.innerHTML = `<span class="text-rose-400 font-mono text-xs">⚠️ Copilot Error: ${err.message}</span>`;
      }
    } finally {
      this.isGenerating = false;
      if (this.sendBtn) this.sendBtn.disabled = false;
    }
  }

  renderSanitizedMarkdown(rawMarkdown) {
    if (window.marked && window.DOMPurify) {
      const rawHtml = window.marked.parse(rawMarkdown);
      return window.DOMPurify.sanitize(rawHtml);
    }
    return rawMarkdown
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\n/g, '<br/>');
  }

  attachMessageActions(container, text) {
    if (!container) return;
    container.innerHTML = '';

    // Action 1: Copy Response
    const copyBtn = document.createElement('button');
    copyBtn.className = 'px-2 py-1 text-[11px] bg-slate-900 border border-slate-700 hover:bg-slate-800 rounded text-slate-300 transition flex items-center space-x-1';
    copyBtn.innerHTML = `<span>📋 Copy</span>`;
    copyBtn.onclick = () => {
      navigator.clipboard.writeText(text);
      copyBtn.innerHTML = `<span>✅ Copied</span>`;
      setTimeout(() => copyBtn.innerHTML = `<span>📋 Copy</span>`, 2000);
    };
    container.appendChild(copyBtn);

    // Action 2: [🔒 Encrypt Note to Vault]
    const encryptNoteBtn = document.createElement('button');
    encryptNoteBtn.className = 'px-2 py-1 text-[11px] bg-cyan-950 border border-cyan-800 hover:bg-cyan-900 rounded text-cyan-300 transition flex items-center space-x-1';
    encryptNoteBtn.innerHTML = `<span>🔒 Encrypt Note to Vault</span>`;
    encryptNoteBtn.onclick = () => this.encryptNoteToVault(text);
    container.appendChild(encryptNoteBtn);

    // Action 3: [+ Apply to Enterprise Firewall] if IP recommendation detected
    const ipMatch = text.match(/IP:\s*([0-9a-fA-F.:/]+)/i);
    const policyMatch = text.match(/POLICY:\s*(ALLOW|BLOCK)/i);

    if (ipMatch && policyMatch) {
      const ip = ipMatch[1];
      const policy = policyMatch[1].toUpperCase();

      const applyFwBtn = document.createElement('button');
      applyFwBtn.className = 'px-2 py-1 text-[11px] bg-amber-950 border border-amber-800 hover:bg-amber-900 rounded text-amber-300 transition flex items-center space-x-1';
      applyFwBtn.innerHTML = `<span>🧱 Apply ${policy} to ${ip}</span>`;
      applyFwBtn.onclick = () => this.applyFirewallRule(ip, policy);
      container.appendChild(applyFwBtn);
    }
  }

  async encryptNoteToVault(noteContent) {
    const filename = `copilot-analysis-${Date.now()}.md`;
    if (!this.crypto?.encryptFile && !window.encryptFile) {
      alert('Local cryptographic engine not ready. Unlock vault first.');
      return;
    }

    try {
      const blob = new Blob([noteContent], { type: 'text/markdown' });
      if (this.crypto?.encryptFile) {
        await this.crypto.encryptFile(blob, filename);
      } else if (window.encryptFile) {
        await window.encryptFile(blob, filename);
      }

      if (this.db?.appendAuditLog) {
        await this.db.appendAuditLog({
          timestamp: new Date().toISOString(),
          action: 'NOTE_ENCRYPTED_TO_VAULT',
          severity: 'INFO',
          details: `Saved Copilot security note '${filename}' to encrypted local vault`
        });
      }

      alert(`✅ Note successfully encrypted and stored in local vault as ${filename}`);
    } catch (e) {
      alert(`Encryption failed: ${e.message}`);
    }
  }

  applyFirewallRule(ip, policy) {
    const tableBody = document.querySelector('#firewall-rules-table tbody, #firewallRulesTable tbody');
    if (!tableBody) {
      alert('Firewall table not found on current view.');
      return;
    }

    const row = document.createElement('tr');
    row.className = 'border-b border-slate-800 font-mono text-xs';
    row.innerHTML = `
      <td class="p-2 text-cyan-300">${ip}</td>
      <td class="p-2 ${policy === 'BLOCK' ? 'text-rose-400' : 'text-emerald-400'} font-bold">${policy}</td>
      <td class="p-2 text-slate-400">Added via AI Copilot recommendation</td>
    `;
    tableBody.prepend(row);

    if (this.db?.appendAuditLog) {
      this.db.appendAuditLog({
        timestamp: new Date().toISOString(),
        action: 'FIREWALL_RULE_ADDED',
        severity: 'WARN',
        details: `Rule: ${policy} for IP ${ip} created from Copilot chat`
      });
    }

    alert(`✅ Firewall rule applied: ${policy} -> ${ip}`);
  }

  createMessageBubble(role) {
    const bubble = document.createElement('div');
    bubble.className = `flex flex-col space-y-1 ${role === 'user' ? 'items-end' : 'items-start'}`;

    bubble.innerHTML = `
      <div class="max-w-[85%] rounded-xl px-4 py-2.5 text-sm ${
        role === 'user'
          ? 'bg-cyan-900/60 border border-cyan-700/60 text-white rounded-br-none'
          : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-none shadow-md'
      }">
        <div class="message-content prose prose-invert prose-sm max-w-none"></div>
        <div class="message-actions mt-2 flex flex-wrap gap-2 pt-2 border-t border-slate-800/80"></div>
      </div>
    `;

    if (this.chatContainer) {
      this.chatContainer.appendChild(bubble);
      this.scrollToBottom();
    }
    return bubble;
  }

  appendMessage(role, text) {
    const bubble = this.createMessageBubble(role);
    const content = bubble.querySelector('.message-content');
    if (content) {
      content.innerHTML = this.renderSanitizedMarkdown(text);
    }
  }

  scrollToBottom() {
    if (this.chatContainer) {
      this.chatContainer.scrollTop = this.chatContainer.scrollHeight;
    }
  }

  // --- Encrypted IndexedDB Chat Memory Management ---

  async loadChatHistory() {
    if (!this.db?.getAllFromStore) return;
    try {
      const history = await this.db.getAllFromStore('copilot_history');
      if (!history || history.length === 0) return;

      for (const item of history) {
        const bubble = this.createMessageBubble(item.role);
        const content = bubble.querySelector('.message-content');
        if (content) {
          content.innerHTML = this.renderSanitizedMarkdown(item.text);
        }
        if (item.role === 'assistant') {
          this.attachMessageActions(bubble.querySelector('.message-actions'), item.text);
        }
      }
    } catch (e) {
      console.warn('Could not load copilot_history from DB:', e);
    }
  }

  async saveMessageToDB(role, text) {
    if (!this.db?.putInStore) return;
    try {
      await this.db.putInStore('copilot_history', {
        timestamp: Date.now(),
        role,
        text
      });
    } catch (e) {
      console.warn('Could not save to copilot_history:', e);
    }
  }

  async purgeChatMemory() {
    if (!confirm('Are you sure you want to permanently purge local Copilot memory?')) return;

    if (this.db?.clearStore) {
      await this.db.clearStore('copilot_history');
    }
    if (this.chatContainer) {
      this.chatContainer.innerHTML = `
        <div class="p-4 text-center text-xs text-slate-500 font-mono">
          Memory wiped. Session initialized in Zero-Knowledge mode.
        </div>
      `;
    }

    if (this.db?.appendAuditLog) {
      await this.db.appendAuditLog({
        timestamp: new Date().toISOString(),
        action: 'CHAT_MEMORY_PURGED',
        severity: 'INFO',
        details: 'All local copilot_history IndexedDB records purged by user'
      });
    }
  }
}
