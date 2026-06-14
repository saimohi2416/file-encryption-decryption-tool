/* chatbot.js */
/* JavaScript for SecureVault AI Customer Service Floating Chat Widget */

(function () {
  // Prevent double loading
  if (document.getElementById('securevault-chatbot')) return;

  // Configuration
  const API_ENDPOINT = '/api/chat';
  
  // Custom Markdown Parser to avoid external dependencies
  function parseMarkdown(text) {
    if (!text) return '';
    
    let html = text;
    
    // Escape HTML tags to prevent XSS (but preserve markdown structure we will create)
    html = html
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // 1. Code blocks (```code```)
    html = html.replace(/```([\s\S]*?)```/g, function(match, code) {
      return '<pre><code>' + code.trim() + '</code></pre>';
    });

    // 2. Inline code (`code`)
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // 3. Bold (**text**)
    html = html.replace(/\*\*([\s\S]*?)\*\*/g, '<strong>$1</strong>');

    // 4. Headers (### Header)
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^# (.*$)/gim, '<h3>$1</h3>');

    // 5. Unordered Lists (- item or * item)
    // First, handle lines that start with - or * and convert them to list items
    html = html.replace(/^\s*[-*]\s+(.*)$/gim, '<li>$1</li>');
    // Group consecutive list items in <ul>
    html = html.replace(/(<li>[\s\S]*?<\/li>)+/g, '<ul>$&</ul>');

    // 6. Paragraphs (separated by double newlines)
    // Avoid double paragraph nesting inside elements like pre, ul, etc.
    const blocks = html.split(/\n{2,}/);
    html = blocks.map(block => {
      block = block.trim();
      if (!block) return '';
      if (block.startsWith('<pre>') || block.startsWith('<ul>') || block.startsWith('<h3>') || block.startsWith('<li>')) {
        return block;
      }
      // Replace single newlines with <br> within paragraphs
      return '<p>' + block.replace(/\n/g, '<br>') + '</p>';
    }).join('');

    return html;
  }
  
  // Expose parser globally for other modules (like app.js)
  window.parseChatMarkdown = parseMarkdown;

  // Initial Conversation History
  let conversationHistory = [
    {
      role: 'system',
      content: `You are SecureVault's Customer Service AI Assistant. You guide users and answer questions about the SecureVault tool.
SecureVault features:
1. File Vault: Client-side AES-256-GCM file encryption and decryption. Uses password-derived keys with PBKDF2 (100k iterations, salt, iv). Files are processed locally; nothing is uploaded to any server.
2. Enterprise Secure Firewall: Local network filtering profiles stored in browser IndexedDB.
3. Cyber Cases Log: Auditable logs of encryption operations and security incidents.
4. Unified File Ledger: Tracks currently active virtual explorer folders.
5. AI Security Copilot: Specialized tab within the dashboard for contextual cryptographic analysis.

Provide precise, brief, professional, and helpful replies. Mention the client-side design and local-first zero data transfer model.`
    }
  ];

  // Create Chatbot Elements
  const container = document.createElement('div');
  container.id = 'securevault-chatbot';
  container.className = 'sv-chatbot-container';
  
  // HTML Template
  container.innerHTML = `
    <!-- Chat Window -->
    <div class="sv-chatbot-window" id="svChatWindow">
      <!-- Header -->
      <div class="sv-chatbot-header">
        <div class="sv-chatbot-brand">
          <div class="sv-chatbot-brand-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div class="sv-chatbot-brand-text">
            <span class="sv-chatbot-title">SecureVault AI</span>
            <span class="sv-chatbot-subtitle">Customer Service Online</span>
          </div>
        </div>
        <button class="sv-chatbot-close-btn" id="svChatClose" title="Minimize Chat">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </div>
      
      <!-- Messages List -->
      <div class="sv-chatbot-messages" id="svChatMessages">
        <div class="sv-chatbot-msg system">
          <div class="sv-chatbot-bubble">
            Hello! I am your <strong>SecureVault Customer Service AI</strong>.<br><br>
            How can I assist you with encryption, security logs, or using our secure enterprise vaults today?
          </div>
        </div>
      </div>
      
      <!-- Input Area -->
      <div class="sv-chatbot-input-area">
        <input type="text" class="sv-chatbot-input" id="svChatInput" placeholder="Type a message..." autocomplete="off" />
        <button class="sv-chatbot-send-btn" id="svChatSend" disabled title="Send Message">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"></line>
            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
          </svg>
        </button>
      </div>
    </div>
    
    <!-- Launcher Bubble -->
    <button class="sv-chatbot-launcher" id="svChatLauncher" title="Open AI Customer Service">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
      </svg>
    </button>
  `;
  
  document.body.appendChild(container);

  // DOM Elements
  const launcher = document.getElementById('svChatLauncher');
  const chatWindow = document.getElementById('svChatWindow');
  const closeBtn = document.getElementById('svChatClose');
  const messagesList = document.getElementById('svChatMessages');
  const chatInput = document.getElementById('svChatInput');
  const sendBtn = document.getElementById('svChatSend');

  // Toggle Window State
  function toggleChat(forceState) {
    const isActive = forceState !== undefined ? forceState : chatWindow.classList.contains('active');
    if (isActive) {
      chatWindow.classList.remove('active');
    } else {
      chatWindow.classList.add('active');
      chatInput.focus();
      // Scroll to bottom when opening
      messagesList.scrollTop = messagesList.scrollHeight;
    }
  }

  launcher.addEventListener('click', () => toggleChat());
  closeBtn.addEventListener('click', () => toggleChat(true));

  // Enable/Disable Send Button based on input
  chatInput.addEventListener('input', () => {
    sendBtn.disabled = !chatInput.value.trim();
  });

  // Handle Enter Key
  chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !sendBtn.disabled) {
      sendMessage();
    }
  });

  sendBtn.addEventListener('click', sendMessage);

  // Send Message Logic
  async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    // Reset input
    chatInput.value = '';
    sendBtn.disabled = true;

    // Render User Message
    appendMessage('user', text);
    
    // Add to History
    conversationHistory.push({ role: 'user', content: text });

    // Render typing indicator
    const typingIndicator = appendTypingIndicator();

    try {
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messages: conversationHistory
        })
      });

      // Remove typing indicator
      typingIndicator.remove();

      if (!response.ok) {
        throw new Error('API request failed with status: ' + response.status);
      }

      const data = await response.json();
      const botResponse = data.choices?.[0]?.message?.content || 'Sorry, I encountered an error.';
      
      // Render Bot Message
      appendMessage('system', botResponse);
      
      // Add to History
      conversationHistory.push({ role: 'assistant', content: botResponse });
    } catch (err) {
      typingIndicator.remove();
      appendMessage('system', `⚠️ **Error**: Could not reach SecureVault AI. Details: \`${err.message}\`. Please check your connection.`);
      console.error('Chatbot API Error:', err);
    }
  }

  // Append Message to UI
  function appendMessage(role, text) {
    const msgDiv = document.createElement('div');
    msgDiv.className = `sv-chatbot-msg ${role}`;
    
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'sv-chatbot-bubble';
    bubbleDiv.innerHTML = parseMarkdown(text);
    
    msgDiv.appendChild(bubbleDiv);
    messagesList.appendChild(msgDiv);
    
    // Scroll to bottom
    messagesList.scrollTop = messagesList.scrollHeight;
  }

  // Typing Indicator helper
  function appendTypingIndicator() {
    const indicatorDiv = document.createElement('div');
    indicatorDiv.className = 'sv-chatbot-msg system';
    indicatorDiv.id = 'sv-typing-indicator';
    
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'sv-chatbot-bubble';
    bubbleDiv.innerHTML = `
      <div class="sv-typing-indicator">
        <div class="sv-typing-dot"></div>
        <div class="sv-typing-dot"></div>
        <div class="sv-typing-dot"></div>
      </div>
    `;
    
    indicatorDiv.appendChild(bubbleDiv);
    messagesList.appendChild(indicatorDiv);
    messagesList.scrollTop = messagesList.scrollHeight;
    
    return indicatorDiv;
  }
})();
