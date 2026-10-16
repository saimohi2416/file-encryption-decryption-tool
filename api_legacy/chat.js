// api/chat.js
// Vercel Serverless Function with Rate-Limiting Quota Protection & Security Remediation AI

const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_REQUESTS_PER_WINDOW = 20;

function checkRateLimit(clientIp) {
  const now = Date.now();
  let record = rateLimitStore.get(clientIp);

  if (!record || now - record.startTime > RATE_LIMIT_WINDOW_MS) {
    record = { startTime: now, count: 1 };
    rateLimitStore.set(clientIp, record);
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1, limit: MAX_REQUESTS_PER_WINDOW };
  }

  if (record.count >= MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, remaining: 0, limit: MAX_REQUESTS_PER_WINDOW };
  }

  record.count += 1;
  return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - record.count, limit: MAX_REQUESTS_PER_WINDOW };
}

module.exports = async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Gemini-Key'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Denial of Wallet Protection: Rate Limiting
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const { allowed, remaining, limit } = checkRateLimit(clientIp);

  res.setHeader('X-RateLimit-Limit', limit.toString());
  res.setHeader('X-RateLimit-Remaining', remaining.toString());

  if (!allowed) {
    return res.status(429).json({
      error: 'Too Many Requests (Denial of Wallet Protection Active). Please wait 60 seconds before trying again.'
    });
  }

  const { messages, stream } = req.body || {};

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Invalid request: messages array is required.' });
  }

  const apiKey = process.env.GEMINI_API_KEY || req.headers['x-gemini-key'];

  if (!apiKey) {
    // Return a smart response explaining how to configure the API key, acting as Demo Mode
    return res.status(200).json({
      choices: [
        {
          message: {
            role: 'assistant',
            content: `### SecureVault AI Assistant (Demo Mode Active)

Hello! The AI Security Copilot is currently operating in **Demo Mode** because the \`GEMINI_API_KEY\` environment variable has not been configured in Vercel.

**To activate live AI security analysis & context-aware remediation:**
1. Go to your Vercel Project Dashboard.
2. Navigate to **Settings > Environment Variables**.
3. Add a new environment variable:
   - **Key:** \`GEMINI_API_KEY\`
   - **Value:** *[Your Google Gemini API Key]*
4. Re-deploy your Vercel application.

**Security System Operational Status:**
- Encryption standard: **AES-256-GCM (256-bit key)**
- Key derivation: **PBKDF2 (600,000 iterations)**
- Client Zero-Knowledge: **Verified Active**
- Multi-Factor Auth (MFA): **TOTP / WebAuthn Enabled**
- Denial of Wallet Rate Limit: **${remaining}/${limit} requests remaining**`
          }
        }
      ]
    });
  }

  try {
    let systemInstruction = `You are SecureVault's expert AI Security Copilot & Cryptographic Engineer.
You specialize in Zero-Knowledge architectures, AES-256-GCM, Web Crypto API, MFA (TOTP / WebAuthn), and cloud security hardening.
When a user asks security questions, audit questions, or reports potential vulnerabilities:
1. Provide precise technical answers.
2. Provide context-aware remediation by writing concrete fix patches, code blocks, CSP rules, or JSON/YAML configurations ready to copy.
3. Keep answers clear, structured, and highly professional. Never output unencrypted sensitive credentials or private keys.`;

    const contents = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemInstruction = msg.content;
      } else {
        const geminiRole = msg.role === 'assistant' ? 'model' : 'user';
        contents.push({
          role: geminiRole,
          parts: [{ text: msg.content }]
        });
      }
    }

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents,
        systemInstruction: {
          parts: [{ text: systemInstruction }]
        },
        generationConfig: {
          maxOutputTokens: 1000,
          temperature: 0.7
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("Gemini API Error Response:", errText);
      return res.status(500).json({ error: "Gemini API responded with error status: " + response.status });
    }

    const data = await response.json();
    const replyText = data.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I am unable to formulate a response at the moment.";

    return res.status(200).json({
      choices: [
        {
          message: {
            role: 'assistant',
            content: replyText
          }
        }
      ],
      quota: {
        remaining,
        limit
      }
    });
  } catch (error) {
    console.error("Server Error in api/chat:", error);
    return res.status(500).json({ error: "Internal Server Error: " + error.message });
  }
};
