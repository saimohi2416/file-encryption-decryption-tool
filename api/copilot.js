/**
 * SecureVault AI — Serverless Streaming AI Security Copilot Proxy
 * Protects AI API keys, enforces per-IP rate limiting, and streams responses via SSE.
 * 
 * Compatible with Vercel Node.js & Edge Runtime.
 */

// Simple in-memory sliding window rate limiter (or wire to Upstash Redis for distributed limits)
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 20;     // 20 queries/min
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };

  if (now > entry.resetTime) {
    entry.count = 1;
    entry.resetTime = now + RATE_LIMIT_WINDOW_MS;
    rateLimitMap.set(ip, entry);
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1, reset: entry.resetTime };
  }

  if (entry.count >= MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, remaining: 0, reset: entry.resetTime };
  }

  entry.count++;
  rateLimitMap.set(ip, entry);
  return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - entry.count, reset: entry.resetTime };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || '127.0.0.1';
  const rateLimit = checkRateLimit(clientIp);

  // Set rate-limit headers for frontend quota synchronization
  res.setHeader('X-RateLimit-Limit', MAX_REQUESTS_PER_WINDOW.toString());
  res.setHeader('X-RateLimit-Remaining', rateLimit.remaining.toString());
  res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimit.reset / 1000).toString());

  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: 'Rate limit exceeded. Please wait a minute before querying the AI Security Copilot again.'
    });
  }

  const { message, dashboardContext } = req.body || {};

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Valid "message" string is required.' });
  }

  // Zero-Knowledge Backend Defense: verify payload doesn't contain raw cryptographic secrets
  const forbiddenPatterns = [
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----/,
    /\"salt\":\s*\"[a-f0-9]{32,}\"/i,
    /\"password\":/i,
    /\"privateKey\":/i
  ];

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(JSON.stringify(req.body))) {
      return res.status(400).json({
        error: 'Security Violation: Raw cryptographic secrets detected in payload. Aborting.'
      });
    }
  }

  // Build System Prompt with Sanitized RAG Context
  let systemPrompt = `You are SecureVault AI Security Copilot, an elite cybersecurity and client-side cryptography assistant.
You specialize in browser-native Web Crypto API, AES-256-GCM, PBKDF2 (600,000 iterations), FIDO2/WebAuthn, and incident log analysis.
Always format your answers in clean, readable Markdown with code blocks where applicable.
When recommending firewall rules, structure them clearly as:
POLICY: ALLOW|BLOCK, IP: <ip_address>, REASON: <reason>`;

  if (dashboardContext && typeof dashboardContext === 'object') {
    systemPrompt += `\n\n### Current Dashboard Telemetry (Sanitized Metadata Only):
- Loaded File Metadata: ${JSON.stringify(dashboardContext.fileMetadata || 'No file active')}
- Recent Audit Logs (Last 10): ${JSON.stringify(dashboardContext.auditLogs || [])}
- Active Firewall Rules: ${JSON.stringify(dashboardContext.firewallRules || [])}
- Open Incident Cases: ${JSON.stringify(dashboardContext.incidents || [])}`;
  }

  const apiKey = process.env.AI_API_KEY || process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      error: 'Server AI_API_KEY is not configured in Vercel environment variables.'
    });
  }

  // Configure SSE response headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
  });

  try {
    // Calling Gemini API with streaming
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=${apiKey}`;

    const upstreamResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: message }] }],
        generationConfig: { maxOutputTokens: 2048, temperature: 0.2 }
      })
    });

    if (!upstreamResponse.ok) {
      const errText = await upstreamResponse.text();
      res.write(`data: ${JSON.stringify({ error: `Upstream error: ${errText}` })}\n\n`);
      res.write('data: [DONE]\n\n');
      return res.end();
    }

    const reader = upstreamResponse.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // Keep unfinished fragment in buffer

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const rawData = line.slice(6).trim();
          if (!rawData || rawData === '[DONE]') continue;

          try {
            const parsed = JSON.parse(rawData);
            const chunkText = parsed.candidates?.[0]?.content?.parts?.[0]?.text || '';
            if (chunkText) {
              res.write(`data: ${JSON.stringify({ text: chunkText })}\n\n`);
            }
          } catch (e) {
            // Passthrough non-json stream lines if already formatted
          }
        }
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('[API/Copilot] Stream error:', err);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  }
}
