// api/chat.js
// Vercel Serverless Function to route chat requests securely to the Google Gemini API.

module.exports = async function handler(req, res) {
  // Set CORS headers for local testing and cross-origin access if needed
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { messages } = req.body;

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
            content: `### SecureVault AI Assistant (Demo Mode)

Hello! The AI service is currently running in **Demo Mode** because the \`GEMINI_API_KEY\` environment variable has not been set in the Vercel deployment yet.

**To enable live AI answers:**
1. Go to your Vercel Project Dashboard.
2. Navigate to **Settings > Environment Variables**.
3. Add a new environment variable:
   - **Key:** \`GEMINI_API_KEY\`
   - **Value:** *[Your Google Gemini API Key]*
4. Re-deploy the project or trigger a new deployment.

**Current local status:**
- Encryption standard: **AES-256-GCM**
- Key derivation: **PBKDF2** with 100,000 iterations
- Client state: Isolated and secured local IndexedDB
- Threat Level: **Low** (All interfaces operational)`
          }
        }
      ]
    });
  }

  try {
    // Map OpenAI-like roles format to Gemini API format.
    // Gemini roles: 'user', 'model'.
    // We separate the system instruction if it's sent.
    let systemInstruction = "You are SecureVault's expert Customer Service AI. You help users understand how SecureVault works: it is an advanced AES-256-GCM file encryption and decryption tool that runs entirely client-side in the browser. You answer cryptographic questions and guide users on how to use the vault, firewall, ledger, and cases features. Keep your answers brief, professional, and secure. Do not share any sensitive system keys or codes.";
    
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

    // Call the Google Gemini API (1.5 Flash is fast and cheap/free for development)
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
          maxOutputTokens: 800,
          temperature: 0.7
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("Gemini API Error Response:", errText);
      return res.status(500).json({ error: "Gemini API responded with an error status: " + response.status });
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
      ]
    });
  } catch (error) {
    console.error("Server Error in api/chat:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};
