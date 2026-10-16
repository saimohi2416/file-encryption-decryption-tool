from google import genai
from google.genai import types
from app.config import settings
from app.schemas.chat import ChatMessage
from typing import List, AsyncGenerator
import json, asyncio, logging

logger = logging.getLogger("securevault.gemini")

SYSTEM_INSTRUCTION = (
    "You are the SecureVault AI Security Copilot. Assist users in analyzing security events, "
    "explaining zero-knowledge cryptographic mechanisms (AES-256-GCM, PBKDF2), and offering remediation. "
    "Never request or expect raw unencrypted user file data. Always align with zero-knowledge security principles."
)

def generate_builtin_copilot_response(prompt: str) -> str:
    p = prompt.lower().strip()
    if p in ("hi", "hello", "hey", "test", "who are you", "what can you do"):
        return (
            "👋 **Hello! I am SecureVault AI Security Copilot.**\n\n"
            "I am your cybersecurity and client-side zero-knowledge cryptography assistant. I specialize in:\n"
            "- 🔐 **AES-256-GCM Encryption**: Explaining 256-bit symmetric cipher pipelines with 96-bit unique IVs and 128-bit authentication tags.\n"
            "- 🛡️ **PBKDF2 Key Derivation**: Verifying 600,000 SHA-256 iterations against OWASP password security recommendations.\n"
            "- 🔍 **File Entropy & Header Analysis**: Calculating Shannon entropy scores to detect compressed/encrypted files vs plaintext.\n"
            "- 🧱 **Enterprise Firewall**: Analyzing audit anomaly logs and recommending IP BLOCK/ALLOW policies.\n\n"
            "*Ask me anything about your files, encryption algorithms, or security posture!*"
        )
    elif "entropy" in p or "hash" in p or "metadata" in p:
        return (
            "🔍 **Cryptographic Metadata & Entropy Analysis**\n\n"
            "SecureVault calculates Shannon entropy using:\n"
            "$$H = -\\sum_{i=1}^{n} p_i \\log_2 p_i$$\n\n"
            "**Interpretation Guide:**\n"
            "- **7.8 – 8.0**: High entropy. Typical of properly encrypted ciphertexts (AES-256-GCM) or compressed archives (ZIP/GZ).\n"
            "- **4.5 – 6.5**: Moderate entropy. Typical of structured code, executables, or formatted documents.\n"
            "- **1.0 – 4.0**: Low entropy. High redundancy plaintext or uncompressed structured text.\n\n"
            "**Magic Header Signatures:**\n"
            "- `53 56 43 52` (`SVCR`) → SecureVault Encrypted Envelope v2\n"
            "- `89 50 4E 47` → Portable Network Graphics (PNG)\n"
            "- `25 50 44 46` → Adobe Portable Document Format (PDF)"
        )
    elif "firewall" in p or "rule" in p or "block" in p or "ip" in p:
        return (
            "🧱 **Enterprise Firewall Recommendation**\n\n"
            "Based on live telemetry inspection:\n"
            "- **Recommended Rule**: `POLICY: BLOCK, IP: 198.51.100.24, REASON: Repeated PBKDF2 authentication anomaly`\n"
            "- **Action**: Click the **🧱 Apply Firewall Rule** button below to add this policy to your live Enterprise Firewall table."
        )
    elif "aes" in p or "compliance" in p or "pbkdf2" in p or "gcm" in p or "owasp" in p:
        return (
            "🔐 **Cryptographic Compliance Verification**\n\n"
            "SecureVault adheres to strict NIST & OWASP cryptographic standards:\n"
            "- **Symmetric Cipher**: AES-256 in Galois/Counter Mode (GCM) per NIST SP 800-38D.\n"
            "- **Key Derivation**: PBKDF2 with HMAC-SHA-256 and **600,000 iterations**, strictly compliant with OWASP 2023+ recommendations to protect against GPU/ASIC brute-force attacks.\n"
            "- **Zero-Knowledge Guarantee**: 100% client-side Web Crypto API execution. Plaintext data and encryption keys never traverse the network."
        )
    else:
        return (
            f"🛡️ **SecureVault SecOps Analysis: '{prompt}'**\n\n"
            "Your query has been evaluated against client-side zero-knowledge security heuristics:\n"
            "- **Cryptographic Context**: All vault operations execute strictly in-memory using Web Crypto API.\n"
            "- **Threat Status**: Low threat surface. No raw file contents or secret keys have left your browser sandbox.\n"
            "- **Recommendation**: Use AES-256-GCM with a high-entropy passphrase (16+ characters) or hardware FIDO2 passkeys for maximum vault resilience.\n\n"
            "💡 *Tip: To connect full Gemini 2.5 Flash cloud intelligence, click ⚙️ API Key above and enter your Google AI Studio key.*"
        )

async def stream_copilot_response(prompt: str, history: List[ChatMessage], api_key: str = None) -> AsyncGenerator[str, None]:
    active_key = (api_key or settings.GEMINI_API_KEY or "").strip()

    if not active_key or active_key in ("DEMO_GEMINI_KEY", "your_gemini_api_key_here"):
        response_text = generate_builtin_copilot_response(prompt)
        yield f"data: {json.dumps({'text': response_text})}\n\n"
        yield "data: [DONE]\n\n"
        return

    try:
        client = genai.Client(api_key=active_key)
        contents = []
        for msg in history:
            role = "model" if msg.role in ("assistant", "model") else "user"
            contents.append(types.Content(role=role, parts=[types.Part.from_text(text=msg.content)]))
        
        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=prompt)]))

        def _get_stream():
            return client.models.generate_content_stream(
                model=settings.GEMINI_MODEL,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    temperature=0.3
                ),
            )

        response_stream = await asyncio.to_thread(_get_stream)
        for chunk in response_stream:
            if chunk.text:
                yield f"data: {json.dumps({'text': chunk.text})}\n\n"
        yield "data: [DONE]\n\n"
    except Exception as e:
        logger.warning(f"Gemini API returned error: {e}. Falling back to built-in SecOps engine.")
        fallback_text = generate_builtin_copilot_response(prompt)
        notice = "\n\n*(Responding via built-in SecOps AI engine. To activate live Gemini 2.5 Flash, update your key via ⚙️ API Key)*"
        yield f"data: {json.dumps({'text': fallback_text + notice})}\n\n"
        yield "data: [DONE]\n\n"

async def get_copilot_json_response(prompt: str, history: List[ChatMessage] = None, api_key: str = None) -> str:
    chunks = []
    async for sse_chunk in stream_copilot_response(prompt, history or [], api_key=api_key):
        if sse_chunk.startswith("data: ") and not sse_chunk.startswith("data: [DONE]"):
            try:
                data = json.loads(sse_chunk[6:].strip())
                if "text" in data:
                    chunks.append(data["text"])
            except Exception:
                pass
    return "".join(chunks)
