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

async def stream_copilot_response(prompt: str, history: List[ChatMessage], api_key: str = None) -> AsyncGenerator[str, None]:
    active_key = (api_key or settings.GEMINI_API_KEY or "").strip()

    if not active_key or active_key in ("DEMO_GEMINI_KEY", "your_gemini_api_key_here"):
        demo_text = (
            "### SecureVault AI Security Copilot (Demo Mode)\n\n"
            "To connect live Gemini 2.5 Flash intelligence:\n"
            "1. Click **⚙️ API Key** in the chat header to enter your Google Gemini API key (stored securely in your browser).\n"
            "2. Or configure `GEMINI_API_KEY` in Vercel environment variables.\n\n"
            "**Verified Cryptographic Architecture**:\n"
            "- **Encryption Algorithm**: AES-256-GCM (256-bit symmetric key)\n"
            "- **Key Derivation Function**: PBKDF2 with SHA-256 (600,000 iterations)\n"
            "- **Zero-Knowledge Compliance**: Active (Client-side Web Crypto API only)\n"
            "- **Rate Limiting**: Distributed Sliding Window Active"
        )
        yield f"data: {json.dumps({'text': demo_text})}\n\n"
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
        logger.error(f"Error in Gemini streaming service: {e}")
        err_str = str(e)
        if "API_KEY_INVALID" in err_str or "API key not valid" in err_str:
            clean_msg = (
                "🔑 **Gemini API Key Required**\n\n"
                "The server's Gemini API key is currently unset or requires updating.\n\n"
                "**How to activate:**\n"
                "- Click the **⚙️ API Key** button above to paste your Google Gemini API key (it is saved locally in your browser and transmitted via HTTPS).\n"
                "- Or set `GEMINI_API_KEY` in your Vercel Project Settings.\n\n"
                "*All client-side AES-256-GCM encryption and zero-knowledge vault functions remain fully operational.*"
            )
        else:
            clean_msg = f"⚠️ **SecureVault AI Copilot Notice**: {err_str}"

        yield f"data: {json.dumps({'text': clean_msg})}\n\n"
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
