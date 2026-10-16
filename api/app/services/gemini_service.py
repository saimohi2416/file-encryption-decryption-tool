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

async def stream_copilot_response(prompt: str, history: List[ChatMessage]) -> AsyncGenerator[str, None]:
    if not settings.GEMINI_API_KEY:
        demo_text = (
            "### SecureVault AI Security Copilot (Demo Mode)\n\n"
            "The `GEMINI_API_KEY` environment variable is not configured. To activate live Gemini 2.5 Flash intelligence:\n"
            "1. Set `GEMINI_API_KEY` in your environment or `.env` file.\n"
            "2. Restart the SecureVault backend server.\n\n"
            "**Verified Cryptographic Architecture**:\n"
            "- **Encryption Algorithm**: AES-256-GCM (256-bit symmetric key)\n"
            "- **Key Derivation Function**: PBKDF2 with SHA-256 (600,000 iterations)\n"
            "- **Zero-Knowledge Compliance**: Active (Client-side Web Crypto API only)\n"
            "- **Rate Limiting**: Distributed Redis Sliding Window Active"
        )
        yield f"data: {json.dumps({'text': demo_text})}\n\n"
        yield "data: [DONE]\n\n"
        return

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
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
        err_text = f"⚠️ **SecureVault AI Copilot Error**: {str(e)}"
        yield f"data: {json.dumps({'text': err_text})}\n\n"
        yield "data: [DONE]\n\n"
