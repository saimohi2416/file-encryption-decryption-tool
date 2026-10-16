from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from app.schemas.chat import CopilotChatRequest
from app.services.gemini_service import stream_copilot_response
from app.middleware.rate_limiter import check_rate_limit

router = APIRouter(prefix="/api/v1/copilot", tags=["AI Copilot"])

@router.post("/chat/stream", dependencies=[Depends(check_rate_limit)])
async def chat_stream(request: CopilotChatRequest):
    return StreamingResponse(
        stream_copilot_response(request.prompt, request.history or []),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
