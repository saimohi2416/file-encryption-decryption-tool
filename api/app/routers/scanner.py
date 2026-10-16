from fastapi import APIRouter, HTTPException
from app.schemas.chat import EntropyScanRequest
from app.services.entropy_service import entropy_service
from typing import Dict, Any

router = APIRouter(prefix="/api/v1/scanner", tags=["Entropy & Metadata Scanner"])

@router.post("/entropy")
async def scan_entropy(request: EntropyScanRequest) -> Dict[str, Any]:
    try:
        return entropy_service.scan_heuristics(
            file_name=request.file_name,
            file_size=request.file_size,
            sha256=request.sha256,
            entropy_score=request.entropy_score,
            header_hex=request.header_hex or "",
            mime_type=request.mime_type or "application/octet-stream"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Entropy scan failed: {str(e)}")
