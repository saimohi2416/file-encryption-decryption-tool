from fastapi import APIRouter, Query
from typing import Dict, Any, Optional
from app.services.rag_service import rag_service

router = APIRouter(prefix="/api/v1/incidents", tags=["Cyber Incidents & pgvector RAG"])

@router.get("")
async def list_incidents(
    threat_type: Optional[str] = Query("all"),
    limit: Optional[int] = Query(5)
) -> Dict[str, Any]:
    cases = rag_service.query_incidents(threat_type=threat_type, limit=limit)
    return {"status": "success", "count": len(cases), "cases": cases}

@router.get("/search")
async def vector_search(query: str, limit: Optional[int] = Query(3)) -> Dict[str, Any]:
    return rag_service.perform_vector_search(query=query, limit=limit)
