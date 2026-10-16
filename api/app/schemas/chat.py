from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ChatMessage(BaseModel):
    role: str
    content: str

class CopilotChatRequest(BaseModel):
    prompt: str
    history: Optional[List[ChatMessage]] = []

class FirewallRuleRequest(BaseModel):
    ip: str
    action: str = Field(description="ALLOW or BLOCK")
    reason: str

class IncidentQueryRequest(BaseModel):
    threat_type: Optional[str] = "all"
    limit: Optional[int] = 5

class EntropyScanRequest(BaseModel):
    file_name: str
    file_size: int
    sha256: str
    entropy_score: float
    header_hex: Optional[str] = ""
    mime_type: Optional[str] = "application/octet-stream"

class WebAuthnRegistrationRequest(BaseModel):
    username: str
    credential: Optional[Dict[str, Any]] = None

class WebAuthnAuthenticationRequest(BaseModel):
    username: str
    credential: Optional[Dict[str, Any]] = None
