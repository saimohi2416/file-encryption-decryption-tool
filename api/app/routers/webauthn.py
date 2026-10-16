from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any
from app.schemas.chat import WebAuthnRegistrationRequest, WebAuthnAuthenticationRequest
from app.services.webauthn_service import webauthn_service

router = APIRouter(prefix="/api/v1/webauthn", tags=["WebAuthn Passkeys"])

@router.post("/register/options")
async def generate_register_options(request: Request, payload: Dict[str, Any]) -> Dict[str, Any]:
    username = payload.get("username", "SecureVaultUser")
    host = request.headers.get("host", "localhost")
    options = webauthn_service.generate_registration_options(username, host)
    return {"success": True, "options": options}

@router.post("/register/verify")
async def verify_registration(payload: WebAuthnRegistrationRequest) -> Dict[str, Any]:
    if not payload.credential:
        raise HTTPException(status_code=400, detail="Missing credential response")
    result = webauthn_service.verify_registration(payload.username, payload.credential)
    return result

@router.post("/authenticate/options")
async def generate_authenticate_options(request: Request, payload: Dict[str, Any]) -> Dict[str, Any]:
    username = payload.get("username", "SecureVaultUser")
    host = request.headers.get("host", "localhost")
    options = webauthn_service.generate_authentication_options(username, host)
    return {"success": True, "options": options}

@router.post("/authenticate/verify")
async def verify_authentication(payload: WebAuthnAuthenticationRequest) -> Dict[str, Any]:
    if not payload.credential:
        raise HTTPException(status_code=400, detail="Missing credential response")
    result = webauthn_service.verify_authentication(payload.username, payload.credential)
    return result
