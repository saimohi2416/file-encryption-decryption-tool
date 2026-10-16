from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
import json
import logging

from app.config import settings
from app.routers import auth, copilot, firewall, scanner, webauthn, incidents, telemetry
from app.services.gemini_service import stream_copilot_response
from app.services.firewall_service import firewall_service
from app.middleware.rate_limiter import check_rate_limit
from app.schemas.chat import CopilotChatRequest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securevault.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SecureVault AI Backend Services...")
    yield
    logger.info("Shutting down SecureVault AI Backend Services...")

app = FastAPI(
    title="SecureVault AI Backend",
    description="Production-Grade Zero-Knowledge SecOps Proxy Backend",
    version="2.5.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API v1 Routers
app.include_router(auth.router)
app.include_router(copilot.router)
app.include_router(firewall.router)
app.include_router(scanner.router)
app.include_router(webauthn.router)
app.include_router(incidents.router)
app.include_router(telemetry.router)

# Health Check Endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "SecureVault AI Backend",
        "version": "2.5.0",
        "gemini_model": settings.GEMINI_MODEL,
        "rate_limiting": f"{settings.RATE_LIMIT_REQUESTS} req / {settings.RATE_LIMIT_WINDOW_SECONDS}s"
    }

# Backward Compatibility Endpoints for existing frontend routes
@app.post("/api/copilot", dependencies=[Depends(check_rate_limit)], tags=["Copilot"])
async def api_copilot(req: Request):
    try:
        body = await req.json()
        message = body.get("message") or body.get("prompt", "")
        dashboard_context = body.get("dashboardContext", {})
        
        full_prompt = message
        if dashboard_context:
            full_prompt = f"{message}\n\nSanitized Context:\n{json.dumps(dashboard_context)}"
            
        return StreamingResponse(
            stream_copilot_response(full_prompt, []),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/chat", dependencies=[Depends(check_rate_limit)], tags=["Legacy"])
async def legacy_chat(req: Request):
    try:
        body = await req.json()
        messages = body.get("messages", [])
        prompt = ""
        history = []
        for msg in messages:
            if msg.get("role") == "user":
                prompt = msg.get("content", "")
            else:
                history.append(msg)

        if not prompt and messages:
            prompt = messages[-1].get("content", "")

        return StreamingResponse(
            stream_copilot_response(prompt, []),
            media_type="text/event-stream"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.api_route("/api/firewall/status", methods=["GET", "POST"], tags=["Legacy"])
async def legacy_firewall_status():
    return firewall_service.get_status()

@app.post("/api/firewall/toggle", tags=["Legacy"])
async def legacy_firewall_toggle(req: Request):
    body = await req.json()
    enable = body.get("enable", True)
    return {"status": "success", "enabled": firewall_service.toggle(enable)}

@app.api_route("/api/firewall/rules", methods=["GET", "POST"], tags=["Legacy"])
async def legacy_firewall_rules(req: Request):
    if req.method == "POST":
        body = await req.json()
        return firewall_service.add_rule(body.get("ip"), body.get("action"), body.get("reason"))
    return firewall_service.get_rules()

@app.api_route("/api/webauthn", methods=["GET", "POST"], tags=["Legacy"])
async def legacy_webauthn(req: Request):
    action = req.query_params.get("action")
    body = {}
    if req.method == "POST":
        try:
            body = await req.json()
        except Exception:
            body = {}
    if not action:
        action = body.get("action")

    from app.services.webauthn_service import webauthn_service
    username = body.get("username") or req.query_params.get("username") or "SecureVaultUser"
    host = req.headers.get("host", "localhost")

    if action == "generate-registration-options":
        options = webauthn_service.generate_registration_options(username, host)
        return {"success": True, "options": options}
    elif action == "verify-registration":
        return webauthn_service.verify_registration(username, body.get("credential", {}))
    elif action == "generate-authentication-options":
        options = webauthn_service.generate_authentication_options(username, host)
        return {"success": True, "options": options}
    elif action == "verify-authentication":
        return webauthn_service.verify_authentication(username, body.get("credential", {}))
    
    return {"success": False, "error": f"Unknown action {action}"}

@app.api_route("/api/db-sync", methods=["GET", "POST"], tags=["Legacy"])
async def legacy_db_sync(req: Request):
    action = req.query_params.get("action")
    if action == "status":
        return {"configured": True, "connected": True, "backend": "FastAPI SecureVault Native"}
    return {"success": True, "message": f"Simulated db-sync action '{action}' executed"}

# Static Frontend Hosting (if static files are located in root directory)
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if os.path.exists(os.path.join(frontend_dir, "index.html")):
    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))
    
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
