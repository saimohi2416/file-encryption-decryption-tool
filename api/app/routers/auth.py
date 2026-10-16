import urllib.parse
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from app.services.auth_service import auth_service
from app.config import settings

router = APIRouter(prefix="/api/v1/auth", tags=["OAuth Authentication"])

def get_request_origin(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", "https")
    host = request.headers.get("host", "file-encryption-decryption-tool-lime.vercel.app")
    if "localhost" in host or "127.0.0.1" in host:
        proto = "http"
    return f"{proto}://{host}"

@router.get("/google/login")
async def google_login(request: Request):
    origin = get_request_origin(request)
    auth_url = auth_service.get_google_auth_url(host_origin=origin)
    return RedirectResponse(url=auth_url)

@router.get("/google/callback")
async def google_callback(request: Request, code: str = None, error: str = None):
    origin = get_request_origin(request)

    if error or not code:
        err_msg = urllib.parse.quote(error or "Google OAuth authorization was cancelled or failed.")
        return RedirectResponse(url=f"{origin}/?oauth_error={err_msg}#auth")

    try:
        session = await auth_service.exchange_google_code(code, host_origin=origin)
        query = urllib.parse.urlencode({
            "oauth_provider": "google",
            "username": session["username"],
            "email": session["email"],
            "name": session["name"],
            "avatar": session["avatar"],
            "passwordHash": session["passwordHash"],
            "token": session["token"]
        })
        return RedirectResponse(url=f"{origin}/?{query}#vault")
    except ValueError as val_err:
        err_text = urllib.parse.quote(str(val_err))
        return RedirectResponse(url=f"{origin}/?oauth_error={err_text}#auth")
    except Exception as e:
        err_text = urllib.parse.quote(f"Google authentication error: {str(e)}")
        return RedirectResponse(url=f"{origin}/?oauth_error={err_text}#auth")

@router.get("/github/login")
async def github_login(request: Request):
    origin = get_request_origin(request)
    auth_url = auth_service.get_github_auth_url(host_origin=origin)
    return RedirectResponse(url=auth_url)

@router.get("/github/callback")
async def github_callback(request: Request, code: str = None, error: str = None):
    origin = get_request_origin(request)

    if error or not code:
        err_msg = urllib.parse.quote(error or "GitHub OAuth authorization was cancelled or failed.")
        return RedirectResponse(url=f"{origin}/?oauth_error={err_msg}#auth")

    try:
        session = await auth_service.exchange_github_code(code, host_origin=origin)
        query = urllib.parse.urlencode({
            "oauth_provider": "github",
            "username": session["username"],
            "email": session["email"],
            "name": session["name"],
            "avatar": session["avatar"],
            "passwordHash": session["passwordHash"],
            "token": session["token"]
        })
        return RedirectResponse(url=f"{origin}/?{query}#vault")
    except ValueError as val_err:
        err_text = urllib.parse.quote(str(val_err))
        return RedirectResponse(url=f"{origin}/?oauth_error={err_text}#auth")
    except Exception as e:
        err_text = urllib.parse.quote(f"GitHub authentication error: {str(e)}")
        return RedirectResponse(url=f"{origin}/?oauth_error={err_text}#auth")
