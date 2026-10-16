import hashlib
import urllib.parse
import secrets
import httpx
import jwt
import time
from typing import Dict, Any, Optional
from app.config import settings

class AuthService:
    def get_google_auth_url(self, host_origin: Optional[str] = None) -> str:
        redirect_uri = settings.GOOGLE_REDIRECT_URI
        if host_origin:
            redirect_uri = f"{host_origin}/api/v1/auth/google/callback"

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID or "DEMO_GOOGLE_CLIENT_ID",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "online",
            "prompt": "select_account",
            "state": secrets.token_urlsafe(16)
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

    def get_github_auth_url(self, host_origin: Optional[str] = None) -> str:
        redirect_uri = settings.GITHUB_REDIRECT_URI
        if host_origin:
            redirect_uri = f"{host_origin}/api/v1/auth/github/callback"

        params = {
            "client_id": settings.GITHUB_CLIENT_ID or "DEMO_GITHUB_CLIENT_ID",
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": secrets.token_urlsafe(16)
        }
        return f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"

    async def exchange_google_code(self, code: str, host_origin: Optional[str] = None) -> Dict[str, Any]:
        if not settings.GOOGLE_CLIENT_SECRET or settings.GOOGLE_CLIENT_ID == "":
            raise ValueError("GOOGLE_CLIENT_SECRET is not configured on the server. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.")

        redirect_uri = settings.GOOGLE_REDIRECT_URI
        if host_origin:
            redirect_uri = f"{host_origin}/api/v1/auth/google/callback"

        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(token_url, data=data)
            if token_res.status_code != 200:
                raise ValueError(f"Google OAuth token exchange failed: {token_res.text}")
            
            tokens = token_res.json()
            access_token = tokens.get("access_token")

            userinfo_res = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if userinfo_res.status_code != 200:
                raise ValueError("Failed to retrieve Google user profile")
            
            user_info = userinfo_res.json()
            email = user_info.get("email", "").lower()
            name = user_info.get("name") or email.split("@")[0]
            avatar = user_info.get("picture") or f"https://api.dicebear.com/7.x/avataaars/svg?seed={urllib.parse.quote(email)}"

            return self.build_user_session(email=email, name=name, provider="google", provider_id=user_info.get("id"), avatar=avatar)

    async def exchange_github_code(self, code: str, host_origin: Optional[str] = None) -> Dict[str, Any]:
        if not settings.GITHUB_CLIENT_SECRET or settings.GITHUB_CLIENT_ID == "":
            raise ValueError("GITHUB_CLIENT_SECRET is not configured on the server. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.")

        redirect_uri = settings.GITHUB_REDIRECT_URI
        if host_origin:
            redirect_uri = f"{host_origin}/api/v1/auth/github/callback"

        token_url = "https://github.com/login/oauth/access_token"
        data = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri
        }
        headers = {"Accept": "application/json"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(token_url, data=data, headers=headers)
            if token_res.status_code != 200:
                raise ValueError(f"GitHub OAuth token exchange failed: {token_res.text}")

            tokens = token_res.json()
            access_token = tokens.get("access_token")
            if not access_token:
                raise ValueError(f"GitHub OAuth error: {tokens.get('error_description', 'No access token returned')}")

            user_res = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "User-Agent": "SecureVault-AI-OAuth"}
            )
            if user_res.status_code != 200:
                raise ValueError("Failed to retrieve GitHub user profile")

            user_data = user_res.json()
            username = user_data.get("login")
            email = user_data.get("email")

            if not email:
                email_res = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}", "User-Agent": "SecureVault-AI-OAuth"}
                )
                if email_res.status_code == 200:
                    emails = email_res.json()
                    primary = next((e for e in emails if e.get("primary")), None)
                    if primary:
                        email = primary.get("email")

            if not email:
                email = f"{username}@github.com"

            avatar = user_data.get("avatar_url") or f"https://github.com/{urllib.parse.quote(username)}.png"

            return self.build_user_session(email=email.lower(), name=f"@{username}", provider="github", provider_id=str(user_data.get("id")), avatar=avatar)

    def build_user_session(self, email: str, name: str, provider: str, provider_id: str, avatar: str) -> Dict[str, Any]:
        clean_email = email.lower().strip()
        username = f"{provider}_{clean_email.replace('@', '_at_').replace('.', '_')}"

        # Securely derive master password hash for Web Crypto API vault encryption
        pass_key_source = f"{provider}_vault_key_{clean_email}_{settings.JWT_SECRET}"
        password_hash = hashlib.sha256(pass_key_source.encode('utf-8')).hexdigest()

        payload = {
            "sub": username,
            "email": clean_email,
            "name": name,
            "provider": provider,
            "provider_id": provider_id,
            "avatar": avatar,
            "iat": int(time.time()),
            "exp": int(time.time()) + (86400 * 7) # 7 day session duration
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

        return {
            "token": token,
            "username": username,
            "email": clean_email,
            "name": name,
            "provider": provider,
            "avatar": avatar,
            "passwordHash": password_hash
        }

auth_service = AuthService()
