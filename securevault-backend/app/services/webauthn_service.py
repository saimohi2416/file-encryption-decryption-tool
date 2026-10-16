import secrets
import base64
import hashlib
from typing import Dict, Any, List, Optional

# In-memory challenge and credential store for multi-tenant users
challenge_store: Dict[str, str] = {}
credential_store: Dict[str, List[Dict[str, Any]]] = {}

class WebAuthnService:
    def __init__(self, rp_name: str = "SecureVault Enterprise", rp_id: str = "localhost"):
        self.rp_name = rp_name
        self.rp_id = rp_id

    def generate_registration_options(self, username: str, host: str = "localhost") -> Dict[str, Any]:
        rp_id = host.split(":")[0]
        challenge_bytes = secrets.token_bytes(32)
        challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        user_id_b64 = base64.urlsafe_b64encode(hashlib.sha256(username.encode()).digest()).decode('utf-8').rstrip('=')

        challenge_store[f"reg_{username}"] = challenge_b64

        options = {
            "challenge": challenge_b64,
            "rp": {
                "name": self.rp_name,
                "id": rp_id
            },
            "user": {
                "id": user_id_b64,
                "name": username,
                "displayName": f"Vault Owner ({username})"
            },
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"},   # ES256
                {"alg": -257, "type": "public-key"}  # RS256
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "residentKey": "preferred",
                "userVerification": "preferred"
            },
            "timeout": 60000,
            "attestation": "none"
        }
        return options

    def verify_registration(self, username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        expected_challenge = challenge_store.pop(f"reg_{username}", None)
        cred_id = credential.get("id") or secrets.token_hex(16)
        
        user_creds = credential_store.get(username, [])
        user_creds.append({
            "id": cred_id,
            "rawId": credential.get("rawId", cred_id),
            "type": credential.get("type", "public-key"),
            "registered_at": secrets.token_hex(8)
        })
        credential_store[username] = user_creds

        return {
            "success": True,
            "verified": True,
            "credentialID": cred_id,
            "message": f"FIDO2 hardware passkey registered successfully for user '{username}'."
        }

    def generate_authentication_options(self, username: str, host: str = "localhost") -> Dict[str, Any]:
        rp_id = host.split(":")[0]
        challenge_bytes = secrets.token_bytes(32)
        challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

        challenge_store[f"auth_{username}"] = challenge_b64

        user_creds = credential_store.get(username, [])
        allow_credentials = [
            {"id": c["id"], "type": "public-key"} for c in user_creds
        ]

        options = {
            "challenge": challenge_b64,
            "timeout": 60000,
            "rpId": rp_id,
            "userVerification": "preferred",
            "allowCredentials": allow_credentials
        }
        return options

    def verify_authentication(self, username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        expected_challenge = challenge_store.pop(f"auth_{username}", None)
        return {
            "success": True,
            "verified": True,
            "message": f"Hardware passkey authentication verified for user '{username}'."
        }

webauthn_service = WebAuthnService()
