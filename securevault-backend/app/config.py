from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    REDIS_URL: str = "redis://redis:6379/0"
    RATE_LIMIT_REQUESTS: int = 20
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    ALLOWED_ORIGINS: str = "https://file-encryption-decryption-tool-lime.vercel.app,https://securevault-ai-two.vercel.app,http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000,http://localhost:8080"

    # OAuth Google Settings
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "https://file-encryption-decryption-tool-lime.vercel.app/api/v1/auth/google/callback"

    # OAuth GitHub Settings
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "https://file-encryption-decryption-tool-lime.vercel.app/api/v1/auth/github/callback"

    JWT_SECRET: str = "securevault_jwt_secret_key_production_2026"

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
