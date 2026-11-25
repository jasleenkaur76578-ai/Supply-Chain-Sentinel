import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Supply Chain Sentinel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Security & Initial Admin Account (override via environment variables in production)
    SECRET_KEY: str = "sentinel_super_secret_enterprise_jwt_key_replace_in_prod_32bytes_minimum!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    ADMIN_EMAIL: str = "admin@sentinel.defense.org"
    ADMIN_PASSWORD: str = "SentinelAdmin2026!"
    ADMIN_FULL_NAME: str = "Platform Administrator"
    
    # Database
    DATABASE_URL: str = "sqlite:///./sentinel.db"
    
    # Threat Intelligence Feeds
    OSV_API_URL: str = "https://api.osv.dev/v1"
    CISA_KEV_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""
    
    # AI Assistant
    AI_PROVIDER: str = "gemini"
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000"
    ]
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
