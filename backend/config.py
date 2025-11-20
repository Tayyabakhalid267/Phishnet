import os
from typing import List

class Settings:
    # Application
    APP_NAME: str = "PHISHNET API"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # CORS - Updated for Railway deployment
    CORS_ORIGINS: List[str] = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000"
    ).split(",")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-jwt-secret-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    
    # Database (optional)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishnet.db")
    
    # Redis (optional)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # AI/ML
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "4"))
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    HUGGINGFACE_TOKEN: str = os.getenv("HUGGINGFACE_TOKEN", "")
    
    # Features
    ENABLE_AI_DETECTION: bool = os.getenv("ENABLE_AI_DETECTION", "true").lower() == "true"
    ENABLE_THREAT_INTEL: bool = os.getenv("ENABLE_THREAT_INTEL", "true").lower() == "true"
    ENABLE_WEBSOCKETS: bool = os.getenv("ENABLE_WEBSOCKETS", "true").lower() == "true"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"
    
    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

settings = Settings()
