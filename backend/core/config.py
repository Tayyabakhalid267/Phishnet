from decouple import config
from typing import List
import os

class Settings:
    """Application configuration settings."""
    
    # Application
    APP_NAME: str = "PHISHNET"
    VERSION: str = "1.0.0"
    DEBUG: bool = config("DEBUG", default=True, cast=bool)
    
    # Security
    SECRET_KEY: str = config("SECRET_KEY", default="phishnet-super-secret-key-change-in-production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES", default=30, cast=int)
    ALGORITHM: str = "HS256"
    
    # Database
    DATABASE_URL: str = config("DATABASE_URL", default="sqlite:///./phishnet.db")
    
    # Redis
    REDIS_URL: str = config("REDIS_URL", default="redis://localhost:6379")
    
    # CORS
    ALLOWED_HOSTS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001", 
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "https://phishnet.ai"
    ]
    
    # AI Model Settings
    VIRUSTOTAL_API_KEY: str = config("VIRUSTOTAL_API_KEY", default="demo_key_replace_in_production")
    PHISHTANK_API_KEY: str = config("PHISHTANK_API_KEY", default="demo_key_replace_in_production")
    BERT_MODEL_NAME: str = "bert-base-uncased"
    SENTENCE_TRANSFORMER_MODEL: str = "all-MiniLM-L6-v2"
    
    # Detection Thresholds
    HIGH_RISK_THRESHOLD: float = 0.7
    MEDIUM_RISK_THRESHOLD: float = 0.4
    LOW_RISK_THRESHOLD: float = 0.2
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = config("VIRUSTOTAL_API_KEY", default="")
    PHISHTANK_API_KEY: str = config("PHISHTANK_API_KEY", default="")
    ABUSEIPDB_API_KEY: str = config("ABUSEIPDB_API_KEY", default="")
    URLVOID_API_KEY: str = config("URLVOID_API_KEY", default="")
    SHODAN_API_KEY: str = config("SHODAN_API_KEY", default="")
    GOOGLE_SAFE_BROWSING_KEY: str = config("GOOGLE_SAFE_BROWSING_KEY", default="")
    
    # AI Models
    HUGGINGFACE_API_KEY: str = config("HUGGINGFACE_API_KEY", default="")
    MODEL_CACHE_DIR: str = config("MODEL_CACHE_DIR", default="./ai_models/cache")
    
    # File Upload
    MAX_FILE_SIZE: int = config("MAX_FILE_SIZE", default=10485760, cast=int)  # 10MB
    UPLOAD_DIR: str = config("UPLOAD_DIR", default="./uploads")
    ALLOWED_EXTENSIONS: List[str] = [".eml", ".msg", ".txt", ".pdf", ".zip", ".docx"]
    
    # Email Analysis
    IMAP_TIMEOUT: int = config("IMAP_TIMEOUT", default=30, cast=int)
    MAX_EMAIL_SIZE: int = config("MAX_EMAIL_SIZE", default=52428800, cast=int)  # 50MB
    
    # Threat Intelligence
    THREAT_INTEL_CACHE_TTL: int = config("THREAT_INTEL_CACHE_TTL", default=3600, cast=int)
    DOMAIN_REPUTATION_THRESHOLD: float = config("DOMAIN_REPUTATION_THRESHOLD", default=0.7, cast=float)
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = config("RATE_LIMIT_REQUESTS", default=100, cast=int)
    RATE_LIMIT_WINDOW: int = config("RATE_LIMIT_WINDOW", default=60, cast=int)
    
    # Logging
    LOG_LEVEL: str = config("LOG_LEVEL", default="INFO")
    LOG_FILE: str = config("LOG_FILE", default="./logs/phishnet.log")
    
    # Blockchain
    BLOCKCHAIN_NETWORK: str = config("BLOCKCHAIN_NETWORK", default="ethereum")
    BLOCKCHAIN_PRIVATE_KEY: str = config("BLOCKCHAIN_PRIVATE_KEY", default="")
    
    # Notifications
    SMTP_HOST: str = config("SMTP_HOST", default="")
    SMTP_PORT: int = config("SMTP_PORT", default=587, cast=int)
    SMTP_USER: str = config("SMTP_USER", default="")
    SMTP_PASSWORD: str = config("SMTP_PASSWORD", default="")
    
    # Webhook
    SLACK_WEBHOOK_URL: str = config("SLACK_WEBHOOK_URL", default="")
    TEAMS_WEBHOOK_URL: str = config("TEAMS_WEBHOOK_URL", default="")
    
    class Config:
        case_sensitive = True

# Create settings instance
settings = Settings()

# Ensure directories exist
os.makedirs(settings.MODEL_CACHE_DIR, exist_ok=True)
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)