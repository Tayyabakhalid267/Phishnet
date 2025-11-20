from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from core.config import settings
import hashlib
import secrets
import base64

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
security = HTTPBearer()

class SecurityManager:
    """Centralized security management for PHISHNET."""
    
    def __init__(self):
        self.algorithm = settings.ALGORITHM
        self.secret_key = settings.SECRET_KEY
    
    def create_access_token(
        self, 
        data: dict, 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
        Args:
            data: Data to encode in token
            expires_delta: Token expiration time
            
        Returns:
            str: Encoded JWT token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> dict:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            HTTPException: If token is invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id: str = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="🔒 Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="🔒 Token validation failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Stored hash
            
        Returns:
            bool: True if password matches
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    def generate_api_key(self) -> str:
        """
        Generate secure API key.
        
        Returns:
            str: Base64 encoded API key
        """
        random_bytes = secrets.token_bytes(32)
        api_key = base64.b64encode(random_bytes).decode('utf-8')
        return f"phish_{api_key}"
    
    def create_evidence_hash(self, data: str) -> str:
        """
        Create SHA-256 hash for evidence integrity.
        
        Args:
            data: Data to hash
            
        Returns:
            str: SHA-256 hash
        """
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        return sha256_hash.hexdigest()
    
    def create_blockchain_signature(self, data: str, timestamp: str) -> str:
        """
        Create blockchain-ready signature.
        
        Args:
            data: Data to sign
            timestamp: Timestamp string
            
        Returns:
            str: Blockchain signature
        """
        # Combine data with timestamp and secret
        combined = f"{data}:{timestamp}:{self.secret_key}"
        signature = hashlib.sha256(combined.encode()).hexdigest()
        return f"0x{signature}"

# Initialize security manager
security_manager = SecurityManager()

# Convenience functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    return security_manager.create_access_token(data, expires_delta)

def verify_token(token: str) -> dict:
    """Verify JWT token."""
    return security_manager.verify_token(token)

def hash_password(password: str) -> str:
    """Hash password."""
    return security_manager.hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password."""
    return security_manager.verify_password(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Get password hash (alias for hash_password)."""
    return hash_password(password)

def authenticate_user(username: str, password: str, stored_hash: str) -> bool:
    """
    Authenticate user credentials.
    
    Args:
        username: Username
        password: Plain text password
        stored_hash: Stored password hash
        
    Returns:
        bool: True if authentication successful
    """
    if not username or not password:
        return False
    return verify_password(password, stored_hash)

class CyberSecurityValidator:
    """Advanced security validation for cybersecurity operations."""
    
    @staticmethod
    def validate_email_headers(headers: dict) -> dict:
        """
        Validate email security headers.
        
        Args:
            headers: Email headers dictionary
            
        Returns:
            dict: Validation results
        """
        results = {
            "spf": {"status": "unknown", "details": ""},
            "dkim": {"status": "unknown", "details": ""},
            "dmarc": {"status": "unknown", "details": ""},
            "score": 0.0
        }
        
        # SPF validation
        if "received-spf" in headers:
            spf_result = headers["received-spf"].lower()
            if "pass" in spf_result:
                results["spf"] = {"status": "pass", "details": "SPF validation passed"}
                results["score"] += 0.3
            elif "fail" in spf_result:
                results["spf"] = {"status": "fail", "details": "SPF validation failed"}
            elif "softfail" in spf_result:
                results["spf"] = {"status": "softfail", "details": "SPF soft failure"}
                results["score"] += 0.1
        
        # DKIM validation
        if "authentication-results" in headers:
            auth_results = headers["authentication-results"].lower()
            if "dkim=pass" in auth_results:
                results["dkim"] = {"status": "pass", "details": "DKIM signature valid"}
                results["score"] += 0.4
            elif "dkim=fail" in auth_results:
                results["dkim"] = {"status": "fail", "details": "DKIM signature invalid"}
        
        # DMARC validation  
        if "authentication-results" in headers:
            auth_results = headers["authentication-results"].lower()
            if "dmarc=pass" in auth_results:
                results["dmarc"] = {"status": "pass", "details": "DMARC policy compliance"}
                results["score"] += 0.3
            elif "dmarc=fail" in auth_results:
                results["dmarc"] = {"status": "fail", "details": "DMARC policy violation"}
        
        return results
    
    @staticmethod
    def calculate_risk_score(factors: dict) -> float:
        """
        Calculate comprehensive risk score.
        
        Args:
            factors: Risk factors dictionary
            
        Returns:
            float: Risk score (0.0 - 1.0)
        """
        base_score = 0.0
        
        # Email security factors
        if factors.get("spf_fail"):
            base_score += 0.2
        if factors.get("dkim_fail"):
            base_score += 0.3
        if factors.get("dmarc_fail"):
            base_score += 0.25
        
        # Content factors
        if factors.get("suspicious_links"):
            base_score += 0.4
        if factors.get("malicious_attachments"):
            base_score += 0.5
        if factors.get("phishing_language"):
            base_score += 0.3
        
        # Domain factors
        if factors.get("new_domain"):
            base_score += 0.2
        if factors.get("suspicious_tld"):
            base_score += 0.15
        if factors.get("typosquatting"):
            base_score += 0.6
        
        return min(base_score, 1.0)

# Initialize validators
cyber_validator = CyberSecurityValidator()