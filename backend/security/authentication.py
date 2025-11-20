"""
Security and Authentication Framework - Production Implementation
JWT authentication, RBAC, multi-tenancy, compliance logging, enterprise security
"""
import asyncio
import jwt
import bcrypt
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import uuid
from enum import Enum
import json

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from passlib.context import CryptContext
import aioredis
from cryptography.fernet import Fernet

from models.database import (
    User, Organization, Role, Permission, UserRole, 
    AuditLog, SecurityEvent, UserSession, APIKey
)
from core.config import settings

logger = logging.getLogger(__name__)

class PermissionType(str, Enum):
    """System permission types"""
    # Email Analysis
    ANALYZE_EMAIL = "analyze_email"
    VIEW_ANALYSIS = "view_analysis"
    EXPORT_ANALYSIS = "export_analysis"
    
    # Campaign Management
    VIEW_CAMPAIGNS = "view_campaigns"
    MANAGE_CAMPAIGNS = "manage_campaigns"
    
    # User Management
    VIEW_USERS = "view_users"
    CREATE_USER = "create_user"
    EDIT_USER = "edit_user"
    DELETE_USER = "delete_user"
    
    # Organization Management
    VIEW_ORG_SETTINGS = "view_org_settings"
    EDIT_ORG_SETTINGS = "edit_org_settings"
    MANAGE_BILLING = "manage_billing"
    
    # Security & Compliance
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_SECURITY = "manage_security"
    EXPORT_COMPLIANCE = "export_compliance"
    
    # System Administration
    SYSTEM_ADMIN = "system_admin"
    API_ACCESS = "api_access"
    WEBHOOK_ACCESS = "webhook_access"

class RoleType(str, Enum):
    """Predefined system roles"""
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    SECURITY_ANALYST = "security_analyst"
    USER = "user"
    API_CLIENT = "api_client"
    READONLY = "readonly"

@dataclass
class AuthenticatedUser:
    """Authenticated user context"""
    user_id: str
    organization_id: str
    email: str
    roles: List[str]
    permissions: List[str]
    session_id: Optional[str] = None
    api_key_id: Optional[str] = None
    
class SecurityContext:
    """Security context for request processing"""
    
    def __init__(
        self,
        user: AuthenticatedUser,
        request_id: str,
        ip_address: str,
        user_agent: str,
        resource: str = None,
        action: str = None
    ):
        self.user = user
        self.request_id = request_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.resource = resource
        self.action = action
        self.timestamp = datetime.now()

class PasswordManager:
    """Secure password management"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.min_length = 12
        self.require_special = True
        self.require_numbers = True
        self.require_uppercase = True
        
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return self.pwd_context.hash(password)
        
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(password, hashed)
        
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password meets security requirements"""
        errors = []
        
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")
            
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain uppercase letters")
            
        if self.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain numbers")
            
        if self.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain special characters")
            
        return len(errors) == 0, errors
        
    def generate_secure_password(self) -> str:
        """Generate cryptographically secure password"""
        import string
        
        # Ensure at least one character from each required type
        chars = []
        chars.append(secrets.choice(string.ascii_uppercase))
        chars.append(secrets.choice(string.ascii_lowercase))
        chars.append(secrets.choice(string.digits))
        chars.append(secrets.choice("!@#$%^&*"))
        
        # Fill remaining length with random characters
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        for _ in range(self.min_length - 4):
            chars.append(secrets.choice(all_chars))
            
        # Shuffle the characters
        secrets.SystemRandom().shuffle(chars)
        return ''.join(chars)

class JWTManager:
    """JWT token management"""
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        self.refresh_token_expire = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
    def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = user_data.copy()
        expire = datetime.utcnow() + self.access_token_expire
        to_encode.update({"exp": expire, "type": "access"})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
    def create_refresh_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = {"sub": user_data["sub"], "type": "refresh"}
        expire = datetime.utcnow() + self.refresh_token_expire
        to_encode.update({"exp": expire})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

class MultiFactorAuth:
    """Multi-factor authentication system"""
    
    def __init__(self):
        self.totp_issuer = "PHISHNET"
        
    async def setup_totp(self, user_id: str, user_email: str) -> Dict[str, str]:
        """Setup TOTP for user"""
        import pyotp
        import qrcode
        from io import BytesIO
        import base64
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            user_email,
            issuer_name=self.totp_issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = BytesIO()
        img.save(img_buffer, format="PNG")
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{img_str}",
            "totp_uri": totp_uri
        }
        
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        import pyotp
        
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
        
    async def send_sms_code(self, phone_number: str) -> str:
        """Send SMS verification code"""
        # Generate 6-digit code
        code = str(secrets.randbelow(1000000)).zfill(6)
        
        # In production, integrate with SMS provider (Twilio, AWS SNS, etc.)
        # For now, log the code (remove in production)
        logger.info(f"SMS code for {phone_number}: {code}")
        
        return code
        
    async def send_email_code(self, email: str) -> str:
        """Send email verification code"""
        # Generate 6-digit code
        code = str(secrets.randbelow(1000000)).zfill(6)
        
        # In production, send actual email
        logger.info(f"Email code for {email}: {code}")
        
        return code

class RoleBasedAccessControl:
    """Role-based access control system"""
    
    def __init__(self):
        self.role_permissions = self._initialize_default_permissions()
        
    def _initialize_default_permissions(self) -> Dict[str, List[str]]:
        """Initialize default role permissions"""
        return {
            RoleType.SUPER_ADMIN: [perm.value for perm in PermissionType],
            RoleType.ORG_ADMIN: [
                PermissionType.ANALYZE_EMAIL,
                PermissionType.VIEW_ANALYSIS,
                PermissionType.EXPORT_ANALYSIS,
                PermissionType.VIEW_CAMPAIGNS,
                PermissionType.MANAGE_CAMPAIGNS,
                PermissionType.VIEW_USERS,
                PermissionType.CREATE_USER,
                PermissionType.EDIT_USER,
                PermissionType.DELETE_USER,
                PermissionType.VIEW_ORG_SETTINGS,
                PermissionType.EDIT_ORG_SETTINGS,
                PermissionType.MANAGE_BILLING,
                PermissionType.VIEW_AUDIT_LOGS,
                PermissionType.MANAGE_SECURITY,
                PermissionType.API_ACCESS
            ],
            RoleType.SECURITY_ANALYST: [
                PermissionType.ANALYZE_EMAIL,
                PermissionType.VIEW_ANALYSIS,
                PermissionType.EXPORT_ANALYSIS,
                PermissionType.VIEW_CAMPAIGNS,
                PermissionType.MANAGE_CAMPAIGNS,
                PermissionType.VIEW_USERS,
                PermissionType.VIEW_AUDIT_LOGS,
                PermissionType.API_ACCESS
            ],
            RoleType.USER: [
                PermissionType.ANALYZE_EMAIL,
                PermissionType.VIEW_ANALYSIS,
                PermissionType.VIEW_CAMPAIGNS
            ],
            RoleType.API_CLIENT: [
                PermissionType.ANALYZE_EMAIL,
                PermissionType.VIEW_ANALYSIS,
                PermissionType.API_ACCESS
            ],
            RoleType.READONLY: [
                PermissionType.VIEW_ANALYSIS,
                PermissionType.VIEW_CAMPAIGNS
            ]
        }
        
    async def check_permission(
        self,
        user: AuthenticatedUser,
        required_permission: PermissionType,
        resource_org_id: str = None
    ) -> bool:
        """Check if user has required permission"""
        
        # Super admin has all permissions
        if RoleType.SUPER_ADMIN in user.roles:
            return True
            
        # Check organization boundary
        if resource_org_id and resource_org_id != user.organization_id:
            return False
            
        # Check if user has permission directly or through roles
        if required_permission.value in user.permissions:
            return True
            
        # Check role-based permissions
        for role in user.roles:
            role_perms = self.role_permissions.get(role, [])
            if required_permission.value in role_perms:
                return True
                
        return False
        
    async def get_user_permissions(
        self, 
        user_id: str, 
        db_session: AsyncSession
    ) -> List[str]:
        """Get all permissions for user"""
        
        # Get user roles
        query = select(UserRole).where(UserRole.user_id == user_id)
        result = await db_session.execute(query)
        user_roles = result.scalars().all()
        
        permissions = set()
        
        # Add role-based permissions
        for user_role in user_roles:
            role_perms = self.role_permissions.get(user_role.role_name, [])
            permissions.update(role_perms)
            
        # Add direct permissions (custom permissions)
        query = select(Permission).join(UserRole).where(UserRole.user_id == user_id)
        result = await db_session.execute(query)
        direct_permissions = result.scalars().all()
        
        for perm in direct_permissions:
            permissions.add(perm.permission_name)
            
        return list(permissions)

class AuditLogger:
    """Comprehensive audit logging system"""
    
    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        
    async def log_security_event(
        self,
        event_type: str,
        user_id: str,
        organization_id: str,
        details: Dict[str, Any],
        db_session: AsyncSession,
        severity: str = "info"
    ):
        """Log security event"""
        
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            user_id=user_id,
            organization_id=organization_id,
            severity=severity,
            details=details,
            timestamp=datetime.now(),
            ip_address=details.get('ip_address'),
            user_agent=details.get('user_agent')
        )
        
        db_session.add(event)
        
        # Also cache in Redis for real-time monitoring
        await self.redis.lpush(
            f"security_events:{organization_id}",
            json.dumps({
                "event_id": event.id,
                "event_type": event_type,
                "user_id": user_id,
                "severity": severity,
                "timestamp": event.timestamp.isoformat(),
                "details": details
            })
        )
        
        # Keep only last 1000 events in Redis
        await self.redis.ltrim(f"security_events:{organization_id}", 0, 999)
        
    async def log_user_action(
        self,
        action: str,
        user_id: str,
        organization_id: str,
        resource: str,
        details: Dict[str, Any],
        db_session: AsyncSession
    ):
        """Log user action for audit trail"""
        
        audit_log = AuditLog(
            id=str(uuid.uuid4()),
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource=resource,
            resource_id=details.get('resource_id'),
            old_values=details.get('old_values'),
            new_values=details.get('new_values'),
            timestamp=datetime.now(),
            ip_address=details.get('ip_address'),
            user_agent=details.get('user_agent'),
            session_id=details.get('session_id')
        )
        
        db_session.add(audit_log)
        
    async def log_authentication_event(
        self,
        event_type: str,  # login_success, login_failed, logout, token_refresh
        user_id: str,
        organization_id: str,
        details: Dict[str, Any],
        db_session: AsyncSession
    ):
        """Log authentication events"""
        
        await self.log_security_event(
            f"auth_{event_type}",
            user_id,
            organization_id,
            details,
            db_session,
            severity="warning" if "failed" in event_type else "info"
        )

class DataEncryption:
    """Data encryption for sensitive information"""
    
    def __init__(self):
        # In production, load from secure key management system
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return data
            
        return self.fernet.encrypt(data.encode()).decode()
        
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return encrypted_data
            
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

class SessionManager:
    """User session management"""
    
    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self.session_timeout = timedelta(hours=8)
        
    async def create_session(
        self,
        user_id: str,
        organization_id: str,
        ip_address: str,
        user_agent: str,
        db_session: AsyncSession
    ) -> str:
        """Create user session"""
        
        session_id = str(uuid.uuid4())
        
        # Store session in database
        session = UserSession(
            id=session_id,
            user_id=user_id,
            organization_id=organization_id,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True
        )
        
        db_session.add(session)
        
        # Cache session in Redis
        session_data = {
            "user_id": user_id,
            "organization_id": organization_id,
            "created_at": datetime.now().isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent
        }
        
        await self.redis.setex(
            f"session:{session_id}",
            int(self.session_timeout.total_seconds()),
            json.dumps(session_data)
        )
        
        return session_id
        
    async def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return session data"""
        
        session_data = await self.redis.get(f"session:{session_id}")
        if session_data:
            # Extend session timeout
            await self.redis.expire(
                f"session:{session_id}",
                int(self.session_timeout.total_seconds())
            )
            return json.loads(session_data)
            
        return None
        
    async def invalidate_session(self, session_id: str, db_session: AsyncSession):
        """Invalidate user session"""
        
        # Remove from Redis
        await self.redis.delete(f"session:{session_id}")
        
        # Mark as inactive in database
        query = update(UserSession).where(UserSession.id == session_id).values(
            is_active=False,
            ended_at=datetime.now()
        )
        await db_session.execute(query)

class ComplianceManager:
    """Compliance and data protection management"""
    
    def __init__(self):
        self.gdpr_enabled = settings.GDPR_COMPLIANCE
        self.data_retention_days = settings.DATA_RETENTION_DAYS
        
    async def handle_data_subject_request(
        self,
        request_type: str,  # access, portability, erasure, rectification
        user_email: str,
        organization_id: str,
        db_session: AsyncSession
    ) -> str:
        """Handle GDPR data subject requests"""
        
        request_id = str(uuid.uuid4())
        
        if request_type == "access":
            # Generate user data export
            data_export = await self._generate_user_data_export(user_email, db_session)
            return data_export
            
        elif request_type == "erasure":
            # Right to be forgotten
            await self._anonymize_user_data(user_email, organization_id, db_session)
            
        elif request_type == "portability":
            # Data portability
            portable_data = await self._generate_portable_data(user_email, db_session)
            return portable_data
            
        return request_id
        
    async def _generate_user_data_export(
        self,
        user_email: str,
        db_session: AsyncSession
    ) -> Dict[str, Any]:
        """Generate complete user data export"""
        
        # Get user data
        query = select(User).where(User.email == user_email)
        result = await db_session.execute(query)
        user = result.scalar_one_or_none()
        
        if not user:
            return {}
            
        # Collect all user-related data
        export_data = {
            "user_profile": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None
            },
            "email_analyses": await self._get_user_email_analyses(user.id, db_session),
            "audit_logs": await self._get_user_audit_logs(user.id, db_session),
            "sessions": await self._get_user_sessions(user.id, db_session)
        }
        
        return export_data

# Global security components
password_manager = PasswordManager()
jwt_manager = JWTManager()
mfa_manager = MultiFactorAuth()
rbac_manager = RoleBasedAccessControl()
encryption_manager = DataEncryption()

# HTTP Bearer security
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db_session: AsyncSession = Depends(get_db_session),
    redis_client: aioredis.Redis = Depends(get_redis_client)
) -> AuthenticatedUser:
    """Get current authenticated user from JWT token"""
    
    token = credentials.credentials
    
    try:
        # Verify JWT token
        payload = jwt_manager.verify_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
            
        # Get user from database
        query = select(User).where(User.id == user_id)
        result = await db_session.execute(query)
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
            
        # Get user roles and permissions
        permissions = await rbac_manager.get_user_permissions(user_id, db_session)
        
        query = select(UserRole).where(UserRole.user_id == user_id)
        result = await db_session.execute(query)
        user_roles = result.scalars().all()
        roles = [ur.role_name for ur in user_roles]
        
        return AuthenticatedUser(
            user_id=user.id,
            organization_id=user.organization_id,
            email=user.email,
            roles=roles,
            permissions=permissions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

def require_permission(required_permission: PermissionType):
    """Dependency to require specific permission"""
    
    async def permission_checker(
        user: AuthenticatedUser = Depends(get_current_user)
    ) -> AuthenticatedUser:
        
        has_permission = await rbac_manager.check_permission(
            user,
            required_permission
        )
        
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {required_permission.value} required"
            )
            
        return user
        
    return permission_checker

async def initialize_security_system(redis_client: aioredis.Redis):
    """Initialize security system components"""
    
    audit_logger = AuditLogger(redis_client)
    session_manager = SessionManager(redis_client)
    compliance_manager = ComplianceManager()
    
    logger.info("Security system initialized")
    
    return audit_logger, session_manager, compliance_manager