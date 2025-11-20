from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime
from core.security import verify_token

router = APIRouter()

class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str

class RegisterRequest(BaseModel):
    """Registration request model."""
    username: str
    email: str
    password: str
    role: Optional[str] = "analyst"

class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str
    expires_in: int
    user_info: Dict[str, Any]

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return access token.
    
    Args:
        request: Login credentials
        
    Returns:
        TokenResponse: Access token and user info
    """
    # Demo authentication (replace with real user verification)
    if request.username == "admin" and request.password == "phishnet123":
        from core.security import create_access_token
        
        token_data = {"sub": request.username, "role": "admin"}
        access_token = create_access_token(data=token_data)
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=1800,  # 30 minutes
            user_info={
                "username": request.username,
                "role": "admin",
                "permissions": ["scan", "analyze", "admin", "reports"],
                "avatar": "https://ui-avatars.com/api/?name=Admin&background=00ff88&color=000"
            }
        )
    else:
        raise HTTPException(
            status_code=401,
            detail="🔒 Invalid credentials"
        )

@router.post("/register", response_model=Dict[str, str])
async def register(request: RegisterRequest):
    """
    Register new user account.
    
    Args:
        request: Registration data
        
    Returns:
        dict: Registration confirmation
    """
    # Demo registration (replace with real user creation)
    return {
        "message": f"✅ User {request.username} registered successfully",
        "user_id": f"user_{request.username}",
        "role": request.role
    }

@router.get("/me")
async def get_current_user(token_data: dict = Depends(verify_token)):
    """
    Get current user information.
    
    Args:
        token_data: Decoded token data
        
    Returns:
        dict: Current user info
    """
    return {
        "username": token_data.get("sub"),
        "role": token_data.get("role", "user"),
        "permissions": ["scan", "analyze"],
        "last_login": datetime.now().isoformat(),
        "active_scans": 3,
        "total_scans": 157
    }

@router.post("/logout")
async def logout(token_data: dict = Depends(verify_token)):
    """
    Logout user and invalidate token.
    
    Args:
        token_data: Decoded token data
        
    Returns:
        dict: Logout confirmation
    """
    return {
        "message": "🔓 Successfully logged out",
        "username": token_data.get("sub")
    }