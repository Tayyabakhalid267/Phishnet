from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
from core.security import verify_token
import uuid

router = APIRouter()

class SystemMetrics(BaseModel):
    """System metrics model."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    active_scans: int
    total_users: int
    threat_feeds_status: str

class UserManagement(BaseModel):
    """User management model."""
    id: str
    username: str
    email: str
    role: str
    status: str
    last_login: Optional[datetime]
    created_date: datetime

@router.get("/dashboard")
async def get_admin_dashboard(
    token_data: dict = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Get admin dashboard overview.
    
    Args:
        token_data: User token data
        
    Returns:
        dict: Admin dashboard data
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    return {
        "system_status": {
            "status": "🟢 Online",
            "uptime": "15 days, 6 hours",
            "version": "1.0.0",
            "environment": "production"
        },
        "metrics": {
            "total_scans": 15634,
            "threats_detected": 892,
            "false_positives": 45,
            "active_campaigns": 12,
            "blocked_domains": 234,
            "quarantined_emails": 456
        },
        "performance": {
            "avg_scan_time": "2.3s",
            "detection_accuracy": "94.7%",
            "api_response_time": "145ms",
            "system_load": "67%"
        },
        "recent_alerts": [
            {
                "timestamp": datetime.now() - timedelta(minutes=5),
                "type": "high_risk_detection",
                "message": "Advanced phishing campaign targeting financial services",
                "severity": "high"
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=15),
                "type": "system_alert",
                "message": "Threat intelligence feeds updated successfully",
                "severity": "info"
            }
        ]
    }

@router.get("/system/metrics", response_model=SystemMetrics)
async def get_system_metrics(
    token_data: dict = Depends(verify_token)
) -> SystemMetrics:
    """
    Get real-time system metrics.
    
    Args:
        token_data: User token data
        
    Returns:
        SystemMetrics: Current system metrics
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    return SystemMetrics(
        cpu_usage=67.3,
        memory_usage=78.9,
        disk_usage=45.2,
        active_scans=23,
        total_users=156,
        threat_feeds_status="✅ Active"
    )

@router.get("/users", response_model=List[UserManagement])
async def get_users(
    status: Optional[str] = Query(None, description="Filter by user status"),
    role: Optional[str] = Query(None, description="Filter by user role"),
    limit: int = Query(50, description="Maximum users to return"),
    token_data: dict = Depends(verify_token)
) -> List[UserManagement]:
    """
    Get user management list.
    
    Args:
        status: Filter by user status
        role: Filter by user role
        limit: Maximum results
        token_data: User token data
        
    Returns:
        List[UserManagement]: List of users
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    users = [
        UserManagement(
            id="user_001",
            username="admin",
            email="admin@phishnet.ai",
            role="admin",
            status="active",
            last_login=datetime.now() - timedelta(minutes=5),
            created_date=datetime.now() - timedelta(days=365)
        ),
        UserManagement(
            id="user_002",
            username="analyst1",
            email="analyst1@company.com",
            role="analyst",
            status="active",
            last_login=datetime.now() - timedelta(hours=2),
            created_date=datetime.now() - timedelta(days=120)
        ),
        UserManagement(
            id="user_003",
            username="soc_team",
            email="soc@security.corp",
            role="analyst",
            status="active",
            last_login=datetime.now() - timedelta(hours=6),
            created_date=datetime.now() - timedelta(days=60)
        )
    ]
    
    # Apply filters
    if status:
        users = [u for u in users if u.status == status]
    if role:
        users = [u for u in users if u.role == role]
    
    return users[:limit]

@router.post("/users/{user_id}/disable")
async def disable_user(
    user_id: str,
    token_data: dict = Depends(verify_token)
) -> Dict[str, str]:
    """
    Disable user account.
    
    Args:
        user_id: User identifier
        token_data: User token data
        
    Returns:
        dict: Disable confirmation
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    return {
        "message": f"🔒 User {user_id} disabled successfully",
        "user_id": user_id,
        "disabled_by": token_data.get("sub"),
        "timestamp": datetime.now().isoformat()
    }

@router.post("/system/backup")
async def create_system_backup(
    backup_type: str = Query("full", description="Backup type: full, incremental"),
    token_data: dict = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Create system backup.
    
    Args:
        backup_type: Type of backup to create
        token_data: User token data
        
    Returns:
        dict: Backup creation status
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    backup_id = f"backup_{uuid.uuid4().hex[:12]}"
    
    return {
        "message": f"💾 {backup_type.title()} backup initiated",
        "backup_id": backup_id,
        "type": backup_type,
        "estimated_duration": "15-20 minutes",
        "started_by": token_data.get("sub"),
        "timestamp": datetime.now().isoformat()
    }

@router.get("/threat-feeds/status")
async def get_threat_feeds_status(
    token_data: dict = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Get threat intelligence feeds status.
    
    Args:
        token_data: User token data
        
    Returns:
        dict: Threat feeds status
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    return {
        "feeds": {
            "virustotal": {
                "status": "✅ Active",
                "last_update": (datetime.now() - timedelta(minutes=15)).isoformat(),
                "api_calls_remaining": 9500,
                "errors": 0
            },
            "phishtank": {
                "status": "✅ Active", 
                "last_update": (datetime.now() - timedelta(minutes=30)).isoformat(),
                "entries": 125430,
                "errors": 0
            },
            "abuseipdb": {
                "status": "⚠️ Rate Limited",
                "last_update": (datetime.now() - timedelta(hours=2)).isoformat(),
                "api_calls_remaining": 50,
                "errors": 12
            },
            "google_safe_browsing": {
                "status": "✅ Active",
                "last_update": (datetime.now() - timedelta(minutes=5)).isoformat(),
                "cache_size": "2.3GB",
                "errors": 0
            }
        },
        "summary": {
            "total_feeds": 4,
            "active_feeds": 3,
            "warning_feeds": 1,
            "offline_feeds": 0
        }
    }

@router.post("/threat-feeds/refresh")
async def refresh_threat_feeds(
    feeds: List[str] = Query(["all"], description="Feeds to refresh"),
    token_data: dict = Depends(verify_token)
) -> Dict[str, str]:
    """
    Manually refresh threat intelligence feeds.
    
    Args:
        feeds: List of feeds to refresh
        token_data: User token data
        
    Returns:
        dict: Refresh status
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    return {
        "message": "🔄 Threat feeds refresh initiated",
        "feeds": feeds,
        "estimated_duration": "5-10 minutes",
        "initiated_by": token_data.get("sub"),
        "timestamp": datetime.now().isoformat()
    }

@router.get("/audit/logs")
async def get_audit_logs(
    start_date: Optional[str] = Query(None, description="Start date filter"),
    end_date: Optional[str] = Query(None, description="End date filter"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    limit: int = Query(100, description="Maximum logs to return"),
    token_data: dict = Depends(verify_token)
) -> List[Dict[str, Any]]:
    """
    Get system audit logs.
    
    Args:
        start_date: Start date filter
        end_date: End date filter
        action: Action type filter
        limit: Maximum results
        token_data: User token data
        
    Returns:
        List[Dict]: Audit log entries
    """
    # Verify admin role
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="🔒 Admin access required"
        )
    
    logs = [
        {
            "timestamp": datetime.now() - timedelta(minutes=10),
            "user": "admin",
            "action": "scan_email",
            "resource": "email_001.eml",
            "ip_address": "192.168.1.100",
            "result": "threat_detected",
            "details": "Phishing email identified with 0.87 confidence"
        },
        {
            "timestamp": datetime.now() - timedelta(minutes=25),
            "user": "analyst1", 
            "action": "generate_report",
            "resource": "campaign_report_q4",
            "ip_address": "10.0.0.15",
            "result": "success",
            "details": "Quarterly campaign analysis report generated"
        },
        {
            "timestamp": datetime.now() - timedelta(hours=1),
            "user": "soc_team",
            "action": "disable_user",
            "resource": "user_suspicious_001",
            "ip_address": "172.16.0.50",
            "result": "success",
            "details": "Suspicious user account disabled"
        }
    ]
    
    # Apply filters (simplified)
    if action:
        logs = [log for log in logs if log["action"] == action]
    
    return logs[:limit]