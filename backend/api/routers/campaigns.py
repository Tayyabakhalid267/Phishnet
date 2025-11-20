from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
from core.security import verify_token
import uuid

router = APIRouter()

class Campaign(BaseModel):
    """Phishing campaign model."""
    id: str
    name: str
    description: str
    start_date: datetime
    end_date: Optional[datetime]
    threat_actor: Optional[str]
    targets: int
    success_rate: float
    status: str
    indicators: List[Dict[str, Any]]

class CampaignCreate(BaseModel):
    """Campaign creation model."""
    name: str
    description: str
    threat_actor: Optional[str] = None

@router.get("/", response_model=List[Campaign])
async def get_campaigns(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, description="Maximum number of campaigns"),
    token_data: dict = Depends(verify_token)
) -> List[Campaign]:
    """
    Get list of phishing campaigns.
    
    Args:
        status: Filter by campaign status
        limit: Maximum results to return
        token_data: User token data
        
    Returns:
        List[Campaign]: List of campaigns
    """
    # Demo campaigns data
    campaigns = [
        Campaign(
            id="camp_001",
            name="Operation DeepFake Bank",
            description="Sophisticated banking credential harvesting campaign using AI-generated fake login pages",
            start_date=datetime.now() - timedelta(days=15),
            end_date=None,
            threat_actor="APT-Banking-001",
            targets=1247,
            success_rate=0.23,
            status="active",
            indicators=[
                {"type": "domain", "value": "secure-banklogin[.]com", "confidence": 0.95},
                {"type": "ip", "value": "185.234.72.89", "confidence": 0.87},
                {"type": "email_pattern", "value": ".*@notification-bank[.].*", "confidence": 0.92}
            ]
        ),
        Campaign(
            id="camp_002", 
            name="COVID-19 Relief Scam",
            description="Fake government relief fund applications targeting personal information",
            start_date=datetime.now() - timedelta(days=7),
            end_date=datetime.now() - timedelta(days=1),
            threat_actor="Unknown",
            targets=892,
            success_rate=0.31,
            status="contained",
            indicators=[
                {"type": "domain", "value": "gov-relief-fund[.]org", "confidence": 0.98},
                {"type": "subject_line", "value": "Emergency Relief Fund Application", "confidence": 0.89}
            ]
        ),
        Campaign(
            id="camp_003",
            name="Tech Support Impersonation",
            description="Microsoft/Apple tech support impersonation with remote access tools",
            start_date=datetime.now() - timedelta(days=3),
            end_date=None,
            threat_actor="TechScam-Group",
            targets=2156,
            success_rate=0.18,
            status="monitoring",
            indicators=[
                {"type": "phone", "value": "+1-888-555-TECH", "confidence": 0.94},
                {"type": "domain", "value": "microsoft-support-center[.]net", "confidence": 0.96}
            ]
        )
    ]
    
    # Filter by status if provided
    if status:
        campaigns = [c for c in campaigns if c.status == status]
    
    return campaigns[:limit]

@router.get("/{campaign_id}", response_model=Campaign)
async def get_campaign(
    campaign_id: str,
    token_data: dict = Depends(verify_token)
) -> Campaign:
    """
    Get specific campaign details.
    
    Args:
        campaign_id: Campaign identifier
        token_data: User token data
        
    Returns:
        Campaign: Campaign details
    """
    # Demo: return mock campaign
    return Campaign(
        id=campaign_id,
        name="Detailed Campaign View",
        description=f"Comprehensive analysis of campaign {campaign_id} with full threat intelligence",
        start_date=datetime.now() - timedelta(days=10),
        end_date=None,
        threat_actor="Advanced Persistent Threat Group",
        targets=5432,
        success_rate=0.27,
        status="active",
        indicators=[
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "confidence": 1.0},
            {"type": "mutex", "value": "PhishMutex_2024", "confidence": 0.88}
        ]
    )

@router.post("/", response_model=Dict[str, str])
async def create_campaign(
    campaign: CampaignCreate,
    token_data: dict = Depends(verify_token)
) -> Dict[str, str]:
    """
    Create new campaign tracking entry.
    
    Args:
        campaign: Campaign creation data
        token_data: User token data
        
    Returns:
        dict: Creation confirmation
    """
    campaign_id = f"camp_{uuid.uuid4().hex[:8]}"
    
    return {
        "message": "🎯 Campaign tracking created successfully",
        "campaign_id": campaign_id,
        "name": campaign.name,
        "status": "created"
    }

@router.get("/{campaign_id}/timeline")
async def get_campaign_timeline(
    campaign_id: str,
    token_data: dict = Depends(verify_token)
) -> List[Dict[str, Any]]:
    """
    Get campaign timeline events.
    
    Args:
        campaign_id: Campaign identifier
        token_data: User token data
        
    Returns:
        List[Dict]: Timeline events
    """
    timeline = [
        {
            "timestamp": (datetime.now() - timedelta(days=10)).isoformat(),
            "event": "Campaign Detected", 
            "description": "Initial phishing emails identified by AI detection engine",
            "severity": "medium",
            "source": "AI_NLP_Engine"
        },
        {
            "timestamp": (datetime.now() - timedelta(days=9)).isoformat(),
            "event": "Domain Registration",
            "description": "Malicious domain registered: fake-secure-bank.com",
            "severity": "high", 
            "source": "Domain_Intelligence"
        },
        {
            "timestamp": (datetime.now() - timedelta(days=8)).isoformat(),
            "event": "Infrastructure Analysis",
            "description": "Hosting provider identified: Bulletproof hosting service",
            "severity": "high",
            "source": "Infrastructure_Analysis"
        },
        {
            "timestamp": (datetime.now() - timedelta(days=5)).isoformat(),
            "event": "Victim Interactions",
            "description": "First confirmed credential harvesting detected",
            "severity": "critical",
            "source": "Honeypot_Network"
        },
        {
            "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
            "event": "Takedown Request",
            "description": "Abuse report submitted to hosting provider",
            "severity": "low",
            "source": "Automated_Takedown"
        }
    ]
    
    return timeline

@router.get("/{campaign_id}/indicators")
async def get_campaign_indicators(
    campaign_id: str,
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    token_data: dict = Depends(verify_token)
) -> List[Dict[str, Any]]:
    """
    Get campaign indicators of compromise (IOCs).
    
    Args:
        campaign_id: Campaign identifier
        ioc_type: Filter by IOC type
        token_data: User token data
        
    Returns:
        List[Dict]: Campaign IOCs
    """
    indicators = [
        {
            "type": "domain",
            "value": "secure-banking-portal.com",
            "confidence": 0.95,
            "first_seen": (datetime.now() - timedelta(days=8)).isoformat(),
            "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
            "tags": ["phishing", "banking", "credential_harvesting"]
        },
        {
            "type": "ip",
            "value": "192.168.1.100",
            "confidence": 0.87,
            "first_seen": (datetime.now() - timedelta(days=7)).isoformat(),
            "last_seen": (datetime.now() - timedelta(hours=1)).isoformat(),
            "tags": ["c2", "bulletproof_hosting"]
        },
        {
            "type": "email",
            "value": "security@bank-notifications.org",
            "confidence": 0.92,
            "first_seen": (datetime.now() - timedelta(days=6)).isoformat(),
            "last_seen": (datetime.now() - timedelta(hours=3)).isoformat(),
            "tags": ["phishing_sender", "impersonation"]
        },
        {
            "type": "hash",
            "value": "e3b0c44298fc1c149afbf4c8996fb924",
            "confidence": 1.0,
            "first_seen": (datetime.now() - timedelta(days=5)).isoformat(),
            "last_seen": (datetime.now() - timedelta(hours=4)).isoformat(),
            "tags": ["malware", "credential_stealer"]
        }
    ]
    
    if ioc_type:
        indicators = [ioc for ioc in indicators if ioc["type"] == ioc_type]
    
    return indicators

@router.post("/{campaign_id}/correlate")
async def correlate_campaign(
    campaign_id: str,
    token_data: dict = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Perform campaign correlation analysis.
    
    Args:
        campaign_id: Campaign identifier
        token_data: User token data
        
    Returns:
        dict: Correlation results
    """
    return {
        "campaign_id": campaign_id,
        "correlation_results": {
            "related_campaigns": [
                {"id": "camp_004", "similarity": 0.87, "overlap": "domain_pattern"},
                {"id": "camp_007", "similarity": 0.73, "overlap": "infrastructure"}
            ],
            "threat_actor_attribution": {
                "confidence": 0.82,
                "actor_name": "FIN7-Banking-Subset",
                "reasoning": "TTPs match historical FIN7 banking operations"
            },
            "infrastructure_overlap": {
                "shared_ips": 3,
                "shared_domains": 5,
                "shared_certificates": 1
            }
        },
        "timestamp": datetime.now().isoformat()
    }