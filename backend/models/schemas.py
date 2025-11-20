"""
Pydantic schemas for API request/response models
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"  
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EmailAnalysisRequest(BaseModel):
    content: str = Field(..., description="Email content to analyze")
    sender: Optional[str] = Field(None, description="Sender email address")
    subject: Optional[str] = Field(None, description="Email subject")
    headers: Optional[Dict[str, str]] = Field(None, description="Email headers")
    
class ThreatAnalysisResponse(BaseModel):
    threat_level: ThreatLevel
    threat_score: float = Field(..., ge=0.0, le=1.0, description="Risk score between 0 and 1")
    analysis: Dict[str, Any] = Field(..., description="Detailed analysis results")
    recommendations: List[str] = Field(..., description="Security recommendations")
    timestamp: str = Field(..., description="Analysis timestamp")
    scan_id: Optional[str] = Field(None, description="Unique scan identifier")

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    
class CampaignInfo(BaseModel):
    id: str
    name: str
    threat_actor: Optional[str] = None
    targets: int = 0
    success_rate: float = Field(0.0, ge=0.0, le=1.0)
    status: str = "unknown"
    start_date: Optional[str] = None
    
class ThreatStatistics(BaseModel):
    total_emails_scanned: int = 0
    threats_detected: int = 0
    threats_blocked: int = 0
    detection_rate: float = Field(0.0, ge=0.0, le=1.0)
    top_threats: List[Dict[str, Any]] = []
    recent_activity: List[Dict[str, Any]] = []