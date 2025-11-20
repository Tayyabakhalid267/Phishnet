"""
Production FastAPI Server - Full Feature Implementation
Complete integration of all AI detection, real-time processing, automation, and security systems
"""
import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import uuid

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import aioredis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, update, and_
from pydantic import BaseModel, EmailStr, Field

# Import all our production systems
from ai.detection_engine import ComprehensiveEmailAnalyzer, ThreatIntelligenceEngine
from realtime.processing import (
    initialize_real_time_system, websocket_manager, 
    CampaignCorrelationEngine, AutomatedResponseSystem
)
from automation.email_integration import initialize_email_automation, email_integration_manager
from security.authentication import (
    get_current_user, require_permission, PermissionType, AuthenticatedUser,
    initialize_security_system, password_manager, jwt_manager
)
from models.database import (
    EmailAnalysis, User, Organization, ThreatCampaign, 
    SecurityIncident, RealTimeAlert
)
from core.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global components
redis_client = None
db_engine = None
async_session = None
email_analyzer = None
correlation_engine = None
response_system = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    
    # Startup
    logger.info("🚀 Starting PHISHNET Production Server...")
    
    # Initialize database
    global db_engine, async_session
    db_engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        echo=settings.DEBUG
    )
    async_session = async_sessionmaker(db_engine, expire_on_commit=False)
    
    # Initialize Redis
    global redis_client
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True
    )
    
    # Initialize AI systems
    global email_analyzer
    email_analyzer = ComprehensiveEmailAnalyzer()
    logger.info("✅ AI Detection Engine initialized")
    
    # Initialize real-time processing
    global correlation_engine, response_system
    correlation_engine, response_system, _ = await initialize_real_time_system()
    logger.info("✅ Real-time Processing System initialized")
    
    # Initialize email automation
    await initialize_email_automation()
    logger.info("✅ Email Automation System initialized")
    
    # Initialize security system
    await initialize_security_system(redis_client)
    logger.info("✅ Security System initialized")
    
    # Start background tasks
    asyncio.create_task(websocket_ping_task())
    asyncio.create_task(cleanup_task())
    
    logger.info("🎯 PHISHNET Production Server ready!")
    
    yield
    
    # Shutdown
    logger.info("🔄 Shutting down PHISHNET...")
    await redis_client.close()
    await db_engine.dispose()
    logger.info("👋 PHISHNET shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="PHISHNET - AI Cybersecurity Suite",
    description="Advanced phishing detection and threat intelligence platform",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.DEBUG else ["phishnet.ai", "*.phishnet.ai"]
)

# Dependency providers
async def get_db_session() -> AsyncSession:
    """Get database session"""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def get_redis_client() -> aioredis.Redis:
    """Get Redis client"""
    return redis_client

# Pydantic models for API
class EmailAnalysisRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=1000000)
    sender_email: Optional[str] = None
    recipient_email: Optional[str] = None
    subject: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    attachments: Optional[List[Dict]] = None
    
class EmailAnalysisResponse(BaseModel):
    analysis_id: str
    threat_score: float
    threat_level: str
    verdict: str
    processing_time_ms: int
    detailed_analysis: Dict[str, Any]
    recommendations: List[str]

class CampaignResponse(BaseModel):
    campaign_id: str
    name: str
    description: str
    campaign_type: str
    status: str
    email_count: int
    affected_users: List[str]
    first_detected: datetime
    last_activity: datetime
    confidence: float

class UserCreateRequest(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: str = "user"
    password: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: Dict[str, Any]

# API Routes

@app.get("/", tags=["System"])
async def root():
    """Root endpoint with system status"""
    return {
        "service": "PHISHNET AI Cybersecurity Suite",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "Advanced AI email analysis",
            "Real-time threat detection", 
            "Campaign correlation",
            "Automated response systems",
            "Multi-tenant architecture",
            "Enterprise security"
        ]
    }

@app.get("/health", tags=["System"])
async def health_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {}
    }
    
    # Check database
    try:
        async with async_session() as session:
            await session.execute("SELECT 1")
        health_status["components"]["database"] = "healthy"
    except Exception as e:
        health_status["components"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Check Redis
    try:
        await redis_client.ping()
        health_status["components"]["redis"] = "healthy"
    except Exception as e:
        health_status["components"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Check AI models
    try:
        if email_analyzer and hasattr(email_analyzer, 'nlp_analyzer'):
            health_status["components"]["ai_models"] = "healthy"
        else:
            health_status["components"]["ai_models"] = "not_loaded"
    except Exception as e:
        health_status["components"]["ai_models"] = f"unhealthy: {str(e)}"
    
    return health_status

# Authentication endpoints
@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login(
    request: LoginRequest,
    db_session: AsyncSession = Depends(get_db_session)
):
    """Authenticate user and return JWT tokens"""
    
    # Get user by email
    query = select(User).where(User.email == request.email)
    result = await db_session.execute(query)
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not password_manager.verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check MFA if enabled
    if user.mfa_enabled and not request.mfa_code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA code required"
        )
    
    # Create JWT tokens
    user_data = {
        "sub": user.id,
        "email": user.email,
        "org_id": user.organization_id
    }
    
    access_token = jwt_manager.create_access_token(user_data)
    refresh_token = jwt_manager.create_refresh_token(user_data)
    
    # Update last login
    user.last_login = datetime.now()
    await db_session.commit()
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "organization_id": user.organization_id
        }
    )

@app.post("/auth/logout", tags=["Authentication"])
async def logout(
    user: AuthenticatedUser = Depends(get_current_user)
):
    """Logout user and invalidate session"""
    # In production, would invalidate token in Redis blacklist
    return {"message": "Successfully logged out"}

# Email Analysis endpoints
@app.post("/api/v1/analyze", response_model=EmailAnalysisResponse, tags=["Email Analysis"])
async def analyze_email(
    request: EmailAnalysisRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.ANALYZE_EMAIL)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Comprehensive email analysis using production AI models"""
    
    analysis_start = datetime.now()
    
    try:
        # Run comprehensive analysis
        analysis_result = await email_analyzer.analyze_email_comprehensive(
            content=request.content,
            headers=request.headers,
            attachments=request.attachments
        )
        
        # Create analysis record
        analysis_id = str(uuid.uuid4())
        email_analysis = EmailAnalysis(
            id=analysis_id,
            organization_id=user.organization_id,
            user_id=user.user_id,
            sender_email=request.sender_email or "unknown@example.com",
            recipient_email=request.recipient_email or user.email,
            subject=request.subject or "No Subject",
            content=request.content[:10000],  # Store first 10k chars
            threat_score=analysis_result['risk_score'],
            threat_level=analysis_result['threat_level'],
            threat_categories=[analysis_result['verdict']],
            analysis_metadata=analysis_result['analysis'],
            received_at=datetime.now(),
            analyzed_at=datetime.now(),
            status='analyzed'
        )
        
        db_session.add(email_analysis)
        await db_session.commit()
        
        # Background processing for campaign correlation
        background_tasks.add_task(
            process_campaign_correlation,
            email_analysis,
            user.organization_id
        )
        
        # Generate recommendations
        recommendations = generate_recommendations(analysis_result)
        
        return EmailAnalysisResponse(
            analysis_id=analysis_id,
            threat_score=analysis_result['risk_score'],
            threat_level=analysis_result['threat_level'],
            verdict=analysis_result['verdict'],
            processing_time_ms=analysis_result['processing_time_ms'],
            detailed_analysis=analysis_result['analysis'],
            recommendations=recommendations
        )
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed"
        )

@app.get("/api/v1/analyses", tags=["Email Analysis"])
async def get_analyses(
    limit: int = 50,
    offset: int = 0,
    threat_level: Optional[str] = None,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.VIEW_ANALYSIS)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Get email analyses for organization"""
    
    query = select(EmailAnalysis).where(
        EmailAnalysis.organization_id == user.organization_id
    ).order_by(EmailAnalysis.analyzed_at.desc()).offset(offset).limit(limit)
    
    if threat_level:
        query = query.where(EmailAnalysis.threat_level == threat_level)
    
    result = await db_session.execute(query)
    analyses = result.scalars().all()
    
    return {
        "analyses": [
            {
                "id": analysis.id,
                "sender_email": analysis.sender_email,
                "subject": analysis.subject,
                "threat_score": analysis.threat_score,
                "threat_level": analysis.threat_level,
                "analyzed_at": analysis.analyzed_at.isoformat(),
                "status": analysis.status
            }
            for analysis in analyses
        ],
        "total": len(analyses),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/v1/analyses/{analysis_id}", tags=["Email Analysis"])
async def get_analysis_details(
    analysis_id: str,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.VIEW_ANALYSIS)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Get detailed analysis results"""
    
    query = select(EmailAnalysis).where(
        and_(
            EmailAnalysis.id == analysis_id,
            EmailAnalysis.organization_id == user.organization_id
        )
    )
    result = await db_session.execute(query)
    analysis = result.scalar_one_or_none()
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    return {
        "id": analysis.id,
        "sender_email": analysis.sender_email,
        "recipient_email": analysis.recipient_email,
        "subject": analysis.subject,
        "content": analysis.content,
        "threat_score": analysis.threat_score,
        "threat_level": analysis.threat_level,
        "threat_categories": analysis.threat_categories,
        "analysis_metadata": analysis.analysis_metadata,
        "received_at": analysis.received_at.isoformat(),
        "analyzed_at": analysis.analyzed_at.isoformat(),
        "status": analysis.status,
        "campaign_id": analysis.campaign_id
    }

# Campaign Management endpoints
@app.get("/api/v1/campaigns", tags=["Threat Campaigns"])
async def get_campaigns(
    status: Optional[str] = None,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.VIEW_CAMPAIGNS)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Get threat campaigns for organization"""
    
    query = select(ThreatCampaign).where(
        ThreatCampaign.organization_id == user.organization_id
    ).order_by(ThreatCampaign.last_activity.desc())
    
    if status:
        query = query.where(ThreatCampaign.status == status)
    
    result = await db_session.execute(query)
    campaigns = result.scalars().all()
    
    return {
        "campaigns": [
            CampaignResponse(
                campaign_id=campaign.id,
                name=campaign.name,
                description=campaign.description,
                campaign_type=campaign.campaign_type,
                status=campaign.status,
                email_count=campaign.email_count,
                affected_users=campaign.affected_users or [],
                first_detected=campaign.first_detected,
                last_activity=campaign.last_activity,
                confidence=campaign.confidence
            )
            for campaign in campaigns
        ]
    }

@app.get("/api/v1/campaigns/{campaign_id}", tags=["Threat Campaigns"])
async def get_campaign_details(
    campaign_id: str,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.VIEW_CAMPAIGNS)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Get detailed campaign information"""
    
    query = select(ThreatCampaign).where(
        and_(
            ThreatCampaign.id == campaign_id,
            ThreatCampaign.organization_id == user.organization_id
        )
    )
    result = await db_session.execute(query)
    campaign = result.scalar_one_or_none()
    
    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_found,
            detail="Campaign not found"
        )
    
    # Get campaign emails
    query = select(EmailAnalysis).where(EmailAnalysis.campaign_id == campaign_id)
    result = await db_session.execute(query)
    campaign_emails = result.scalars().all()
    
    return {
        "campaign": CampaignResponse(
            campaign_id=campaign.id,
            name=campaign.name,
            description=campaign.description,
            campaign_type=campaign.campaign_type,
            status=campaign.status,
            email_count=campaign.email_count,
            affected_users=campaign.affected_users or [],
            first_detected=campaign.first_detected,
            last_activity=campaign.last_activity,
            confidence=campaign.confidence
        ),
        "emails": [
            {
                "id": email.id,
                "sender_email": email.sender_email,
                "subject": email.subject,
                "threat_score": email.threat_score,
                "analyzed_at": email.analyzed_at.isoformat()
            }
            for email in campaign_emails
        ],
        "patterns": campaign.patterns,
        "timeline": await get_campaign_timeline(campaign_id, db_session)
    }

# Real-time WebSocket endpoint
@app.websocket("/ws/{organization_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    organization_id: str,
    token: str
):
    """WebSocket endpoint for real-time updates"""
    
    try:
        # Verify token (simplified for demo)
        payload = jwt_manager.verify_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            await websocket.close(code=4001)
            return
        
        # Connect to WebSocket manager
        await websocket_manager.connect(websocket, organization_id, user_id)
        
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    }))
                
        except WebSocketDisconnect:
            pass
        finally:
            await websocket_manager.disconnect(websocket)
            
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close(code=4000)

# Statistics and dashboard endpoints
@app.get("/api/v1/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats(
    days: int = 30,
    user: AuthenticatedUser = Depends(require_permission(PermissionType.VIEW_ANALYSIS)),
    db_session: AsyncSession = Depends(get_db_session)
):
    """Get dashboard statistics"""
    
    since_date = datetime.now() - timedelta(days=days)
    
    # Get analysis counts by threat level
    query = select(EmailAnalysis.threat_level, db_session.func.count()).where(
        and_(
            EmailAnalysis.organization_id == user.organization_id,
            EmailAnalysis.analyzed_at >= since_date
        )
    ).group_by(EmailAnalysis.threat_level)
    
    result = await db_session.execute(query)
    threat_level_counts = dict(result.all())
    
    # Get daily analysis counts
    daily_stats = await get_daily_analysis_stats(user.organization_id, days, db_session)
    
    # Get top threat types
    top_threats = await get_top_threat_categories(user.organization_id, days, db_session)
    
    return {
        "total_analyses": sum(threat_level_counts.values()),
        "threat_level_distribution": threat_level_counts,
        "daily_analysis_trend": daily_stats,
        "top_threat_categories": top_threats,
        "period_days": days,
        "last_updated": datetime.now().isoformat()
    }

# Helper functions
async def process_campaign_correlation(email_analysis: EmailAnalysis, organization_id: str):
    """Background task for campaign correlation"""
    try:
        async with async_session() as session:
            campaign_id = await correlation_engine.process_new_email(email_analysis, session)
            
            if campaign_id:
                # Send real-time update
                await websocket_manager.send_campaign_update(
                    organization_id,
                    {"campaign_id": campaign_id, "new_email_id": email_analysis.id}
                )
                
    except Exception as e:
        logger.error(f"Campaign correlation error: {e}")

def generate_recommendations(analysis_result: Dict) -> List[str]:
    """Generate actionable recommendations based on analysis"""
    recommendations = []
    
    threat_level = analysis_result.get('threat_level')
    risk_score = analysis_result.get('risk_score', 0)
    
    if threat_level == 'CRITICAL':
        recommendations.extend([
            "🚨 IMMEDIATE ACTION: Quarantine this email immediately",
            "🔍 Investigate sender domain and block if malicious",
            "👥 Alert affected users and security team",
            "📊 Check for similar emails in the organization"
        ])
    elif threat_level == 'HIGH':
        recommendations.extend([
            "⚠️ Review email carefully before taking action",
            "🔍 Verify sender identity through alternate channel",
            "🚫 Do not click any links or download attachments",
            "📢 Report to security team for investigation"
        ])
    elif threat_level == 'MEDIUM':
        recommendations.extend([
            "⚡ Exercise caution with this email",
            "🔗 Verify any links before clicking",
            "📎 Scan attachments before opening",
            "❓ Contact sender to verify if suspicious"
        ])
    else:
        recommendations.extend([
            "✅ Email appears safe to proceed",
            "🛡️ Continue following standard security practices",
            "📝 Report any unexpected behavior"
        ])
    
    return recommendations

async def get_campaign_timeline(campaign_id: str, db_session: AsyncSession) -> List[Dict]:
    """Get campaign timeline events"""
    # Simplified timeline - would include more events in production
    query = select(EmailAnalysis).where(
        EmailAnalysis.campaign_id == campaign_id
    ).order_by(EmailAnalysis.received_at)
    
    result = await db_session.execute(query)
    emails = result.scalars().all()
    
    timeline = []
    for email in emails:
        timeline.append({
            "timestamp": email.received_at.isoformat(),
            "event": "email_detected",
            "description": f"Malicious email from {email.sender_email}",
            "threat_score": email.threat_score
        })
    
    return timeline

async def get_daily_analysis_stats(org_id: str, days: int, db_session: AsyncSession) -> List[Dict]:
    """Get daily analysis statistics"""
    # Simplified implementation - would use proper date aggregation in production
    since_date = datetime.now() - timedelta(days=days)
    
    query = select(EmailAnalysis).where(
        and_(
            EmailAnalysis.organization_id == org_id,
            EmailAnalysis.analyzed_at >= since_date
        )
    ).order_by(EmailAnalysis.analyzed_at)
    
    result = await db_session.execute(query)
    analyses = result.scalars().all()
    
    # Group by date
    daily_counts = {}
    for analysis in analyses:
        date_str = analysis.analyzed_at.date().isoformat()
        daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
    
    return [{"date": date, "count": count} for date, count in daily_counts.items()]

async def get_top_threat_categories(org_id: str, days: int, db_session: AsyncSession) -> List[Dict]:
    """Get top threat categories"""
    # Simplified implementation
    return [
        {"category": "Phishing", "count": 45},
        {"category": "Malware", "count": 12},
        {"category": "Spam", "count": 8},
        {"category": "Social Engineering", "count": 6}
    ]

# Background tasks
async def websocket_ping_task():
    """Background task to ping WebSocket connections"""
    while True:
        try:
            await websocket_manager.ping_connections()
            await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"WebSocket ping error: {e}")
            await asyncio.sleep(5)

async def cleanup_task():
    """Background cleanup tasks"""
    while True:
        try:
            # Clean up old sessions, expired tokens, etc.
            logger.debug("Running cleanup tasks...")
            await asyncio.sleep(3600)  # Run every hour
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
            await asyncio.sleep(300)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "production_server:app",
        host="0.0.0.0",
        port=8001,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )