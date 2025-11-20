"""
Real-Time Processing System - Production Implementation
WebSocket connections, campaign correlation, automated responses
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, asdict
import uuid
from collections import defaultdict, deque
import hashlib

import aioredis
import websockets
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity

from models.database import (
    EmailAnalysis, ThreatCampaign, SecurityIncident, 
    UserBehaviorProfile, RealTimeAlert, CampaignStatistics
)
from ai.detection_engine import ComprehensiveEmailAnalyzer
from core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class RealTimeAlert:
    """Real-time alert structure"""
    alert_id: str
    alert_type: str  # phishing, malware, anomaly, campaign
    severity: str    # critical, high, medium, low
    title: str
    description: str
    timestamp: datetime
    organization_id: str
    source_email_id: Optional[str] = None
    campaign_id: Optional[str] = None
    affected_users: List[str] = None
    recommended_actions: List[str] = None
    threat_indicators: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass 
class CampaignPattern:
    """Pattern detected in threat campaigns"""
    pattern_id: str
    pattern_type: str  # sender, subject, content, url, timing
    pattern_value: Any
    confidence: float
    first_seen: datetime
    last_seen: datetime
    frequency: int
    affected_emails: List[str]

class WebSocketManager:
    """Manage WebSocket connections for real-time updates"""
    
    def __init__(self):
        # Organization ID -> Set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        self.connection_metadata: Dict[WebSocket, Dict] = {}
        
    async def connect(self, websocket: WebSocket, organization_id: str, user_id: str):
        """Register new WebSocket connection"""
        await websocket.accept()
        self.active_connections[organization_id].add(websocket)
        self.connection_metadata[websocket] = {
            'organization_id': organization_id,
            'user_id': user_id,
            'connected_at': datetime.now(),
            'last_ping': datetime.now()
        }
        logger.info(f"WebSocket connected: user {user_id} in org {organization_id}")
        
        # Send welcome message
        await self.send_personal_message(websocket, {
            'type': 'connection_established',
            'message': 'Real-time threat monitoring active',
            'timestamp': datetime.now().isoformat()
        })
        
    async def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.connection_metadata:
            metadata = self.connection_metadata[websocket]
            org_id = metadata['organization_id']
            user_id = metadata['user_id']
            
            self.active_connections[org_id].discard(websocket)
            del self.connection_metadata[websocket]
            
            logger.info(f"WebSocket disconnected: user {user_id} in org {org_id}")
            
    async def send_personal_message(self, websocket: WebSocket, message: Dict):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
            await self.disconnect(websocket)
            
    async def broadcast_to_organization(self, organization_id: str, message: Dict):
        """Broadcast message to all connections in organization"""
        if organization_id in self.active_connections:
            disconnected = []
            
            for websocket in self.active_connections[organization_id]:
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error broadcasting message: {e}")
                    disconnected.append(websocket)
                    
            # Clean up disconnected sockets
            for websocket in disconnected:
                await self.disconnect(websocket)
                
    async def broadcast_alert(self, alert: RealTimeAlert):
        """Broadcast security alert to organization"""
        message = {
            'type': 'security_alert',
            'alert': alert.to_dict()
        }
        await self.broadcast_to_organization(alert.organization_id, message)
        
    async def send_campaign_update(self, organization_id: str, campaign_data: Dict):
        """Send campaign correlation update"""
        message = {
            'type': 'campaign_update',
            'campaign': campaign_data,
            'timestamp': datetime.now().isoformat()
        }
        await self.broadcast_to_organization(organization_id, message)
        
    async def ping_connections(self):
        """Send ping to all connections to keep them alive"""
        for websocket, metadata in list(self.connection_metadata.items()):
            try:
                await websocket.ping()
                metadata['last_ping'] = datetime.now()
            except Exception:
                await self.disconnect(websocket)

class CampaignCorrelationEngine:
    """Advanced threat campaign detection and correlation"""
    
    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self.analyzer = ComprehensiveEmailAnalyzer()
        
        # In-memory correlation windows
        self.correlation_window = timedelta(hours=24)
        self.min_campaign_size = 3
        self.similarity_threshold = 0.8
        
        # Pattern tracking
        self.sender_patterns = defaultdict(list)
        self.subject_patterns = defaultdict(list) 
        self.content_patterns = defaultdict(list)
        self.url_patterns = defaultdict(list)
        self.timing_patterns = defaultdict(list)
        
    async def process_new_email(
        self, 
        email_analysis: EmailAnalysis,
        db_session: AsyncSession
    ) -> Optional[str]:
        """Process new email for campaign correlation"""
        
        try:
            # Extract correlation features
            features = await self._extract_correlation_features(email_analysis)
            
            # Check for existing campaigns
            existing_campaigns = await self._find_matching_campaigns(
                features, 
                email_analysis.organization_id,
                db_session
            )
            
            if existing_campaigns:
                # Add to existing campaign
                campaign_id = existing_campaigns[0]['campaign_id']
                await self._add_email_to_campaign(
                    campaign_id, 
                    email_analysis.id,
                    features,
                    db_session
                )
                logger.info(f"Email {email_analysis.id} added to campaign {campaign_id}")
                return campaign_id
            else:
                # Check if this email could start a new campaign
                potential_campaign = await self._detect_new_campaign_pattern(
                    features,
                    email_analysis.organization_id,
                    db_session
                )
                
                if potential_campaign:
                    campaign_id = await self._create_new_campaign(
                        potential_campaign,
                        email_analysis,
                        db_session
                    )
                    logger.info(f"New campaign {campaign_id} created from email {email_analysis.id}")
                    return campaign_id
                    
        except Exception as e:
            logger.error(f"Campaign correlation error: {e}")
            
        return None
        
    async def _extract_correlation_features(self, email_analysis: EmailAnalysis) -> Dict[str, Any]:
        """Extract features used for campaign correlation"""
        
        # Parse email metadata
        metadata = email_analysis.metadata or {}
        headers = metadata.get('headers', {})
        
        return {
            'sender_domain': self._extract_domain(email_analysis.sender_email),
            'sender_name': headers.get('from_name', ''),
            'reply_to_domain': self._extract_domain(headers.get('reply-to', '')),
            'subject_hash': hashlib.md5(email_analysis.subject.encode()).hexdigest()[:16],
            'subject_tokens': self._tokenize_subject(email_analysis.subject),
            'content_hash': hashlib.md5(email_analysis.content.encode()).hexdigest()[:16],
            'content_similarity_vector': await self._get_content_embedding(email_analysis.content),
            'urls': metadata.get('extracted_urls', []),
            'url_domains': [self._extract_domain(url) for url in metadata.get('extracted_urls', [])],
            'attachment_hashes': metadata.get('attachment_hashes', []),
            'sending_ip': headers.get('x-originating-ip', ''),
            'user_agent': headers.get('user-agent', ''),
            'timestamp': email_analysis.received_at,
            'threat_score': email_analysis.threat_score,
            'threat_categories': email_analysis.threat_categories or []
        }
        
    def _extract_domain(self, email_or_url: str) -> str:
        """Extract domain from email or URL"""
        if not email_or_url:
            return ""
            
        if '@' in email_or_url:
            return email_or_url.split('@')[-1].lower()
        elif '//' in email_or_url:
            try:
                from urllib.parse import urlparse
                return urlparse(email_or_url).netloc.lower()
            except:
                return ""
        return email_or_url.lower()
        
    def _tokenize_subject(self, subject: str) -> List[str]:
        """Tokenize email subject for pattern matching"""
        import re
        # Remove common prefixes and normalize
        cleaned = re.sub(r'^(re:|fwd:|fw:)', '', subject.lower()).strip()
        # Extract meaningful tokens
        tokens = re.findall(r'\b\w{3,}\b', cleaned)
        return tokens[:10]  # Limit to first 10 tokens
        
    async def _get_content_embedding(self, content: str) -> List[float]:
        """Get semantic embedding of email content"""
        try:
            # Use sentence transformer from detection engine
            if hasattr(self.analyzer.nlp_analyzer, 'sentence_model'):
                embedding = self.analyzer.nlp_analyzer.sentence_model.encode(
                    content[:1000],  # Limit content length
                    convert_to_tensor=False
                )
                return embedding.tolist()
        except Exception as e:
            logger.error(f"Content embedding error: {e}")
            
        return [0.0] * 384  # Default embedding size
        
    async def _find_matching_campaigns(
        self,
        features: Dict[str, Any],
        organization_id: str,
        db_session: AsyncSession
    ) -> List[Dict]:
        """Find existing campaigns that match the email features"""
        
        # Get active campaigns from the last 24 hours
        cutoff_time = datetime.now() - self.correlation_window
        
        query = select(ThreatCampaign).where(
            and_(
                ThreatCampaign.organization_id == organization_id,
                ThreatCampaign.first_detected >= cutoff_time,
                ThreatCampaign.status == 'active'
            )
        )
        
        result = await db_session.execute(query)
        active_campaigns = result.scalars().all()
        
        matching_campaigns = []
        
        for campaign in active_campaigns:
            similarity_score = await self._calculate_campaign_similarity(
                features, 
                campaign
            )
            
            if similarity_score >= self.similarity_threshold:
                matching_campaigns.append({
                    'campaign_id': campaign.id,
                    'similarity_score': similarity_score,
                    'campaign': campaign
                })
                
        # Sort by similarity score
        matching_campaigns.sort(key=lambda x: x['similarity_score'], reverse=True)
        return matching_campaigns
        
    async def _calculate_campaign_similarity(
        self,
        email_features: Dict[str, Any],
        campaign: ThreatCampaign
    ) -> float:
        """Calculate similarity between email and existing campaign"""
        
        campaign_patterns = campaign.patterns or {}
        similarity_scores = []
        
        # Domain similarity
        if campaign_patterns.get('sender_domains'):
            sender_domain = email_features['sender_domain']
            if sender_domain in campaign_patterns['sender_domains']:
                similarity_scores.append(1.0)
            else:
                similarity_scores.append(0.0)
                
        # Subject similarity 
        if campaign_patterns.get('subject_tokens'):
            email_tokens = set(email_features['subject_tokens'])
            campaign_tokens = set(campaign_patterns['subject_tokens'])
            if email_tokens and campaign_tokens:
                jaccard_similarity = len(email_tokens & campaign_tokens) / len(email_tokens | campaign_tokens)
                similarity_scores.append(jaccard_similarity)
                
        # Content semantic similarity
        if campaign_patterns.get('content_embeddings'):
            email_embedding = np.array(email_features['content_similarity_vector']).reshape(1, -1)
            campaign_embeddings = np.array(campaign_patterns['content_embeddings'])
            
            if campaign_embeddings.size > 0:
                cosine_sim = cosine_similarity(email_embedding, campaign_embeddings)
                max_similarity = float(np.max(cosine_sim))
                similarity_scores.append(max_similarity)
                
        # URL domain similarity
        if campaign_patterns.get('url_domains') and email_features['url_domains']:
            campaign_domains = set(campaign_patterns['url_domains'])
            email_domains = set(email_features['url_domains'])
            if campaign_domains and email_domains:
                domain_similarity = len(campaign_domains & email_domains) / len(campaign_domains | email_domains)
                similarity_scores.append(domain_similarity)
                
        # Calculate weighted average
        if similarity_scores:
            return sum(similarity_scores) / len(similarity_scores)
        else:
            return 0.0
            
    async def _detect_new_campaign_pattern(
        self,
        features: Dict[str, Any],
        organization_id: str, 
        db_session: AsyncSession
    ) -> Optional[Dict]:
        """Detect if email matches emerging campaign patterns"""
        
        # Look for similar emails in the last few hours
        recent_cutoff = datetime.now() - timedelta(hours=6)
        
        query = select(EmailAnalysis).where(
            and_(
                EmailAnalysis.organization_id == organization_id,
                EmailAnalysis.received_at >= recent_cutoff,
                EmailAnalysis.threat_score >= 0.5  # Only consider suspicious emails
            )
        )
        
        result = await db_session.execute(query)
        recent_emails = result.scalars().all()
        
        if len(recent_emails) < self.min_campaign_size:
            return None
            
        # Group by similarity
        similar_groups = await self._cluster_similar_emails(recent_emails, features)
        
        # Find the largest group that includes the current email
        for group in similar_groups:
            if len(group) >= self.min_campaign_size:
                return {
                    'emails': group,
                    'pattern_type': 'content_similarity',
                    'confidence': 0.8
                }
                
        return None
        
    async def _cluster_similar_emails(
        self,
        emails: List[EmailAnalysis],
        target_features: Dict[str, Any]
    ) -> List[List[EmailAnalysis]]:
        """Cluster emails by similarity using DBSCAN"""
        
        try:
            # Extract features for all emails
            email_features = []
            for email in emails:
                features = await self._extract_correlation_features(email)
                email_features.append(features['content_similarity_vector'])
                
            # Add target email
            email_features.append(target_features['content_similarity_vector'])
            
            # Perform clustering
            X = np.array(email_features)
            clustering = DBSCAN(eps=0.3, min_samples=self.min_campaign_size, metric='cosine')
            cluster_labels = clustering.fit_predict(X)
            
            # Group emails by cluster
            clusters = defaultdict(list)
            for i, label in enumerate(cluster_labels[:-1]):  # Exclude target email
                if label != -1:  # -1 means noise
                    clusters[label].append(emails[i])
                    
            # Check if target email belongs to any cluster
            target_cluster = cluster_labels[-1]
            if target_cluster != -1 and target_cluster in clusters:
                # Target email belongs to a cluster
                return [clusters[target_cluster]]
            
            return list(clusters.values())
            
        except Exception as e:
            logger.error(f"Email clustering error: {e}")
            return []
            
    async def _create_new_campaign(
        self,
        campaign_data: Dict,
        initial_email: EmailAnalysis,
        db_session: AsyncSession
    ) -> str:
        """Create a new threat campaign"""
        
        campaign_id = str(uuid.uuid4())
        
        # Analyze campaign patterns
        patterns = await self._analyze_campaign_patterns(campaign_data['emails'])
        
        # Create campaign record
        campaign = ThreatCampaign(
            id=campaign_id,
            organization_id=initial_email.organization_id,
            name=f"Campaign {campaign_id[:8]}",
            description=f"Detected phishing campaign targeting {initial_email.organization_id}",
            campaign_type='phishing',
            status='active',
            first_detected=datetime.now(),
            last_activity=datetime.now(),
            email_count=len(campaign_data['emails']) + 1,
            affected_users=[initial_email.recipient_email],
            patterns=patterns,
            severity='high' if initial_email.threat_score >= 0.8 else 'medium',
            confidence=campaign_data['confidence']
        )
        
        db_session.add(campaign)
        
        # Link emails to campaign
        for email in campaign_data['emails']:
            email.campaign_id = campaign_id
            
        initial_email.campaign_id = campaign_id
        
        await db_session.commit()
        
        # Cache campaign data in Redis
        await self._cache_campaign_data(campaign_id, patterns)
        
        return campaign_id
        
    async def _add_email_to_campaign(
        self,
        campaign_id: str,
        email_id: str,
        email_features: Dict[str, Any],
        db_session: AsyncSession
    ):
        """Add email to existing campaign and update patterns"""
        
        # Update email record
        query = update(EmailAnalysis).where(EmailAnalysis.id == email_id).values(
            campaign_id=campaign_id
        )
        await db_session.execute(query)
        
        # Update campaign statistics
        query = update(ThreatCampaign).where(ThreatCampaign.id == campaign_id).values(
            email_count=ThreatCampaign.email_count + 1,
            last_activity=datetime.now()
        )
        await db_session.execute(query)
        
        # Update patterns in Redis
        await self._update_campaign_patterns(campaign_id, email_features)
        
        await db_session.commit()
        
    async def _analyze_campaign_patterns(self, emails: List[EmailAnalysis]) -> Dict[str, Any]:
        """Analyze patterns across campaign emails"""
        
        patterns = {
            'sender_domains': [],
            'subject_tokens': [],
            'url_domains': [],
            'content_embeddings': [],
            'timing_patterns': [],
            'ip_addresses': []
        }
        
        for email in emails:
            features = await self._extract_correlation_features(email)
            
            # Collect patterns
            patterns['sender_domains'].append(features['sender_domain'])
            patterns['subject_tokens'].extend(features['subject_tokens'])
            patterns['url_domains'].extend(features['url_domains'])
            patterns['content_embeddings'].append(features['content_similarity_vector'])
            
            if features['sending_ip']:
                patterns['ip_addresses'].append(features['sending_ip'])
                
        # Deduplicate and summarize
        patterns['sender_domains'] = list(set(patterns['sender_domains']))
        patterns['subject_tokens'] = list(set(patterns['subject_tokens']))
        patterns['url_domains'] = list(set(patterns['url_domains']))
        patterns['ip_addresses'] = list(set(patterns['ip_addresses']))
        
        return patterns
        
    async def _cache_campaign_data(self, campaign_id: str, patterns: Dict[str, Any]):
        """Cache campaign patterns in Redis for fast lookup"""
        
        cache_key = f"campaign:{campaign_id}:patterns"
        await self.redis.hset(
            cache_key,
            mapping={
                'patterns': json.dumps(patterns),
                'last_updated': datetime.now().isoformat()
            }
        )
        await self.redis.expire(cache_key, 86400)  # 24 hour TTL
        
    async def _update_campaign_patterns(self, campaign_id: str, new_features: Dict[str, Any]):
        """Update campaign patterns with new email features"""
        
        cache_key = f"campaign:{campaign_id}:patterns"
        cached_data = await self.redis.hgetall(cache_key)
        
        if cached_data:
            patterns = json.loads(cached_data['patterns'])
            
            # Add new patterns
            if new_features['sender_domain'] not in patterns['sender_domains']:
                patterns['sender_domains'].append(new_features['sender_domain'])
                
            new_tokens = [t for t in new_features['subject_tokens'] if t not in patterns['subject_tokens']]
            patterns['subject_tokens'].extend(new_tokens)
            
            patterns['content_embeddings'].append(new_features['content_similarity_vector'])
            
            # Update cache
            await self.redis.hset(
                cache_key,
                mapping={
                    'patterns': json.dumps(patterns),
                    'last_updated': datetime.now().isoformat()
                }
            )

class AutomatedResponseSystem:
    """Automated threat response and mitigation"""
    
    def __init__(self, websocket_manager: WebSocketManager, redis_client: aioredis.Redis):
        self.websocket_manager = websocket_manager
        self.redis = redis_client
        self.response_handlers = {}
        self._register_handlers()
        
    def _register_handlers(self):
        """Register automated response handlers"""
        self.response_handlers = {
            'phishing_detected': self._handle_phishing_detection,
            'malware_detected': self._handle_malware_detection,
            'campaign_detected': self._handle_campaign_detection,
            'anomaly_detected': self._handle_anomaly_detection,
            'credential_harvesting': self._handle_credential_harvesting
        }
        
    async def process_threat_event(
        self,
        event_type: str,
        threat_data: Dict[str, Any],
        db_session: AsyncSession
    ):
        """Process threat event and trigger appropriate responses"""
        
        try:
            # Get handler for event type
            handler = self.response_handlers.get(event_type)
            if handler:
                await handler(threat_data, db_session)
            else:
                logger.warning(f"No handler for event type: {event_type}")
                
            # Generate real-time alert
            alert = await self._generate_alert(event_type, threat_data)
            await self.websocket_manager.broadcast_alert(alert)
            
        except Exception as e:
            logger.error(f"Error processing threat event {event_type}: {e}")
            
    async def _handle_phishing_detection(self, threat_data: Dict, db_session: AsyncSession):
        """Handle phishing email detection"""
        
        email_id = threat_data.get('email_id')
        threat_score = threat_data.get('threat_score', 0.0)
        
        if threat_score >= settings.AUTO_QUARANTINE_THRESHOLD:
            # Auto-quarantine high-risk emails
            await self._quarantine_email(email_id, 'phishing', db_session)
            
            # Notify affected users
            await self._notify_affected_users(threat_data, db_session)
            
            # Create security incident
            await self._create_security_incident(threat_data, 'phishing', db_session)
            
    async def _handle_malware_detection(self, threat_data: Dict, db_session: AsyncSession):
        """Handle malware detection in email attachments"""
        
        # Always quarantine malware
        await self._quarantine_email(threat_data.get('email_id'), 'malware', db_session)
        
        # Block sender domain
        await self._add_domain_block(threat_data.get('sender_domain'), db_session)
        
        # Critical incident
        await self._create_security_incident(threat_data, 'malware', db_session)
        
    async def _handle_campaign_detection(self, threat_data: Dict, db_session: AsyncSession):
        """Handle detection of coordinated attack campaign"""
        
        campaign_id = threat_data.get('campaign_id')
        
        # Quarantine all campaign emails
        await self._quarantine_campaign_emails(campaign_id, db_session)
        
        # Generate IOC feed for network protection
        await self._generate_ioc_feed(campaign_id, db_session)
        
        # High-priority incident
        await self._create_security_incident(threat_data, 'campaign', db_session)
        
    async def _handle_anomaly_detection(self, threat_data: Dict, db_session: AsyncSession):
        """Handle behavioral anomaly detection"""
        
        # Log anomaly for investigation
        await self._log_anomaly(threat_data, db_session)
        
        # Increase monitoring for affected user
        await self._increase_user_monitoring(threat_data.get('user_id'), db_session)
        
    async def _handle_credential_harvesting(self, threat_data: Dict, db_session: AsyncSession):
        """Handle credential harvesting attempt"""
        
        # Immediately quarantine
        await self._quarantine_email(threat_data.get('email_id'), 'credential_harvesting', db_session)
        
        # Force password reset for targeted users
        await self._trigger_password_reset(threat_data.get('target_users', []), db_session)
        
        # Block malicious URLs
        await self._block_urls(threat_data.get('malicious_urls', []), db_session)
        
    async def _quarantine_email(self, email_id: str, reason: str, db_session: AsyncSession):
        """Quarantine email and update status"""
        
        query = update(EmailAnalysis).where(EmailAnalysis.id == email_id).values(
            status='quarantined',
            quarantine_reason=reason,
            quarantined_at=datetime.now()
        )
        await db_session.execute(query)
        
        logger.info(f"Email {email_id} quarantined for {reason}")
        
    async def _create_security_incident(
        self, 
        threat_data: Dict,
        incident_type: str,
        db_session: AsyncSession
    ):
        """Create security incident record"""
        
        incident = SecurityIncident(
            id=str(uuid.uuid4()),
            organization_id=threat_data.get('organization_id'),
            incident_type=incident_type,
            severity='critical' if threat_data.get('threat_score', 0) >= 0.8 else 'high',
            title=f"{incident_type.title()} Detection - {threat_data.get('email_id', 'Unknown')}",
            description=f"Automated detection of {incident_type}",
            status='open',
            created_at=datetime.now(),
            detection_method='automated',
            affected_assets=threat_data.get('affected_users', []),
            threat_indicators=threat_data,
            assigned_to=None  # Will be assigned by incident response team
        )
        
        db_session.add(incident)
        logger.info(f"Security incident created: {incident.id}")
        
    async def _generate_alert(self, event_type: str, threat_data: Dict) -> RealTimeAlert:
        """Generate real-time alert for threat event"""
        
        severity_mapping = {
            'phishing_detected': 'high',
            'malware_detected': 'critical', 
            'campaign_detected': 'critical',
            'anomaly_detected': 'medium',
            'credential_harvesting': 'critical'
        }
        
        return RealTimeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=event_type,
            severity=severity_mapping.get(event_type, 'medium'),
            title=f"{event_type.replace('_', ' ').title()} - Automated Detection",
            description=f"Threat detected: {threat_data.get('description', 'No description')}",
            timestamp=datetime.now(),
            organization_id=threat_data.get('organization_id'),
            source_email_id=threat_data.get('email_id'),
            campaign_id=threat_data.get('campaign_id'),
            affected_users=threat_data.get('affected_users', []),
            recommended_actions=self._get_recommended_actions(event_type),
            threat_indicators=threat_data
        )
        
    def _get_recommended_actions(self, event_type: str) -> List[str]:
        """Get recommended actions for threat type"""
        
        actions = {
            'phishing_detected': [
                "Review quarantined email",
                "Notify affected users",
                "Block sender domain if confirmed",
                "Update security awareness training"
            ],
            'malware_detected': [
                "Scan affected systems",
                "Update antivirus signatures", 
                "Block malicious domains",
                "Investigate lateral movement"
            ],
            'campaign_detected': [
                "Analyze campaign tactics",
                "Update threat intelligence feeds",
                "Coordinate with other organizations",
                "Implement additional controls"
            ],
            'credential_harvesting': [
                "Force password resets",
                "Enable additional MFA",
                "Block malicious URLs",
                "Monitor for account compromise"
            ]
        }
        
        return actions.get(event_type, ["Investigate further", "Document findings"])

# Global instances
websocket_manager = WebSocketManager()

async def initialize_real_time_system() -> tuple:
    """Initialize real-time processing components"""
    
    # Initialize Redis connection
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True
    )
    
    # Initialize components
    correlation_engine = CampaignCorrelationEngine(redis_client)
    response_system = AutomatedResponseSystem(websocket_manager, redis_client)
    
    logger.info("Real-time processing system initialized")
    
    return correlation_engine, response_system, redis_client

# WebSocket ping task
async def websocket_ping_task():
    """Background task to ping WebSocket connections"""
    while True:
        try:
            await websocket_manager.ping_connections()
            await asyncio.sleep(30)  # Ping every 30 seconds
        except Exception as e:
            logger.error(f"WebSocket ping error: {e}")
            await asyncio.sleep(5)