"""
PHISHNET Database Models - Production Schema
Complete database models for all platform features
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import func

Base = declarative_base()

# Enums
class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AnalysisStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING" 
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    USER = "USER"

class ThreatType(str, Enum):
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    SAFE = "SAFE"

# Organizations and Multi-tenancy
class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True, nullable=False)
    settings = Column(JSONB, default={})
    subscription_tier = Column(String(50), default="free")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    # Relationships
    users = relationship("User", back_populates="organization")
    email_analyses = relationship("EmailAnalysis", back_populates="organization")
    campaigns = relationship("ThreatCampaign", back_populates="organization")

# User Management
class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.USER)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    email_analyses = relationship("EmailAnalysis", back_populates="user")
    
    __table_args__ = (
        Index('ix_users_org_role', 'organization_id', 'role'),
    )

# Email Analysis Core
class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # Email metadata
    sender_email = Column(String(255), nullable=True, index=True)
    sender_name = Column(String(255), nullable=True)
    recipient_email = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    message_id = Column(String(500), nullable=True)
    
    # Content
    content_text = Column(Text, nullable=True)
    content_html = Column(Text, nullable=True)
    raw_headers = Column(JSONB, nullable=True)
    raw_message = Column(Text, nullable=True)
    
    # Analysis results
    risk_score = Column(Float, nullable=False, index=True)
    threat_level = Column(String(20), nullable=False, index=True)
    threat_type = Column(String(20), nullable=True, index=True)
    verdict = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.0)
    
    # AI Analysis Details
    content_analysis = Column(JSONB, default={})
    header_analysis = Column(JSONB, default={})
    url_analysis = Column(JSONB, default={})
    attachment_analysis = Column(JSONB, default={})
    
    # Processing
    status = Column(String(20), default=AnalysisStatus.PENDING, index=True)
    processing_time_ms = Column(Integer, nullable=True)
    ai_model_version = Column(String(50), nullable=True)
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("threat_campaigns.id"), nullable=True)
    
    # Timestamps
    submitted_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="email_analyses")
    organization = relationship("Organization", back_populates="email_analyses")
    campaign = relationship("ThreatCampaign", back_populates="analyses")
    urls = relationship("URLAnalysis", back_populates="email_analysis")
    attachments = relationship("AttachmentAnalysis", back_populates="email_analysis")
    
    __table_args__ = (
        Index('ix_email_analyses_org_date', 'organization_id', 'created_at'),
        Index('ix_email_analyses_risk_date', 'risk_score', 'created_at'),
        Index('ix_email_analyses_sender', 'sender_email', 'created_at'),
    )

# URL Analysis
class URLAnalysis(Base):
    __tablename__ = "url_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    
    # Reputation data
    reputation_score = Column(Float, nullable=False)
    threat_categories = Column(JSONB, default=[])
    threat_sources = Column(JSONB, default=[])
    
    # Technical analysis
    whois_data = Column(JSONB, nullable=True)
    dns_records = Column(JSONB, nullable=True)
    ssl_info = Column(JSONB, nullable=True)
    
    # Pattern analysis
    is_punycode = Column(Boolean, default=False)
    is_homograph = Column(Boolean, default=False)
    typosquatting_score = Column(Float, default=0.0)
    suspicious_patterns = Column(JSONB, default=[])
    
    # Threat intelligence
    virustotal_data = Column(JSONB, nullable=True)
    phishtank_data = Column(JSONB, nullable=True)
    safebrowsing_data = Column(JSONB, nullable=True)
    
    # Relationships
    email_analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id"))
    
    # Timestamps
    analyzed_at = Column(DateTime(timezone=True), default=func.now())
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    email_analysis = relationship("EmailAnalysis", back_populates="urls")
    
    __table_args__ = (
        Index('ix_url_analyses_domain_date', 'domain', 'created_at'),
        Index('ix_url_analyses_reputation', 'reputation_score', 'created_at'),
    )

# Attachment Analysis
class AttachmentAnalysis(Base):
    __tablename__ = "attachment_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(500), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_hash_md5 = Column(String(32), nullable=False, index=True)
    file_hash_sha256 = Column(String(64), nullable=False, index=True)
    
    # Malware analysis
    is_malicious = Column(Boolean, default=False)
    malware_families = Column(JSONB, default=[])
    yara_matches = Column(JSONB, default=[])
    
    # Content analysis
    embedded_urls = Column(JSONB, default=[])
    macros_detected = Column(Boolean, default=False)
    metadata = Column(JSONB, default={})
    
    # Threat intelligence
    virustotal_report = Column(JSONB, nullable=True)
    
    # Relationships
    email_analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id"))
    
    analyzed_at = Column(DateTime(timezone=True), default=func.now())
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    email_analysis = relationship("EmailAnalysis", back_populates="attachments")

# Threat Campaigns
class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Campaign characteristics
    threat_type = Column(String(20), nullable=False, index=True)
    sophistication_level = Column(String(20), default="MEDIUM")
    target_sectors = Column(JSONB, default=[])
    
    # Pattern indicators
    common_senders = Column(JSONB, default=[])
    common_subjects = Column(JSONB, default=[])
    common_domains = Column(JSONB, default=[])
    common_keywords = Column(JSONB, default=[])
    
    # Statistics
    total_emails = Column(Integer, default=0)
    unique_recipients = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    
    # Timeline
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="campaigns")
    analyses = relationship("EmailAnalysis", back_populates="campaign")

# Real-time Statistics
class ThreatStatistics(Base):
    __tablename__ = "threat_statistics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    # Time period
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    hour = Column(Integer, nullable=False)  # 0-23
    
    # Counts
    total_scans = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    phishing_detected = Column(Integer, default=0)
    malware_detected = Column(Integer, default=0)
    safe_emails = Column(Integer, default=0)
    
    # Performance
    avg_processing_time = Column(Float, default=0.0)
    false_positives = Column(Integer, default=0)
    false_negatives = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        Index('ix_threat_stats_org_date', 'organization_id', 'date'),
    )

# User Behavior Profiles
class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_address = Column(String(255), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    # Behavioral patterns
    typical_send_times = Column(JSONB, default=[])  # Hour patterns
    typical_domains = Column(JSONB, default=[])
    language_patterns = Column(JSONB, default={})
    writing_style = Column(JSONB, default={})
    
    # Anomaly detection
    anomaly_threshold = Column(Float, default=0.7)
    last_baseline_update = Column(DateTime(timezone=True), nullable=True)
    
    # Statistics
    total_emails_analyzed = Column(Integer, default=0)
    anomalies_detected = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        Index('ix_behavior_profiles_email_org', 'email_address', 'organization_id'),
    )

# Incident Response
class SecurityIncident(Base):
    __tablename__ = "security_incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_number = Column(String(50), unique=True, nullable=False)
    
    # Incident details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default="OPEN", index=True)
    
    # Response actions
    actions_taken = Column(JSONB, default=[])
    automated_responses = Column(JSONB, default=[])
    
    # Assignment
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    __table_args__ = (
        Index('ix_incidents_org_status', 'organization_id', 'status'),
    )

# API Keys and Integration
class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    
    # Permissions
    permissions = Column(JSONB, default=[])
    rate_limit = Column(Integer, default=1000)  # requests per hour
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    # Status
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

# Audit Logging
class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=True)
    
    # Context
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Data
    old_values = Column(JSONB, nullable=True)
    new_values = Column(JSONB, nullable=True)
    metadata = Column(JSONB, default={})
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        Index('ix_audit_logs_org_date', 'organization_id', 'created_at'),
        Index('ix_audit_logs_user_action', 'user_id', 'action'),
    )

# Threat Intelligence Cache
class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Identifier (URL, domain, IP, hash)
    indicator = Column(String(500), nullable=False, unique=True, index=True)
    indicator_type = Column(String(20), nullable=False)  # url, domain, ip, hash
    
    # Intelligence data
    reputation_data = Column(JSONB, nullable=False)
    sources = Column(JSONB, default=[])
    confidence = Column(Float, default=0.0)
    
    # Caching
    last_checked = Column(DateTime(timezone=True), default=func.now())
    cache_expires = Column(DateTime(timezone=True), nullable=False)
    check_count = Column(Integer, default=1)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        Index('ix_threat_intel_type_indicator', 'indicator_type', 'indicator'),
    )