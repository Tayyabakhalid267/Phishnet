from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl
import aiofiles
import os
import json
from datetime import datetime
import hashlib
import re
import email
from email.parser import Parser
import dns.resolver
import ssl
import socket
import whois
import requests
from urllib.parse import urlparse
import asyncio
from core.config import settings
from core.security import security_manager, cyber_validator

router = APIRouter()

# Pydantic models
class EmailAnalysisRequest(BaseModel):
    """Request model for email text analysis."""
    content: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    headers: Optional[Dict[str, str]] = {}

class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis."""
    urls: List[HttpUrl]
    deep_scan: bool = False

class AnalysisResponse(BaseModel):
    """Response model for analysis results."""
    scan_id: str
    timestamp: str
    risk_score: float
    threat_level: str
    verdict: str
    details: Dict[str, Any]
    recommendations: List[str]

class ThreatIntelligence:
    """Threat intelligence integration service."""
    
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.phishtank_key = settings.PHISHTANK_API_KEY
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
    
    async def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation across multiple threat intelligence sources.
        
        Args:
            url: URL to check
            
        Returns:
            dict: Reputation analysis results
        """
        results = {
            "url": url,
            "reputation_score": 0.0,
            "threat_sources": [],
            "categories": [],
            "last_seen": None
        }
        
        # Simulate threat intelligence check (replace with real API calls)
        domain = urlparse(url).netloc
        
        # Basic domain analysis
        try:
            # DNS resolution check
            socket.gethostbyname(domain)
            results["reputation_score"] += 0.2
            
            # SSL certificate check
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        results["reputation_score"] += 0.3
                        results["ssl_valid"] = True
                    
        except Exception:
            results["ssl_valid"] = False
            results["threat_sources"].append("SSL_INVALID")
        
        # Domain age check (simplified)
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                days_old = (datetime.now() - creation_date).days
                if days_old < 30:
                    results["reputation_score"] -= 0.4
                    results["threat_sources"].append("NEW_DOMAIN")
                elif days_old > 365:
                    results["reputation_score"] += 0.2
                    
        except Exception:
            results["reputation_score"] -= 0.2
            results["threat_sources"].append("WHOIS_LOOKUP_FAILED")
        
        # Normalize score
        results["reputation_score"] = max(0.0, min(1.0, results["reputation_score"]))
        
        return results
    
    async def analyze_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain for suspicious patterns.
        
        Args:
            domain: Domain to analyze
            
        Returns:
            dict: Pattern analysis results
        """
        results = {
            "domain": domain,
            "suspicious_patterns": [],
            "typosquatting_score": 0.0,
            "homograph_detected": False,
            "punycode_detected": False
        }
        
        # Check for punycode (internationalized domains)
        if domain.startswith("xn--"):
            results["punycode_detected"] = True
            results["suspicious_patterns"].append("PUNYCODE_DOMAIN")
        
        # Check for homograph characters
        suspicious_chars = ['ο', 'а', 'е', 'р', 'х', 'у', 'с']  # Cyrillic lookalikes
        if any(char in domain for char in suspicious_chars):
            results["homograph_detected"] = True
            results["suspicious_patterns"].append("HOMOGRAPH_CHARACTERS")
        
        # Check for common typosquatting patterns
        typo_patterns = [
            r'g[o0]{2,}gle',  # Google variations
            r'fac[e3]b[o0]{2,}k',  # Facebook variations
            r'micr[o0]s[o0]ft',  # Microsoft variations
            r'amaz[o0]n',  # Amazon variations
        ]
        
        for pattern in typo_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                results["typosquatting_score"] += 0.3
                results["suspicious_patterns"].append(f"TYPOSQUATTING_{pattern}")
        
        return results

class PhishingAnalyzer:
    """Advanced phishing detection using NLP and heuristics."""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        
        # Phishing keywords and patterns
        self.urgency_words = [
            "urgent", "immediate", "expires", "limited time", "act now",
            "verify now", "suspend", "locked", "unauthorized", "security alert"
        ]
        
        self.reward_words = [
            "prize", "winner", "congratulations", "claim", "reward",
            "bonus", "gift", "free", "inheritance", "lottery"
        ]
        
        self.impersonation_words = [
            "bank", "paypal", "amazon", "microsoft", "apple", "google",
            "irs", "government", "police", "security team"
        ]
    
    async def analyze_email_content(self, content: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Analyze email content for phishing indicators.
        
        Args:
            content: Email content to analyze
            headers: Email headers
            
        Returns:
            dict: Analysis results
        """
        results = {
            "content_analysis": {
                "urgency_score": 0.0,
                "reward_score": 0.0,
                "impersonation_score": 0.0,
                "suspicious_links": [],
                "risk_indicators": []
            },
            "header_analysis": {},
            "overall_risk": 0.0
        }
        
        # Content analysis
        content_lower = content.lower()
        
        # Check for urgency indicators
        urgency_count = sum(1 for word in self.urgency_words if word in content_lower)
        results["content_analysis"]["urgency_score"] = min(1.0, urgency_count * 0.2)
        
        # Check for reward/prize indicators
        reward_count = sum(1 for word in self.reward_words if word in content_lower)
        results["content_analysis"]["reward_score"] = min(1.0, reward_count * 0.25)
        
        # Check for impersonation
        impersonation_count = sum(1 for word in self.impersonation_words if word in content_lower)
        results["content_analysis"]["impersonation_score"] = min(1.0, impersonation_count * 0.3)
        
        # Extract and analyze URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            url_analysis = await self.threat_intel.check_url_reputation(url)
            if url_analysis["reputation_score"] < 0.5:
                results["content_analysis"]["suspicious_links"].append({
                    "url": url,
                    "risk_score": 1.0 - url_analysis["reputation_score"],
                    "threats": url_analysis["threat_sources"]
                })
        
        # Header analysis
        if headers:
            header_validation = cyber_validator.validate_email_headers(headers)
            results["header_analysis"] = header_validation
        
        # Calculate overall risk
        risk_factors = {
            "urgency_detected": results["content_analysis"]["urgency_score"] > 0.3,
            "reward_detected": results["content_analysis"]["reward_score"] > 0.3,
            "impersonation_detected": results["content_analysis"]["impersonation_score"] > 0.3,
            "suspicious_links": len(results["content_analysis"]["suspicious_links"]) > 0,
            "spf_fail": results["header_analysis"].get("spf", {}).get("status") == "fail",
            "dkim_fail": results["header_analysis"].get("dkim", {}).get("status") == "fail",
            "dmarc_fail": results["header_analysis"].get("dmarc", {}).get("status") == "fail"
        }
        
        results["overall_risk"] = cyber_validator.calculate_risk_score(risk_factors)
        
        return results

# Initialize analyzer
phishing_analyzer = PhishingAnalyzer()

@router.post("/email", response_model=AnalysisResponse)
async def analyze_email_text(
    request: EmailAnalysisRequest,
    background_tasks: BackgroundTasks
) -> AnalysisResponse:
    """
    Analyze email content for phishing indicators.
    
    Args:
        request: Email analysis request
        background_tasks: Background task manager
        
    Returns:
        AnalysisResponse: Detailed analysis results
    """
    # Generate scan ID
    scan_id = hashlib.md5(f"{request.content}{datetime.now()}".encode()).hexdigest()
    timestamp = datetime.now().isoformat()
    
    try:
        # Perform analysis
        analysis = await phishing_analyzer.analyze_email_content(
            request.content, 
            request.headers or {}
        )
        
        # Determine threat level
        risk_score = analysis["overall_risk"]
        if risk_score >= 0.8:
            threat_level = "CRITICAL"
            verdict = "🚨 HIGH RISK - Likely Phishing"
        elif risk_score >= 0.6:
            threat_level = "HIGH"
            verdict = "⚠️ SUSPICIOUS - Potential Phishing"
        elif risk_score >= 0.4:
            threat_level = "MEDIUM"
            verdict = "⚡ CAUTION - Some Risk Indicators"
        elif risk_score >= 0.2:
            threat_level = "LOW"
            verdict = "✅ LOW RISK - Appears Safe"
        else:
            threat_level = "SAFE"
            verdict = "✅ SAFE - No Threats Detected"
        
        # Generate recommendations
        recommendations = []
        if analysis["content_analysis"]["urgency_score"] > 0.3:
            recommendations.append("🔍 Verify sender identity - urgent language detected")
        if analysis["content_analysis"]["suspicious_links"]:
            recommendations.append("🔗 Do not click suspicious links")
        if analysis["header_analysis"].get("spf", {}).get("status") == "fail":
            recommendations.append("📧 Sender authentication failed (SPF)")
        if risk_score > 0.6:
            recommendations.append("🛡️ Report and delete this message")
        
        # Store analysis in background
        background_tasks.add_task(store_analysis_result, scan_id, analysis)
        
        return AnalysisResponse(
            scan_id=scan_id,
            timestamp=timestamp,
            risk_score=risk_score,
            threat_level=threat_level,
            verdict=verdict,
            details=analysis,
            recommendations=recommendations
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"🚨 Analysis failed: {str(e)}"
        )

@router.post("/email/file")
async def analyze_email_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Analyze uploaded email file (.eml, .msg, .txt).
    
    Args:
        file: Uploaded email file
        background_tasks: Background task manager
        
    Returns:
        dict: Analysis results
    """
    # Validate file type
    if not file.filename.lower().endswith(('.eml', '.msg', '.txt')):
        raise HTTPException(
            status_code=400,
            detail="🚨 Invalid file type. Supported: .eml, .msg, .txt"
        )
    
    # Read file content
    try:
        content = await file.read()
        content_str = content.decode('utf-8', errors='ignore')
        
        # Parse email if .eml format
        headers = {}
        if file.filename.lower().endswith('.eml'):
            email_obj = email.message_from_string(content_str)
            headers = dict(email_obj.items())
            content_str = email_obj.get_payload(decode=True)
            if isinstance(content_str, bytes):
                content_str = content_str.decode('utf-8', errors='ignore')
        
        # Create analysis request
        request = EmailAnalysisRequest(
            content=content_str,
            headers=headers
        )
        
        # Perform analysis
        return await analyze_email_text(request, background_tasks)
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"🚨 File analysis failed: {str(e)}"
        )

@router.post("/urls", response_model=List[Dict[str, Any]])
async def analyze_urls(request: URLAnalysisRequest) -> List[Dict[str, Any]]:
    """
    Analyze multiple URLs for threats.
    
    Args:
        request: URL analysis request
        
    Returns:
        List[Dict]: Analysis results for each URL
    """
    results = []
    
    for url in request.urls:
        try:
            # URL reputation check
            reputation = await phishing_analyzer.threat_intel.check_url_reputation(str(url))
            
            # Domain pattern analysis
            domain = urlparse(str(url)).netloc
            patterns = await phishing_analyzer.threat_intel.analyze_domain_patterns(domain)
            
            # Combine results
            url_result = {
                "url": str(url),
                "timestamp": datetime.now().isoformat(),
                "reputation": reputation,
                "patterns": patterns,
                "risk_score": 1.0 - reputation["reputation_score"] + patterns["typosquatting_score"],
                "verdict": "SAFE" if reputation["reputation_score"] > 0.7 else "SUSPICIOUS"
            }
            
            results.append(url_result)
            
        except Exception as e:
            results.append({
                "url": str(url),
                "error": str(e),
                "verdict": "ERROR"
            })
    
    return results

@router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """
    Retrieve analysis results by scan ID.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        dict: Stored analysis results
    """
    # This would typically retrieve from database
    # For demo, return placeholder
    return {
        "scan_id": scan_id,
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "message": f"🔍 Scan {scan_id} results would be retrieved from database"
    }

async def store_analysis_result(scan_id: str, analysis: Dict[str, Any]):
    """
    Store analysis result in database (background task).
    
    Args:
        scan_id: Unique scan identifier
        analysis: Analysis results to store
    """
    # This would store in database
    print(f"📊 Storing analysis result for scan {scan_id}")
    # await db.store_scan_result(scan_id, analysis)