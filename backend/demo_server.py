from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import json

# Create FastAPI application
app = FastAPI(
    title="🧠 PHISHNET API - Demo",
    description="AI-Powered Cybersecurity Suite for Phishing Detection & Analysis",
    version="1.0.0-demo",
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    print("🧠 PHISHNET API Demo Started Successfully!")
    print(f"🌐 Docs available at: http://localhost:8001/docs")

@app.get("/")
async def root():
    """Welcome endpoint with API information."""
    return {
        "message": "🧠 PHISHNET - AI Cybersecurity Suite",
        "tagline": "Detect, analyze, visualize, and neutralize phishing in real time",
        "version": "1.0.0-demo",
        "status": "🟢 Online",
        "features": {
            "ai_detection": "✅ Active",
            "threat_intelligence": "✅ Active", 
            "real_time_scanning": "✅ Active",
            "global_visualization": "✅ Active"
        },
        "docs": "/docs",
        "demo_endpoints": [
            "/api/v1/analyze/email",
            "/api/v1/analyze/url",
            "/api/v1/campaigns",
            "/api/v1/stats"
        ]
    }

@app.get("/health")
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "database": "✅ Connected",
            "redis": "✅ Connected", 
            "ai_models": "✅ Loaded",
            "threat_feeds": "✅ Active"
        }
    }

@app.post("/api/v1/analyze/email")
async def analyze_email_demo(data: dict):
    """Demo email analysis endpoint."""
    content = data.get("content", "")
    
    # Simulate AI analysis
    risk_score = 0.85 if "urgent" in content.lower() or "click here" in content.lower() else 0.25
    
    if risk_score >= 0.8:
        threat_level = "CRITICAL"
        verdict = "🚨 HIGH RISK - Likely Phishing"
    elif risk_score >= 0.6:
        threat_level = "HIGH"
        verdict = "⚠️ SUSPICIOUS - Potential Phishing"
    elif risk_score >= 0.4:
        threat_level = "MEDIUM"
        verdict = "⚡ CAUTION - Some Risk Indicators"
    else:
        threat_level = "LOW"
        verdict = "✅ SAFE - No Major Threats Detected"
    
    return {
        "scan_id": f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "risk_score": risk_score,
        "threat_level": threat_level,
        "verdict": verdict,
        "details": {
            "content_analysis": {
                "urgency_score": 0.7 if "urgent" in content.lower() else 0.1,
                "suspicious_links": ["http://phishing-site.evil"] if "click" in content.lower() else [],
                "risk_indicators": [
                    "urgency_language" if "urgent" in content.lower() else None,
                    "suspicious_links" if "click" in content.lower() else None
                ]
            },
            "header_analysis": {
                "spf": {"status": "fail" if risk_score > 0.5 else "pass"},
                "dkim": {"status": "fail" if risk_score > 0.7 else "pass"},
                "dmarc": {"status": "fail" if risk_score > 0.6 else "pass"}
            }
        },
        "recommendations": [
            "🔍 Verify sender identity before taking action",
            "🔗 Do not click suspicious links",
            "📧 Check email headers for authenticity"
        ]
    }

@app.post("/api/v1/analyze/url")
async def analyze_url_demo(data: dict):
    """Demo URL analysis endpoint."""
    url = data.get("url", "")
    
    # Simple demo logic
    is_suspicious = any(word in url.lower() for word in ["phishing", "malware", "scam", "fake"])
    
    return {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "reputation_score": 0.2 if is_suspicious else 0.9,
        "verdict": "🚨 MALICIOUS" if is_suspicious else "✅ SAFE",
        "analysis": {
            "domain_age": "suspicious" if is_suspicious else "legitimate",
            "ssl_certificate": "invalid" if is_suspicious else "valid",
            "threat_feeds": ["PhishTank"] if is_suspicious else []
        }
    }

@app.get("/api/v1/campaigns")
async def get_campaigns_demo():
    """Demo campaigns endpoint."""
    return [
        {
            "id": "camp_001",
            "name": "Banking Phishing Campaign",
            "threat_actor": "APT-Banking-001",
            "targets": 1247,
            "success_rate": 0.23,
            "status": "active",
            "start_date": "2024-10-01T00:00:00Z"
        },
        {
            "id": "camp_002",
            "name": "COVID Relief Scam",
            "threat_actor": "Scammer Group",
            "targets": 892,
            "success_rate": 0.31,
            "status": "contained",
            "start_date": "2024-09-15T00:00:00Z"
        }
    ]

@app.get("/api/v1/stats")
async def get_stats_demo():
    """Demo statistics endpoint."""
    return {
        "threats_detected_today": 15742,
        "active_campaigns": 156,
        "detection_accuracy": 99.4,
        "avg_response_time": "2.1s",
        "global_stats": {
            "total_scans": 2847392,
            "blocked_threats": 284739,
            "protected_users": 15847
        }
    }

@app.post("/analyze/email")
async def analyze_email_simple(data: dict):
    """Simple email analysis endpoint for frontend."""
    content = data.get("content", "")
    
    # Demo AI analysis with basic pattern detection
    threat_score = 0.1  # Base score
    analysis_details = {}
    
    # Check for common phishing indicators
    if any(word in content.lower() for word in ["urgent", "click here", "verify now", "suspended", "expire"]):
        threat_score += 0.4
        analysis_details["urgency_detected"] = True
    
    if any(word in content.lower() for word in ["winner", "congratulations", "prize", "lottery", "million"]):
        threat_score += 0.3
        analysis_details["reward_scam_detected"] = True
    
    if any(word in content.lower() for word in ["paypal", "amazon", "microsoft", "bank", "irs"]):
        threat_score += 0.2
        analysis_details["impersonation_detected"] = True
    
    # Determine threat level
    if threat_score >= 0.7:
        threat_level = "high"
    elif threat_score >= 0.4:
        threat_level = "medium"
    elif threat_score >= 0.2:
        threat_level = "low"
    else:
        threat_level = "safe"
    
    return {
        "threat_level": threat_level,
        "threat_score": min(1.0, threat_score),
        "analysis": {
            "message": f"Analysis completed using demo AI detection",
            "indicators_found": analysis_details,
            "content_length": len(content),
            "scan_timestamp": datetime.now().isoformat()
        }
    }

@app.get("/detect/campaign")
async def detect_campaign():
    """Campaign detection endpoint."""
    return {
        "status": "success",
        "active_campaigns": [
            {
                "id": "camp_001",
                "name": "Banking Phishing Campaign",
                "threat_actor": "APT-Banking-001",
                "targets": 1247,
                "success_rate": 0.23,
                "status": "active",
                "start_date": "2024-10-01T00:00:00Z"
            },
            {
                "id": "camp_002",
                "name": "COVID Relief Scam",
                "threat_actor": "Scammer Group",
                "targets": 892,
                "success_rate": 0.31,
                "status": "monitoring",
                "start_date": "2024-09-28T00:00:00Z"
            }
        ]
    }

@app.get("/dashboard/threats")
async def dashboard_threats():
    """Dashboard threats endpoint for reports page."""
    return {
        "total_emails_scanned": 15847,
        "threats_detected": 2847,
        "threats_blocked": 2739,
        "detection_rate": 0.179,
        "top_threats": [
            {"type": "Phishing", "count": 1247, "percentage": 43.8},
            {"type": "Malware", "count": 892, "percentage": 31.3},
            {"type": "Spam", "count": 438, "percentage": 15.4},
            {"type": "Suspicious Links", "count": 270, "percentage": 9.5}
        ],
        "recent_activity": [
            {
                "timestamp": "2024-10-11T10:30:00Z",
                "event": "High-risk phishing campaign detected",
                "severity": "high"
            },
            {
                "timestamp": "2024-10-11T09:15:00Z", 
                "event": "Malware signature updated",
                "severity": "info"
            },
            {
                "timestamp": "2024-10-11T08:45:00Z",
                "event": "Suspicious domain blocked", 
                "severity": "medium"
            }
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8004)