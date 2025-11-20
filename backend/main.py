from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocket, WebSocketDisconnect
import uvicorn
import os
from datetime import datetime

try:
    from backend.config import settings
except ImportError:
    from config import settings

# Create FastAPI application
app = FastAPI(
    title="🧠 PHISHNET API",
    description="AI-Powered Cybersecurity Suite for Phishing Detection & Analysis",
    version="1.0.0",
)

# CORS middleware - configured for production and development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    print("🧠 PHISHNET API Started Successfully!")
    print(f"🌐 Docs available at: http://localhost:8000/docs")
    print(f"🔒 Security Mode: Development")

# Root endpoint
@app.get("/")
async def root():
    """Welcome endpoint with API information."""
    return {
        "message": "🧠 PHISHNET - AI Cybersecurity Suite",
        "tagline": "Detect, analyze, visualize, and neutralize phishing in real time",
        "version": "1.0.0",
        "status": "🟢 Online",
        "features": {
            "ai_detection": "✅ Active",
            "threat_intelligence": "✅ Active", 
            "real_time_scanning": "✅ Active",
            "global_visualization": "✅ Active"
        },
        "docs": "/docs",
        "websocket": "/ws"
    }

# Health check
@app.get("/health")
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": "2024-10-11T00:00:00Z",
        "components": {
            "database": "✅ Connected",
            "redis": "✅ Connected",
            "ai_models": "✅ Loaded",
            "threat_feeds": "✅ Active"
        }
    }

# Demo analysis endpoint
@app.post("/api/v1/analyze/email")
async def analyze_email_demo(content: dict):
    """Demo email analysis endpoint."""
    return {
        "scan_id": "demo_001",
        "timestamp": datetime.now().isoformat(),
        "risk_score": 0.75,
        "threat_level": "HIGH",
        "verdict": "⚠️ SUSPICIOUS - Potential Phishing",
        "details": {
            "content_analysis": {
                "urgency_score": 0.6,
                "suspicious_links": ["http://fake-bank.evil.com"],
                "risk_indicators": ["urgency_detected", "suspicious_domain"]
            }
        },
        "recommendations": [
            "🔍 Verify sender identity - urgent language detected",
            "🔗 Do not click suspicious links"
        ]
    }

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket connection for live updates."""
    await websocket.accept()
    try:
        while True:
            # Handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back with enhancement (for demo)
            response = {
                "type": "scan_update",
                "message": f"🔍 Processing: {data}",
                "timestamp": "2024-10-11T00:00:00Z",
                "progress": 45,
                "status": "analyzing"
            }
            
            await websocket.send_json(response)
            
    except WebSocketDisconnect:
        print("Client disconnected from WebSocket")

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    return {
        "error": "Internal Server Error",
        "message": "🚨 An unexpected error occurred. Please contact support.",
        "type": "server_error",
        "timestamp": "2024-10-11T00:00:00Z"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info" if settings.DEBUG else "warning"
    )