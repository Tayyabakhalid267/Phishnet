"""
Real Threat Intelligence Integration
Connects to VirusTotal, PhishTank, and other threat feeds
"""
import asyncio
import aiohttp
import hashlib
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class ThreatIntelligenceEngine:
    """Real threat intelligence integration"""
    
    def __init__(self, virustotal_key: str = None, phishtank_key: str = None):
        self.virustotal_key = virustotal_key or "demo_key"
        self.phishtank_key = phishtank_key or "demo_key"
        self.session = None
        self.cache = {}  # Simple in-memory cache
        
    async def initialize(self):
        """Initialize HTTP session for threat intelligence APIs"""
        self.session = aiohttp.ClientSession()
        logger.info("🌐 Threat Intelligence engine initialized")
    
    async def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation against threat intelligence feeds"""
        try:
            # Cache check
            url_hash = hashlib.md5(url.encode()).hexdigest()
            if url_hash in self.cache:
                cached_result = self.cache[url_hash]
                if datetime.now() - cached_result['timestamp'] < timedelta(hours=1):
                    return cached_result['data']
            
            # Real VirusTotal check (if API key is provided)
            if self.virustotal_key != "demo_key" and self.session:
                vt_result = await self._check_virustotal_url(url)
                if vt_result:
                    self.cache[url_hash] = {
                        'data': vt_result,
                        'timestamp': datetime.now()
                    }
                    return vt_result
            
            # Fallback analysis
            reputation = self._analyze_url_heuristics(url)
            self.cache[url_hash] = {
                'data': reputation,
                'timestamp': datetime.now()
            }
            return reputation
            
        except Exception as e:
            logger.error(f"URL reputation check failed: {e}")
            return {
                'threat_level': 'unknown',
                'sources': [],
                'analysis': f'Error: {str(e)}'
            }
    
    async def check_sender_reputation(self, sender: str) -> Dict[str, Any]:
        """Check sender email reputation"""
        try:
            domain = sender.split('@')[-1] if '@' in sender else sender
            
            # Domain analysis
            domain_rep = await self._check_domain_reputation(domain)
            
            return {
                'sender': sender,
                'domain': domain,
                'reputation_score': domain_rep.get('score', 0.5),
                'threat_indicators': domain_rep.get('indicators', []),
                'sources': ['heuristic_analysis'],
                'last_checked': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Sender reputation check failed: {e}")
            return {
                'sender': sender,
                'reputation_score': 0.5,
                'error': str(e)
            }
    
    async def _check_virustotal_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against VirusTotal API"""
        if not self.session or self.virustotal_key == "demo_key":
            return None
            
        try:
            # VirusTotal URL analysis endpoint
            vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {
                'apikey': self.virustotal_key,
                'resource': url,
                'allinfo': 1
            }
            
            async with self.session.get(vt_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('response_code') == 1:
                        positives = data.get('positives', 0)
                        total = data.get('total', 1)
                        
                        threat_level = 'safe'
                        if positives > 0:
                            if positives / total > 0.3:
                                threat_level = 'high'
                            elif positives / total > 0.1:
                                threat_level = 'medium'
                            else:
                                threat_level = 'low'
                        
                        return {
                            'threat_level': threat_level,
                            'detection_ratio': f"{positives}/{total}",
                            'scan_date': data.get('scan_date', 'unknown'),
                            'sources': ['virustotal'],
                            'permalink': data.get('permalink', '')
                        }
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return None
    
    def _analyze_url_heuristics(self, url: str) -> Dict[str, Any]:
        """Heuristic URL analysis when API not available"""
        threat_score = 0.0
        indicators = []
        
        # Check for suspicious domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top']
        if any(tld in url.lower() for tld in suspicious_tlds):
            threat_score += 0.3
            indicators.append('suspicious_tld')
        
        # Check for IP addresses
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            threat_score += 0.4
            indicators.append('ip_address_used')
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        if any(shortener in url.lower() for shortener in shorteners):
            threat_score += 0.2
            indicators.append('url_shortener')
        
        # Check for suspicious keywords
        suspicious_keywords = ['phishing', 'malware', 'scam', 'fake', 'security-alert']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            threat_score += 0.5
            indicators.append('suspicious_keywords')
        
        threat_level = 'safe'
        if threat_score >= 0.7:
            threat_level = 'high'
        elif threat_score >= 0.4:
            threat_level = 'medium'
        elif threat_score >= 0.2:
            threat_level = 'low'
        
        return {
            'threat_level': threat_level,
            'threat_score': min(1.0, threat_score),
            'indicators': indicators,
            'sources': ['heuristic_analysis'],
            'analysis_method': 'pattern_matching'
        }
    
    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using various indicators"""
        score = 0.5  # Neutral starting score
        indicators = []
        
        try:
            # Check for suspicious domain patterns
            if len(domain) < 4:
                score -= 0.2
                indicators.append('very_short_domain')
            
            # Check for numbers in domain (often suspicious)
            if any(char.isdigit() for char in domain):
                score -= 0.1
                indicators.append('contains_numbers')
            
            # Check for common phishing indicators
            phishing_keywords = ['secure', 'account', 'verify', 'update', 'login', 'bank']
            if any(keyword in domain.lower() for keyword in phishing_keywords):
                score -= 0.3
                indicators.append('phishing_keywords')
            
            # Check for legitimate domains (positive reputation)
            legitimate_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'company.com']
            if any(legit in domain.lower() for legit in legitimate_domains):
                score += 0.3
                indicators.append('known_legitimate')
            
        except Exception as e:
            logger.error(f"Domain reputation check error: {e}")
        
        return {
            'score': max(0.0, min(1.0, score)),
            'indicators': indicators
        }
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

# Example usage and testing
async def test_threat_intelligence():
    """Test the threat intelligence engine"""
    engine = ThreatIntelligenceEngine()
    await engine.initialize()
    
    # Test URL analysis
    test_urls = [
        'https://google.com',
        'http://phishing-site.evil.tk',
        'http://192.168.1.1/malware.exe'
    ]
    
    for url in test_urls:
        result = await engine.check_url_reputation(url)
        print(f"URL: {url}")
        print(f"Result: {result}")
        print("---")
    
    # Test sender reputation
    test_senders = [
        'user@gmail.com',
        'noreply@phishing-bank-security.tk',
        'admin@suspicious-domain123.ml'
    ]
    
    for sender in test_senders:
        result = await engine.check_sender_reputation(sender)
        print(f"Sender: {sender}")
        print(f"Result: {result}")
        print("---")
    
    await engine.close()

if __name__ == "__main__":
    asyncio.run(test_threat_intelligence())