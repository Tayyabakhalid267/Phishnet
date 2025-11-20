# Helper functions for production server

def extract_iocs_from_content(content: str) -> Dict[str, List[str]]:
    """Extract Indicators of Compromise from email content"""
    import re
    from urllib.parse import urlparse
    
    indicators = {
        'urls': [],
        'domains': [],
        'ips': [],
        'hashes': []
    }
    
    # Extract URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, content)
    indicators['urls'] = urls
    
    # Extract domains from URLs
    for url in urls:
        try:
            domain = urlparse(url).netloc
            if domain and domain not in indicators['domains']:
                indicators['domains'].append(domain)
        except:
            continue
    
    # Extract IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, content)
    indicators['ips'] = list(set(ips))
    
    # Extract potential file hashes (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b'   # SHA256
    ]
    
    for pattern in hash_patterns:
        hashes = re.findall(pattern, content)
        indicators['hashes'].extend(hashes)
    
    indicators['hashes'] = list(set(indicators['hashes']))
    
    return indicators

def merge_enterprise_analysis(ai_result, threat_intel_result):
    """Merge Enterprise AI analysis with Advanced Threat Intelligence"""
    
    # Update threat intelligence results
    ai_result.threat_intel_results = {
        'overall_assessment': {
            'threat_score': threat_intel_result.threat_score,
            'risk_level': threat_intel_result.risk_level,
            'confidence': threat_intel_result.confidence
        },
        'url_reputation': threat_intel_result.url_reputation,
        'domain_reputation': threat_intel_result.domain_reputation,
        'ip_reputation': threat_intel_result.ip_reputation,
        'attribution': {
            'threat_actors': threat_intel_result.threat_actor_attribution,
            'campaigns': threat_intel_result.campaign_associations,
            'techniques': threat_intel_result.attack_techniques
        },
        'data_sources': threat_intel_result.data_sources,
        'ioc_count': threat_intel_result.ioc_count
    }
    
    # Enhance risk assessment with threat intelligence
    combined_risk_score = (ai_result.risk_score * 0.7) + (threat_intel_result.threat_score * 0.3)
    ai_result.risk_score = min(combined_risk_score, 1.0)
    
    # Update threat level based on combined analysis
    if ai_result.risk_score >= 0.8:
        ai_result.threat_level = "critical"
    elif ai_result.risk_score >= 0.6:
        ai_result.threat_level = "high"
    elif ai_result.risk_score >= 0.4:
        ai_result.threat_level = "medium" 
    elif ai_result.risk_score >= 0.2:
        ai_result.threat_level = "low"
    else:
        ai_result.threat_level = "safe"
    
    # Enhance threat categories
    if threat_intel_result.threat_actor_attribution:
        ai_result.threat_categories.extend(['apt_campaign', 'targeted_attack'])
    
    # Add threat intelligence recommendations
    if threat_intel_result.risk_level in ['critical', 'high']:
        ai_result.recommended_actions.extend([
            f"🚨 THREAT INTEL: {threat_intel_result.risk_level.upper()} threat detected",
            "🔒 Immediately isolate affected systems",
            "📢 Activate incident response protocol",
            "🔍 Investigate IOCs across network infrastructure"
        ])
    
    return ai_result