import requests
import json
import time
from typing import Annotated, Dict, List
from payload_manager import DynamicPayloadManager
from target_analyzer import IntelligentTargetAnalyzer

def intelligent_sqli_test(target_url: Annotated[str, "Target URL"]) -> str:
    """Intelligent SQL Injection testing with dynamic payloads"""
    results = ["=== INTELLIGENT SQL INJECTION TEST ==="]
    
    # Analyze target first
    analyzer = IntelligentTargetAnalyzer(target_url)
    analysis = analyzer.comprehensive_analysis()
    tech_stack = analysis.get('tech_stack', {})
    
    # Get contextual payloads
    payload_manager = DynamicPayloadManager()
    sql_payloads = payload_manager.get_contextual_payloads(
        target_url, "sql_injection", tech_stack
    )
    
    endpoints = analysis.get('endpoints', [])
    tested = 0
    vulnerabilities = []
    
    for endpoint in endpoints[:10]:
        endpoint_url = endpoint['url']
        
        for payload in sql_payloads[:15]:
            try:
                test_params = {'id': payload, 'user': payload, 'query': payload}
                response = requests.get(endpoint_url, params=test_params, timeout=8)
                
                if detect_sqli_success(response, payload):
                    vulnerabilities.append({
                        'url': endpoint_url,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    payload_manager.update_payload_effectiveness(payload, True)
                    results.append(f"🚨 SQLi: {endpoint_url} with {payload}")
                else:
                    payload_manager.update_payload_effectiveness(payload, False)
                
                tested += 1
                
            except Exception as e:
                continue
    
    results.append(f"Tested {tested} combinations")
    results.append(f"Found {len(vulnerabilities)} potential SQLi vulnerabilities")
    return "\n".join(results)

def detect_sqli_success(response, payload: str) -> bool:
    """Intelligent SQL injection detection"""
    content = response.text.lower()
    
    error_indicators = [
        "sql", "mysql", "ora-", "postgresql", "syntax error",
        "database", "query failed", "unclosed quotation"
    ]
    
    time_indicators = ["sleep", "waitfor", "benchmark"]
    union_indicators = ["union", "select", "from", "where"]
    
    error_score = sum(1 for indicator in error_indicators if indicator in content)
    time_score = sum(1 for indicator in time_indicators if indicator in payload.lower())
    union_score = sum(1 for indicator in union_indicators if indicator in payload.lower())
    
    return (error_score >= 2) or (time_score >= 1 and len(content) < 100) or (union_score >= 2)

def advanced_xss_hunter(target_url: Annotated[str, "Target URL"]) -> str:
    """Advanced XSS testing with modern techniques"""
    results = ["=== ADVANCED XSS HUNTER ==="]
    
    analyzer = IntelligentTargetAnalyzer(target_url)
    payload_manager = DynamicPayloadManager()
    
    xss_payloads = payload_manager.get_contextual_payloads(
        target_url, "xss", analyzer.tech_stack
    )
    
    test_points = [
        {'search': '{{payload}}'},
        {'q': '{{payload}}'}, 
        {'query': '{{payload}}'},
        {'term': '{{payload}}'}
    ]
    
    for test_point in test_points:
        param_name = list(test_point.keys())[0]
        
        for payload in xss_payloads[:10]:
            try:
                test_data = {param_name: payload}
                response = requests.post(target_url, data=test_data, timeout=8)
                
                if payload in response.text:
                    results.append(f"⚠️ XSS: {param_name} parameter with {payload}")
                    payload_manager.update_payload_effectiveness(payload, True)
                else:
                    payload_manager.update_payload_effectiveness(payload, False)
                    
            except Exception as e:
                continue
    
    return "\n".join(results)

def bug_bounty_intelligence_scan(target_url: Annotated[str, "Target URL"]) -> str:
    """Scan using patterns from successful bug bounty reports"""
    results = ["=== BUG BOUNTY INTELLIGENCE SCAN ==="]
    
    bounty_patterns = [
        {
            "name": "Subdomain Takeover",
            "test": f"host -t CNAME nonexistent.{target_url}",
            "indicator": "pointing to"
        },
        {
            "name": "JWT Vulnerabilities", 
            "test": f"curl -H 'Authorization: Bearer null' {target_url}/api/user",
            "indicator": "401"
        },
        {
            "name": "GraphQL Introspection",
            "test": f"curl -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' {target_url}/graphql",
            "indicator": "__schema"
        }
    ]
    
    for pattern in bounty_patterns:
        try:
            import subprocess
            process = subprocess.run(
                pattern["test"], 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=10
            )
            
            if pattern["indicator"] in process.stdout:
                results.append(f"🔍 {pattern['name']}: Potential vulnerability detected")
        except:
            pass
    
    return "\n".join(results)