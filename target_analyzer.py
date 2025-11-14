import requests
import re
from typing import Dict, List
import json

class IntelligentTargetAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.tech_stack = {}
        self.endpoints = []
        self.parameters = {}
    
    def comprehensive_analysis(self) -> Dict:
        """Perform comprehensive target analysis"""
        analysis = {
            'tech_stack': self.detect_tech_stack(),
            'endpoints': self.discover_endpoints(),
            'security_headers': self.check_security_headers(),
            'sensitive_files': self.find_sensitive_files(),
            'attack_surface': self.analyze_attack_surface()
        }
        return analysis
    
    def detect_tech_stack(self) -> Dict:
        """Detect technology stack using multiple methods"""
        tech_stack = {}
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            content = response.text
            
            if 'X-Powered-By' in headers:
                tech_stack['server'] = headers['X-Powered-By']
            
            if 'react' in content.lower() or '/static/js/' in content:
                tech_stack['framework'] = 'react'
            elif 'angular' in content.lower():
                tech_stack['framework'] = 'angular'
            elif 'vue' in content.lower():
                tech_stack['framework'] = 'vue'
            
            if 'mysql' in content.lower() or 'mysqli' in content:
                tech_stack['database'] = 'mysql'
            elif 'postgresql' in content.lower() or 'pg_' in content:
                tech_stack['database'] = 'postgresql'
            elif 'oracle' in content.lower():
                tech_stack['database'] = 'oracle'
            
            if '/wp-content/' in content or 'wordpress' in content:
                tech_stack['cms'] = 'wordpress'
            elif '/media/jui/' in content or 'joomla' in content:
                tech_stack['cms'] = 'joomla'
            elif '/sites/all/' in content or 'drupal' in content:
                tech_stack['cms'] = 'drupal'
                
        except Exception as e:
            print(f"Tech detection error: {e}")
        
        return tech_stack
    
    def discover_endpoints(self) -> List[Dict]:
        """Discover API endpoints and parameters"""
        endpoints = []
        
        try:
            common_endpoints = [
                '/api/v1/users', '/api/v1/admin', '/api/graphql',
                '/oauth/token', '/oauth/authorize', '/api/search',
                '/upload', '/export', '/import', '/backup'
            ]
            
            for endpoint in common_endpoints:
                test_url = f"{self.target_url}{endpoint}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code != 404:
                        endpoints.append({
                            'url': test_url,
                            'status': response.status_code,
                            'methods': self.test_http_methods(test_url)
                        })
                except:
                    pass
            
            js_endpoints = self.extract_js_endpoints()
            endpoints.extend(js_endpoints)
            
        except Exception as e:
            print(f"Endpoint discovery error: {e}")
        
        return endpoints
    
    def extract_js_endpoints(self) -> List[Dict]:
        """Extract endpoints from JavaScript files"""
        endpoints = []
        
        try:
            response = requests.get(self.target_url, timeout=10)
            js_files = re.findall(r'src="([^"]+\.js)"', response.text)
            
            for js_file in js_files[:5]:
                if js_file.startswith('http'):
                    js_url = js_file
                else:
                    js_url = f"{self.target_url}/{js_file.lstrip('/')}"
                
                try:
                    js_response = requests.get(js_url, timeout=8)
                    api_patterns = re.findall(r'["\'](/api/v[12]/[^"\']+)["\']', js_response.text)
                    for api in api_patterns:
                        endpoints.append({
                            'url': f"{self.target_url}{api}",
                            'source': 'javascript',
                            'method': 'GET'
                        })
                except:
                    continue
                    
        except Exception as e:
            print(f"JS extraction error: {e}")
        
        return endpoints
    
    def check_security_headers(self) -> Dict:
        """Check for security headers"""
        headers = {}
        try:
            response = requests.get(self.target_url, timeout=10)
            security_headers = [
                'Content-Security-Policy', 'X-Frame-Options', 
                'X-Content-Type-Options', 'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                headers[header] = response.headers.get(header, 'MISSING')
                
        except Exception as e:
            print(f"Header check error: {e}")
        
        return headers
    
    def test_http_methods(self, url: str) -> List[str]:
        """Test available HTTP methods"""
        methods = ['GET']  # GET always available
        try:
            for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                response = requests.request(method, url, timeout=5)
                if response.status_code not in [405, 501]:
                    methods.append(method)
        except:
            pass
        
        return methods
    
    def find_sensitive_files(self) -> List[str]:
        """Find sensitive files on the target"""
        return []
    
    def analyze_attack_surface(self) -> Dict:
        """Analyze the attack surface of the target"""
        return {}