"""
Threat Intelligence Module
Integration with external threat intelligence sources
"""

import requests
import json
import socket
import whois
import dns.resolver
from typing import Dict, List, Optional, Any
from datetime import datetime
from rich.console import Console
import time

from core.logger import logger

console = Console()

class ThreatIntel:
    """Threat intelligence integration for enhanced vulnerability detection."""
    
    def __init__(self, config):
        self.config = config
        self.cache = {}  # Simple cache for API responses
        self.cache_timeout = 3600  # 1 hour cache
    
    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain against threat intelligence sources."""
        
        logger.info(f"Checking threat intelligence for domain: {domain}")
        
        threat_info = {}
        
        try:
            # Check multiple sources
            if 'virustotal' in self.config.threat_intel_sources and self.config.virustotal_api_key:
                vt_info = await self._check_virustotal(domain)
                if vt_info:
                    threat_info['virustotal'] = vt_info
            
            if 'shodan' in self.config.threat_intel_sources and self.config.shodan_api_key:
                shodan_info = await self._check_shodan(domain)
                if shodan_info:
                    threat_info['shodan'] = shodan_info
            
            if 'censys' in self.config.threat_intel_sources and self.config.censys_api_id:
                censys_info = await self._check_censys(domain)
                if censys_info:
                    threat_info['censys'] = censys_info
            
            # DNS-based checks
            dns_info = await self._check_dns(domain)
            if dns_info:
                threat_info['dns'] = dns_info
            
            # WHOIS information
            whois_info = await self._check_whois(domain)
            if whois_info:
                threat_info['whois'] = whois_info
            
            # Combine threat scores
            if threat_info:
                threat_info['combined_score'] = self._calculate_threat_score(threat_info)
                threat_info['risk_level'] = self._calculate_risk_level(threat_info['combined_score'])
            
            return threat_info if threat_info else None
            
        except Exception as e:
            logger.error(f"Error checking threat intelligence for {domain}: {str(e)}")
            return None
    
    async def _check_virustotal(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check VirusTotal for domain reputation."""
        
        try:
            cache_key = f"virustotal_{domain}"
            if cache_key in self.cache:
                cache_time, data = self.cache[cache_key]
                if time.time() - cache_time < self.cache_timeout:
                    return data
            
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.config.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                result = {
                    'last_analysis_stats': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'categories': data.get('data', {}).get('attributes', {}).get('categories', []),
                    'last_dns_records': data.get('data', {}).get('attributes', {}).get('last_dns_records', []),
                    'last_https_certificate': data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}),
                    'threat_score': self._calculate_virustotal_score(data)
                }
                
                # Cache result
                self.cache[cache_key] = (time.time(), result)
                
                logger.info(f"VirusTotal check completed for {domain}")
                return result
            
            elif response.status_code == 401:
                logger.warning("VirusTotal API key invalid or expired")
            
            return None
            
        except Exception as e:
            logger.error(f"VirusTotal check error for {domain}: {str(e)}")
            return None
    
    async def _check_shodan(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check Shodan for host information."""
        
        try:
            cache_key = f"shodan_{domain}"
            if cache_key in self.cache:
                cache_time, data = self.cache[cache_key]
                if time.time() - cache_time < self.cache_timeout:
                    return data
            
            # Resolve domain to IP first
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                logger.warning(f"Could not resolve {domain} to IP")
                return None
            
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": self.config.shodan_api_key}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                result = {
                    'ip': ip,
                    'hostnames': data.get('hostnames', []),
                    'domains': data.get('domains', []),
                    'country': data.get('country_name', ''),
                    'city': data.get('city', ''),
                    'os': data.get('os', ''),
                    'ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', []),
                    'services': self._extract_shodan_services(data),
                    'threat_score': self._calculate_shodan_score(data)
                }
                
                # Cache result
                self.cache[cache_key] = (time.time(), result)
                
                logger.info(f"Shodan check completed for {domain} ({ip})")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Shodan check error for {domain}: {str(e)}")
            return None
    
    async def _check_censys(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check Censys for host information."""
        
        try:
            cache_key = f"censys_{domain}"
            if cache_key in self.cache:
                cache_time, data = self.cache[cache_key]
                if time.time() - cache_time < self.cache_timeout:
                    return data
            
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                return None
            
            url = f"https://search.censys.io/api/v2/hosts/{ip}"
            auth = (self.config.censys_api_id, self.config.censys_api_secret)
            
            response = requests.get(url, auth=auth, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    'ip': ip,
                    'services': data.get('result', {}).get('services', []),
                    'location': data.get('result', {}).get('location', {}),
                    'autonomous_system': data.get('result', {}).get('autonomous_system', {}),
                    'threat_score': self._calculate_censys_score(data)
                }
                
                # Cache result
                self.cache[cache_key] = (time.time(), result)
                
                logger.info(f"Censys check completed for {domain} ({ip})")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Censys check error for {domain}: {str(e)}")
            return None
    
    async def _check_dns(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform DNS-based checks."""
        
        try:
            dns_info = {
                'a_records': [],
                'mx_records': [],
                'txt_records': [],
                'ns_records': [],
                'cname_records': [],
                'dnssec': False,
                'subdomains': []
            }
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [{'preference': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                dns_info['cname_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # Check for common subdomains
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'support']
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    answers = dns.resolver.resolve(full_domain, 'A')
                    dns_info['subdomains'].append({
                        'subdomain': full_domain,
                        'ip': str(answers[0])
                    })
                except:
                    pass
            
            return dns_info if any(dns_info.values()) else None
            
        except Exception as e:
            logger.error(f"DNS check error for {domain}: {str(e)}")
            return None
    
    async def _check_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS information for domain."""
        
        try:
            domain_info = whois.whois(domain)
            
            result = {
                'registrar': domain_info.registrar,
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
                'updated_date': domain_info.updated_date,
                'name_servers': domain_info.name_servers,
                'status': domain_info.status,
                'emails': domain_info.emails,
                'organization': domain_info.org,
                'country': domain_info.country
            }
            
            # Calculate domain age
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age_days = (datetime.now() - creation_date).days
                result['domain_age_days'] = domain_age_days
            
            return result
            
        except Exception as e:
            logger.error(f"WHOIS check error for {domain}: {str(e)}")
            return None
    
    def _extract_shodan_services(self, data: Dict) -> List[Dict]:
        """Extract service information from Shodan data."""
        
        services = []
        
        try:
            for service in data.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'cpe': service.get('cpe'),
                    'vulnerabilities': service.get('vulns', []),
                    'banner': service.get('data', '')[:200]  # Truncate banner
                }
                services.append(service_info)
        
        except Exception as e:
            logger.error(f"Error extracting Shodan services: {str(e)}")
        
        return services
    
    def _calculate_virustotal_score(self, data: Dict) -> float:
        """Calculate threat score from VirusTotal data."""
        
        try:
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            
            total = malicious + suspicious + harmless
            
            if total == 0:
                return 0.0
            
            # Calculate score (0-1 range)
            score = (malicious * 1.0 + suspicious * 0.5) / total
            
            return min(score, 1.0)
        
        except Exception as e:
            logger.error(f"Error calculating VirusTotal score: {str(e)}")
            return 0.0
    
    def _calculate_shodan_score(self, data: Dict) -> float:
        """Calculate threat score from Shodan data."""
        
        try:
            score = 0.0
            
            # Check for vulnerabilities
            vulns = data.get('vulns', [])
            score += min(len(vulns) * 0.1, 0.5)
            
            # Check for common vulnerable ports
            ports = data.get('ports', [])
            vulnerable_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389]
            
            for port in ports:
                if port in vulnerable_ports:
                    score += 0.1
            
            # Check for outdated services
            services = data.get('data', [])
            for service in services:
                product = service.get('product', '').lower()
                version = service.get('version', '')
                
                # Check for known vulnerable software
                vulnerable_software = ['apache', 'nginx', 'iis', 'tomcat', 'mysql', 'postgresql']
                if any(soft in product for soft in vulnerable_software):
                    if version:  # Version information available
                        score += 0.05
            
            return min(score, 1.0)
        
        except Exception as e:
            logger.error(f"Error calculating Shodan score: {str(e)}")
            return 0.0
    
    def _calculate_censys_score(self, data: Dict) -> float:
        """Calculate threat score from Censys data."""
        
        try:
            score = 0.0
            
            services = data.get('result', {}).get('services', [])
            
            # Check for vulnerable services
            for service in services:
                port = service.get('port')
                if port in [21, 23, 135, 139, 445, 1433, 3306, 3389]:
                    score += 0.1
            
            return min(score, 1.0)
        
        except Exception as e:
            logger.error(f"Error calculating Censys score: {str(e)}")
            return 0.0
    
    def _calculate_threat_score(self, threat_info: Dict) -> float:
        """Calculate combined threat score from all sources."""
        
        try:
            scores = []
            
            # VirusTotal score
            if 'virustotal' in threat_info and 'threat_score' in threat_info['virustotal']:
                scores.append(threat_info['virustotal']['threat_score'])
            
            # Shodan score
            if 'shodan' in threat_info and 'threat_score' in threat_info['shodan']:
                scores.append(threat_info['shodan']['threat_score'])
            
            # Censys score
            if 'censys' in threat_info and 'threat_score' in threat_info['censys']:
                scores.append(threat_info['censys']['threat_score'])
            
            if not scores:
                return 0.0
            
            # Average the scores
            return sum(scores) / len(scores)
        
        except Exception as e:
            logger.error(f"Error calculating combined threat score: {str(e)}")
            return 0.0
    
    def _calculate_risk_level(self, score: float) -> str:
        """Convert threat score to risk level."""
        
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"