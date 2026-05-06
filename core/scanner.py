"""
Pallock Scanner Core Module
Main scanning engine with advanced vulnerability detection
"""

import asyncio
import aiohttp
import ssl
import socket
import json
import time
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Set, Any
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import validators

from core.config import Config
from core.logger import get_vulnerability_logger, logger
from core.banner import show_scan_start, show_scan_complete
from modules.zero_day_detector import ZeroDayDetector
from modules.exploit_framework import ExploitFramework
from modules.threat_intel import ThreatIntel
from modules.crawler import AdvancedCrawler
from modules.fuzzer import AdvancedFuzzer

console = Console()

class PallockScanner:
    """Main scanner class for Pallock vulnerability scanner."""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = None
        self.vuln_logger = None
        self.zero_day_detector = ZeroDayDetector(config)
        self.exploit_framework = ExploitFramework(config)
        self.threat_intel = ThreatIntel(config)
        self.crawler = AdvancedCrawler(config)
        self.fuzzer = AdvancedFuzzer(config)
        
        self.scanned_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.start_time = None
        self.scan_id = str(uuid.uuid4())
        
        # Initialize session
        self._setup_session()
    
    def _setup_session(self):
        """Setup HTTP session with retry strategy."""
        
        # Create session
        self.session = requests.Session()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=self.config.retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=self.config.max_threads)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update(self.config.get_headers())
        
        # Set proxy if configured
        if self.config.proxy:
            self.session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }
        
        # Disable SSL verification if configured
        if not self.config.verify_ssl:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    async def scan_single_url(self, url: str):
        """Scan a single URL for vulnerabilities."""
        
        if not validators.url(url):
            logger.error(f"Invalid URL: {url}")
            return
        
        # Initialize vulnerability logger
        self.vuln_logger = get_vulnerability_logger(self.scan_id)
        
        logger.info(f"Starting scan for: {url}")
        show_scan_start(url)
        
        self.start_time = datetime.now()
        
        try:
            # Normalize URL
            target_url = self._normalize_url(url)
            
            # Basic reconnaissance
            await self._reconnaissance(target_url)
            
            # Crawl the website
            if self.config.deep_scan:
                crawled_urls = await self.crawler.crawl(target_url)
                logger.info(f"Crawled {len(crawled_urls)} URLs")
            else:
                crawled_urls = [target_url]
            
            # Scan each URL
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                task = progress.add_task(f"Scanning {len(crawled_urls)} URLs...", total=len(crawled_urls))
                
                # Use semaphore to limit concurrent requests
                semaphore = asyncio.Semaphore(self.config.max_threads)
                
                async def scan_url_with_semaphore(url_to_scan: str):
                    async with semaphore:
                        await self._scan_url(url_to_scan)
                        progress.advance(task)
                
                # Create scan tasks
                scan_tasks = [
                    scan_url_with_semaphore(crawled_url)
                    for crawled_url in crawled_urls
                ]
                
                # Execute scans
                await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Generate exploit proofs-of-concept
            if self.config.enable_exploit_testing:
                await self._generate_exploits()
            
            # Calculate scan duration
            duration = datetime.now() - self.start_time
            duration_str = str(duration).split('.')[0]
            
            show_scan_complete(duration_str, len(self.vuln_logger.findings))
            
            # Print summary
            self.vuln_logger.print_summary()
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {str(e)}")
            if self.config.verbose:
                console.print_exception()
    
    async def scan_from_file(self, filepath: str):
        """Scan URLs from a file."""
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            logger.info(f"Loaded {len(urls)} URLs from {filepath}")
            
            for url in urls:
                await self.scan_single_url(url)
                
                # Add delay between scans to avoid overwhelming targets
                await asyncio.sleep(self.config.delay)
                
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {str(e)}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize and validate URL."""
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse URL
        parsed = urlparse(url)
        
        # Remove trailing slash
        path = parsed.path.rstrip('/') if parsed.path != '/' else ''
        
        # Reconstruct URL
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized
    
    async def _reconnaissance(self, url: str):
        """Perform initial reconnaissance on target."""
        
        logger.info("Performing reconnaissance...")
        
        try:
            # Get basic info
            response = self.session.get(url, timeout=self.config.timeout)
            
            # Extract technologies
            technologies = await self._detect_technologies(response)
            
            # Check threat intelligence
            if self.config.enable_threat_intel:
                threat_info = await self.threat_intel.check_domain(urlparse(url).netloc)
                if threat_info:
                    logger.warning(f"Threat intelligence found: {threat_info}")
            
            # Log reconnaissance findings
            logger.info(f"Target technologies: {', '.join(technologies)}")
            logger.info(f"Server: {response.headers.get('Server', 'Unknown')}")
            logger.info(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Reconnaissance error: {str(e)}")
    
    async def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies used by the target."""
        
        technologies = []
        headers = response.headers
        content = response.text.lower()
        
        # Server technologies
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'tomcat' in server:
            technologies.append('Tomcat')
        
        # Programming languages
        if 'php' in content or 'php' in server:
            technologies.append('PHP')
        if 'jsp' in content or 'tomcat' in server:
            technologies.append('Java/JSP')
        if 'asp' in content or 'iis' in server:
            technologies.append('ASP.NET')
        if 'python' in server or 'django' in content or 'flask' in content:
            technologies.append('Python')
        if 'ruby' in server or 'rails' in content:
            technologies.append('Ruby/Rails')
        if 'node.js' in server or 'express' in content:
            technologies.append('Node.js')
        
        # Frameworks and CMS
        if 'wordpress' in content:
            technologies.append('WordPress')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'django' in content:
            technologies.append('Django')
        if 'laravel' in content:
            technologies.append('Laravel')
        if 'react' in content:
            technologies.append('React')
        if 'vue.js' in content:
            technologies.append('Vue.js')
        if 'angular' in content:
            technologies.append('Angular')
        
        # JavaScript libraries
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        
        return list(set(technologies))
    
    async def _scan_url(self, url: str):
        """Scan individual URL for vulnerabilities."""
        
        if url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        
        try:
            # Basic request
            response = self.session.get(url, timeout=self.config.timeout)
            
            # Check for basic vulnerabilities
            await self._check_basic_vulnerabilities(url, response)
            
            # Zero-day detection
            if self.config.zero_day_only or self.config.enable_ai_detection:
                zero_day_findings = await self.zero_day_detector.scan(url, response)
                for finding in zero_day_findings:
                    self.vuln_logger.log_zero_day(
                        finding['type'],
                        url,
                        finding['description'],
                        finding['confidence'],
                        finding.get('evidence')
                    )
            
            # Fuzzing
            if self.config.deep_scan:
                fuzz_results = await self.fuzzer.fuzz_url(url)
                for result in fuzz_results:
                    self.vuln_logger.log_vulnerability(
                        result['type'],
                        result['severity'],
                        url,
                        result['description'],
                        result.get('evidence')
                    )
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error scanning {url}: {str(e)}")
            if self.config.verbose:
                console.print_exception()
    
    async def _check_basic_vulnerabilities(self, url: str, response):
        """Check for basic/common vulnerabilities."""
        
        # Security headers check
        headers = response.headers
        
        if 'X-Frame-Options' not in headers:
            self.vuln_logger.log_vulnerability(
                "Missing Security Header",
                "MEDIUM",
                url,
                "X-Frame-Options header is missing - potential clickjacking vulnerability"
            )
        
        if 'X-Content-Type-Options' not in headers:
            self.vuln_logger.log_vulnerability(
                "Missing Security Header", 
                "MEDIUM",
                url,
                "X-Content-Type-Options header is missing - potential MIME sniffing"
            )
        
        if 'X-XSS-Protection' not in headers:
            self.vuln_logger.log_vulnerability(
                "Missing Security Header",
                "LOW", 
                url,
                "X-XSS-Protection header is missing"
            )
        
        if 'Strict-Transport-Security' not in headers and url.startswith('https://'):
            self.vuln_logger.log_vulnerability(
                "Missing Security Header",
                "HIGH",
                url, 
                "HSTS header is missing - potential downgrade attacks"
            )
        
        # Server information disclosure
        if 'Server' in headers:
            server = headers['Server']
            self.vuln_logger.log_vulnerability(
                "Information Disclosure",
                "LOW",
                url,
                f"Server information disclosed: {server}"
            )
        
        # Check for debug information
        if response.status_code == 500:
            if 'traceback' in response.text.lower() or 'stack trace' in response.text.lower():
                self.vuln_logger.log_vulnerability(
                    "Information Disclosure",
                    "HIGH",
                    url,
                    "Debug information disclosed in error page"
                )
    
    async def _generate_exploits(self):
        """Generate exploit proofs-of-concept for discovered vulnerabilities."""
        
        logger.info("Generating exploit proofs-of-concept...")
        
        for finding in self.vuln_logger.findings:
            if finding['severity'] in ['CRITICAL', 'HIGH']:
                exploit = await self.exploit_framework.generate_exploit(finding)
                if exploit:
                    logger.info(f"Generated exploit for {finding['type']}")
    
    def generate_report(self, output_file: str, format_type: str = 'html'):
        """Generate scan report."""
        
        logger.info(f"Generating {format_type.upper()} report: {output_file}")
        
        try:
            if format_type.lower() == 'json':
                self._generate_json_report(output_file)
            elif format_type.lower() == 'html':
                self._generate_html_report(output_file)
            elif format_type.lower() == 'xml':
                self._generate_xml_report(output_file)
            else:
                self._generate_text_report(output_file)
            
            logger.info(f"Report saved to: {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
    
    def _generate_json_report(self, output_file: str):
        """Generate JSON report."""
        
        report = {
            "scan_id": self.scan_id,
            "scan_info": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": datetime.now().isoformat(),
                "config": {
                    "deep_scan": self.config.deep_scan,
                    "zero_day_only": self.config.zero_day_only,
                    "max_threads": self.config.max_threads
                }
            },
            "statistics": self.vuln_logger.get_statistics(),
            "findings": self.vuln_logger.findings
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self, output_file: str):
        """Generate HTML report."""
        
        # This is a simplified HTML report - in production you'd want a proper template
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Pallock Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; margin: 20px 0; }}
        .finding {{ background-color: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #27ae60; }}
        .zero-day {{ background-color: #ffebee; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Pallock Vulnerability Scan Report</h1>
        <p>Scan ID: {self.scan_id}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total findings: {self.vuln_logger.get_statistics()['total']}</p>
        <p>Critical: {self.vuln_logger.get_statistics()['critical']}</p>
        <p>High: {self.vuln_logger.get_statistics()['high']}</p>
        <p>Medium: {self.vuln_logger.get_statistics()['medium']}</p>
        <p>Low: {self.vuln_logger.get_statistics()['low']}</p>
    </div>
    
    <h2>Findings</h2>
"""
        
        for finding in self.vuln_logger.findings:
            severity_class = finding['severity'].lower()
            zero_day_class = 'zero-day' if finding.get('zero_day', False) else ''
            
            html_content += f"""
    <div class="finding {severity_class} {zero_day_class}">
        <h3>{finding['type']}</h3>
        <p><strong>URL:</strong> {finding['url']}</p>
        <p><strong>Severity:</strong> {finding['severity']}</p>
        <p><strong>Description:</strong> {finding['description']}</p>
        <p><strong>Timestamp:</strong> {finding['timestamp']}</p>
        {f'<p><strong>Zero-Day:</strong> Potential zero-day vulnerability (Confidence: {finding.get("confidence", 0):.2f})</p>' if finding.get('zero_day', False) else ''}
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_xml_report(self, output_file: str):
        """Generate XML report."""
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<scan_report>
    <scan_info>
        <scan_id>{self.scan_id}</scan_id>
        <start_time>{self.start_time.isoformat() if self.start_time else ''}</start_time>
        <end_time>{datetime.now().isoformat()}</end_time>
    </scan_info>
    <summary>
        <total_findings>{self.vuln_logger.get_statistics()['total']}</total_findings>
        <critical>{self.vuln_logger.get_statistics()['critical']}</critical>
        <high>{self.vuln_logger.get_statistics()['high']}</high>
        <medium>{self.vuln_logger.get_statistics()['medium']}</medium>
        <low>{self.vuln_logger.get_statistics()['low']}</low>
        <zero_days>{self.vuln_logger.get_statistics()['zero_days']}</zero_days>
    </summary>
    <findings>
"""
        
        for finding in self.vuln_logger.findings:
            xml_content += f"""
        <finding>
            <type>{finding['type']}</type>
            <severity>{finding['severity']}</severity>
            <url>{finding['url']}</url>
            <description><![CDATA[{finding['description']}]]></description>
            <timestamp>{finding['timestamp']}</timestamp>
            {f'<zero_day confidence="{finding.get("confidence", 0)}">true</zero_day>' if finding.get('zero_day', False) else ''}
        </finding>
"""
        
        xml_content += """
    </findings>
</scan_report>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    def _generate_text_report(self, output_file: str):
        """Generate plain text report."""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("Pallock Vulnerability Scan Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\nSUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total findings: {self.vuln_logger.get_statistics()['total']}\n")
            f.write(f"Critical: {self.vuln_logger.get_statistics()['critical']}\n")
            f.write(f"High: {self.vuln_logger.get_statistics()['high']}\n")
            f.write(f"Medium: {self.vuln_logger.get_statistics()['medium']}\n")
            f.write(f"Low: {self.vuln_logger.get_statistics()['low']}\n")
            f.write(f"Zero-days: {self.vuln_logger.get_statistics()['zero_days']}\n")
            f.write("\nFINDINGS\n")
            f.write("-" * 20 + "\n")
            
            for finding in self.vuln_logger.findings:
                f.write(f"\nType: {finding['type']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Timestamp: {finding['timestamp']}\n")
                if finding.get('zero_day', False):
                    f.write(f"Zero-Day: Yes (Confidence: {finding.get('confidence', 0):.2f})\n")
                f.write("-" * 40 + "\n")