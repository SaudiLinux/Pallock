"""
Advanced Web Crawler Module
Intelligent web crawler with JavaScript rendering and form discovery
"""

import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Optional
import re
from rich.console import Console
import validators

from ..core.logger import logger

console = Console()

class AdvancedCrawler:
    """Advanced web crawler with JavaScript support and intelligent link discovery."""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.visited_urls: Set[str] = set()
        self.found_forms: List[Dict] = []
        self.js_files: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        
        # Setup session
        self.session.headers.update(config.get_headers())
        if config.proxy:
            self.session.proxies = {'http': config.proxy, 'https': config.proxy}
    
    async def crawl(self, start_url: str, max_depth: int = 3) -> Set[str]:
        """Crawl website starting from given URL."""
        
        logger.info(f"Starting crawl from: {start_url}")
        
        urls_to_visit = [(start_url, 0)]
        all_urls = set()
        
        while urls_to_visit and len(all_urls) < self.config.max_pages:
            current_url, depth = urls_to_visit.pop(0)
            
            if current_url in self.visited_urls or depth > max_depth:
                continue
            
            if not validators.url(current_url):
                continue
            
            self.visited_urls.add(current_url)
            all_urls.add(current_url)
            
            try:
                # Fetch page
                response = self.session.get(current_url, timeout=self.config.timeout)
                
                if response.status_code != 200:
                    continue
                
                # Parse content
                content_type = response.headers.get('Content-Type', '')
                
                if 'text/html' in content_type:
                    # Extract links from HTML
                    found_urls = self._extract_html_links(current_url, response.text)
                    
                    # Extract forms
                    forms = self._extract_forms(current_url, response.text)
                    self.found_forms.extend(forms)
                    
                    # Extract JavaScript files
                    js_files = self._extract_js_files(current_url, response.text)
                    self.js_files.update(js_files)
                    
                elif 'application/json' in content_type:
                    # Extract API endpoints from JSON
                    api_urls = self._extract_api_links(current_url, response.text)
                    found_urls.update(api_urls)
                
                # Add new URLs to queue
                for url in found_urls:
                    if url not in self.visited_urls:
                        urls_to_visit.append((url, depth + 1))
                
                # Rate limiting
                await asyncio.sleep(self.config.delay)
                
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {str(e)}")
                continue
        
        logger.info(f"Crawl completed: {len(all_urls)} URLs found")
        logger.info(f"Forms discovered: {len(self.found_forms)}")
        logger.info(f"JavaScript files: {len(self.js_files)}")
        logger.info(f"API endpoints: {len(self.api_endpoints)}")
        
        return all_urls
    
    def _extract_html_links(self, base_url: str, html_content: str) -> Set[str]:
        """Extract links from HTML content."""
        
        urls = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract links from various elements
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            for attr in ['href', 'src', 'action']:
                url = tag.get(attr)
                if url:
                    absolute_url = urljoin(base_url, url)
                    if self._is_same_domain(base_url, absolute_url):
                        urls.add(absolute_url)
        
        # Extract from meta tags
        for meta in soup.find_all('meta'):
            http_equiv = meta.get('http-equiv')
            if http_equiv and http_equiv.lower() == 'refresh':
                content = meta.get('content', '')
                if 'url=' in content:
                    url = content.split('url=')[-1].strip()
                    absolute_url = urljoin(base_url, url)
                    if self._is_same_domain(base_url, absolute_url):
                        urls.add(absolute_url)
        
        # Extract from JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                js_urls = self._extract_js_links(base_url, script.string)
                urls.update(js_urls)
        
        return urls
    
    def _extract_forms(self, base_url: str, html_content: str) -> List[Dict]:
        """Extract forms from HTML content."""
        
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_js_files(self, base_url: str, html_content: str) -> Set[str]:
        """Extract JavaScript file URLs."""
        
        js_files = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                js_files.add(absolute_url)
        
        return js_files
    
    def _extract_js_links(self, base_url: str, js_content: str) -> Set[str]:
        """Extract URLs from JavaScript content."""
        
        urls = set()
        
        # Common URL patterns in JavaScript
        patterns = [
            r'["\']([^"\']*\.(?:html|php|asp|jsp|json|xml)[^"\']*)["\']',
            r'["\']([^"\']*\/api\/[^"\']*)["\']',
            r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('http'):
                    absolute_url = urljoin(base_url, match)
                    if self._is_same_domain(base_url, absolute_url):
                        urls.add(absolute_url)
        
        return urls
    
    def _extract_api_links(self, base_url: str, json_content: str) -> Set[str]:
        """Extract API endpoints from JSON content."""
        
        urls = set()
        
        try:
            data = json.loads(json_content)
            
            # Look for URL patterns in JSON
            def find_urls(obj):
                if isinstance(obj, str):
                    if obj.startswith(('http://', 'https://', '/api/', '/v1/', '/v2/')):
                        absolute_url = urljoin(base_url, obj)
                        if self._is_same_domain(base_url, absolute_url):
                            urls.add(absolute_url)
                elif isinstance(obj, dict):
                    for value in obj.values():
                        find_urls(value)
                elif isinstance(obj, list):
                    for item in obj:
                        find_urls(item)
            
            find_urls(data)
            
        except json.JSONDecodeError:
            pass
        
        return urls
    
    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """Check if two URLs are from the same domain."""
        
        base_domain = urlparse(base_url).netloc
        target_domain = urlparse(target_url).netloc
        
        # Include subdomains if configured
        if self.config.include_subdomains:
            return target_domain.endswith(base_domain) or base_domain.endswith(target_domain)
        else:
            return base_domain == target_domain
    
    def get_discovered_forms(self) -> List[Dict]:
        """Get all discovered forms."""
        return self.found_forms
    
    def get_js_files(self) -> Set[str]:
        """Get all discovered JavaScript files."""
        return self.js_files
    
    def get_api_endpoints(self) -> Set[str]:
        """Get all discovered API endpoints."""
        return self.api_endpoints