"""
Pallock Logger Module
Advanced logging system with colored output and multiple formats
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console
from loguru import logger
import json

console = Console()

def setup_logging(verbose: bool = False, quiet: bool = False, log_file: Optional[str] = None):
    """Setup advanced logging configuration."""
    
    # Remove default logger
    logger.remove()
    
    # Set log level
    if quiet:
        level = "WARNING"
    elif verbose:
        level = "DEBUG"
    else:
        level = "INFO"
    
    # Console handler with rich formatting
    logger.add(
        console.print,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True
    )
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="10 MB",
            retention="30 days",
            compression="zip"
        )
    
    logger.info("Pallock logging system initialized")
    logger.info(f"Log level: {level}")
    
    return logger

class VulnerabilityLogger:
    """Specialized logger for vulnerability findings."""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.findings = []
        
    def log_vulnerability(self, vulnerability_type: str, severity: str, 
                         url: str, description: str, evidence: dict = None):
        """Log a discovered vulnerability."""
        
        finding = {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "type": vulnerability_type,
            "severity": severity,
            "url": url,
            "description": description,
            "evidence": evidence or {}
        }
        
        self.findings.append(finding)
        
        # Log with appropriate color based on severity
        if severity.upper() == "CRITICAL":
            logger.critical(f"🚨 {vulnerability_type} found at {url}: {description}")
        elif severity.upper() == "HIGH":
            logger.error(f"🔥 {vulnerability_type} found at {url}: {description}")
        elif severity.upper() == "MEDIUM":
            logger.warning(f"⚠️  {vulnerability_type} found at {url}: {description}")
        elif severity.upper() == "LOW":
            logger.info(f"ℹ️  {vulnerability_type} found at {url}: {description}")
        else:
            logger.info(f"🔍 {vulnerability_type} found at {url}: {description}")
    
    def log_zero_day(self, vulnerability_type: str, url: str, 
                    description: str, confidence: float, evidence: dict = None):
        """Log a potential zero-day vulnerability."""
        
        finding = {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "type": vulnerability_type,
            "severity": "CRITICAL",
            "url": url,
            "description": description,
            "confidence": confidence,
            "zero_day": True,
            "evidence": evidence or {}
        }
        
        self.findings.append(finding)
        
        logger.critical(
            f"🎯 POTENTIAL ZERO-DAY: {vulnerability_type} at {url} "
            f"(Confidence: {confidence:.2f}): {description}"
        )
    
    def log_exploit_attempt(self, exploit_type: str, url: str, 
                            payload: str, result: str):
        """Log exploit attempt results."""
        
        logger.info(
            f"🎯 Exploit Attempt: {exploit_type} at {url}\n"
            f"   Payload: {payload}\n"
            f"   Result: {result}"
        )
    
    def save_findings(self, filepath: str):
        """Save all findings to JSON file."""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Saved {len(self.findings)} findings to {filepath}")
    
    def get_statistics(self) -> dict:
        """Get vulnerability statistics."""
        
        stats = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "zero_days": 0
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "UNKNOWN").upper()
            if severity == "CRITICAL":
                stats["critical"] += 1
                if finding.get("zero_day", False):
                    stats["zero_days"] += 1
            elif severity == "HIGH":
                stats["high"] += 1
            elif severity == "MEDIUM":
                stats["medium"] += 1
            elif severity == "LOW":
                stats["low"] += 1
        
        return stats
    
    def print_summary(self):
        """Print vulnerability summary."""
        
        stats = self.get_statistics()
        
        console.print("\n[bold cyan]Vulnerability Summary:[/bold cyan]")
        console.print(f"Total findings: {stats['total']}")
        console.print(f"Critical: [red]{stats['critical']}[/red]")
        console.print(f"High: [orange1]{stats['high']}[/orange1]")
        console.print(f"Medium: [yellow]{stats['medium']}[/yellow]")
        console.print(f"Low: [green]{stats['low']}[/green]")
        
        if stats['zero_days'] > 0:
            console.print(f"Zero-days detected: [bold red]{stats['zero_days']}[/bold red]")

# Global vulnerability logger instance
vuln_logger = None

def get_vulnerability_logger(scan_id: str) -> VulnerabilityLogger:
    """Get or create vulnerability logger for a scan."""
    global vuln_logger
    
    if vuln_logger is None or vuln_logger.scan_id != scan_id:
        vuln_logger = VulnerabilityLogger(scan_id)
    
    return vuln_logger