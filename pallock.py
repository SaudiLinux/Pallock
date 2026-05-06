#!/usr/bin/env python3
"""
Pallock - Advanced Zero-Day Vulnerability Scanner
Author: SayerLinux (SayerLinux1@gmail.com)
Version: 1.0.0

A powerful Python-based web vulnerability scanner that uses advanced techniques
to detect zero-day vulnerabilities, security misconfigurations, and potential
exploitation vectors.
"""

import asyncio
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import argparse

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.logger import setup_logging
from core.banner import show_banner
from core.scanner import PallockScanner

console = Console()

async def main():
    """Main entry point for Pallock scanner."""
    
    parser = argparse.ArgumentParser(
        description="Pallock - Advanced Zero-Day Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python pallock.py -u https://example.com
    python pallock.py -u https://example.com --deep-scan
    python pallock.py -u https://example.com --zero-day-only
    python pallock.py -f urls.txt --output report.html
        """
    )
    
    parser.add_argument('-u', '--url', 
                       help='Target URL to scan',
                       required=False)
    
    parser.add_argument('-f', '--file', 
                       help='File containing URLs to scan',
                       required=False)
    
    parser.add_argument('--deep-scan', 
                       action='store_true',
                       help='Enable deep scanning mode')
    
    parser.add_argument('--zero-day-only', 
                       action='store_true',
                       help='Scan only for zero-day vulnerabilities')
    
    parser.add_argument('--threads', 
                       type=int, 
                       default=10,
                       help='Number of threads to use (default: 10)')
    
    parser.add_argument('--timeout', 
                       type=int, 
                       default=30,
                       help='Request timeout in seconds (default: 30)')
    
    parser.add_argument('--user-agent', 
                       type=str,
                       help='Custom User-Agent string')
    
    parser.add_argument('--proxy', 
                       type=str,
                       help='Proxy URL (http://proxy:port)')
    
    parser.add_argument('--output', 
                       type=str,
                       help='Output file for results')
    
    parser.add_argument('--format', 
                       choices=['json', 'html', 'xml', 'txt'],
                       default='html',
                       help='Output format (default: html)')
    
    parser.add_argument('--verbose', '-v', 
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--quiet', '-q', 
                       action='store_true',
                       help='Quiet mode - minimal output')
    
    args = parser.parse_args()
    
    # Show banner
    # if not args.quiet:
    #     show_banner()
    
    # Setup logging
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    
    # Validate arguments
    if not args.url and not args.file:
        console.print("[red]Error: Either --url or --file must be specified[/red]")
        sys.exit(1)
    
    # Load configuration
    config = Config()
    config.update_from_args(args)
    
    try:
        # Initialize scanner
        scanner = PallockScanner(config)
        
        # Start scanning
        if args.url:
            await scanner.scan_single_url(args.url)
        elif args.file:
            await scanner.scan_from_file(args.file)
        
        # Generate report
        if args.output:
            scanner.generate_report(args.output, args.format)
        
        console.print("\n[green]✓ Scan completed successfully![/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Program interrupted[/yellow]")
        sys.exit(0)