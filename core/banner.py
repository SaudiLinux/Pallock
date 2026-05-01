"""
Pallock Banner Module
Display awesome ASCII art banner for Pallock scanner
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import print as rprint
import random

console = Console()

def show_banner():
    """Display Pallock banner with random colors."""
    
    # Multiple banner designs
    banners = [
        """
    ██████╗ ██�  ██╗██████╗ ██████╗ ██╗  ██╗
    ██╔══██╗██║  ██║██╔══██╗██╔══██╗██║ ██╔╝
    ██████╔╝███████║██████╔╝██████╔╝█████╔╝ 
    ██╔═══╝ ██╔══██║██╔══██╗██╔══██╗██╔═██╗ 
    ██║     ██║  ██║██║  ██║██║  ██║██║  ██╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
        """,
        """
    ░█████╗░███╗░░██╗░█████╗░██╗░░██╗
    ██╔══██╗████╗░██║██╔══██╗██║░██╔╝
    ███████║██╔██╗██║██║░░╚═╝█████═╝░
    ██╔══██║██║╚████║██║░░██╗██╔═██╗░
    ██║░░██║██║░╚███║╚█████╔╝██║░╚██╗
    ╚═╝░░╚═╝╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝
        """,
        """
    ╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗
    ║║╚╝║║║╦╝║╣ ║╣ ║╣ ║║║║╣ ║╣ ║║║║║
    ║╚╗╔╝║║╩╗╚═╝╚═╝╚═╝║╩║╚═╝╚═╝║╩║
    ╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝
        """
    ]
    
    # Random colors for banner
    colors = ["red", "green", "blue", "yellow", "magenta", "cyan", "white", "bright_red", "bright_green", "bright_blue"]
    
    banner = random.choice(banners)
    color = random.choice(colors)
    
    # Create styled text
    styled_banner = Text(banner, style=f"bold {color}")
    
    # Create info text
    info_text = Text()
    info_text.append("Pallock - Advanced Zero-Day Vulnerability Scanner\n", style="bold white")
    info_text.append("Author: ", style="dim")
    info_text.append("SayerLinux\n", style="cyan")
    info_text.append("Email: ", style="dim")
    info_text.append("SayerLinux1@gmail.com\n", style="cyan")
    info_text.append("Version: ", style="dim")
    info_text.append("1.0.0\n", style="green")
    info_text.append("GitHub: ", style="dim")
    info_text.append("https://github.com/SayerLinux/Pallock\n", style="blue")
    
    # Create panel
    panel = Panel(
        Align.center(info_text),
        title=Align.center(styled_banner),
        border_style=color,
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()
    
    # Show loading animation
    show_loading_message()

def show_loading_message():
    """Show loading message with animation."""
    
    messages = [
        "🚀 Initializing Pallock Zero-Day Scanner...",
        "🔍 Loading vulnerability detection modules...",
        "🧠 Preparing AI-powered threat detection...",
        "⚡ Activating advanced exploit framework...",
        "🛡️  Ready to hunt zero-day vulnerabilities!"
    ]
    
    for message in messages:
        console.print(f"[dim]{message}[/dim]")
    
    console.print()

def show_scan_start(target: str):
    """Show scan start message."""
    
    console.print(f"[bold green]🔍 Starting scan for: {target}[/bold green]")
    console.print(f"[dim]Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print()

def show_scan_complete(duration: str, findings: int):
    """Show scan completion message."""
    
    console.print(f"[bold green]✅ Scan completed in {duration}[/bold green]")
    console.print(f"[cyan]📊 Total findings: {findings}[/cyan]")
    console.print()

def show_error(message: str):
    """Show error message."""
    
    console.print(f"[bold red]❌ Error: {message}[/bold red]")

def show_warning(message: str):
    """Show warning message."""
    
    console.print(f"[bold yellow]⚠️  Warning: {message}[/bold yellow]")

def show_success(message: str):
    """Show success message."""
    
    console.print(f"[bold green]✅ {message}[/bold green]")

def show_info(message: str):
    """Show info message."""
    
    console.print(f"[blue]ℹ️  {message}[/blue]")

# Import datetime for banner
from datetime import datetime