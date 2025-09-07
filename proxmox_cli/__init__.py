"""
Proxmox CLI - A flexible command-line interface for managing Proxmox VE servers.
"""

from .cli import main, CLICommands
from .client import ProxmoxClient
from .config import Config, ExitCode

__version__ = "1.0.0"
__all__ = ["main", "Config", "ProxmoxClient", "CLICommands", "ExitCode"]
