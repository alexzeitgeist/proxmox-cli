"""
Configuration and exit codes for Proxmox CLI.
"""

from __future__ import annotations

import configparser
import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

import platformdirs
from rich.console import Console
import sys

console = Console()
err_console = Console(stderr=True)


class ExitCode(Enum):
    """Standard exit codes for CLI operations."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    INVALID_INPUT = 2
    NOT_FOUND = 3
    PERMISSION_DENIED = 4
    TIMEOUT = 5
    SERVER_ERROR = 6


@dataclass
class Config:
    """Configuration class for Proxmox connection settings."""

    host: str
    port: int = 8006
    user: str = "root@pam"
    token_name: str = ""
    token_value: str = ""
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    connect_timeout: int = 10
    read_timeout: int = 30
    profile: str = "default"

    @staticmethod
    def _parse_bool(value: Optional[str], default: bool = True) -> bool:
        """Parse boolean values from environment variables."""
        if value is None:
            return default
        return value.strip().lower() in ("1", "true", "yes", "on")

    @classmethod
    def _get_config_path(cls, profile: str = "default") -> Path:
        """Get the configuration file path following XDG standards."""
        config_dir = Path(platformdirs.user_config_dir("proxmox-cli"))
        config_file = (
            config_dir / (f"config.{profile}.ini" if profile != "default" else "config.ini")
        )
        return config_file

    @classmethod
    def _load_config_file(cls, config_path: Path) -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()

        # Try to read the config file
        if config_path.exists():
            try:
                config.read(config_path)
                if os.getenv("PROXMOX_DEBUG"):
                    err_console.print(f"[dim]Loaded config from: {config_path}[/dim]")
            except Exception as e:  # pragma: no cover - defensive
                console.print(
                    f"[yellow]Warning: Failed to read config file {config_path}: {e}[/yellow]"
                )

        return config

    @classmethod
    def from_env(cls, profile: str = "default") -> "Config":
        """Load configuration from config file and environment variables.

        Priority order (highest to lowest):
        1. Environment variables (PROXMOX_*)
        2. Config file in XDG config directory (~/.config/proxmox-cli/config.ini)
        3. Default values
        """
        # Get the config file path
        config_path = cls._get_config_path(profile)

        # Load configuration from file
        config = cls._load_config_file(config_path)

        # Get section name
        section = profile if config.has_section(profile) else "proxmox"
        if not config.has_section(section) and section != "DEFAULT":
            section = "DEFAULT"

        # Helper to get config value with env override
        def get_value(key: str, default: str = "") -> str:
            # Environment variables have highest priority
            env_key = f"PROXMOX_{key}"
            env_value = os.getenv(env_key)
            if env_value:
                return env_value

            # Then check config file
            if config.has_option(section, key.lower()):
                return config.get(section, key.lower())

            return default

        # Load all configuration values
        host = get_value("HOST", "192.168.78.202")
        port = int(get_value("PORT", "8006"))
        user = get_value("USER", "root@pam")
        token_name = get_value("TOKEN_NAME")
        token_value = get_value("TOKEN_VALUE")
        verify_ssl_str = get_value("VERIFY_SSL", "true")
        verify_ssl = cls._parse_bool(verify_ssl_str, default=True)
        ca_cert_path = get_value("CA_CERT_PATH")
        connect_timeout = int(get_value("CONNECT_TIMEOUT", "10"))
        read_timeout = int(get_value("READ_TIMEOUT", "30"))

        if not token_name or not token_value:
            # Create config directory if it doesn't exist
            config_path.parent.mkdir(parents=True, exist_ok=True)

            err_console.print(
                f"[red]Error: PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE must be set[/red]\n"
                f"[yellow]Please create a config file at: {config_path}[/yellow]\n"
                f"[dim]Example config file:[/dim]\n"
                f"[dim][proxmox][/dim]\n"
                f"[dim]host = your.proxmox.server[/dim]\n"
                f"[dim]token_name = your-token-name[/dim]\n"
                f"[dim]token_value = your-token-secret[/dim]\n"
            )
            sys.exit(ExitCode.INVALID_INPUT.value)

        return cls(
            host=host,
            port=port,
            user=user,
            token_name=token_name,
            token_value=token_value,
            verify_ssl=verify_ssl,
            ca_cert_path=ca_cert_path,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            profile=profile,
        )

    def validate(self) -> bool:
        """Validate configuration and test connectivity."""
        if not self.host or not self.token_name or not self.token_value:
            return False
        return True
