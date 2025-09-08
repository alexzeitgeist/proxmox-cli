#!/usr/bin/env python3
"""
Proxmox CLI entrypoint: argument parsing and command dispatch.
"""

import argparse
import os
import sys
import traceback

from rich.console import Console

from .config import Config, ExitCode
from .client import ProxmoxClient
from .commands import CLICommands


console = Console()
err_console = Console(stderr=True)


def create_parser():
    """Create the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description='Proxmox CLI Controller - Enhanced',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options
    parser.add_argument('--profile', default='default', help='Configuration profile to use')
    parser.add_argument('--output', choices=['table', 'json'], default='table', help='Output format')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (use with caution)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # List VMs command
    list_parser = subparsers.add_parser('list', help='List all VMs')
    list_parser.add_argument('--node', help='Filter by specific node')
    list_parser.add_argument('--tags', help='Filter by tags (comma-separated)')

    # VM info command
    info_parser = subparsers.add_parser('info', help='Show detailed VM information')
    info_group = info_parser.add_mutually_exclusive_group(required=True)
    info_group.add_argument('vmid', type=int, nargs='?', help='VM ID')
    info_group.add_argument('--name', help='VM name')
    info_parser.add_argument('--node', help='Node name (optional, will auto-detect)')
    info_parser.add_argument('--with-osinfo', action='store_true', default=None, help='Query guest OS and hostname via QEMU Guest Agent')
    info_parser.add_argument('--no-osinfo', dest='with_osinfo', action='store_false', help='Disable OS/hostname query (overrides default)')
    info_parser.add_argument('--with-stats', action='store_true', default=None, help='Include last-hour averages (RRD) for CPU/memory/network/disk')
    info_parser.add_argument('--no-stats', dest='with_stats', action='store_false', help='Disable stats (overrides default)')

    # Start VM command
    start_parser = subparsers.add_parser('start', help='Start a VM')
    start_group = start_parser.add_mutually_exclusive_group(required=True)
    start_group.add_argument('vmid', type=int, nargs='?', help='VM ID')
    start_group.add_argument('--name', help='VM name')
    start_parser.add_argument('--node', help='Node name (optional, will auto-detect)')
    start_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    start_parser.add_argument('--wait', action='store_true', help='Wait for operation to complete')
    start_parser.add_argument('--timeout', type=int, default=60, help='Timeout for --wait (seconds)')

    # Stop VM command
    stop_parser = subparsers.add_parser('stop', help='Stop a VM')
    stop_group = stop_parser.add_mutually_exclusive_group(required=True)
    stop_group.add_argument('vmid', type=int, nargs='?', help='VM ID')
    stop_group.add_argument('--name', help='VM name')
    stop_parser.add_argument('--node', help='Node name (optional, will auto-detect)')
    stop_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    stop_parser.add_argument('--hard', action='store_true', help='Force stop (no graceful shutdown)')
    stop_parser.add_argument('--wait', action='store_true', help='Wait for operation to complete')
    stop_parser.add_argument('--timeout', type=int, default=60, help='Timeout for --wait (seconds)')

    # Suspend VM command
    suspend_parser = subparsers.add_parser('suspend', help='Suspend/pause a VM')
    suspend_group = suspend_parser.add_mutually_exclusive_group(required=True)
    suspend_group.add_argument('vmid', type=int, nargs='?', help='VM ID')
    suspend_group.add_argument('--name', help='VM name')
    suspend_parser.add_argument('--node', help='Node name (optional, will auto-detect)')
    suspend_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    suspend_parser.add_argument('--wait', action='store_true', help='Wait for operation to complete')

    # Resume VM command
    resume_parser = subparsers.add_parser('resume', help='Resume a suspended VM')
    resume_group = resume_parser.add_mutually_exclusive_group(required=True)
    resume_group.add_argument('vmid', type=int, nargs='?', help='VM ID')
    resume_group.add_argument('--name', help='VM name')
    resume_parser.add_argument('--node', help='Node name (optional, will auto-detect)')
    resume_parser.add_argument('--wait', action='store_true', help='Wait for operation to complete')

    # Cluster overview
    subparsers.add_parser('cluster', help='Show cluster overview (version, nodes, VM counts)')

    # Node status
    node_parser = subparsers.add_parser('node', help='Show node status summary')
    node_parser.add_argument('--node', help='Node name (defaults to the only node when single-node)')

    return parser


def main():
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(ExitCode.SUCCESS.value)

    # Handle --insecure flag
    if args.insecure:
        os.environ['PROXMOX_VERIFY_SSL'] = 'false'
        err_console.print("[yellow]⚠ Warning: SSL verification disabled via --insecure flag[/yellow]")

    try:
        config = Config.from_env(args.profile)
        client = ProxmoxClient(config, quiet=args.output == 'json')

        capabilities = client.discover_capabilities()
        if args.debug:
            err_console.print(f"[dim]Discovered: {capabilities}[/dim]")

        # Apply config-driven defaults for flags when unset (None)
        if args.command == 'info':
            if getattr(args, 'with_stats', None) is None:
                args.with_stats = bool(getattr(config, 'with_stats', False))
            if getattr(args, 'with_osinfo', None) is None:
                args.with_osinfo = bool(getattr(config, 'with_osinfo', False))

        commands = CLICommands(client, output_format=args.output)
    except Exception as e:
        err_console.print(f"[red]Initialization error: {e}[/red]")
        sys.exit(ExitCode.GENERAL_ERROR.value)

    command_map = {
        'list': commands.list_vms,
        'info': commands.vm_info,
        'start': commands.start_vm,
        'stop': commands.stop_vm,
        'suspend': commands.suspend_vm,
        'resume': commands.resume_vm,
        'cluster': commands.cluster_overview,
        'node': commands.node_status,
    }

    handler = command_map.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            err_console.print("\n[yellow]Operation cancelled[/yellow]")
            sys.exit(ExitCode.SUCCESS.value)
        except Exception as e:
            if args.debug:
                err_console.print("[red]Debug trace:[/red]")
                traceback.print_exc()
            err_console.print(f"[red]Error: {e}[/red]")
            sys.exit(ExitCode.GENERAL_ERROR.value)
    else:
        err_console.print(f"[red]Unknown command: {args.command}[/red]")
        parser.print_help()
        sys.exit(ExitCode.INVALID_INPUT.value)


if __name__ == "__main__":
    main()
