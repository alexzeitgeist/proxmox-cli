"""
CLI command handlers and output formatting.
"""

import json
import sys
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from .config import ExitCode

console = Console()
err_console = Console(stderr=True)


class CLICommands:
    """Command handlers for the CLI interface."""

    def __init__(self, client: Any, output_format: str = 'table'):
        self.client = client
        self.output_format = output_format

    def _output_result(self, data: Any, table_func=None):
        """Output data in the requested format."""
        if self.output_format == 'json':
            print(json.dumps(data, indent=2))
        else:
            if table_func:
                table_func(data)
            else:
                console.print(data)

    def _map_exit_code(self, success: bool, message: str) -> int:
        if success:
            return ExitCode.SUCCESS.value
        ml = (message or '').lower()
        if 'timeout' in ml or 'timed out' in ml:
            return ExitCode.TIMEOUT.value
        if 'permission denied' in ml or 'unauthorized' in ml or 'forbidden' in ml:
            return ExitCode.PERMISSION_DENIED.value
        if 'not found' in ml or 'no vm found' in ml:
            return ExitCode.NOT_FOUND.value
        return ExitCode.SERVER_ERROR.value

    def _emit_result(self, success: bool, message: str):
        code = self._map_exit_code(success, message)
        if self.output_format == 'json':
            self._output_result({'success': success, 'message': message})
        else:
            if success:
                console.print(f"[green]✓ {message}[/green]")
            else:
                err_console.print(f"[red]✗ {message}[/red]")
        if code != ExitCode.SUCCESS.value:
            sys.exit(code)

    def _maybe_confirm(self, args, prompt_text: str):
        if hasattr(args, 'yes'):
            if not args.yes and not Confirm.ask(prompt_text):
                sys.exit(ExitCode.SUCCESS.value)

    def list_vms(self, args):
        tags = [t.strip() for t in args.tags.split(',') if t.strip()] if args.tags else None
        vms = self.client.get_vms(node=args.node, tags=tags)

        # Prefetch guest IPs via client helper (concurrent under the hood)
        ip_map: Dict[int, List[str]] = self.client.get_ips_for_vms(vms)

        if self.output_format == 'json':
            enriched: List[Dict[str, Any]] = []
            for vm in vms:
                vm_out = dict(vm)
                primary_ip: Optional[str] = None
                guest_ips: List[str] = []
                if vm.get('status') == 'running':
                    guest_ips = ip_map.get(vm['vmid'], [])
                    if guest_ips:
                        primary_ip = guest_ips[0]
                vm_out['primary_ip'] = primary_ip
                vm_out['guest_ips'] = guest_ips
                enriched.append(vm_out)

            self._output_result(enriched)
            return

        if not vms:
            console.print("[yellow]No VMs found[/yellow]")
            return

        table = Table(title="Virtual Machines")
        table.add_column("VMID", style="cyan", no_wrap=True)
        table.add_column("Name", style="magenta")
        table.add_column("Node", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("IP Address", style="bright_cyan")
        table.add_column("Tags", style="blue")
        table.add_column("CPU", justify="right")
        table.add_column("Memory", justify="right")
        table.add_column("Uptime", justify="right")

        for vm in sorted(vms, key=lambda x: x['vmid']):
            status_color = {
                'running': 'green',
                'stopped': 'red',
                'suspended': 'yellow',
                'paused': 'yellow'
            }.get(vm['status'], 'white')

            uptime = vm.get('uptime', 0)
            if uptime > 0:
                hours = uptime // 3600
                minutes = (uptime % 3600) // 60
                uptime_str = f"{hours}h {minutes}m"
            else:
                uptime_str = "-"

            cpus_val = vm.get('cpus')
            cpus_str = f"{cpus_val} cores" if isinstance(cpus_val, (int, float)) else "N/A"

            maxmem = vm.get('maxmem')
            mem_str = f"{(maxmem or 0) / (1024**3):.1f} GB" if maxmem else "N/A"

            ip_str = "-"
            if vm['status'] == 'running':
                ips = ip_map.get(vm['vmid'])
                if ips:
                    ip_str = ips[0]

            table.add_row(
                str(vm['vmid']),
                vm.get('name', 'N/A'),
                vm['node'],
                f"[{status_color}]{vm['status']}[/{status_color}]",
                ip_str,
                vm.get('tags', '') or '',
                cpus_str,
                mem_str,
                uptime_str
            )

        console.print(table)

    def vm_info(self, args):
        vmid = args.vmid
        if args.name:
            vms = self.client.get_vm_by_name(args.name)
            if not vms:
                err_console.print(f"[red]No VM found with name '{args.name}'[/red]")
                sys.exit(ExitCode.NOT_FOUND.value)
            elif len(vms) > 1:
                err_console.print(f"[yellow]Multiple VMs found with name '{args.name}':[/yellow]")
                for vm in vms:
                    err_console.print(f"  - VMID {vm['vmid']} on node {vm['node']}")
                err_console.print("[yellow]Please specify by VMID[/yellow]")
                sys.exit(ExitCode.INVALID_INPUT.value)
            else:
                vmid = vms[0]['vmid']

        runtime = self.client.get_vm_runtime(vmid, args.node)
        status = runtime['status']
        config = runtime['config']

        if self.output_format == 'json':
            guest_ips: List[str] = []
            primary_ip: Optional[str] = None
            guest_os: Optional[Dict[str, Any]] = None
            guest_hostname: Optional[str] = None
            console_type: str = "spice" if bool(status.get('spice')) else "none"
            tpm_version: Optional[str] = None
            firmware: Optional[str] = None
            secure_boot: Optional[bool] = None
            disk_total_bytes: int = 0
            try:
                if status.get('status') == 'running' and status.get('agent'):
                    guest_ips = self.client.get_vm_guest_ips(vmid, runtime.get('node')) or []
                    if guest_ips:
                        primary_ip = guest_ips[0]
                    if getattr(args, 'with_osinfo', False):
                        guest_os = self.client.get_vm_guest_osinfo(vmid, runtime.get('node'))
                        guest_hostname = self.client.get_vm_guest_hostname(vmid, runtime.get('node'))
            except Exception:
                guest_ips = []
            cfg = config or {}
            if isinstance(cfg, dict):
                tpm = cfg.get('tpmstate0')
                if isinstance(tpm, str) and 'version=' in tpm:
                    for part in tpm.split(','):
                        if part.startswith('version='):
                            tpm_version = part.split('=', 1)[1]
                            break
                bios = cfg.get('bios')
                if bios:
                    firmware = str(bios).lower()
                efi = cfg.get('efidisk0')
                if isinstance(efi, str):
                    secure_boot = 'pre-enrolled-keys=1' in efi
                for k, v in cfg.items():
                    if not isinstance(k, str) or not isinstance(v, str):
                        continue
                    if not (k.startswith('scsi') or k.startswith('virtio') or k.startswith('sata') or k.startswith('ide')):
                        continue
                    if ':' not in v:
                        continue
                    size_bytes = 0
                    parts = v.split(',')
                    for p in parts:
                        if p.startswith('size='):
                            sval = p.split('=', 1)[1].strip()
                            try:
                                if sval.lower().endswith('t'):
                                    size_bytes = int(float(sval[:-1]) * (1024**4))
                                elif sval.lower().endswith('g'):
                                    size_bytes = int(float(sval[:-1]) * (1024**3))
                                elif sval.lower().endswith('m'):
                                    size_bytes = int(float(sval[:-1]) * (1024**2))
                                else:
                                    size_bytes = int(sval)
                            except Exception:
                                size_bytes = 0
                            break
                    if size_bytes:
                        disk_total_bytes += size_bytes
            combined = {
                'status': status,
                'config': config,
                'guest_ips': guest_ips,
                'primary_ip': primary_ip,
                'guest_os': guest_os,
                'guest_hostname': guest_hostname,
                'console': console_type,
                'tpm_version': tpm_version,
                'firmware': firmware,
                'secure_boot': secure_boot,
                'disk_total_bytes': disk_total_bytes,
            }
            self._output_result(combined)
            return

        cached = (
            getattr(self.client, 'vm_cache', {}).get(vmid)
            if hasattr(self.client, 'vm_cache') else None
        )
        vm_node = args.node or runtime.get('node') or (cached['node'] if cached and 'node' in cached else None)
        if not vm_node:
            vm_node = self.client.find_vm_node(vmid)

        vm_name = None
        if isinstance(config, dict):
            vm_name = config.get('name')
        if not vm_name and cached and 'data' in cached:
            vm_name = cached['data'].get('name')

        vm_tags = None
        if isinstance(config, dict):
            vm_tags = config.get('tags')
        if vm_tags is None and cached and 'data' in cached:
            vm_tags = cached['data'].get('tags')

        vm_data = {'name': vm_name or 'Unnamed', 'node': vm_node or 'Unknown', 'tags': vm_tags}

        uptime_seconds = status.get('uptime', 0)
        if uptime_seconds > 0:
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            uptime_str = f"{hours}h {minutes}m {seconds}s"
        else:
            uptime_str = "Not running"

        mem_used = status.get('mem', 0)
        mem_max = status.get('maxmem', 0)
        mem_percent = (mem_used / mem_max * 100) if mem_max > 0 else 0

        console.print(
            f"\n[bold cyan]═══ VM Information - {vm_data.get('name', 'Unnamed')} "
            f"(ID: {vmid}) ═══[/bold cyan]\n"
        )

        console.print("[bold]Status Information:[/bold]")
        console.print(f"  Node: {vm_data.get('node', 'Unknown')}")

        vm_status = status.get('status', 'unknown')
        if (vm_status == 'paused' or (status.get('qmpstatus') == 'paused' and vm_status == 'running')):
            vm_status = 'suspended'
            status_color = 'yellow'
        else:
            status_color = 'green' if vm_status == 'running' else 'red'

        console.print(f"  Status: [{status_color}]{vm_status}[/{status_color}]")
        guest_ips: List[str] = []
        try:
            if vm_status == 'running' and vm_node and bool(status.get('agent')):
                guest_ips = self.client.get_vm_guest_ips(vmid, vm_node)
        except Exception:
            guest_ips = []
        if guest_ips:
            if len(guest_ips) <= 2:
                console.print(f"  Guest IPs: {', '.join(guest_ips)}")
            else:
                console.print(f"  Guest IPs: {guest_ips[0]}")
                for ip in guest_ips[1:]:
                    console.print(f"             {ip}")
        else:
            console.print("  Guest IPs: N/A")
        console.print(f"  Uptime: {uptime_str}")
        if status.get('pid'):
            console.print(f"  Process ID: {status['pid']}")
        console.print(f"  CPU Usage: {status.get('cpu', 0) * 100:.1f}%")
        console.print(
            f"  Memory: {mem_used / (1024**3):.2f} GB / {mem_max / (1024**3):.2f} GB ({mem_percent:.1f}%)"
        )

        if getattr(args, 'with_osinfo', False) and bool(status.get('agent')):
            try:
                host_name = self.client.get_vm_guest_hostname(vmid, vm_node)
                osinfo = self.client.get_vm_guest_osinfo(vmid, vm_node)
            except Exception:
                host_name, osinfo = None, None
            if host_name:
                console.print(f"  Hostname: {host_name}")
            if isinstance(osinfo, dict) and osinfo:
                pretty = osinfo.get('pretty-name') or osinfo.get('name')
                version = osinfo.get('version-id') or osinfo.get('version')
                if pretty and version and version not in str(pretty):
                    console.print(f"  Guest OS: {pretty} ({version})")
                elif pretty:
                    console.print(f"  Guest OS: {pretty}")
                else:
                    console.print(f"  Guest OS: {osinfo}")

        if status.get('diskread') or status.get('diskwrite'):
            console.print("  Disk I/O:")
            console.print(f"    Read: {status.get('diskread', 0) / (1024**2):.2f} MB")
            console.print(f"    Write: {status.get('diskwrite', 0) / (1024**2):.2f} MB")

        if status.get('netin') or status.get('netout'):
            console.print("  Network I/O:")
            console.print(f"    In: {status.get('netin', 0) / (1024**2):.2f} MB")
            console.print(f"    Out: {status.get('netout', 0) / (1024**2):.2f} MB")

        lock = self.client.check_vm_lock(vmid, vm_node, status=status)
        if lock:
            console.print(f"  [yellow]Lock: {lock} (VM is currently locked)[/yellow]")

        if 'tags' in vm_data and vm_data['tags']:
            console.print(f"  Tags: {vm_data['tags']}")

        console.print("\n[bold]Configuration:[/bold]")
        console.print(f"  OS Type: {config.get('ostype', 'Unknown')}")
        console.print(f"  Boot Order: {config.get('boot', 'Default')}")
        console.print(f"  Auto-start: {'Yes' if config.get('onboot') else 'No'}")

        sockets = config.get('sockets', 1)
        cores = config.get('cores', 1)
        total_cpus = sockets * cores
        socket_plural = 's' if sockets > 1 else ''
        core_plural = 's' if cores > 1 else ''
        console.print(
            f"  CPU: {total_cpus} vCPUs ({sockets} socket{socket_plural} × {cores} core{core_plural})"
        )
        if config.get('cpu'):
            console.print(f"    Type: {config['cpu']}")

        console.print(f"  Memory: {config.get('memory', 0)} MB")
        if config.get('balloon') is not None:
            if str(config.get('balloon')) == '0':
                console.print("    Ballooning: Disabled (pinned)")
            else:
                console.print("    Ballooning: Enabled")

        agent_enabled = config.get('agent') == '1' or status.get('agent')
        console.print(f"  QEMU Agent: {'Enabled' if agent_enabled else 'Disabled'}")

        if status.get('running-qemu'):
            console.print(f"  QEMU Version: {status['running-qemu']}")
        if status.get('running-machine'):
            console.print(f"  Machine Type: {status['running-machine']}")

        if 'ha' in status:
            ha_managed = status['ha'].get('managed', 0)
            console.print(f"  High Availability: {'Managed' if ha_managed else 'Not managed'}")

        console.print("\n[bold]Storage:[/bold]")
        total_bytes = 0
        for key, value in config.items():
            if key.startswith(('scsi', 'ide', 'sata', 'virtio')) and ':' in str(value):
                disk_info = str(value).split(',')
                disk_location = disk_info[0]
                disk_params = {}
                for param in disk_info[1:]:
                    if '=' in param:
                        k, v = param.split('=', 1)
                        disk_params[k] = v
                console.print(f"  {key}: {disk_location}")
                if disk_params:
                    console.print(f"    Size: {disk_params.get('size', 'Unknown')}")
                    if disk_params.get('ssd'):
                        console.print("    Type: SSD")
                    if disk_params.get('discard'):
                        console.print(f"    Discard: {disk_params['discard']}")
                size_str = disk_params.get('size') if disk_params else None
                if size_str:
                    sval = str(size_str)
                    try:
                        if sval.lower().endswith('t'):
                            total_bytes += int(float(sval[:-1]) * (1024**4))
                        elif sval.lower().endswith('g'):
                            total_bytes += int(float(sval[:-1]) * (1024**3))
                        elif sval.lower().endswith('m'):
                            total_bytes += int(float(sval[:-1]) * (1024**2))
                        else:
                            total_bytes += int(sval)
                    except Exception:
                        pass
        if total_bytes:
            if total_bytes >= 1024**4:
                total_tb = total_bytes / (1024**4)
                console.print(f"  Total provisioned disk: {total_tb:.2f} TB")
            else:
                total_gb = total_bytes / (1024**3)
                console.print(f"  Total provisioned disk: {total_gb:.2f} GB")

        if 'nics' in status or any(k.startswith('net') for k in config.keys()):
            console.print("\n[bold]Network:[/bold]")
            nic_params: List[Dict[str, str]] = []
            for key, value in config.items():
                if key.startswith('net'):
                    net_info = str(value).split(',')
                    net_params = {}
                    for param in net_info:
                        if '=' in param:
                            k, v = param.split('=', 1)
                            net_params[k] = v
                    console.print(f"  {key}:")
                    if net_params.get('virtio'):
                        console.print(f"    MAC: {net_params['virtio']}")
                    elif net_params.get('e1000'):
                        console.print(f"    MAC: {net_params['e1000']}")
                    if net_params.get('bridge'):
                        console.print(f"    Bridge: {net_params['bridge']}")
                    if net_params.get('firewall'):
                        firewall_status = 'Enabled' if net_params['firewall'] == '1' else 'Disabled'
                        console.print(f"    Firewall: {firewall_status}")
                    nic_params.append(net_params)

                    if 'nics' in status and key.replace('net', 'tap') + 'i0' in status['nics']:
                        nic_name = key.replace('net', 'tap') + 'i0'
                        nic_stats = status['nics'][nic_name]
                        traffic_in = nic_stats.get('netin', 0) / (1024**2)
                        traffic_out = nic_stats.get('netout', 0) / (1024**2)
                        console.print(f"    Traffic In: {traffic_in:.2f} MB")
                        console.print(f"    Traffic Out: {traffic_out:.2f} MB")
            if nic_params:
                bridges = [p.get('bridge') for p in nic_params if p.get('bridge')]
                unique_br = sorted(set(bridges))
                fw_on = any(p.get('firewall') == '1' for p in nic_params)
                br_str = unique_br[0] if len(unique_br) == 1 else ','.join(unique_br)
                fw_str = 'on' if fw_on else 'off'
                console.print(f"  NICs: {len(nic_params)} (bridge {br_str if br_str else '-'}, firewall {fw_str})")

        # Firmware / Secure Boot / TPM / Console hints
        bios = str(config.get('bios', '') or '').lower()
        if bios:
            if bios == 'ovmf':
                console.print("\n[bold]Firmware:[/bold] OVMF (UEFI)")
            else:
                console.print(f"\n[bold]Firmware:[/bold] {bios}")
        efid = str(config.get('efidisk0', '') or '')
        if efid and 'pre-enrolled-keys=1' in efid:
            console.print("[bold]Secure Boot keys:[/bold] pre-enrolled")
        tpm = str(config.get('tpmstate0', '') or '')
        if tpm:
            tver = None
            for part in tpm.split(','):
                if part.startswith('version='):
                    tver = part.split('=', 1)[1]
                    break
            console.print(f"[bold]TPM:[/bold] {tver}" if tver else "[bold]TPM:[/bold] present")
        if bool(status.get('spice')):
            console.print("[bold]Console:[/bold] SPICE")

        if bool(status.get('agent')):
            console.print("\n[dim]Guest info available via QEMU Guest Agent (--with-osinfo).[/dim]")

    def start_vm(self, args):
        vmid = self._resolve_vm_identifier(args)
        self._maybe_confirm(args, f"Start VM {vmid}?")
        success, message = self.client.start_vm(
            vmid, args.node, wait=args.wait, timeout=args.timeout
        )
        self._emit_result(success, message)

    def stop_vm(self, args):
        vmid = self._resolve_vm_identifier(args)
        action = "force stop" if args.hard else "gracefully shutdown"
        self._maybe_confirm(args, f"{action} VM {vmid}?")
        success, message = self.client.stop_vm(
            vmid, args.node, hard=args.hard, wait=args.wait, timeout=args.timeout
        )
        self._emit_result(success, message)

    def suspend_vm(self, args):
        vmid = self._resolve_vm_identifier(args)
        self._maybe_confirm(args, f"Suspend VM {vmid}?")
        success, message = self.client.suspend_vm(vmid, args.node, wait=args.wait)
        self._emit_result(success, message)

    def resume_vm(self, args):
        vmid = self._resolve_vm_identifier(args)
        success, message = self.client.resume_vm(vmid, args.node, wait=args.wait)
        self._emit_result(success, message)

    def _resolve_vm_identifier(self, args):
        if hasattr(args, 'name') and args.name:
            vms = self.client.get_vm_by_name(args.name)
            if not vms:
                err_console.print(f"[red]No VM found with name '{args.name}'[/red]")
                sys.exit(ExitCode.NOT_FOUND.value)
            elif len(vms) > 1:
                err_console.print(
                    f"[yellow]Multiple VMs found with name '{args.name}'. Please use VMID.[/yellow]"
                )
                sys.exit(ExitCode.INVALID_INPUT.value)
            return vms[0]['vmid']
        return args.vmid
