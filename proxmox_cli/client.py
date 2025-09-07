"""
Proxmox API client wrapper used by the CLI.
"""

import random
import time
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from rich.console import Console
import sys

from .config import Config, ExitCode
from .task import TaskPoller
from .ip_utils import normalize_qga_interface_payload, select_ordered_ips

console = Console()
err_console = Console(stderr=True)


class ProxmoxClient:
    """Enhanced wrapper class for Proxmox API operations."""

    def __init__(self, config: Config, quiet: bool = False):
        self.config = config
        self.quiet = quiet
        self.proxmox = None
        self.nodes_cache = None
        self.vm_cache: Dict[int, Dict[str, Any]] = {}
        self.ip_cache: Dict[Tuple[str, int], List[str]] = {}
        self.task_poller: Optional[TaskPoller] = None
        self._connect()

    def retry(self, func, attempts: int = 3, base_delay: float = 0.5):
        """Lightweight retry with exponential backoff and jitter for transient GETs.

        Retries non-auth, non-404 ResourceExceptions and generic transient exceptions.
        """
        delay = base_delay
        last_exc = None
        for _ in range(attempts):
            try:
                return func()
            except ResourceException as e:
                sc = getattr(e, "status_code", None)
                if sc in (401, 403, 404):
                    raise
                last_exc = e
            except Exception as e:  # pragma: no cover - defensive
                last_exc = e
            jitter = delay * 0.1
            time.sleep(delay + random.uniform(-jitter, jitter))
            delay = min(delay * 2, 2.0)
        if last_exc:
            raise last_exc
        raise RuntimeError("Retry attempts exhausted")

    def _connect(self):
        """Establish connection to Proxmox server with health check."""
        try:
            # Determine effective SSL verification behavior
            verify_ssl_param: Any
            if not self.config.verify_ssl:
                verify_ssl_param = False
            elif self.config.ca_cert_path:
                verify_ssl_param = self.config.ca_cert_path
            else:
                verify_ssl_param = True

            # Disable SSL warnings only when verification is actually disabled
            if verify_ssl_param is False:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            self.proxmox = ProxmoxAPI(
                self.config.host,
                port=self.config.port,
                user=self.config.user,
                token_name=self.config.token_name,
                token_value=self.config.token_value,
                verify_ssl=verify_ssl_param,
                service="PVE",
                timeout=(self.config.connect_timeout, self.config.read_timeout),
            )

            version = self.proxmox.version.get()

            if verify_ssl_param is False:
                err_console.print("[yellow]⚠ Warning: SSL verification is disabled[/yellow]")

            if not self.quiet:
                console.print(
                    f"[green]✓ Connected to Proxmox {version['version']} "
                    f"at {self.config.host}:{self.config.port}[/green]"
                )

            self.task_poller = TaskPoller(self)

        except Exception as e:
            if "authentication failed" in str(e).lower():
                err_console.print("[red]Authentication failed. Check API token and user.[/red]")
                raise SystemExit(ExitCode.PERMISSION_DENIED.value)
            err_console.print(f"[red]Failed to connect to Proxmox: {e}[/red]")
            raise SystemExit(ExitCode.SERVER_ERROR.value)

    def discover_capabilities(self):
        """Discover and cache cluster capabilities."""
        try:
            self.nodes_cache = self.retry(self.proxmox.nodes.get)
            return {"nodes": [n["node"] for n in self.nodes_cache], "cluster": len(self.nodes_cache) > 1}
        except Exception as e:
            err_console.print(f"[yellow]Warning: Could not discover capabilities: {e}[/yellow]")
            return {"nodes": [], "cluster": False}

    def get_nodes(self):
        if not self.nodes_cache:
            self.nodes_cache = self.retry(self.proxmox.nodes.get)
        return self.nodes_cache

    @staticmethod
    def _tokenize_tags(tag_str: Optional[str]) -> List[str]:
        return [t.strip() for t in (tag_str or "").split(",") if t and t.strip()]

    def _matches_tags(self, vm: Dict[str, Any], tags: Optional[List[str]]) -> bool:
        if not tags:
            return True
        vm_tags = set(self._tokenize_tags(vm.get("tags")))
        return any(tag in vm_tags for tag in tags)

    def find_vm_node(self, vmid: int) -> Optional[str]:
        if vmid in self.vm_cache:
            return self.vm_cache[vmid]["node"]
        try:
            cluster_vms = self.retry(lambda: self.proxmox.cluster.resources.get(type="vm"))
            for vm in cluster_vms:
                if vm.get("type") != "qemu":
                    continue
                if int(vm.get("vmid", -1)) == vmid:
                    self.vm_cache[vmid] = {"node": vm["node"], "data": vm}
                    return vm["node"]
        except Exception:
            pass
        for node in self.get_nodes():
            try:
                vms = self.retry(lambda: self.proxmox.nodes(node["node"]).qemu.get())
                for vm in vms:
                    if vm["vmid"] == vmid:
                        self.vm_cache[vmid] = {"node": node["node"], "data": vm}
                        return node["node"]
            except Exception:
                continue
        return None

    def get_cluster_vms(self, tags: Optional[List[str]] = None) -> list:
        vms = []
        try:
            cluster_vms = self.retry(lambda: self.proxmox.cluster.resources.get(type="vm"))
            for vm in cluster_vms:
                if vm.get("type") != "qemu":
                    continue
                if not self._matches_tags(vm, tags):
                    continue
                if vm.get("status") == "paused":
                    vm["status"] = "suspended"
                if "maxcpu" in vm and "cpus" not in vm:
                    vm["cpus"] = vm["maxcpu"]
                vms.append(vm)
                self.vm_cache[vm["vmid"]] = {"node": vm["node"], "data": vm}
        except Exception as e:
            err_console.print(f"[yellow]Warning: Could not get cluster VMs: {e}[/yellow]")
        return vms

    def get_vms(self, node: Optional[str] = None, tags: Optional[List[str]] = None, check_suspended: bool = True) -> list:
        if check_suspended and not node:
            return self.get_cluster_vms(tags=tags)
        vms = []
        nodes = [node] if node else [n["node"] for n in self.get_nodes()]
        for node_name in nodes:
            try:
                node_vms = self.retry(lambda: self.proxmox.nodes(node_name).qemu.get())
                for vm in node_vms:
                    vm["node"] = node_name
                    if not self._matches_tags(vm, tags):
                        continue
                    vms.append(vm)
                    self.vm_cache[vm["vmid"]] = {"node": node_name, "data": vm}
            except Exception as e:
                err_console.print(f"[yellow]Warning: Could not get VMs from node {node_name}: {e}[/yellow]")
        return vms

    def get_vm_by_name(self, name: str) -> List[Dict[str, Any]]:
        matching_vms: List[Dict[str, Any]] = []
        try:
            cluster_vms = self.get_cluster_vms()
            for vm in cluster_vms:
                if vm.get("type") != "qemu":
                    continue
                if vm.get("name") == name:
                    matching_vms.append(vm)
        except Exception:
            for vm in self.get_vms(check_suspended=False):
                if vm.get("name") == name:
                    matching_vms.append(vm)
        return matching_vms

    def get_vm_status(self, vmid: int, node: Optional[str] = None) -> Dict[str, Any]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                raise ValueError(f"VM {vmid} not found")
        return self.retry(lambda: self.proxmox.nodes(node).qemu(vmid).status.current.get())

    def get_vm_config(self, vmid: int, node: Optional[str] = None) -> Dict[str, Any]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                raise ValueError(f"VM {vmid} not found")
        return self.retry(lambda: self.proxmox.nodes(node).qemu(vmid).config.get())

    def get_vm_guest_ips(self, vmid: int, node: Optional[str] = None) -> List[str]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                return []
        cache_key = (node, vmid)
        cached_ips = self.ip_cache.get(cache_key)
        if cached_ips is not None:
            return list(cached_ips)
        try:
            resp = self.retry(
                lambda: self.proxmox.nodes(node).qemu(vmid).agent.post(command="network-get-interfaces"),
                attempts=1,
                base_delay=0.3,
            )
        except Exception:
            return []
        interfaces = normalize_qga_interface_payload(resp)
        if not interfaces:
            return []
        ordered_ips = select_ordered_ips(interfaces)
        self.ip_cache[cache_key] = ordered_ips
        return ordered_ips

    def get_ips_for_vms(self, vms: List[Dict[str, Any]], max_workers: Optional[int] = None) -> Dict[int, List[str]]:
        """Bulk-fetch guest IPs for a list of VMs concurrently.

        Only attempts lookups for running VMs. Returns a mapping of vmid to ordered IP list.
        """
        ip_map: Dict[int, List[str]] = {}
        running = [vm for vm in vms if vm.get('status') == 'running']
        if not running:
            return ip_map
        try:
            workers = min(max_workers or 8, len(running))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self.get_vm_guest_ips, vm['vmid'], vm.get('node')): vm['vmid']
                    for vm in running
                }
                for fut in as_completed(futures):
                    vmid = futures[fut]
                    try:
                        ip_map[vmid] = fut.result() or []
                    except Exception:
                        ip_map[vmid] = []
        except Exception:
            # Fallback: serial lookups in case of thread pool issues
            for vm in running:
                try:
                    ip_map[vm['vmid']] = self.get_vm_guest_ips(vm['vmid'], vm.get('node'))
                except Exception:
                    ip_map[vm['vmid']] = []
        return ip_map

    def get_vm_runtime(self, vmid: int, node: Optional[str] = None) -> Dict[str, Any]:
        """Return a combined runtime view for a VM: status and config (and resolved node)."""
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                raise ValueError(f"VM {vmid} not found")
        status = self.get_vm_status(vmid, node)
        config = self.get_vm_config(vmid, node)
        return {'vmid': vmid, 'node': node, 'status': status, 'config': config}

    def get_vm_guest_osinfo(self, vmid: int, node: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                return None
        try:
            resp = self.retry(
                lambda: self.proxmox.nodes(node).qemu(vmid).agent.post(command="get-osinfo"),
                attempts=1,
                base_delay=0.3,
            )
        except Exception:
            return None
        payload = resp.get("result") if isinstance(resp, dict) and "result" in resp else resp
        return payload if isinstance(payload, dict) else None

    def get_vm_guest_hostname(self, vmid: int, node: Optional[str] = None) -> Optional[str]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                return None
        try:
            resp = self.retry(
                lambda: self.proxmox.nodes(node).qemu(vmid).agent.post(command="get-host-name"),
                attempts=1,
                base_delay=0.3,
            )
        except Exception:
            return None
        payload = resp.get("result") if isinstance(resp, dict) and "result" in resp else resp
        if isinstance(payload, dict):
            for key in ("host-name", "hostname", "fqdn", "name"):
                if key in payload and payload[key]:
                    return str(payload[key])
        if isinstance(payload, str) and payload:
            return payload
        return None

    def check_vm_lock(self, vmid: int, node: Optional[str] = None, status: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if not node:
            node = self.find_vm_node(vmid)
        try:
            st = status or self.get_vm_status(vmid, node)
            if isinstance(st, dict) and "lock" in st:
                return st.get("lock")
        except Exception:
            pass
        try:
            config = self.get_vm_config(vmid, node)
            return config.get("lock")
        except Exception:
            return None

    def _execute_vm_action(
        self, action: str, vmid: int, node: Optional[str] = None, wait: bool = False, timeout: int = 60, status: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        if not node:
            node = self.find_vm_node(vmid)
            if not node:
                return False, f"VM {vmid} not found"
        lock = self.check_vm_lock(vmid, node, status=status)
        if lock:
            return False, f"VM {vmid} is locked by {lock} operation. Use --wait or try again later."
        try:
            vm_api = self.proxmox.nodes(node).qemu(vmid).status
            if action == "start":
                result = vm_api.start.post()
            elif action == "stop":
                result = vm_api.stop.post()
            elif action == "shutdown":
                result = vm_api.shutdown.post()
            elif action == "suspend":
                result = vm_api.suspend.post()
            elif action == "resume":
                result = vm_api.resume.post()
            elif action == "reset":
                result = vm_api.reset.post()
            elif action == "reboot":
                result = vm_api.reboot.post()
            else:
                return False, f"Unknown action: {action}"
            if wait and isinstance(result, str) and result.startswith("UPID:"):
                success, stat = self.task_poller.wait_for_task(node, result, timeout)
                if success:
                    return True, f"Task completed: {stat}"
                return False, f"Task failed: {stat}"
            return True, f"Task initiated: {result}" if result else "Action completed"
        except ResourceException as e:
            if e.status_code == 404:
                return False, f"VM {vmid} not found on node {node}"
            if e.status_code in [401, 403]:
                return False, f"Permission denied for {action} on VM {vmid}"
            return False, f"API error: {e}"
        except Exception as e:
            return False, f"Failed to {action} VM {vmid}: {e}"

    def start_vm(self, vmid: int, node: Optional[str] = None, wait: bool = False, timeout: int = 60) -> Tuple[bool, str]:
        try:
            status = self.get_vm_status(vmid, node)
            if status["status"] == "running":
                return True, f"VM {vmid} is already running (no-op)"
        except Exception:
            status = None
        return self._execute_vm_action("start", vmid, node, wait, timeout, status=status)

    def stop_vm(self, vmid: int, node: Optional[str] = None, hard: bool = False, wait: bool = False, timeout: int = 60) -> Tuple[bool, str]:
        try:
            status = self.get_vm_status(vmid, node)
            if status["status"] == "stopped":
                return True, f"VM {vmid} is already stopped (no-op)"
        except Exception:
            status = None
        action = "stop" if hard else "shutdown"
        return self._execute_vm_action(action, vmid, node, wait, timeout, status=status)

    def suspend_vm(self, vmid: int, node: Optional[str] = None, wait: bool = False, timeout: int = 60) -> Tuple[bool, str]:
        return self._execute_vm_action("suspend", vmid, node, wait, timeout)

    def resume_vm(self, vmid: int, node: Optional[str] = None, wait: bool = False, timeout: int = 60) -> Tuple[bool, str]:
        return self._execute_vm_action("resume", vmid, node, wait, timeout)
