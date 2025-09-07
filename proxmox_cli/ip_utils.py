"""
IP utility helpers for parsing QEMU Guest Agent results and selecting
primary/ordered guest IPs.
"""

from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Tuple


def normalize_qga_interface_payload(resp: Any) -> List[Dict[str, Any]]:
    """Normalize QGA 'network-get-interfaces' response to a list of interfaces.

    Accepts shapes like:
    - {'result': [...]} (common)
    - {'interfaces': [...]} (some formats)
    - {'return': [...]} (older/libvirt-like)
    - [...] (already a list)
    Returns [] on unrecognized formats.
    """
    payload = resp
    if isinstance(resp, dict) and 'result' in resp:
        payload = resp.get('result')

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if 'interfaces' in payload and isinstance(payload['interfaces'], list):
            return payload['interfaces']
        if 'return' in payload and isinstance(payload['return'], list):
            return payload['return']
    return []


def select_ordered_ips(interfaces: List[Dict[str, Any]]) -> List[str]:
    """Select and order IPs from QGA interface data using heuristics.

    Heuristics:
    - Filter loopback, link-local, and APIPA ranges
    - Prefer primary NIC name prefixes (eth/en*/eno/em/bond/br0)
    - De-prioritize container/VPN/bridge interfaces (docker, veth, cni, flannel, kube, virbr, tailscale, zt, tun, tap, wg, br-)
    - Prefer IPv4 before IPv6
    - Prefer RFC1918 ranges 192.168/16, then 10/8, then 172.16/12, then CGNAT 100.64/10, then others
    - For IPv6, prefer ULA (fc00::/7) before global
    Returns an ordered list of IP strings.
    """
    skip_iface_prefixes = (
        'lo', 'docker', 'veth', 'cni', 'flannel', 'kube', 'virbr', 'tailscale',
        'zt', 'tun', 'tap', 'wg', 'br-'
    )
    preferred_iface_prefixes = (
        'eth', 'en', 'ens', 'enp', 'eno', 'em', 'bond', 'br0'
    )

    private_192 = ip_network('192.168.0.0/16')
    private_10 = ip_network('10.0.0.0/8')
    private_172 = ip_network('172.16.0.0/12')
    cgnat_100 = ip_network('100.64.0.0/10')

    candidates: List[Tuple[str, str]] = []  # (ip, ifname)
    seen = set()

    for iface in interfaces:
        ifname = str(iface.get('name', '') or '')
        addrs = iface.get('ip-addresses') or iface.get('addresses') or []
        for addr in addrs:
            ip_str = addr.get('ip-address') or addr.get('address')
            if not ip_str:
                continue
            # Filter loopback and link-local
            if ip_str.startswith('127.') or ip_str == '::1':
                continue
            if ip_str.startswith('169.254.'):
                continue
            if ip_str.lower().startswith('fe80:'):
                continue
            key = (ip_str, ifname)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((ip_str, ifname))

    if not candidates:
        return []

    def iface_priority(name: str) -> int:
        if not name:
            return 2
        if name.startswith(skip_iface_prefixes):
            return 5
        if name.startswith(preferred_iface_prefixes):
            return 0
        if name.startswith('br'):
            return 2
        return 3

    def range_priority(ip_str: str) -> int:
        try:
            ipa = ip_address(ip_str)
        except ValueError:
            return 9
        is_v6 = ipa.version == 6
        vfam = 0 if not is_v6 else 1  # IPv4 first
        if not is_v6:
            if ipa in private_192:
                rpri = 0
            elif ipa in private_10:
                rpri = 1
            elif ipa in private_172:
                rpri = 2
            elif ipa in cgnat_100:
                rpri = 3
            else:
                rpri = 4
        else:
            # IPv6: prefer ULA (fc00::/7) over global
            if ip_str.lower().startswith(('fc', 'fd')):
                rpri = 0
            else:
                rpri = 1
        return vfam * 10 + rpri

    scored: List[Tuple[int, int, str]] = []  # (iface_pri, range_pri, ip)
    for ip_str, ifname in candidates:
        ip_pri = range_priority(ip_str)
        if_pri = iface_priority(ifname)
        scored.append((if_pri, ip_pri, ip_str))

    scored.sort(key=lambda t: (t[0], t[1], t[2]))
    ordered = [ip for iface_pri, _, ip in scored if iface_pri < 5]
    if not ordered:
        # Fallback: IPv4/private ordering only
        ordered = [ip for _, __, ip in sorted(scored, key=lambda t: (t[1], t[2]))]
    return ordered

