"""Trust relationship inference from scan evidence."""

from __future__ import annotations

import ipaddress
import logging

from backend.graph.model import HostNode, TrustEdge, TrustType

logger = logging.getLogger(__name__)

# Port → (trust_type, weight)
TRUST_PORT_MAP: dict[int, tuple[TrustType, float]] = {
    445: ("smb", 0.7),
    389: ("ldap", 0.8),
    636: ("ldap", 0.8),
    88: ("kerberos", 0.9),
    3389: ("rdp", 0.6),
    5985: ("winrm", 0.8),
    5986: ("winrm", 0.8),
}


def _same_subnet(a: str, b: str, prefix: int = 24) -> bool:
    try:
        net_a = ipaddress.ip_network(f"{a}/{prefix}", strict=False)
        net_b = ipaddress.ip_network(f"{b}/{prefix}", strict=False)
        return net_a == net_b
    except ValueError:
        return False


def infer_trust_edges(hosts: list[HostNode]) -> list[TrustEdge]:
    """Derive trust edges:
    1. Service-based trust (SMB/LDAP/Kerberos/RDP/WinRM ports open on target)
    2. Subnet adjacency (same /24 → weak 'reachable' edge)
    """
    edges: list[TrustEdge] = []
    seen: set[tuple[str, str, str]] = set()

    for source in hosts:
        for target in hosts:
            if source.ip == target.ip:
                continue
            for port in target.ports:
                mapping = TRUST_PORT_MAP.get(port.port)
                if not mapping:
                    continue
                trust_type, weight = mapping
                key = (source.ip, target.ip, trust_type)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    TrustEdge(
                        source_ip=source.ip,
                        target_ip=target.ip,
                        trust_type=trust_type,
                        weight=weight,
                        evidence={
                            "port": port.port,
                            "service": port.service,
                            "product": port.product,
                        },
                    )
                )

    # Subnet adjacency — only if no stronger edge exists in either direction
    strong_pairs = {(e.source_ip, e.target_ip) for e in edges}
    for i, a in enumerate(hosts):
        for b in hosts[i + 1 :]:
            if _same_subnet(a.ip, b.ip):
                if (a.ip, b.ip) not in strong_pairs and (b.ip, a.ip) not in strong_pairs:
                    edges.append(
                        TrustEdge(
                            source_ip=a.ip,
                            target_ip=b.ip,
                            trust_type="subnet",
                            weight=0.3,
                            evidence={"reason": "same /24 subnet"},
                        )
                    )
    return edges
