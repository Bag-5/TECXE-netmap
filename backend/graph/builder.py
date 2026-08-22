"""networkx graph construction + serialization for the frontend."""

from __future__ import annotations

import networkx as nx

from backend.graph.model import AttackPath, AttackPathHop, HostNode, TrustEdge


def build_graph(hosts: list[HostNode], edges: list[TrustEdge]) -> nx.DiGraph:
    g = nx.DiGraph()
    for host in hosts:
        g.add_node(host.ip, data=host)
    for edge in edges:
        if edge.source_ip in g and edge.target_ip in g:
            g.add_edge(
                edge.source_ip,
                edge.target_ip,
                trust_type=edge.trust_type,
                weight=edge.weight,
                evidence=edge.evidence,
            )
    return g


def compute_attack_paths(
    graph: nx.DiGraph, crown_jewel_ips: list[str], max_paths_per_jewel: int = 3
) -> list[AttackPath]:
    """From every host with critical/high vulns, find cheapest paths to crown jewels."""
    paths: list[AttackPath] = []

    compromised_candidates = []
    for node_id, attrs in graph.nodes(data=True):
        host: HostNode | None = attrs.get("data")
        if host is None:
            continue
        risky = any(v.severity in ("critical", "high") for v in host.vulns)
        if risky:
            compromised_candidates.append(node_id)

    for jewel in crown_jewel_ips:
        if jewel not in graph:
            continue
        collected: list[tuple[float, list[str]]] = []
        for source in compromised_candidates:
            if source == jewel:
                continue
            try:
                cost, path = nx.single_source_dijkstra(
                    graph, source, target=jewel, weight="weight"
                )
                assert isinstance(cost, float) and isinstance(path, list)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            collected.append((cost, path))

        collected.sort(key=lambda t: t[0])
        for cost, path in collected[:max_paths_per_jewel]:
            risk = min(1.0, cost / 3.0)  # fewer hops → higher risk
            paths.append(
                AttackPath(
                    source_ip=path[0],
                    target_ip=jewel,
                    hops=[AttackPathHop(hop_index=i, ip=ip) for i, ip in enumerate(path)],
                    total_weight=round(cost, 4),
                    risk_score=round(risk, 4),
                )
            )
    return paths


def graph_summary_for_ai(hosts: list[HostNode], edges: list[TrustEdge], paths: list[AttackPath]) -> dict:
    """Compact JSON-serializable context for the AI copilot (token-bounded)."""
    return {
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os_name,
                "open_ports": [
                    {"port": p.port, "service": p.service, "version": p.version} for p in h.ports
                ],
                "vulns": [
                    {"cve": v.cve_id, "severity": v.severity, "cvss": v.cvss} for v in h.vulns
                ],
                "crown_jewel": h.is_crown_jewel,
                "criticality": round(h.criticality_score, 2),
            }
            for h in hosts
        ],
        "trust_edges": [
            {"from": e.source_ip, "to": e.target_ip, "type": e.trust_type, "weight": e.weight}
            for e in edges
        ],
        "attack_paths": [
            {"from": p.source_ip, "to": p.target_ip, "hops": [h.ip for h in p.hops], "risk": p.risk_score}
            for p in paths
        ],
    }
