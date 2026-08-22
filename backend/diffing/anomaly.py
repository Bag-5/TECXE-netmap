"""Snapshot diffing — detect what changed between scans."""

from __future__ import annotations

import logging

from backend.graph.model import AlertItem, HostNode

logger = logging.getLogger(__name__)


def _ports_signature(host: HostNode) -> dict[int, str]:
    return {p.port: p.version or "" for p in host.ports}


def _vuln_ids(host: HostNode) -> set[str]:
    return {v.cve_id for v in host.vulns}


def diff_snapshots(prev_hosts: list[HostNode], curr_hosts: list[HostNode]) -> list[AlertItem]:
    alerts: list[AlertItem] = []
    prev_map = {h.ip: h for h in prev_hosts}
    curr_map = {h.ip: h for h in curr_hosts}

    # New hosts
    for ip, host in curr_map.items():
        if ip not in prev_map:
            alerts.append(
                AlertItem(
                    alert_type="new_host",
                    severity="medium",
                    description=f"New host appeared: {ip}"
                    + (f" ({host.hostname})" if host.hostname else ""),
                    details={"ip": ip, "os": host.os_name},
                )
            )

    # Vanished hosts
    for ip, host in prev_map.items():
        if ip not in curr_map:
            alerts.append(
                AlertItem(
                    alert_type="host_gone",
                    severity="low",
                    description=f"Host disappeared: {ip}",
                    details={"ip": ip},
                )
            )

    # Per-host diffs
    for ip, curr in curr_map.items():
        prev = prev_map.get(ip)
        if prev is None:
            continue

        prev_ports = _ports_signature(prev)
        curr_ports = _ports_signature(curr)

        for port, version in curr_ports.items():
            if port not in prev_ports:
                service = next((p.service for p in curr.ports if p.port == port), str(port))
                alerts.append(
                    AlertItem(
                        alert_type="new_port",
                        severity="high" if port in (22, 3389, 445, 23) else "medium",
                        description=f"{ip}: new open port {port} ({service})",
                        details={"ip": ip, "port": port, "version": version},
                    )
                )
            elif prev_ports[port] != version:
                alerts.append(
                    AlertItem(
                        alert_type="version_change",
                        severity="info",
                        description=f"{ip}: port {port} version changed "
                        f"'{prev_ports[port]}' → '{version}'",
                        details={"ip": ip, "port": port},
                    )
                )

        for port in set(prev_ports) - set(curr_ports):
            alerts.append(
                AlertItem(
                    alert_type="port_closed",
                    severity="info",
                    description=f"{ip}: port {port} closed since last scan",
                    details={"ip": ip, "port": port},
                )
            )

        prev_vulns = _vuln_ids(prev)
        curr_vulns = _vuln_ids(curr)
        for cve in curr_vulns - prev_vulns:
            vuln = next((v for v in curr.vulns if v.cve_id == cve), None)
            severity = vuln.severity if vuln else "medium"
            alerts.append(
                AlertItem(
                    alert_type="vuln_added",
                    severity=severity,
                    description=f"{ip}: new vulnerability {cve}",
                    details={"ip": ip, "cve": cve, "cvss": vuln.cvss if vuln else 0},
                )
            )
        for cve in prev_vulns - curr_vulns:
            alerts.append(
                AlertItem(
                    alert_type="vuln_gone",
                    severity="low",
                    description=f"{ip}: vulnerability no longer detected: {cve}",
                    details={"ip": ip, "cve": cve},
                )
            )

    return alerts
