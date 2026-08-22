"""NVD API 2.0 client — CPE/version matching with a TTL cache."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from backend.config import settings
from backend.graph.model import Severity, Vuln

logger = logging.getLogger(__name__)

SEVERITY_ORDER: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Rough keyword → CPE product mapping for common services seen in nmap output.
SERVICE_CPE_HINTS = {
    "http": ["apache_http_server", "nginx", "lighttpd", "iis"],
    "https": ["openssl"],
    "ssh": ["openssh"],
    "ftp": ["vsftpd", "proftpd", "filezilla"],
    "smb": ["samba"],
    "microsoft-ds": ["windows"],
    "rdp": ["windows"],
    "mysql": ["mysql"],
    "postgres": ["postgresql"],
    "domain": ["bind"],
    "smtp": ["postfix", "exim"],
    "telnet": ["linux_kernel"],
    "vnc": ["tightvnc", "realvnc"],
}


@dataclass
class _CacheEntry:
    vulns: list[Vuln]
    expires_at: float


class NVDClient:
    """Queries NVD 2.0 for CVEs by keyword search. Caches per service signature."""

    def __init__(self):
        self._cache: dict[str, _CacheEntry] = {}
        self._semaphore = asyncio.Semaphore(2)

    def _cache_key(self, product: str, version: str) -> str:
        return f"{product.lower()}:{version.lower()}"

    async def lookup_service(
        self, product: str, version: str, limit: int = 10
    ) -> list[Vuln]:
        if not product:
            return []

        key = self._cache_key(product, version)
        entry = self._cache.get(key)
        ttl = settings.NVD_CACHE_TTL_HOURS * 3600
        if entry and entry.expires_at > time.monotonic():
            return entry.vulns

        query = f"{product} {version}".strip()
        params: dict[str, str | int] = {
            "keywordSearch": query,
            "resultsPerPage": limit,
        }
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            async with self._semaphore:  # respect rate limits (0.6 rps w/o key)
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(settings.NVD_BASE_URL, params=params, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
        except Exception as exc:
            logger.warning("NVD lookup failed for %r: %s", query, exc)
            self._cache[key] = _CacheEntry(vulns=[], expires_at=time.monotonic() + 600)
            return []

        vulns = self._parse_nvd_response(data)
        self._cache[key] = _CacheEntry(vulns=vulns, expires_at=time.monotonic() + ttl)
        return vulns

    @staticmethod
    def _parse_nvd_response(data: dict) -> list[Vuln]:
        vulns: list[Vuln] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity: Severity = "medium"

            v31 = metrics.get("cvssMetricV31", [])
            v30 = metrics.get("cvssMetricV30", [])
            v2 = metrics.get("cvssMetricV2", [])
            metric_list = v31 or v30 or v2
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                raw_severity = (
                    cvss_data.get("baseSeverity")
                    or metric_list[0].get("baseSeverity")
                    or ""
                )
                severity = SEVERITY_ORDER.get(raw_severity.upper(), "medium")

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            if cve_id:
                vulns.append(
                    Vuln(cve_id=cve_id, severity=severity, cvss=cvss_score, description=desc[:300])
                )
        return vulns


async def enrich_hosts_with_vulns(hosts) -> None:
    """Attach NVD CVEs to each host based on open service product/version."""
    client = NVDClient()
    tasks = []
    for host in hosts:
        for port in host.ports:
            product_hint = port.product or port.service
            if not product_hint:
                continue
            tasks.append(_enrich_port(client, host, port))
    if tasks:
        await asyncio.gather(*tasks)


async def _enrich_port(client: NVDClient, host, port) -> None:
    found = await client.lookup_service(port.product or port.service, port.version)
    for vuln in found:
        # de-dupe across ports on the same host
        if not any(v.cve_id == vuln.cve_id for v in host.vulns):
            host.vulns.append(vuln)
    if found:
        max_cvss = max(v.cvss for v in found)
        host.criticality_score = min(1.0, max(host.criticality_score, max_cvss / 10.0))
