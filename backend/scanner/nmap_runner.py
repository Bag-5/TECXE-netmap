"""Async nmap orchestration — runs the binary, parses XML into HostNodes."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator

from backend.config import settings
from backend.graph.model import HostNode, ServicePort, Vuln
from backend.scanner.profiles import get_profile

logger = logging.getLogger(__name__)

OS_FAMILY_MAP = {
    "windows": "Windows",
    "linux": "Linux",
    "apple": "Apple",
    "ios": "Apple",
    "macos": "Apple",
    "cisco": "Cisco",
    "freebsd": "BSD",
    "netbsd": "BSD",
    "openbsd": "BSD",
    "embedded": "Embedded",
    "android": "Android",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _classify_os_family(os_name: str | None) -> str | None:
    if not os_name:
        return None
    lowered = os_name.lower()
    for needle, family in OS_FAMILY_MAP.items():
        if needle in lowered:
            return family
    return "Unknown"


def _parse_os(xml_host: ET.Element) -> dict:
    os_match = xml_host.find("./os/osmatch")
    if os_match is None:
        return {"name": None, "accuracy": None}
    return {
        "name": os_match.get("name"),
        "accuracy": int(os_match.get("accuracy", "0")),
    }


def _parse_ports(xml_host: ET.Element) -> list[ServicePort]:
    ports: list[ServicePort] = []
    for port_el in xml_host.findall("./ports/port"):
        state_el = port_el.find("state")
        svc_el = port_el.find("service")
        if state_el is None or state_el.get("state") != "open":
            continue
        ports.append(
            ServicePort(
                port=int(port_el.get("portid", "0")),
                proto=port_el.get("protocol", "tcp"),
                service=(svc_el.get("name") if svc_el is not None else "") or "",
                product=(svc_el.get("product") if svc_el is not None else "") or "",
                version=(svc_el.get("version") if svc_el is not None else "") or "",
                cpe=(svc_el.findtext("cpe") or "") if svc_el is not None else "",
                state=state_el.get("state", "open"),
            )
        )
    return ports


_SCRIPT_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def _parse_script_vulns(xml_host: ET.Element) -> list[Vuln]:
    """Pull CVEs surfaced by nmap NSE scripts as a baseline enrichment layer."""
    seen: set[str] = set()
    vulns: list[Vuln] = []
    for script_el in xml_host.findall(".//script"):
        output = script_el.get("output", "") or ""
        for cve in _SCRIPT_CVE_RE.findall(output):
            cve_id = cve.upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            vulns.append(Vuln(cve_id=cve_id, severity="medium", cvss=0.0))
    return vulns


def parse_xml_to_hosts(xml_text: str) -> list[HostNode]:
    root = ET.fromstring(xml_text)
    hosts: list[HostNode] = []
    for xml_host in root.findall("host"):
        status = xml_host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr_el = xml_host.find('./address[@addrtype="ipv4"]')
        if addr_el is None:
            continue
        mac_el = xml_host.find('./address[@addrtype="mac"]')
        hostname = xml_host.findtext("./hostnames/hostname/@name")

        os_info = _parse_os(xml_host)
        hosts.append(
            HostNode(
                ip=addr_el.get("addr"),
                mac=mac_el.get("addr") if mac_el is not None else None,
                hostname=hostname,
                os_name=os_info["name"],
                os_accuracy=os_info["accuracy"],
                os_family=_classify_os_family(os_info["name"]),
                ports=_parse_ports(xml_host),
                vulns=_parse_script_vulns(xml_host),
            )
        )
    return hosts


class NmapRunner:
    def __init__(self, nmap_path: str | None = None):
        self.nmap_path = nmap_path or settings.NMAP_PATH

    async def scan_stream(
        self, target_cidr: str, profile_name: str = "quick"
    ) -> AsyncIterator[tuple[str, object]]:
        """Yield ('progress', msg) tuples then a final ('result', [HostNode])."""
        profile = get_profile(profile_name)
        network = ipaddress.ip_network(target_cidr, strict=False)
        args = ["-oX", "-", *profile.flags, str(network)]

        logger.info("Starting nmap %s on %s", profile.name, network)

        yield "progress", f"Launching nmap ({profile.name}) against {network}…"

        proc = await asyncio.create_subprocess_exec(
            self.nmap_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        chunks: list[bytes] = []
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            # crude progress signal: XML grows as results stream in
            yield "progress", f"Scanning {network}… ({sum(len(c) for c in chunks)} bytes)"

        stderr = await proc.stderr.read()
        return_code = await proc.wait()
        if return_code != 0:
            raise RuntimeError(f"nmap exited {return_code}: {stderr.decode(errors='replace')}")

        yield "progress", "Parsing results…"
        xml_text = b"".join(chunks).decode(errors="replace")
        hosts = parse_xml_to_hosts(xml_text)
        yield "result", hosts


async def run_scan(target_cidr: str, profile_name: str = "quick") -> list[HostNode]:
    runner = NmapRunner()
    result: list[HostNode] = []
    async for kind, payload in runner.scan_stream(target_cidr, profile_name):
        if kind == "result":
            result = payload
    return result
