"""Shared domain models — serialized to the frontend over WebSocket/REST."""

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
TrustType = Literal["smb", "ldap", "kerberos", "subnet", "rdp", "winrm", "reachable"]


class ServicePort(BaseModel):
    port: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""
    product: str = ""
    state: str = "open"
    cpe: str = ""


class Vuln(BaseModel):
    cve_id: str
    severity: Severity = "medium"
    cvss: float = 0.0
    description: str = ""


class HostNode(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_family: Optional[str] = None
    os_accuracy: Optional[int] = None
    ports: list[ServicePort] = Field(default_factory=list)
    vulns: list[Vuln] = Field(default_factory=list)
    criticality_score: float = 0.0
    is_crown_jewel: bool = False


class TrustEdge(BaseModel):
    source_ip: str
    target_ip: str
    trust_type: TrustType
    weight: float
    evidence: dict = Field(default_factory=dict)


class AttackPathHop(BaseModel):
    hop_index: int
    ip: str


class AttackPath(BaseModel):
    source_ip: str
    target_ip: str
    hops: list[AttackPathHop]
    total_weight: float
    risk_score: float


class AlertItem(BaseModel):
    alert_type: Literal[
        "new_host",
        "new_port",
        "port_closed",
        "version_change",
        "vuln_added",
        "vuln_gone",
        "host_gone",
    ]
    severity: Severity
    description: str
    details: dict = Field(default_factory=dict)


class GraphSnapshot(BaseModel):
    """Complete graph state pushed to clients after each scan."""

    snapshot_id: str
    hosts: list[HostNode]
    edges: list[TrustEdge]
    attack_paths: list[AttackPath]
    alerts: list[AlertItem]


class ScanProgressEvent(BaseModel):
    type: Literal["scan_progress"] = "scan_progress"
    stage: str
    message: str
    progress: float = Field(ge=0.0, le=1.0)


class ScanCompleteEvent(BaseModel):
    type: Literal["graph_update"] = "graph_update"
    snapshot: GraphSnapshot
