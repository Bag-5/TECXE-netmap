// Shared graph types — mirror backend Pydantic models.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type TrustType =
  | 'smb'
  | 'ldap'
  | 'kerberos'
  | 'subnet'
  | 'rdp'
  | 'winrm'
  | 'reachable'

export interface ServicePort {
  port: number
  proto: string
  service: string
  version: string
  product: string
  state: string
  cpe: string
}

export interface Vuln {
  cve_id: string
  severity: Severity
  cvss: number
  description: string
}

export interface HostNode {
  ip: string
  mac?: string | null
  hostname?: string | null
  os_name?: string | null
  os_family?: string | null
  os_accuracy?: number | null
  ports: ServicePort[]
  vulns: Vuln[]
  criticality_score: number
  is_crown_jewel: boolean
}

export interface TrustEdge {
  source_ip: string
  target_ip: string
  trust_type: TrustType
  weight: number
  evidence: Record<string, unknown>
}

export interface AttackPathHop {
  hop_index: number
  ip: string
}

export interface AttackPath {
  source_ip: string
  target_ip: string
  hops: AttackPathHop[]
  total_weight: number
  risk_score: number
}

export interface AlertItem {
  alert_type:
    | 'new_host'
    | 'new_port'
    | 'port_closed'
    | 'version_change'
    | 'vuln_added'
    | 'vuln_gone'
    | 'host_gone'
  severity: Severity
  description: string
  details: Record<string, unknown>
}

export interface GraphSnapshot {
  snapshot_id: string
  hosts: HostNode[]
  edges: TrustEdge[]
  attack_paths: AttackPath[]
  alerts: AlertItem[]
}

export type WsEvent =
  | { type: 'scan_progress'; message: string }
  | { type: 'graph_update'; snapshot: GraphSnapshot }
  | { type: 'scan_done'; snapshot_id: string }
  | { type: 'scan_error'; error: string }

// Simulated node with force-layout position state
export interface SimNode extends HostNode {
  id: string
  x?: number
  y?: number
  z?: number
  vx?: number
  vy?: number
  vz?: number
}

export interface SimLink {
  source: string | SimNode
  target: string | SimNode
  trustType: TrustType
  weight: number
}
