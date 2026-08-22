import { useState } from 'react'
import { api } from '../hooks/useWebSocket'
import { severityColor } from '../hooks/useGraphSimulation'
import type { HostNode, ServicePort, Vuln } from '../types/graph'

interface Props {
  host: HostNode
  onClose: () => void
}

export default function NodeDetailPanel({ host, onClose }: Props) {
  const [toggling, setToggling] = useState(false)

  async function toggleCrownJewel() {
    setToggling(true)
    try {
      // fetch current list is overkill for MVP: send union of this host only.
      // The backend clears all then sets the provided ones — so we send this IP
      // plus nothing else; acceptable for single-jewel tagging UX in v1.
      const next = !host.is_crown_jewel
      await api('/api/crown-jewels', {
        method: 'POST',
        body: JSON.stringify({ ips: next ? [host.ip] : [] }),
      })
      host.is_crown_jewel = next
    } finally {
      setToggling(false)
    }
  }

  return (
    <div className="panel detail-panel">
      <div className="panel-header">
        <h2>{host.hostname ?? host.ip}</h2>
        <button className="btn-icon" onClick={onClose} aria-label="Close">✕</button>
      </div>

      <div className="detail-grid">
        <span className="muted">IP</span><span>{host.ip}</span>
        {host.mac && (<><span className="muted">MAC</span><span>{host.mac}</span></>)}
        {host.os_name && (
          <>
            <span className="muted">OS</span>
            <span>{host.os_name}{host.os_accuracy != null ? ` (${host.os_accuracy}%)` : ''}</span>
          </>
        )}
        <span className="muted">Criticality</span>
        <span>{(host.criticality_score * 100).toFixed(0)}%</span>
        <span className="muted">Crown Jewel</span>
        <span>{host.is_crown_jewel ? '👑 Yes' : 'No'}</span>
      </div>

      <button className="btn" onClick={toggleCrownJewel} disabled={toggling}>
        {host.is_crown_jewel ? 'Remove Crown Jewel' : 'Mark as Crown Jewel'}
      </button>

      <h3>Open Ports ({host.ports.length})</h3>
      <table className="ports-table">
        <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>
          {host.ports.map((p: ServicePort) => (
            <tr key={`${p.port}/${p.proto}`}>
              <td>{p.port}/{p.proto}</td>
              <td>{p.service}</td>
              <td>{[p.product, p.version].filter(Boolean).join(' ') || '—'}</td>
            </tr>
          ))}
          {host.ports.length === 0 && (
            <tr><td colSpan={3} className="muted">No open ports recorded.</td></tr>
          )}
        </tbody>
      </table>

      <h3>Vulnerabilities ({host.vulns.length})</h3>
      <ul className="vuln-list">
        {host.vulns.map((v: Vuln) => (
          <li key={v.cve_id}>
            <span className="sev-badge" style={{ background: severityColor(v.severity) }}>
              {v.severity}
            </span>
            <strong>{v.cve_id}</strong> <span className="muted">CVSS {v.cvss.toFixed(1)}</span>
            {v.description && <p className="muted small clamp">{v.description}</p>}
          </li>
        ))}
        {host.vulns.length === 0 && <li className="muted">No CVEs matched.</li>}
      </ul>
    </div>
  )
}
