import { osColor, trustColor } from '../hooks/useGraphSimulation'

const OS_FAMILIES = ['Windows', 'Linux', 'Apple', 'Cisco', 'BSD', 'Android']
const TRUST_TYPES = [
  { t: 'kerberos', label: 'Kerberos' },
  { t: 'winrm', label: 'WinRM' },
  { t: 'ldap', label: 'LDAP' },
  { t: 'smb', label: 'SMB' },
  { t: 'rdp', label: 'RDP' },
  { t: 'subnet', label: 'Subnet' },
]

export default function Legend() {
  return (
    <div className="panel legend">
      <div className="panel-header"><h2>Legend</h2></div>

      <p className="legend-title">OS family</p>
      <div className="legend-grid">
        {OS_FAMILIES.map((f) => (
          <span key={f} className="legend-item">
            <i style={{ background: osColor(f) }} /> {f}
          </span>
        ))}
      </div>

      <p className="legend-title">Trust edges</p>
      <div className="legend-grid">
        {TRUST_TYPES.map(({ t, label }) => (
          <span key={t} className="legend-item">
            <i className="line-swatch" style={{ background: trustColor(t) }} /> {label}
          </span>
        ))}
      </div>

      <p className="legend-title">Special</p>
      <div className="legend-grid">
        <span className="legend-item">
          <i className="line-swatch attack" style={{ background: '#ff2d55' }} /> Attack path
        </span>
        <span className="legend-item">👑 Crown jewel</span>
      </div>
    </div>
  )
}
