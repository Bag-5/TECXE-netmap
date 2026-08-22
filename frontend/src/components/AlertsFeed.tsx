import { severityColor } from '../hooks/useGraphSimulation'
import type { AlertItem } from '../types/graph'

export default function AlertsFeed({ alerts }: { alerts: AlertItem[] }) {
  if (alerts.length === 0) return null

  return (
    <div className="panel alerts-panel">
      <div className="panel-header">
        <h2>Alerts ({alerts.length})</h2>
      </div>
      <ul className="alerts-list">
        {alerts.slice(0, 30).map((a, i) => (
          <li key={i} className={`alert alert-${a.severity}`}>
            <span className="sev-badge" style={{ background: severityColor(a.severity) }}>
              {a.severity}
            </span>
            <span className="alert-text">{a.description}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
