import { useState } from 'react'
import { api } from '../hooks/useWebSocket'

interface ProfileInfo {
  name: string
  description: string
  requires_admin: boolean
}

interface Props {
  defaultCidr: string
  profiles: ProfileInfo[]
  scanning: boolean
  progressMessage: string | null
}

export default function ScanControls({ defaultCidr, profiles, scanning, progressMessage }: Props) {
  const [cidr, setCidr] = useState(defaultCidr)
  const [profile, setProfile] = useState(profiles[0]?.name ?? 'quick')
  const [error, setError] = useState<string | null>(null)

  async function startScan() {
    setError(null)
    try {
      await api('/api/scan/background', {
        method: 'POST',
        body: JSON.stringify({ cidr: cidr || null, profile }),
      })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const activeProfile = profiles.find((p) => p.name === profile)

  return (
    <div className="panel scan-controls">
      <div className="panel-header">
        <h2>Scan</h2>
        <span className={`ws-dot ${scanning ? 'busy' : ''}`} title={scanning ? 'Scanning' : 'Idle'} />
      </div>

      <label className="field">
        <span>Target CIDR</span>
        <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" />
      </label>

      <label className="field">
        <span>Profile</span>
        <select value={profile} onChange={(e) => setProfile(e.target.value)}>
          {profiles.map((p) => (
            <option key={p.name} value={p.name}>{p.name}</option>
          ))}
        </select>
      </label>

      {activeProfile && <p className="muted small">{activeProfile.description}</p>}

      <button className="btn btn-primary" onClick={startScan} disabled={scanning}>
        {scanning ? 'Scanning…' : 'Start Scan'}
      </button>

      {progressMessage && <p className="progress-msg">{progressMessage}</p>}
      {error && <p className="error-msg">{error}</p>}
    </div>
  )
}
