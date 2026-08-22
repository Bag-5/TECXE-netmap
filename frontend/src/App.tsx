import { useCallback, useEffect, useState } from 'react'
import NetworkCanvas from './components/NetworkCanvas'
import NodeDetailPanel from './components/NodeDetailPanel'
import ScanControls from './components/ScanControls'
import ChatPanel from './components/ChatPanel'
import AlertsFeed from './components/AlertsFeed'
import Legend from './components/Legend'
import ThemeToggle from './components/ThemeToggle'
import { useGraphSimulation } from './hooks/useGraphSimulation'
import { api, useWebSocket } from './hooks/useWebSocket'
import type { GraphSnapshot, SimNode, WsEvent } from './types/graph'

interface BackendConfig {
  target_cidr: string
  scan_profile: string
  profiles: { name: string; description: string; requires_admin: boolean }[]
  ai_enabled: boolean
}

export default function App() {
  const [snapshot, setSnapshot] = useState<GraphSnapshot | null>(null)
  const [config, setConfig] = useState<BackendConfig | null>(null)
  const [selected, setSelected] = useState<SimNode | null>(null)
  const [progressMessage, setProgressMessage] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)

  const graph = useGraphSimulation(snapshot)

  const onEvent = useCallback((e: WsEvent) => {
    switch (e.type) {
      case 'scan_progress':
        setScanning(true)
        setProgressMessage(e.message)
        break
      case 'graph_update':
        setSnapshot(e.snapshot)
        setSelected(null)
        break
      case 'scan_done':
        setScanning(false)
        setProgressMessage(null)
        break
      case 'scan_error':
        setScanning(false)
        setProgressMessage(`⚠️ ${e.error}`)
        break
    }
  }, [])

  const { connected } = useWebSocket(onEvent)

  useEffect(() => {
    api<BackendConfig>('/api/config').then(setConfig).catch(() => {})
    api<{ snapshot: GraphSnapshot | null }>('/api/graph/latest')
      .then((r) => r.snapshot && setSnapshot(r.snapshot))
      .catch(() => {})
  }, [])

  return (
    <div className="app">
      <header className="topbar">
        <h1>
          TECXE<span className="accent">·</span>netmap <span className="tagline">AI Network Twin</span>
        </h1>
        <div className="topbar-right">
          <span className={`conn ${connected ? 'ok' : 'down'}`}>
            {connected ? '● backend online' : '○ backend offline'}
          </span>
          <ThemeToggle />
        </div>
      </header>

      <main className="stage">
        <NetworkCanvas graph={graph} paths={snapshot?.attack_paths ?? []} selected={selected} onSelect={setSelected} />

        <aside className="left-rail">
          {config && (
            <ScanControls
              defaultCidr={config.target_cidr}
              profiles={config.profiles}
              scanning={scanning}
              progressMessage={progressMessage}
            />
          )}
          <Legend />
        </aside>

        {selected && (
          <NodeDetailPanel host={selected} onClose={() => setSelected(null)} />
        )}

        {snapshot && snapshot.alerts.length > 0 && !selected && (
          <AlertsFeed alerts={snapshot.alerts} />
        )}

        <ChatPanel aiEnabled={config?.ai_enabled ?? false} />

        <footer className="stats">
          {snapshot ? (
            <>
              <span>{snapshot.hosts.length} hosts</span> ·{' '}
              <span>{snapshot.edges.length} trust edges</span> ·{' '}
              <span style={{ color: '#ff2d55' }}>{snapshot.attack_paths.length} attack paths</span>
            </>
          ) : (
            <span className="muted">No scan yet — point it at your LAN and hit Start.</span>
          )}
        </footer>
      </main>
    </div>
  )
}
