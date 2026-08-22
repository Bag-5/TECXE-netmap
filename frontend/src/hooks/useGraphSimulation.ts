import { useEffect, useMemo, useRef, useState } from 'react'
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  forceZ,
  type Simulation,
  type SimulationNodeDatum,
} from 'd3-force-3d'
import type { GraphSnapshot, Severity, SimLink, SimNode } from '../types/graph'

interface SimNodeDatum extends SimNode, SimulationNodeDatum {}

export interface GraphState {
  nodes: SimNode[]
  links: SimLink[]
}

const EMPTY: GraphState = { nodes: [], links: [] }

/**
 * Maintains a d3-force-3d simulation fed by graph snapshots.
 * Positions mutate in-place on the node objects; the R3F frame loop reads them.
 */
export function useGraphSimulation(snapshot: GraphSnapshot | null): GraphState {
  const [state, setState] = useState<GraphState>(EMPTY)
  const simRef = useRef<Simulation<SimNodeDatum> | null>(null)
  const nodesRef = useRef<Map<string, SimNodeDatum>>(new Map())

  // Rebuild topology when snapshot changes
  useEffect(() => {
    if (!snapshot) return

    const nodes: SimNodeDatum[] = snapshot.hosts.map((h) => {
      const existing = nodesRef.current.get(h.ip)
      const node: SimNodeDatum = {
        ...h,
        id: h.ip,
        x: existing?.x ?? (Math.random() - 0.5) * 60,
        y: existing?.y ?? (Math.random() - 0.5) * 60,
        z: existing?.z ?? (Math.random() - 0.5) * 60,
      }
      return node
    })

    const links: SimLink[] = snapshot.edges
      .filter((e) => e.source_ip !== e.target_ip)
      .map((e) => ({
        source: e.source_ip,
        target: e.target_ip,
        trustType: e.trust_type,
        weight: e.weight,
      }))

    // Keep identity stable across updates so the simulation doesn't explode
    const nextMap = new Map<string, SimNodeDatum>()
    for (const n of nodes) nextMap.set(n.id, n)
    nodesRef.current = nextMap

    setState({ nodes, links })
  }, [snapshot])

  // Start/refresh simulation whenever topology changes
  useEffect(() => {
    if (state.nodes.length === 0) return

    const sim = forceSimulation<SimNodeDatum>(state.nodes as SimNodeDatum[], 3)
      .numDimensions(3)
      .force('charge', forceManyBody().strength(-120))
      .force(
        'link',
        forceLink<SimNodeDatum, SimLink & SimulationNodeDatum>(state.links as never)
          .id((d) => d.id)
          .distance((l) => 18 + (1 - l.weight) * 30)
          .strength((l) => 0.1 + l.weight * 0.4)
      )
      .force('center', forceCenter())
      .force('x', forceX(0).strength(0.05))
      .force('y', forceY(0).strength(0.05))
      .force('z', forceZ(0).strength(0.05))
      .force('collide', forceCollide(6))
      .alphaDecay(0.02)

    simRef.current = sim
    return () => {
      sim.stop()
      simRef.current = null
    }
  }, [state])

  // Tick positions into React state at ~15fps for smooth-but-cheap re-renders.
  // The Canvas reads live positions via the same node objects each frame.
  useEffect(() => {
    const interval = setInterval(() => {
      if (!simRef.current || simRef.current.alpha() < 0.001) return
      simRef.current.tick()
    }, 66)
    return () => clearInterval(interval)
  }, [])

  return state
}

/** Stable per-IP color derived from OS family. */
export function osColor(osFamily?: string | null): string {
  switch ((osFamily ?? '').toLowerCase()) {
    case 'windows':
      return '#38bdf8'
    case 'linux':
      return '#fbbf24'
    case 'apple':
      return '#e879f9'
    case 'cisco':
      return '#34d399'
    case 'bsd':
      return '#fb7185'
    case 'android':
      return '#a3e635'
    default:
      return '#94a3b8'
  }
}

export function severityColor(sev: string): string {
  switch (sev) {
    case 'critical':
      return '#ef4444'
    case 'high':
      return '#f97316'
    case 'medium':
      return '#eab308'
    case 'low':
      return '#22c55e'
    default:
      return '#64748b'
  }
}

export function trustColor(t: string): string {
  switch (t) {
    case 'kerberos':
      return '#f43f5e'
    case 'winrm':
      return '#fb923c'
    case 'ldap':
      return '#facc15'
    case 'smb':
      return '#4ade80'
    case 'rdp':
      return '#2dd4bf'
    default:
      return '#475569'
  }
}

export function maxSeverity(host: SimNode | null): Severity | null {
  if (!host || host.vulns.length === 0) return null
  const order: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  }
  return host.vulns.reduce<Severity>(
    (worst, v) => (order[v.severity] > order[worst] ? v.severity : worst),
    'info'
  )
}

export function useMemoizedGraph(state: GraphState): GraphState {
  return useMemo(() => state, [state])
}
