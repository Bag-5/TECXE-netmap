import { useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Html, OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import type { ThreeEvent } from '@react-three/fiber'
import {
  maxSeverity,
  osColor,
  severityColor,
  trustColor,
  type GraphState,
} from '../hooks/useGraphSimulation'
import type { AttackPath, SimNode } from '../types/graph'

interface CanvasProps {
  graph: GraphState
  paths: AttackPath[]
  selected: SimNode | null
  onSelect: (node: SimNode | null) => void
}

function hostRadius(host: SimNode): number {
  return 0.8 + Math.min(host.ports.length, 20) * 0.12
}

// --------------------------------------------------------------------------- //
// Node
// --------------------------------------------------------------------------- //

function HostSphere({
  node,
  selected,
  onClick,
}: {
  node: SimNode
  selected: boolean
  onClick: (e: ThreeEvent<MouseEvent>) => void
}) {
  const meshRef = useRef<THREE.Mesh>(null)
  const haloRef = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  const color = osColor(node.os_family)
  const worst = maxSeverity(node)
  const haloColor = severityColor(worst ?? '')
  const radius = hostRadius(node)

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.position.set(node.x ?? 0, node.y ?? 0, node.z ?? 0)
      const scale =
        node.is_crown_jewel || selected || hovered
          ? 1 + Math.sin(clock.elapsedTime * 3) * 0.06
          : 1
      meshRef.current.scale.setScalar(scale)
    }
    if (haloRef.current && meshRef.current) {
      haloRef.current.position.copy(meshRef.current.position)
      const pulse = 1.25 + Math.sin(clock.elapsedTime * 2.5) * 0.18
      haloRef.current.scale.setScalar(pulse)
    }
  })

  return (
    <group>
      <mesh
        ref={meshRef}
        onClick={onClick}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
      >
        <sphereGeometry args={[radius, 24, 24]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={selected ? 0.9 : hovered ? 0.6 : 0.25}
          roughness={0.35}
          metalness={0.4}
        />
        <Html distanceFactor={40} center style={{ pointerEvents: 'none' }}>
          <div className="node-label">
            {node.hostname ?? node.ip}
            {node.is_crown_jewel ? ' 👑' : ''}
            <span className="node-sub">{node.os_name ?? 'unknown OS'}</span>
          </div>
        </Html>
      </mesh>

      {worst && (
        <mesh ref={haloRef}>
          <sphereGeometry args={[radius, 16, 16]} />
          <meshBasicMaterial color={haloColor} transparent opacity={0.22} />
        </mesh>
      )}
    </group>
  )
}

// --------------------------------------------------------------------------- //
// Trust edge
// --------------------------------------------------------------------------- //

function TrustEdgeLine({ a, b, color }: { a: SimNode; b: SimNode; color: string }) {
  const geomRef = useRef<THREE.BufferGeometry>(null)

  useFrame(() => {
    if (!geomRef.current) return
    const pos = geomRef.current.attributes.position as THREE.BufferAttribute | undefined
    if (!pos) return
    pos.setXYZ(0, a.x ?? 0, a.y ?? 0, a.z ?? 0)
    pos.setXYZ(1, b.x ?? 0, b.y ?? 0, b.z ?? 0)
    pos.needsUpdate = true
    geomRef.current.computeBoundingSphere()
  })

  return (
    <line>
      <bufferGeometry ref={geomRef}>
        <bufferAttribute
          attach="attributes-position"
          args={[
            new Float32Array([
              a.x ?? 0, a.y ?? 0, a.z ?? 0,
              b.x ?? 0, b.y ?? 0, b.z ?? 0,
            ]),
            3,
          ]}
        />
      </bufferGeometry>
      <lineBasicMaterial color={color} transparent opacity={0.45} />
    </line>
  )
}

// --------------------------------------------------------------------------- //
// Attack path — smoothed curve following live sim positions
// --------------------------------------------------------------------------- //

const FLOW_SEGMENTS = 80

function AttackPathFlow({
  path,
  lookup,
}: {
  path: AttackPath
  lookup: Map<string, SimNode>
}) {
  const geometry = useMemo(() => {
    const pts = Array.from({ length: FLOW_SEGMENTS + 1 }, () => new THREE.Vector3())
    return new THREE.BufferGeometry().setFromPoints(pts)
  }, [])

  const materialRef = useRef<THREE.LineBasicMaterial>(null)

  useFrame(({ clock }) => {
    const coords: THREE.Vector3[] = []
    for (const hop of path.hops) {
      const n = lookup.get(hop.ip)
      if (n && n.x !== undefined) {
        coords.push(new THREE.Vector3(n.x, n.y ?? 0, n.z ?? 0))
      }
    }
    if (coords.length >= 2) {
      const curve = new THREE.CatmullRomCurve3(coords)
      const sampled = curve.getPoints(FLOW_SEGMENTS)
      const posAttr = geometry.attributes.position as THREE.BufferAttribute
      for (let i = 0; i <= FLOW_SEGMENTS; i++) {
        posAttr.setXYZ(i, sampled[i].x, sampled[i].y, sampled[i].z)
      }
      posAttr.needsUpdate = true
      geometry.computeBoundingSphere()
    }
    if (materialRef.current) {
      // subtle opacity shimmer so the path reads as "live traffic"
      materialRef.current.opacity = 0.65 + Math.sin(clock.elapsedTime * 4) * 0.25
    }
  })

  return (
    <line>
      <primitive object={geometry} attach="geometry" />
      <lineBasicMaterial ref={materialRef} color="#ff2d55" transparent opacity={0.85} />
    </line>
  )
}

function AttackPaths({ paths, nodes }: { paths: AttackPath[]; nodes: SimNode[] }) {
  const lookup = useMemo(() => {
    const m = new Map<string, SimNode>()
    for (const n of nodes) m.set(n.ip, n)
    return m
  }, [nodes])

  if (paths.length === 0) return null
  return (
    <>
      {paths.map((p, idx) => (
        <AttackPathFlow key={`${p.source_ip}-${p.target_ip}-${idx}`} path={p} lookup={lookup} />
      ))}
    </>
  )
}

// --------------------------------------------------------------------------- //
// Scene
// --------------------------------------------------------------------------- //

export default function NetworkCanvas({ graph, paths, selected, onSelect }: CanvasProps) {
  const nodeMap = useMemo(() => {
    const m = new Map<string, SimNode>()
    for (const n of graph.nodes) m.set(n.id, n)
    return m
  }, [graph.nodes])

  function handleNodeClick(node: SimNode) {
    return (_e: ThreeEvent<MouseEvent>) =>
      onSelect(selected?.ip === node.ip ? null : node)
  }

  return (
    <Canvas camera={{ position: [0, 10, 60], fov: 60 }} className="network-canvas">
      <ambientLight intensity={0.5} />
      <pointLight position={[30, 30, 30]} intensity={1.2} />
      <pointLight position={[-30, -20, -30]} intensity={0.4} color="#38bdf8" />

      {graph.nodes.map((n) => (
        <HostSphere
          key={n.id}
          node={n}
          selected={selected?.ip === n.ip}
          onClick={handleNodeClick(n)}
        />
      ))}

      {graph.links.map((l, i) => {
        const src = typeof l.source === 'string' ? nodeMap.get(l.source) : l.source
        const dst = typeof l.target === 'string' ? nodeMap.get(l.target) : l.target
        if (!src || !dst) return null
        return (
          <TrustEdgeLine key={`e-${i}`} a={src} b={dst} color={trustColor(l.trustType)} />
        )
      })}

      <AttackPaths paths={paths} nodes={graph.nodes} />

      <OrbitControls
        enablePan
        enableZoom
        minDistance={10}
        maxDistance={200}
        autoRotate={!selected}
        autoRotateSpeed={0.35}
      />
    </Canvas>
  )
}
