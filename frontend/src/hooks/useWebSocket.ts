import { useEffect, useRef, useState } from 'react'
import type { WsEvent } from '../types/graph'

const API_URL = import.meta.env.VITE_API_URL ?? ''
const WS_URL =
  import.meta.env.VITE_WS_URL ??
  `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`

export function useWebSocket(onEvent: (e: WsEvent) => void) {
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent

  useEffect(() => {
    let retry = 0
    let closed = false

    function connect() {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        retry = 0
      }
      ws.onmessage = (ev) => {
        try {
          handlerRef.current(JSON.parse(ev.data) as WsEvent)
        } catch {
          // ignore malformed frames
        }
      }
      ws.onclose = () => {
        setConnected(false)
        if (!closed) {
          const delay = Math.min(1000 * 2 ** retry++, 15000)
          setTimeout(connect, delay)
        }
      }
      ws.onerror = () => ws.close()
    }

    connect()
    return () => {
      closed = true
      wsRef.current?.close()
    }
  }, [])

  return { connected }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`API ${path} failed (${resp.status}): ${text}`)
  }
  return resp.json() as Promise<T>
}
