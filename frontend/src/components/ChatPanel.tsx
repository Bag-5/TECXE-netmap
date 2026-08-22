import { useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? ''

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export default function ChatPanel({ aiEnabled }: { aiEnabled: boolean }) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  function scrollBottom() {
    requestAnimationFrame(() => {
      scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
    })
  }

  async function send() {
    const question = input.trim()
    if (!question || streaming) return
    setInput('')
    setMessages((m) => [...m, { role: 'user', content: question }, { role: 'assistant', content: '' }])
    setStreaming(true)
    scrollBottom()

    try {
      const history = messages.map((m) => ({ role: m.role, content: m.content }))
      const resp = await fetch(`${API_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, history }),
      })

      if (!resp.ok || !resp.body) {
        throw new Error(`Chat failed (${resp.status})`)
      }

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let acc = ''

      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        acc += decoder.decode(value, { stream: true })
        setMessages((m) => {
          const next = [...m]
          next[next.length - 1] = { role: 'assistant', content: acc }
          return next
        })
        scrollBottom()
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setMessages((m) => {
        const next = [...m]
        next[next.length - 1] = { role: 'assistant', content: `⚠️ ${msg}` }
        return next
      })
    } finally {
      setStreaming(false)
      scrollBottom()
    }
  }

  const suggestions = [
    'Which host is the most exposed?',
    'Show me every attack path to a crown jewel',
    'Summarize the riskiest findings',
  ]

  return (
    <div className="panel chat-panel">
      <div className="panel-header">
        <h2>AI Copilot</h2>
        <span className={`badge ${aiEnabled ? 'ok' : 'warn'}`}>{aiEnabled ? 'online' : 'no key'}</span>
      </div>

      <div className="chat-scroll" ref={scrollRef}>
        {messages.length === 0 && (
          <div className="chat-empty">
            <p className="muted">Ask about your network:</p>
            {suggestions.map((s) => (
              <button key={s} className="suggestion" onClick={() => setInput(s)}>
                {s}
              </button>
            ))}
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>
            <span>{m.content || (streaming && i === messages.length - 1 ? '…' : '')}</span>
          </div>
        ))}
      </div>

      <div className="chat-input-row">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send()}
          placeholder={aiEnabled ? 'Ask the twin…' : 'Set OPENROUTER_API_KEY first'}
          disabled={!aiEnabled || streaming}
        />
        <button className="btn btn-primary" onClick={send} disabled={!aiEnabled || streaming}>
          {streaming ? '…' : 'Send'}
        </button>
      </div>
    </div>
  )
}
