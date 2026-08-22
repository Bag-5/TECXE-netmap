import { useEffect, useState } from 'react'

type Theme = 'system' | 'light' | 'dark'

const KEY = 'tecxe-theme'

function apply(theme: Theme) {
  const root = document.documentElement
  if (theme === 'system') {
    root.removeAttribute('data-theme')
  } else {
    root.setAttribute('data-theme', theme)
  }
}

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(KEY) as Theme) ?? 'system'
  )

  useEffect(() => {
    localStorage.setItem(KEY, theme)
    apply(theme)
    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)')
      const listener = () => apply('system')
      mq.addEventListener('change', listener)
      return () => mq.removeEventListener('change', listener)
    }
  }, [theme])

  const options: { value: Theme; icon: string; title: string }[] = [
    { value: 'system', icon: '🖥', title: 'System' },
    { value: 'light', icon: '☀️', title: 'Light' },
    { value: 'dark', icon: '🌙', title: 'Dark' },
  ]

  return (
    <div className="theme-toggle" role="radiogroup" aria-label="Theme">
      {options.map((o) => (
        <button
          key={o.value}
          className={theme === o.value ? 'active' : ''}
          onClick={() => setTheme(o.value)}
          title={o.title}
        >
          {o.icon}
        </button>
      ))}
    </div>
  )
}
