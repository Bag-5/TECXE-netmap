# 🌐 TECXE-netmap — AI Network Twin

**Google Maps for corporate networks.** Scan with Nmap, explore a live 3D graph of your
network: hosts, operating systems, vulnerabilities, trust relationships, and animated
attack paths — with an AI copilot that answers questions about the map.

![stack](https://img.shields.io/badge/backend-FastAPI%20%2B%20Neon%20Postgres-38bdf8)
![stack](https://img.shields.io/badge/frontend-React%203D%20(Three.js)-f97316)

## Features

- 🔍 **Nmap-powered scanning** — quick / full / stealth / vuln profiles
- 🧊 **3D force-directed map** — OS-colored nodes sized by open ports, WebGL via React Three Fiber
- 🛡 **CVE enrichment** — service versions matched against the NVD API, severity halos pulse on nodes
- 🔗 **Trust inference** — SMB / LDAP / Kerberos / RDP / WinRM / subnet edges
- ⚔️ **Attack paths** — Dijkstra from vulnerable hosts to crown jewels, rendered as glowing red routes
- 👑 **Crown jewels** — right-click a node in the panel to mark what matters; persists in Postgres
- 💬 **AI copilot** — streaming chat over live graph state (OpenRouter, model fallback chain)
- 🔔 **Anomaly alerts** — new hosts/ports/CVEs detected by diffing consecutive scans
- 🌗 **System / Light / Dark themes**

## Architecture

```
┌──────────────┐   nmap XML   ┌──────────────────────────────────────────┐
│ nmap (local) │ ───────────▶ │ FastAPI backend                          │
└──────────────┘              │  scanner → NVD → trust → paths → alerts  │
                              └─────────────┬───────────────┬────────────┘
                                            │ WebSocket     │ SQLAlchemy
                                            ▼               ▼
                                   ┌────────────────┐  ┌──────────────┐
                                   │ React + Three  │  │ Neon Postgres│
                                   │ 3D graph UI    │  │ snapshots    │
                                   └────────────────┘  └──────────────┘
```

## Quick Start (Windows)

```powershell
# Prerequisites: Python 3.12+, Node 20+, Nmap + Npcap installed
.\setup.ps1
# → edit .env (DATABASE_URL from Neon, OPENROUTER_API_KEY optional)

# Terminal 1 — backend
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm run dev
# open http://localhost:5173
```

> OS detection (`-O`) and SYN scans need an **elevated terminal**. The `quick`
> profile works fine without admin rights.

## Frontend on Vercel

The frontend deploys as a static build:

```bash
cd frontend && npm run build   # outputs dist/
```

Import `frontend/` in Vercel and set:

| Env var | Value |
|---------|-------|
| `VITE_API_URL` | your backend URL (`http://localhost:8000` for local dev) |
| `VITE_WS_URL` | your backend WS URL (`ws://localhost:8000/ws`) |

To reach a locally-running backend from Vercel, tunnel it:
`ngrok http 8000` or `cloudflared tunnel --url http://localhost:8000`.

## Safety

- Only scan networks you own or are authorized to test.
- Default profile is polite (`-T4 -F`). Aggressive profiles require admin.
- Scan data lives in *your* Neon database.

## Roadmap

- [ ] Timeline scrubber (A/B snapshot diff view)
- [ ] GLSL particle shaders on attack paths
- [ ] Credential-aware path scoring
- [ ] Docker Compose packaging

---

Built with ❤️ by ENI & LO · scan responsibly
