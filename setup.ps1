# TECXE-netmap setup script (Windows)
# Verifies prerequisites and prepares the local dev environment.

$ErrorActionPreference = "Stop"
Write-Host "=== TECXE-netmap setup ===" -ForegroundColor Cyan

# 1. Nmap
$nmapPaths = @(
    "C:\Program Files (x86)\Nmap\nmap.exe",
    "C:\Program Files\Nmap\nmap.exe"
)
$nmap = $nmapPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $nmap) {
    Write-Host "[!] nmap not found. Install from https://nmap.org/download.html (include Npcap)" -ForegroundColor Red
    exit 1
}
Write-Host "[+] nmap found: $nmap"

# 2. Python
try { $pyVer = python --version } catch {
    Write-Host "[!] Python not found on PATH." -ForegroundColor Red; exit 1
}
Write-Host "[+] Python: $pyVer"

# 3. Node
try { $nodeVer = node --version } catch {
    Write-Host "[!] Node.js not found on PATH. Install from https://nodejs.org" -ForegroundColor Red; exit 1
}
Write-Host "[+] Node: $nodeVer"

# 4. Virtualenv + deps
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "[+] Created .venv"
}
$activate = Join-Path $PWD ".venv\Scripts\Activate.ps1"
& $activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
Write-Host "[+] Python dependencies installed"

# 5. Frontend deps
Push-Location frontend
npm install --silent
Pop-Location
Write-Host "[+] Frontend dependencies installed"

# 6. .env
if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
    Write-Host "[~] Created .env from template — FILL IN DATABASE_URL and OPENROUTER_API_KEY!" -ForegroundColor Yellow
} else {
    Write-Host "[+] .env exists"
}

Write-Host ""
Write-Host "Setup complete. To run:" -ForegroundColor Green
Write-Host "  Terminal 1:  .\.venv\Scripts\Activate.ps1 ; uvicorn backend.main:app --reload --port 8000" -ForegroundColor White
Write-Host "  Terminal 2:  cd frontend ; npm run dev" -ForegroundColor White
Write-Host "  Open:        http://localhost:5173" -ForegroundColor White
Write-Host ""
Write-Host "Note: OS detection (-O) requires an elevated (admin) terminal with Npcap installed." -ForegroundColor Yellow
