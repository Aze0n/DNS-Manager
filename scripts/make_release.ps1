param(
    [string]$Version = (Get-Date -Format 'yyyyMMdd')
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (this script lives in scripts/)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Resolve-Path (Join-Path $ScriptDir '..')
Set-Location $Root

Write-Host "[1/6] Checking Python tests..." -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pytest -q

Write-Host "[2/6] Building frontend (vite)..." -ForegroundColor Cyan
Push-Location frontend
if (-not (Test-Path package-lock.json)) { npm install } else { npm ci }
npm run build --silent
Pop-Location

Write-Host "[3/6] Preparing staging folder..." -ForegroundColor Cyan
$releaseRoot = Join-Path $Root 'release'
$stage = Join-Path $releaseRoot 'dns-manager-poc'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# Copy backend (exclude caches)
$null = New-Item -ItemType Directory -Force -Path (Join-Path $stage 'app')
robocopy app (Join-Path $stage 'app') /E /NFL /NDL /NJH /NJS /NC /NS /XD __pycache__ .pytest_cache .mypy_cache /XF *.pyc *.pyo *.pyd | Out-Null

# Copy frontend/dist
$distSrc = Join-Path $Root 'frontend\dist'
if (Test-Path $distSrc) {
  $null = New-Item -ItemType Directory -Force -Path (Join-Path $stage 'frontend')
  robocopy $distSrc (Join-Path $stage 'frontend\dist') /E /NFL /NDL /NJH /NJS /NC /NS | Out-Null
}

# Copy top-level files
Copy-Item -Path (Join-Path $Root 'requirements.txt') -Destination $stage -Force
Copy-Item -Path (Join-Path $Root '.env.example') -Destination $stage -Force
Copy-Item -Path (Join-Path $Root 'README.md') -Destination $stage -Force

# Cert placeholders (do not ship example private keys)
$certsStage = Join-Path $stage 'certs'
New-Item -ItemType Directory -Force -Path $certsStage | Out-Null
@(
  'Diese Zertifikate (key.pem, cert.pem) sind NICHT im Release enthalten.',
  'Bitte generieren Sie lokale Dev-Zertifikate oder verwenden Sie Produktionszertifikate.',
  '',
  'Beispiel (PowerShell, nur lokal):',
  '  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"',
  '',
  'Start Uvicorn (Beispiel):',
  '  uvicorn app.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile=certs/key.pem --ssl-certfile=certs/cert.pem'
) | Set-Content -Path (Join-Path $certsStage 'README.txt') -Encoding UTF8

# Never ship secrets directory
# (the app will create secrets/master.key on demand if configured)

Write-Host "[4/6] Creating archive..." -ForegroundColor Cyan
$zipName = "dns-manager-poc-$Version.zip"
$zipPath = Join-Path $releaseRoot $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force

Write-Host "[5/6] Cleaning staging folder..." -ForegroundColor Cyan
try { Remove-Item $stage -Recurse -Force -ErrorAction Stop } catch {}

Write-Host "[6/6] Done." -ForegroundColor Green
$info = Get-Item $zipPath
Write-Host ("Created: {0} ({1:N0} bytes)" -f $info.FullName, $info.Length)
