$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Python = Join-Path $Backend ".venv\Scripts\python.exe"
$CaddyConfig = Join-Path $Root "config\caddy\Caddyfile"
$DockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"

$env:INTELSOC_GATEWAY_HOST = "Pareezyy.local"

Write-Host "`n=== Starting IntelSOC ===" -ForegroundColor Cyan

# --------------------------------------------------
# 1. Docker engine
# --------------------------------------------------

docker info *> $null

if ($LASTEXITCODE -ne 0) {
    Write-Host "Starting Docker Desktop..." -ForegroundColor Yellow

    Start-Process $DockerDesktop

    do {
        Start-Sleep -Seconds 3
        docker info *> $null
    }
    until ($LASTEXITCODE -eq 0)
}

Write-Host "Docker engine: READY" -ForegroundColor Green

# --------------------------------------------------
# 2. PostgreSQL + Redis
# --------------------------------------------------

Set-Location $Root
docker compose up -d

Write-Host "Waiting for PostgreSQL and Redis..." -ForegroundColor Yellow

$deadline = (Get-Date).AddSeconds(60)

do {
    $services = docker compose ps --format json | ConvertFrom-Json

    $dbReady = $services |
        Where-Object {
            $_.Service -eq "db" -and
            $_.Health -eq "healthy"
        }

    $redisReady = $services |
        Where-Object {
            $_.Service -eq "redis" -and
            $_.Health -eq "healthy"
        }

    if ($dbReady -and $redisReady) {
        break
    }

    if ((Get-Date) -gt $deadline) {
        throw "PostgreSQL/Redis did not become healthy within 60 seconds."
    }

    Start-Sleep -Seconds 2
}
while ($true)

Write-Host "PostgreSQL + Redis: HEALTHY" -ForegroundColor Green

# --------------------------------------------------
# 3. FastAPI
# --------------------------------------------------

$FastAPI = Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "uvicorn.*app\.main:app"
}

if (-not $FastAPI) {
    Start-Process `
        -FilePath $Python `
        -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" `
        -WorkingDirectory $Backend `
        -WindowStyle Minimized

    Write-Host "FastAPI: STARTED" -ForegroundColor Green
}
else {
    Write-Host "FastAPI: already running" -ForegroundColor DarkGreen
}

# --------------------------------------------------
# 4. Event worker
# --------------------------------------------------

$Worker = Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.event_worker"
}

if (-not $Worker) {
    Start-Process `
        -FilePath $Python `
        -ArgumentList "-m app.workers.event_worker" `
        -WorkingDirectory $Backend `
        -WindowStyle Minimized

    Write-Host "IntelSOC Worker: STARTED" -ForegroundColor Green
}
else {
    Write-Host "IntelSOC Worker: already running" -ForegroundColor DarkGreen
}

# --------------------------------------------------
# 5. Caddy
# --------------------------------------------------

$CaddyProcess = Get-Process caddy -ErrorAction SilentlyContinue

if (-not $CaddyProcess) {
    Start-Process `
        -FilePath "caddy" `
        -ArgumentList "run --config `"$CaddyConfig`"" `
        -WorkingDirectory $Root `
        -WindowStyle Minimized

    Write-Host "Caddy: STARTED" -ForegroundColor Green
}
else {
    Write-Host "Caddy: already running" -ForegroundColor DarkGreen
}

# --------------------------------------------------
# 6. Health checks
# --------------------------------------------------

Start-Sleep -Seconds 3

Write-Host "`n=== IntelSOC Health ===" -ForegroundColor Cyan

$fastApiHealth = Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/v1/health"

Write-Host "FastAPI: $($fastApiHealth.status)" -ForegroundColor Green

$gatewayHealth = Invoke-RestMethod `
    -Uri "https://Pareezyy.local:8445/api/v1/health"

Write-Host "HTTPS Gateway: $($gatewayHealth.status)" -ForegroundColor Green

Write-Host "`nIntelSOC startup complete." -ForegroundColor Green
