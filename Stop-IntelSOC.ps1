$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot

Write-Host "`n=== Stopping IntelSOC ===" -ForegroundColor Cyan

# Caddy
Get-Process caddy -ErrorAction SilentlyContinue |
Stop-Process -Force

Write-Host "Caddy: STOPPED" -ForegroundColor Green

# FastAPI
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "uvicorn.*app\.main:app"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "FastAPI: STOPPED" -ForegroundColor Green

# Worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.event_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Worker: STOPPED" -ForegroundColor Green

# PostgreSQL + Redis
Set-Location $Root
docker compose stop

Write-Host "PostgreSQL + Redis: STOPPED" -ForegroundColor Green

Write-Host "`nIntelSOC shutdown complete." -ForegroundColor Cyan
