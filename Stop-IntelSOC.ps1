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

# Event storage worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.event_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Event Worker: STOPPED" -ForegroundColor Green

# Analysis worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.analysis_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Analysis Worker: STOPPED" -ForegroundColor Green

# PostgreSQL + Redis
Set-Location $Root
docker compose stop

Write-Host "PostgreSQL + Redis: STOPPED" -ForegroundColor Green

Write-Host "`nIntelSOC shutdown complete." -ForegroundColor Cyan
