$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot

Write-Host ""
Write-Host "=== Stopping IntelSOC ===" -ForegroundColor Cyan

# Stop ingress first so no new endpoint batches arrive during shutdown.
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

# Threat Intelligence worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.ti_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "TI Worker: STOPPED" -ForegroundColor Green

# Analysis worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.analysis_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Analysis Worker: STOPPED" -ForegroundColor Green

# Event storage worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.event_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Event Worker: STOPPED" -ForegroundColor Green

# PostgreSQL + Redis are stopped only after all backend workers.
Set-Location $Root
docker compose stop

Write-Host "PostgreSQL + Redis: STOPPED" -ForegroundColor Green

Write-Host ""
Write-Host "IntelSOC shutdown complete." -ForegroundColor Cyan
