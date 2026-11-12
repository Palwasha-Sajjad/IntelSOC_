$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot

Write-Host ""
Write-Host "=== Stopping IntelSOC ===" -ForegroundColor Cyan

# Stop IntelSOC public ingress first.
$NgrokInstances = @(Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "ngrok.exe" -and
        $_.CommandLine -like "*molehill-entomb-riveting.ngrok-free.dev*" -and
        $_.CommandLine -like "*127.0.0.1:8767*"
    })

foreach ($process in $NgrokInstances) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
}

Write-Host "IntelSOC ngrok: STOPPED" -ForegroundColor Green

$OriginalConfig = Join-Path $Root "config\caddy\Caddyfile"
$PortableConfig = Join-Path $env:LOCALAPPDATA "IntelSOC\gateway\Caddyfile"
$LegacyPortableConfig = Join-Path $env:TEMP "intelsoc-caddy-remote-test\Caddyfile"

$CaddyInstances = @(Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "caddy.exe" -and
        $_.CommandLine -and (
            $_.CommandLine.Contains($OriginalConfig) -or
            $_.CommandLine.Contains($PortableConfig) -or
            $_.CommandLine.Contains($LegacyPortableConfig)
        )
    })

foreach ($process in $CaddyInstances) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
}

Write-Host "IntelSOC Caddy gateways: STOPPED" -ForegroundColor Green
# FastAPI
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "uvicorn.*app\.main:app"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "FastAPI: STOPPED" -ForegroundColor Green

# Risk scoring worker
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -match "app\.workers\.risk_worker"
} |
ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Risk Worker: STOPPED" -ForegroundColor Green

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
