$ErrorActionPreference = "Stop"

$MonitorPattern = '(^|\s)-m\s+lanobert_v02\.ai_monitor(?:\s|$)'

Write-Host ""
Write-Host "=== Stopping IntelSOC LAnoBERT Advisory Monitor ===" -ForegroundColor Cyan

$Processes = @(
    Get-CimInstance Win32_Process |
    Where-Object {
        $_.CommandLine -and
        $_.CommandLine -match $MonitorPattern
    }
)

if ($Processes.Count -eq 0) {
    Write-Host "LAnoBERT Monitor: not running" -ForegroundColor DarkGreen
    exit 0
}

foreach ($process in $Processes) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 750

$Remaining = @(
    Get-CimInstance Win32_Process |
    Where-Object {
        $_.CommandLine -and
        $_.CommandLine -match $MonitorPattern
    }
)

if ($Remaining.Count -gt 0) {
    throw "LAnoBERT monitor is still running."
}

Write-Host "LAnoBERT Monitor: STOPPED" -ForegroundColor Green
