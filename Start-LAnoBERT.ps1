param(
    [string]$Since,

    [ValidateRange(1, 20)]
    [int]$Limit = 5,

    [ValidateRange(2, 300)]
    [double]$PollSeconds = 10,

    [string]$ModelDir = "$HOME\Downloads\IntelSOC-LAnoBERT-v0.2-model"
)

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Python = Join-Path $Root ".venv-lanobert\Scripts\python.exe"
$MonitorPattern = '(^|\s)-m\s+lanobert_v02\.ai_monitor(?:\s|$)'

Write-Host ""
Write-Host "=== Starting IntelSOC LAnoBERT Advisory Monitor ===" -ForegroundColor Cyan

if (-not (Test-Path $Python)) {
    throw "LAnoBERT Python environment missing: $Python"
}

if (-not (Test-Path $ModelDir -PathType Container)) {
    throw "LAnoBERT model directory missing: $ModelDir"
}

if ([string]::IsNullOrWhiteSpace($Since)) {
    $Since = (Get-Date).AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssK")
    Write-Host "Since: $Since (automatic 5-minute lookback)" -ForegroundColor DarkGray
}
else {
    if ($Since -notmatch '(Z|[+-]\d{2}:\d{2})$') {
        throw "Invalid -Since value. Include an explicit timezone."
    }

    try {
        [void][DateTimeOffset]::Parse($Since)
    }
    catch {
        throw "Invalid -Since value. Use an ISO 8601 timestamp with timezone."
    }

    Write-Host "Since: $Since (manual override)" -ForegroundColor DarkGray
}

$Existing = @(
    Get-CimInstance Win32_Process |
    Where-Object {
        $_.CommandLine -and
        $_.CommandLine -match $MonitorPattern
    }
)

if ($Existing.Count -gt 0) {
    Write-Host "LAnoBERT Monitor: already running" -ForegroundColor DarkGreen
    foreach ($process in $Existing) {
        Write-Host "PID: $($process.ProcessId)"
    }
    exit 0
}

$Arguments = @(
    "-m",
    "lanobert_v02.ai_monitor",
    "--since",
    $Since,
    "--limit",
    $Limit,
    "--poll-seconds",
    $PollSeconds,
    "--model-dir",
    $ModelDir,
    "--write-results"
)

$Process = Start-Process `
    -FilePath $Python `
    -ArgumentList $Arguments `
    -WorkingDirectory $Root `
    -WindowStyle Minimized `
    -PassThru

Start-Sleep -Seconds 2

if ($Process.HasExited) {
    throw "LAnoBERT monitor exited during startup."
}

$Running = @(
    Get-CimInstance Win32_Process |
    Where-Object {
        $_.CommandLine -and
        $_.CommandLine -match $MonitorPattern
    }
)

if ($Running.Count -eq 0) {
    throw "LAnoBERT monitor process was not found after startup."
}

Write-Host "LAnoBERT Monitor: RUNNING" -ForegroundColor Green
Write-Host "PID: $($Process.Id)"
Write-Host "Mode: advisory-only"
Write-Host "Risk scoring: unchanged"
Write-Host "Automatic response: disabled"
