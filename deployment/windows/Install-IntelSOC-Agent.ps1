[CmdletBinding()]
param(
    [string]$ServerHost = "molehill-entomb-riveting.ngrok-free.dev",
    [int]$ServerPort = 443,
    [string]$FluentBitVersion = "5.1.3",
    [switch]$MigrateExisting
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Net.Http

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Require-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from PowerShell as Administrator."
    }
}

Require-Administrator

$BaseDir = "C:\ProgramData\IntelSOC"
$ConfigDir = Join-Path $BaseDir "fluent-bit"
$CertDir = Join-Path $BaseDir "certs"
$StorageDir = Join-Path $ConfigDir "storage"
$InstallDir = "C:\IntelSOC\FluentBit"
$FluentBitExe = $null
$ConfigPath = Join-Path $ConfigDir "windows.yaml"
$CaSource = Join-Path $PSScriptRoot "intelsoc-caddy-root.crt"
$CaPath = Join-Path $CertDir "intelsoc-caddy-root.crt"
$ServiceName = "IntelSOC-FluentBit"

# Existing endpoint identity must not be silently replaced or re-enrolled.
$existingService = Get-Service $ServiceName -ErrorAction SilentlyContinue
$existingConfig = Test-Path $ConfigPath
$existingInstall = $existingService -or $existingConfig

if ($existingInstall -and -not $MigrateExisting) {
    throw "Existing IntelSOC Windows agent detected. Nothing changed. Inspect it first, then rerun with -MigrateExisting."
}

$existingEnrollment = $null
if ($existingConfig) {
    $existingText = Get-Content $ConfigPath -Raw -ErrorAction Stop
    $keyMatch = [regex]::Match(
        $existingText,
        '(?m)^\s*-\s*"X-IntelSOC-Key\s+([^"]+)"\s*$'
    )
    $idMatch = [regex]::Match(
        $existingText,
        '(?m)^\s*-\s*"X-Device-ID\s+([^"]+)"\s*$'
    )
    if ($keyMatch.Success -xor $idMatch.Success) {
        throw "Partial existing IntelSOC enrollment found. Restore/repair it before migration."
    }
    if ($keyMatch.Success -and $idMatch.Success) {
        $existingEnrollment = [pscustomobject]@{
            ingest_key = $keyMatch.Groups[1].Value.Trim()
            device_id = $idMatch.Groups[1].Value.Trim()
        }
    }
}

$BackupDir = $null
if ($existingInstall) {
    $BackupDir = Join-Path $env:ProgramData (
        "IntelSOC\backups\agent-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    )
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    if ($existingConfig) {
        Copy-Item $ConfigPath (Join-Path $BackupDir "windows.yaml") -Force
    }
    if (Test-Path $CaPath) {
        Copy-Item $CaPath (Join-Path $BackupDir "intelsoc-caddy-root.crt") -Force
    }
    Write-Host "Existing IntelSOC configuration backed up to: $BackupDir"
}

Write-Step "Configuring Windows audit telemetry policies"

auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable Process Creation auditing." }

auditpol /set /subcategory:"Other Object Access Events" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable Other Object Access Events auditing." }

auditpol /set /subcategory:"User Account Management" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable User Account Management auditing." }

auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable Security Group Management auditing." }

auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable Logon auditing." }

$AuditKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $AuditKey -Force | Out-Null
Set-ItemProperty -Path $AuditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

$ScriptBlockKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $ScriptBlockKey -Force | Out-Null
Set-ItemProperty -Path $ScriptBlockKey -Name "EnableScriptBlockLogging" -Type DWord -Value 1

Write-Step "Preparing IntelSOC directories"
New-Item -ItemType Directory -Path $ConfigDir,$StorageDir -Force | Out-Null

# The ngrok endpoint uses a public TLS certificate trusted by Windows.
# Keep the Caddy root certificate in the deployment kit for direct-Caddy use;
# do not install it into this endpoint or pin the server to a LAN IP.

Write-Step "Verifying IntelSOC HTTPS health"
$healthUri = "https://${ServerHost}:$ServerPort/api/v1/health"
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.CheckCertificateRevocationList = $false
$client = New-Object System.Net.Http.HttpClient($handler)
try {
    $client.DefaultRequestHeaders.Add("ngrok-skip-browser-warning", "1")
    $response = $client.GetAsync($healthUri).GetAwaiter().GetResult()
    if (-not $response.IsSuccessStatusCode) {
        throw "IntelSOC health endpoint returned HTTP $([int]$response.StatusCode)."
    }
}
finally {
    $client.Dispose()
    $handler.Dispose()
}

if ($existingEnrollment) {
    Write-Step "Reusing existing IntelSOC device identity"
    $enrollment = $existingEnrollment
}
else {
    Write-Step "Enrolling this Windows device"
    $secureToken = Read-Host "IntelSOC enrollment token" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try { $enrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }

    $payload = @{ hostname = $env:COMPUTERNAME; platform = "windows" } | ConvertTo-Json -Compress
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.CheckCertificateRevocationList = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    try {
        $client.DefaultRequestHeaders.Add("X-IntelSOC-Enrollment-Token", $enrollmentToken)
        $client.DefaultRequestHeaders.Add("ngrok-skip-browser-warning", "1")
        $content = New-Object System.Net.Http.StringContent($payload,[Text.Encoding]::UTF8,"application/json")
        $uri = "https://${ServerHost}:$ServerPort/api/v1/devices/enroll"
        $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "Enrollment failed: HTTP $([int]$response.StatusCode) $body"
        }
        $enrollment = $body | ConvertFrom-Json
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
        $enrollmentToken = $null
    }
}
if (-not $enrollment.device_id -or -not $enrollment.ingest_key) {
    throw "Enrollment did not provide both device_id and ingest_key."
}

Write-Step "Installing Fluent Bit $FluentBitVersion"

$existingFluentBit = Get-ChildItem `
    -Path $InstallDir `
    -Filter "fluent-bit.exe" `
    -Recurse `
    -File `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $existingFluentBit) {
    $archive = Join-Path $env:TEMP "fluent-bit-$FluentBitVersion-win64.zip"
    $download = "https://packages.fluentbit.io/windows/fluent-bit-$FluentBitVersion-win64.zip"

    Invoke-WebRequest -Uri $download -OutFile $archive

    if ($FluentBitVersion -eq "5.1.3") {
        $expected = "2a06c1a3c0ecddc970f50486a94a775b54fa28bf2ebe42c57a325511d33c0bb5"
        $actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($actual -ne $expected) {
            Remove-Item $archive -Force
            throw "Fluent Bit archive SHA256 mismatch."
        }
    }

    if (Test-Path $InstallDir) {
        Remove-Item $InstallDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    Expand-Archive `
        -Path $archive `
        -DestinationPath $InstallDir `
        -Force
}

$FluentBitExe = (
    Get-ChildItem `
        -Path $InstallDir `
        -Filter "fluent-bit.exe" `
        -Recurse `
        -File `
        -ErrorAction SilentlyContinue |
    Select-Object -First 1
).FullName

if (-not $FluentBitExe) {
    throw "Fluent Bit executable was not found under $InstallDir."
}

Write-Host "Fluent Bit executable: $FluentBitExe"

Write-Step "Writing Windows Fluent Bit configuration"
$config = @"
service:
  flush: 1
  daemon: off
  log_level: info
  storage.path: C:\\ProgramData\\IntelSOC\\fluent-bit\\storage
  storage.sync: full
  storage.checksum: on

pipeline:
  inputs:
    - name: winevtlog
      tag: intelsoc.windows.application
      channels: Application
      interval_sec: 1
      read_existing_events: false
      db: C:\\ProgramData\\IntelSOC\\fluent-bit\\application.db
      storage.type: filesystem

    - name: winevtlog
      tag: intelsoc.windows.system
      channels: System
      interval_sec: 1
      read_existing_events: false
      db: C:\\ProgramData\\IntelSOC\\fluent-bit\\system.db
      storage.type: filesystem

    - name: winevtlog
      tag: intelsoc.windows.security
      channels: Security
      interval_sec: 1
      read_existing_events: false
      event_query: '*[System[(EventID=4624 or EventID=4625 or EventID=4740 or EventID=4648 or EventID=4688 or EventID=4698 or EventID=4702 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4725 or EventID=4726 or EventID=4732 or EventID=1102)]]'
      db: C:\\ProgramData\\IntelSOC\\fluent-bit\\security.db
      storage.type: filesystem

    - name: winevtlog
      tag: intelsoc.windows.powershell
      channels: Microsoft-Windows-PowerShell/Operational
      interval_sec: 1
      read_existing_events: false
      event_query: '*[System[(EventID=4104)]]'
      db: C:\\ProgramData\\IntelSOC\\fluent-bit\\powershell.db
      storage.type: filesystem

  outputs:
    - name: http
      match: 'intelsoc.windows.*'
      host: $ServerHost
      port: $ServerPort
      uri: /api/v1/events/windows
      format: json
      tls: on
      tls.verify: on
      tls.verify_hostname: on
      net.dns.resolver: LEGACY
      header:
        - "X-IntelSOC-Key $($enrollment.ingest_key)"
        - "X-Device-ID $($enrollment.device_id)"
        - "ngrok-skip-browser-warning: 1"
      retry_limit: false
"@

Set-Content -Path $ConfigPath -Value $config -Encoding UTF8

# Restrict the config because it contains the endpoint authentication material.
icacls $ConfigPath /inheritance:r | Out-Null
icacls $ConfigPath /grant:r "SYSTEM:F" "Administrators:F" | Out-Null

Write-Step "Validating Fluent Bit configuration"
& $FluentBitExe --dry-run -c $ConfigPath
if ($LASTEXITCODE -ne 0) {
    throw "Fluent Bit configuration validation failed. Existing service was not replaced."
}

Write-Step "Installing IntelSOC Fluent Bit Windows service"
$existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

New-Service `
    -Name $ServiceName `
    -DisplayName "IntelSOC Fluent Bit Collector" `
    -BinaryPathName "`"$FluentBitExe`" -c `"$ConfigPath`"" `
    -StartupType Automatic `
    -Description "IntelSOC Windows Event Log collector powered by Fluent Bit" | Out-Null

Start-Service $ServiceName

Write-Step "Generating onboarding acceptance event"
eventcreate /T INFORMATION /ID 105 /L SYSTEM /SO IntelSOC-Onboarding /D "IntelSOC automated Windows onboarding test" | Out-Null

Start-Sleep -Seconds 3

$svc = Get-Service $ServiceName
if ($svc.Status -ne "Running") {
    throw "IntelSOC Fluent Bit service is not running."
}

Write-Host "`nIntelSOC Windows agent installation completed." -ForegroundColor Green
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "Device ID: $($enrollment.device_id)"
Write-Host "Service: $($svc.Status) / Automatic"
Write-Host "Server: https://${ServerHost}:$ServerPort"


