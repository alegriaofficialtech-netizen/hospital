#Requires -Version 5.1
<#
.SYNOPSIS
Starts the isolated local Keycloak + Python backend used for real-integration tests.

.DESCRIPTION
- Uses WSL2 Ubuntu's Docker engine with an isolated Compose project.
- Creates a local-only realm at http://127.0.0.1:8085/realms/hospital-lab-local.
- Starts the recovered Python backend on http://127.0.0.1:8000 with a local SQLite file.
- Optionally starts the Angular dev server in local-real mode.
- Never uses production secrets, production data, /opt, or a cutover.
#>
[CmdletBinding()]
param(
    [switch]$WithFrontend,
    [switch]$SkipRealmSetup
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$infra = Join-Path $root 'infra\local-test'
$runtime = Join-Path $infra 'runtime'
$envFile = Join-Path $infra '.env'
$credentialsFile = Join-Path $infra '.test-credentials.local.json'
$pidsFile = Join-Path $runtime 'pids.json'
$backendDir = Join-Path $root 'backend'
$backendPython = Join-Path $backendDir '.venv\Scripts\python.exe'

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function New-RandomSecret([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Wait-Http([string]$Url, [int]$TimeoutSeconds = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ''
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
            $lastError = "HTTP $($response.StatusCode)"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for $Url. Last error: $lastError"
}

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    throw 'WSL2 is required for the local Keycloak stack.'
}
if (-not (Test-Path $backendPython)) {
    throw "Backend virtual environment not found at $backendPython. See backend/README.md."
}

New-Item -ItemType Directory -Force -Path $runtime | Out-Null

if (-not (Test-Path $envFile)) {
    Write-Utf8NoBom $envFile ("KEYCLOAK_ADMIN_USERNAME=admin`nKEYCLOAK_ADMIN_PASSWORD={0}`n" -f (New-RandomSecret 32))
    Write-Host "Created local Keycloak admin credentials in $envFile (ignored by git)."
}

$envValues = @{}
Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.*)$') {
        $envValues[$Matches[1].Trim()] = $Matches[2].Trim()
    }
}
$adminPassword = $envValues['KEYCLOAK_ADMIN_PASSWORD']
if (-not $adminPassword) {
    throw "KEYCLOAK_ADMIN_PASSWORD is missing from $envFile."
}

$secretsFile = Join-Path $runtime 'backend-secrets.json'
if (-not (Test-Path $secretsFile)) {
    $secrets = [ordered]@{
        clinicalSigningKey = New-RandomSecret 32
        iomtDeviceId = 'synthetic-analyzer-01'
        iomtDeviceKey = New-RandomSecret 32
        auditHmacKey = New-RandomSecret 32
    }
    Write-Utf8NoBom $secretsFile ($secrets | ConvertTo-Json)
    Write-Host "Created synthetic local backend keys in $secretsFile (ignored by git)."
}
$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json

Write-Host 'Starting isolated Keycloak container via WSL2 Docker ...'
$infraForWsl = $infra -replace '\\', '/'
$wslInfra = (& wsl -d Ubuntu -- wslpath -a "$infraForWsl").Trim()
& wsl -d Ubuntu -- docker compose -p sgsi-zta-f11 -f "$wslInfra/compose.yaml" up -d
if ($LASTEXITCODE -ne 0) {
    throw 'docker compose up failed.'
}

Wait-Http 'http://127.0.0.1:8085/realms/master/.well-known/openid-configuration' 150

if (-not $SkipRealmSetup) {
    Write-Host 'Provisioning synthetic realm, users, PKCE client, AMR mapper, and TOTP flow ...'
    $setup = Join-Path $infra 'setup_realm.py'
    & $backendPython $setup --admin-password $adminPassword --credentials-file $credentialsFile
    if ($LASTEXITCODE -ne 0) {
        throw 'Realm setup failed.'
    }
} elseif (-not (Test-Path $credentialsFile)) {
    throw "Realm setup was skipped but $credentialsFile does not exist."
}

$existing = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    $owner = Get-Process -Id $existing[0].OwningProcess -ErrorAction SilentlyContinue
    if ($owner -and $owner.ProcessName -match 'python') {
        Write-Host "Stopping previous backend process $($owner.Id) on port 8000 ..."
        Stop-Process -Id $owner.Id -Force
        Start-Sleep -Seconds 2
    } else {
        throw "Port 8000 is already in use by $($owner.ProcessName) (PID $($owner.Id))."
    }
}

$dbPath = Join-Path $runtime 'lis.db'
$iomtJson = @{ $secrets.iomtDeviceId = $secrets.iomtDeviceKey } | ConvertTo-Json -Compress
$env:KEYCLOAK_DISCOVERY_URL = 'http://127.0.0.1:8085/realms/hospital-lab-local/.well-known/openid-configuration'
$env:KEYCLOAK_AUDIENCE = 'clinical-poc-api'
$env:KEYCLOAK_EXPECTED_AZP = 'clinical-poc'
$env:LIS_DB_PATH = $dbPath
$env:CLINICAL_SIGNING_KEY = $secrets.clinicalSigningKey
$env:AUDIT_HMAC_KEY = $secrets.auditHmacKey
$env:IOMT_DEVICE_KEYS_JSON = $iomtJson
$env:HOST = '127.0.0.1'
$env:PORT = '8000'

Write-Host 'Starting Python backend on http://127.0.0.1:8000 ...'
$backendOut = Join-Path $runtime 'backend.out.log'
$backendErr = Join-Path $runtime 'backend.err.log'
$backend = Start-Process -FilePath $backendPython -ArgumentList 'server.py' -WorkingDirectory $backendDir -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr -PassThru
Wait-Http 'http://127.0.0.1:8000/health' 60

$frontend = $null
if ($WithFrontend) {
    $existingFront = Get-NetTCPConnection -LocalPort 4200 -State Listen -ErrorAction SilentlyContinue
    if ($existingFront) {
        Write-Host 'Angular dev server already listening on port 4200; reusing it.'
    } else {
        Write-Host 'Starting Angular dev server in local-real mode on http://127.0.0.1:4200 ...'
        $frontendOut = Join-Path $runtime 'frontend.out.log'
        $frontendErr = Join-Path $runtime 'frontend.err.log'
        $frontend = Start-Process -FilePath 'npm.cmd' -ArgumentList 'run start:real' -WorkingDirectory (Join-Path $root 'frontend') -RedirectStandardOutput $frontendOut -RedirectStandardError $frontendErr -PassThru
        Wait-Http 'http://127.0.0.1:4200' 120
    }
}

$pids = [ordered]@{
    backend = $backend.Id
    frontend = if ($frontend) { $frontend.Id } else { $null }
    startedAt = (Get-Date).ToString('o')
}
Write-Utf8NoBom $pidsFile ($pids | ConvertTo-Json)

Write-Host ''
Write-Host 'Local real-mode stack is ready.'
Write-Host '  Keycloak: http://127.0.0.1:8085 (realm hospital-lab-local)'
Write-Host '  Backend:  http://127.0.0.1:8000'
if ($WithFrontend) { Write-Host '  Frontend: http://127.0.0.1:4200' }
Write-Host "  Credentials: $credentialsFile (ignored by git)"
Write-Host "  Logs: $runtime"
