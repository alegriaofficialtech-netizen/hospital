#Requires -Version 5.1
<#
.SYNOPSIS
Stops the isolated local integration stack.

.PARAMETER Reset
Also removes the local Keycloak volume, generated credentials, SQLite data, and logs.
#>
[CmdletBinding()]
param([switch]$Reset)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$infra = Join-Path $root 'infra\local-test'
$runtime = Join-Path $infra 'runtime'
$pidsFile = Join-Path $runtime 'pids.json'

if (Test-Path $pidsFile) {
    $pids = Get-Content $pidsFile -Raw | ConvertFrom-Json
    foreach ($name in @('frontend', 'backend')) {
        $processId = $pids.$name
        if ($processId) {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "Stopping $name process $processId ..."
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Remove-Item $pidsFile -Force -ErrorAction SilentlyContinue
}

Write-Host 'Stopping isolated Keycloak container ...'
$infraForWsl = $infra -replace '\\', '/'
$wslInfra = (& wsl -d Ubuntu -- wslpath -a "$infraForWsl").Trim()
$composeArgs = @('compose', '-p', 'sgsi-zta-f11', '-f', "$wslInfra/compose.yaml", 'down')
if ($Reset) { $composeArgs += '-v' }
& wsl -d Ubuntu -- docker @composeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'docker compose down returned a non-zero exit code.'
}

if ($Reset) {
    Write-Host 'Removing generated local test state ...'
    Remove-Item (Join-Path $infra '.test-credentials.local.json') -Force -ErrorAction SilentlyContinue
    Remove-Item $runtime -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Local integration stack stopped.'
