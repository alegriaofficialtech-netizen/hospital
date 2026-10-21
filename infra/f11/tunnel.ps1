<#
.SYNOPSIS
  Opens the SSH tunnel that lets a Windows browser drive the F11 stack that
  runs entirely on Debian.

.DESCRIPTION
  Every hospital component (Keycloak, the Python backend, the static Angular
  frontend) keeps running on servidor-1. Windows only runs a browser, and
  this tunnel forwards two loopback ports:

    4200 -> 127.0.0.1:4200   the static Angular frontend (Caddy)
    8085 -> 127.0.0.1:8085   the Keycloak issuer

  The forwarded addresses match the ones the stack was configured with, so the
  OIDC redirect URIs (http://127.0.0.1:4200/*) and the issuer
  (http://127.0.0.1:8085) resolve identically from the browser. Do not use
  a different local port: the client is registered for 4200.

.PARAMETER Server
  SSH alias or host name of the Debian machine.

.PARAMETER User
  SSH user on that machine.

.PARAMETER Check
  Only test whether both local ports answer, then exit. Useful right after
  the stack was started on the server.

.EXAMPLE
  .\tunnel.ps1 -Check
  .\tunnel.ps1
#>
[CmdletBinding()]
param(
  [string]$Server = 'servidor-1',
  [string]$User = 'elcra',
  [int]$FrontendPort = 4200,
  [int]$KeycloakPort = 8085,
  [switch]$Check
)

$ErrorActionPreference = 'Stop'

function Test-LocalPort {
  param([int]$Port, [string]$Label)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $task = $client.ConnectAsync('127.0.0.1', $Port)
    if (-not $task.Wait(2000)) {
      Write-Host ("  {0,-10} port {1}: NOT reachable" -f $Label, $Port) -ForegroundColor Red
      return $false
    }
    Write-Host ("  {0,-10} port {1}: reachable" -f $Label, $Port) -ForegroundColor Green
    return $true
  } catch {
    Write-Host ("  {0,-10} port {1}: NOT reachable" -f $Label, $Port) -ForegroundColor Red
    return $false
  } finally {
    $client.Close()
  }
}

if ($Check) {
  Write-Host 'Checking the forwarded ports...'
  $front = Test-LocalPort -Port $FrontendPort -Label 'frontend'
  $kc = Test-LocalPort -Port $KeycloakPort -Label 'keycloak'
  if ($front -and $kc) {
    Write-Host 'Tunnel is up.' -ForegroundColor Green
    exit 0
  }
  Write-Host 'Tunnel is not complete. Is the stack running and is the tunnel open?' -ForegroundColor Red
  exit 1
}

Write-Host 'F11 manual UI session over SSH.' -ForegroundColor Cyan
Write-Host ''
Write-Host ("  frontend : http://127.0.0.1:{0}" -f $FrontendPort)
Write-Host ("  keycloak : http://127.0.0.1:{0}/realms/hospital-lab-local" -f $KeycloakPort)
Write-Host ''
Write-Host 'Synthetic users (passwords in credentials.json on the server):'
Write-Host '  recepcion.test   admision    creates orders'
Write-Host '  laboratorio.test laboratorio  reads orders'
Write-Host '  medico.test      medico + TOTP, validates and releases results'
Write-Host '  medico.sinmfa    medico, no TOTP, validation must be refused'
Write-Host '  auditor.test     auditor     reads the audit trail'
Write-Host ''
Write-Host 'Press Ctrl+C to close the tunnel.' -ForegroundColor Yellow

$sshArgs = @(
  '-N',
  '-o', 'ServerAliveInterval=30',
  '-o', 'ExitOnForwardFailure=yes',
  '-L', ("{0}:127.0.0.1:{0}" -f $FrontendPort),
  '-L', ("{0}:127.0.0.1:{0}" -f $KeycloakPort),
  ("{0}@{1}" -f $User, $Server)
)

& ssh @sshArgs
exit $LASTEXITCODE
