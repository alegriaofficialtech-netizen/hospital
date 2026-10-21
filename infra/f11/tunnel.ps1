<#
.SYNOPSIS
  Opens the SSH tunnel that lets a Windows browser drive the F11 stack that
  runs entirely on Debian.

.DESCRIPTION
  Every hospital component (Keycloak, the Python backend, the static Angular
  frontend served by Caddy) keeps running on servidor-1. Windows only runs a
  browser, and this tunnel forwards two loopback ports:

    4200 -> 127.0.0.1:4200   the Angular frontend served by Caddy
    8085 -> 127.0.0.1:8085   the Keycloak issuer

  Open http://localhost:4200 in the browser. The forwarded addresses match the
  ones the stack is configured with, so the OIDC redirect URIs
  (http://localhost:4200/* and http://127.0.0.1:4200/*) and the issuer
  (http://127.0.0.1:8085) resolve identically from the browser. Do not use a
  different local port: the Keycloak client is registered for 4200.

  IMPORTANT: connect over the LAN address, not through the Tailscale alias.
  The server allows TCP forwarding only for sessions coming from
  192.168.1.7, and only towards the destinations listed in its PermitOpen
  directive. Over Tailscale every forward is refused with
  "administratively prohibited". 127.0.0.1:8085 is permitted today;
  127.0.0.1:4200 is not, so the frontend forward only works once the server
  policy allows it.

  AddressFamily=inet makes the forward IPv4-only on purpose. The browser
  resolves localhost to ::1 first and falls back to 127.0.0.1, which is the
  only address this tunnel listens on.

.PARAMETER Server
  LAN address or alias of the Debian machine. Use the LAN address: the
  Tailscale alias does not match the server's forwarding policy.

.PARAMETER User
  SSH user on that machine.

.PARAMETER Check
  Only test the tunnel and the stack behind it, then exit. Run it right after
  the stack was started on the server.

.EXAMPLE
  .\tunnel.ps1 -Check
  .\tunnel.ps1
#>
[CmdletBinding()]
param(
  [string]$Server = '192.168.1.36',
  [string]$User = 'elcra',
  [int]$FrontendPort = 4200,
  [int]$KeycloakPort = 8085,
  [switch]$Check
)

$ErrorActionPreference = 'Continue'

function Get-Status {
  param([string]$Url)
  try {
    $r = Invoke-WebRequest -Uri $Url -TimeoutSec 8 -UseBasicParsing
    return [int]$r.StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return 0
  }
}

if ($Check) {
  Write-Host 'Checking the tunnel and the stack behind it...' -ForegroundColor Cyan
  $app = Get-Status -Url ("http://localhost:{0}/" -f $FrontendPort)
  Write-Host ("  frontend     : HTTP {0}" -f $app)
  $api = Get-Status -Url ("http://localhost:{0}/api/v1/orders" -f $FrontendPort)
  Write-Host ("  api proxy    : HTTP {0}  (401 means the proxy reached the real backend)" -f $api)
  try {
    $disc = Invoke-RestMethod -Uri ("http://localhost:{0}/realms/hospital-lab-local/.well-known/openid-configuration" -f $KeycloakPort) -TimeoutSec 8
    Write-Host ("  issuer       : {0}" -f $disc.issuer) -ForegroundColor Green
  } catch {
    Write-Host '  issuer       : NOT reachable' -ForegroundColor Red
  }
  if ($app -ne 200) {
    Write-Host ''
    Write-Host 'The frontend forward did not work.' -ForegroundColor Red
    Write-Host 'The server permits forwarding only from 192.168.1.7 and only to the'
    Write-Host 'destinations in its PermitOpen list. If the ssh log says'
    Write-Host '"administratively prohibited", 127.0.0.1:4200 is not in that list.'
    exit 1
  }
  if ($api -eq 401) {
    Write-Host 'Tunnel and stack are consistent.' -ForegroundColor Green
    exit 0
  }
  Write-Host 'The tunnel works but the API behind the proxy did not answer 401.' -ForegroundColor Yellow
  exit 1
}

Write-Host 'F11 manual UI session over SSH.' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Open in the browser : http://localhost:4200' -ForegroundColor Green
Write-Host '  Keycloak issuer     : http://localhost:8085/realms/hospital-lab-local'
Write-Host ''
Write-Host 'Synthetic users (passwords in credentials.json on the server):'
Write-Host '  recepcion.test   admision    creates orders'
Write-Host '  laboratorio.test laboratorio  reads orders'
Write-Host '  medico.test      medico + TOTP, validates and releases results'
Write-Host '  medico.sinmfa    medico, no TOTP, validation must be refused'
Write-Host '  auditor.test     auditor     reads the audit trail'
Write-Host ''
Write-Host '  The TOTP secret for medico.test lives on the server at'
Write-Host '  /home/elcra/sgsi-zta-runtime/f11/credentials.json (mode 0600).'
Write-Host ''
Write-Host 'Press Ctrl+C to close the tunnel.' -ForegroundColor Yellow

$sshArgs = @(
  '-N',
  '-o', 'AddressFamily=inet',
  '-o', 'ServerAliveInterval=30',
  '-o', 'ExitOnForwardFailure=yes',
  '-L', ("{0}:127.0.0.1:{0}" -f $FrontendPort),
  '-L', ("{0}:127.0.0.1:{0}" -f $KeycloakPort),
  ("{0}@{1}" -f $User, $Server)
)

& ssh @sshArgs
exit $LASTEXITCODE
