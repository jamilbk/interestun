# Run from elevated PowerShell as the same Windows user on every invocation.
[CmdletBinding()]
param(
    [string]$Interface = 'interestun',
    [string]$Endpoint = '192.168.1.211',
    [ValidateRange(1, 65535)][int]$Port = 51820,
    [string]$MacPublicKey,
    [string]$LocalAddress = '10.20.0.1',
    [string]$PeerAddress = '10.20.0.2'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in your elevated PowerShell terminal'
}
if ($Interface -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use an alphanumeric interface name' }
foreach ($address in @($Endpoint, $LocalAddress, $PeerAddress)) {
    if ([Net.IPAddress]::Parse($address).AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'This setup helper expects IPv4 addresses'
    }
}
$peerHex = $null
if ($MacPublicKey) {
    $publicBytes = [Convert]::FromBase64String($MacPublicKey.Trim())
    if ($publicBytes.Length -ne 32) { throw 'Mac public key must decode to 32 bytes' }
    $peerHex = -join ($publicBytes | ForEach-Object { $_.ToString('x2') })
}
$adapter = Get-NetAdapter -Name $Interface
# Refuse to replace an unrelated IPv4 configuration on this adapter.
$existing = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if ($existing | Where-Object { $_.IPAddress -ne $LocalAddress -and $_.IPAddress -notlike '169.254.*' }) {
    throw 'Adapter already has a different IPv4 address; inspect it before applying this setup'
}
$peerRoute = "$PeerAddress/32"
if (Get-NetRoute -DestinationPrefix $peerRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -ne $adapter.ifIndex }) {
    throw 'The peer address already has a host route through another adapter'
}
$keyDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'interestun'
$keyFile = Join-Path $keyDirectory "$Interface.keys.dpapi"
if (Test-Path -LiteralPath $keyFile) {
    $clear = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyFile), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $keys = [Text.Encoding]::UTF8.GetString($clear) | ConvertFrom-Json
} else {
    # Never rotate a live identity just because the saved file is missing.
    $current = @(& (Join-Path $PSScriptRoot 'uapi.ps1') -Interface $Interface)
    if ($current -notcontains 'errno=0') { throw 'Could not query daemon' }
    if ($current | Where-Object { $_ -like 'private_key=*' }) {
        throw 'Daemon already has a private key but no saved key file exists; refusing to rotate it'
    }
    $manifest = Join-Path $PSScriptRoot '..\Cargo.toml'
    $generated = & cargo run --quiet --locked --manifest-path $manifest --example keygen
    if ($LASTEXITCODE -ne 0) { throw 'Key generation failed' }
    $keys = $generated | ConvertFrom-Json
    $encrypted = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($generated), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.Directory]::CreateDirectory($keyDirectory) | Out-Null
    $file = [IO.File]::Open($keyFile, [IO.FileMode]::CreateNew)
    try { $file.Write($encrypted, 0, $encrypted.Length) } finally { $file.Dispose() }
}
$lines = @('set=1', "private_key=$($keys.private_key)", "listen_port=$Port")
if ($peerHex) {
    $lines += @("public_key=$peerHex", "endpoint=${Endpoint}:$Port", 'replace_allowed_ips=true', "allowed_ip=$peerRoute", 'persistent_keepalive_interval=25')
}
$response = @(& (Join-Path $PSScriptRoot 'uapi.ps1') -Interface $Interface -Request ($lines -join "`n"))
if ($response -notcontains 'errno=0') { throw "Daemon rejected configuration: $response" }
if (-not ($existing | Where-Object { $_.IPAddress -eq $LocalAddress })) {
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $LocalAddress -PrefixLength 32 -PolicyStore ActiveStore | Out-Null
}
if (-not (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix $peerRoute -ErrorAction SilentlyContinue)) {
    New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix $peerRoute -NextHop 0.0.0.0 -PolicyStore ActiveStore | Out-Null
}
# Scope inbound ping to this one adapter and tunnel peer. Windows initiates UDP;
# no broad inbound UDP/firewall rule is needed for this test setup.
$rule = "interestun-$Interface-test-icmp"
if (-not (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias $Interface -RemoteAddress $PeerAddress -LocalAddress $LocalAddress -Profile Any | Out-Null
}
$publicBytes = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $publicBytes[$i] = [Convert]::ToByte($keys.public_key.Substring($i * 2, 2), 16) }
Write-Output "Windows public key: $([Convert]::ToBase64String($publicBytes))"
Write-Output "Tunnel: $LocalAddress -> $PeerAddress; UDP port: $Port"
Write-Output "Saved key pair encrypted for this Windows user: $keyFile"
if (-not $peerHex) { Write-Output 'Run again with -MacPublicKey after obtaining the Mac public key.' }
else { Write-Output "Peer configured at ${Endpoint}:$Port. Test with: ping $PeerAddress" }
