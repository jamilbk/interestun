# Install the official signed Wintun DLL next to a built interestun executable.
[CmdletBinding()]
param(
    [string]$ExecutablePath = (Join-Path $PSScriptRoot '..\target\release\interestun.exe')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
$destination = Split-Path -Parent $executable
# Read the executable's PE machine type, so cross-built binaries and ARM64
# machines running x64 PowerShell get the correct DLL too.
$stream = [IO.File]::OpenRead($executable)
$reader = [IO.BinaryReader]::new($stream)
try {
    if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Executable is not a PE file' }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE signature' }
    $architecture = switch ($reader.ReadUInt16()) {
        0x8664 { 'amd64' }
        0x014C { 'x86' }
        0xAA64 { 'arm64' }
        0x01C4 { 'arm' }
        default { throw 'Unsupported executable architecture' }
    }
} finally { $reader.Dispose() }

# Version and SHA-256 published at https://www.wintun.net/.
$version = '0.14.1'
$expectedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$url = "https://www.wintun.net/builds/wintun-$version.zip"
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$tempName = 'interestun-wintun-' + [Guid]::NewGuid().ToString('N')
$staging = Join-Path $tempRoot $tempName
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $archive = Join-Path $staging 'wintun.zip'
    Write-Host "Downloading official Wintun $version ($architecture)..."
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
        throw 'Wintun archive SHA-256 does not match the official release'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $staging
    $dll = Join-Path $staging "wintun\bin\$architecture\wintun.dll"
    $signature = Get-AuthenticodeSignature -LiteralPath $dll
    if ($signature.Status -ne 'Valid') {
        throw "Wintun signature verification failed: $($signature.Status) - $($signature.StatusMessage)"
    }
    Write-Host "Verified SHA-256 and Authenticode signer: $($signature.SignerCertificate.Subject)"
    $files = @(
        @{ Source = $dll; Target = (Join-Path $destination 'wintun.dll') },
        @{ Source = (Join-Path $staging 'wintun\LICENSE.txt'); Target = (Join-Path $destination 'wintun-LICENSE.txt') }
    )
    # Check every destination before copying; never overwrite a different version.
    foreach ($file in $files) {
        if (-not (Test-Path -LiteralPath $file.Source -PathType Leaf)) { throw "Missing release file: $($file.Source)" }
        if (Test-Path -LiteralPath $file.Target) {
            if ((Get-FileHash -LiteralPath $file.Target).Hash -ne (Get-FileHash -LiteralPath $file.Source).Hash) {
                throw "A different file already exists at $($file.Target); move it aside before installing"
            }
        }
    }
    foreach ($file in $files) {
        if (-not (Test-Path -LiteralPath $file.Target)) {
            # File.Copy without overwrite also protects against a destination race.
            [IO.File]::Copy($file.Source, $file.Target, $false)
        }
    }
    Write-Host "Installed Wintun $version ($architecture) in $destination"
    Write-Host 'The kernel driver is initialized when the elevated daemon creates an adapter.'
} finally {
    # Delete only this invocation's checked, randomly named staging directory.
    $resolvedStaging = [IO.Path]::GetFullPath($staging)
    if ((Split-Path -Parent $resolvedStaging) -ne $tempRoot -or
        (Split-Path -Leaf $resolvedStaging) -ne $tempName) {
        throw 'Refusing to clean an unexpected staging path'
    }
    Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
}
