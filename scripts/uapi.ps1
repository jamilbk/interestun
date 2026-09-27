# Direct UAPI client for an interestun daemon running as elevated Administrator.
# Stock wg.exe additionally requires the daemon/pipe owner to be LocalSystem.
[CmdletBinding()]
param(
    [string]$Interface = 'interestun',
    [string]$RequestFile,
    [string]$Request
)
$ErrorActionPreference = 'Stop'
if ($Interface -match '[\\/:\x00-\x1f]' -or $Interface.Length -eq 0) {
    throw 'Invalid interface name'
}
if ($RequestFile -and $Request) { throw 'Use either RequestFile or Request, not both' }
$requestText = "get=1`n`n"
if ($Request) { $requestText = $Request.Replace("`r`n", "`n").TrimEnd("`n") + "`n`n" }
if ($RequestFile) {
    $requestText = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $RequestFile).Path).Replace("`r`n", "`n").TrimEnd("`n") + "`n`n"
}
if ([Text.Encoding]::UTF8.GetByteCount($requestText) -gt 1MB) { throw 'Request exceeds 1 MiB' }
$pipe = [IO.Pipes.NamedPipeClientStream]::new(
    '.', "ProtectedPrefix\Administrators\WireGuard\$Interface",
    [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous,
    [Security.Principal.TokenImpersonationLevel]::Anonymous
)
try {
    $pipe.Connect(5000)
    $bytes = [Text.Encoding]::UTF8.GetBytes($requestText)
    if (-not $pipe.WriteAsync($bytes, 0, $bytes.Length).Wait(5000)) { throw 'Write timed out' }
    $reader = [IO.StreamReader]::new($pipe, [Text.Encoding]::UTF8, $false, 4096, $true)
    try {
        while ($true) {
            $read = $reader.ReadLineAsync()
            if (-not $read.Wait(5000)) { throw 'Read timed out' }
            $line = $read.GetAwaiter().GetResult()
            if ($null -eq $line) { throw 'Server closed before completing the response' }
            if ($line.Length -eq 0) { break }
            Write-Output $line
        }
    } finally { $reader.Dispose() }
} finally { $pipe.Dispose() }
