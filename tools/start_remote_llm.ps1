# Share the local Ollama model with a remote CodeBloodhound backend.
# Starts tools/llm_gateway.py (API key check, two allowed calls) and an SSH tunnel through
# localhost.run. Prints the tunnel URL and the path of the token file; the token itself is
# never printed or logged.
#
# Files in %LOCALAPPDATA%\codebloodhound-llm:
#   token.txt       the API key, readable only by the current user (the one place it is stored)
#   tunnel-url.txt  the current public URL (no secrets)
#   gateway.pid, tunnel.pid  processes started by this script; a restart stops only these
#   *.log           gateway and tunnel logs (no request bodies, no token)
#
# The free tunnel gets a new URL on every start. Cloudflare quick tunnels were blocked on this
# network (TLS to the edge is dropped), so this script uses plain SSH instead.
# Pass -RotateToken to issue a new key; the remote backend then needs the new value.

param([switch]$RotateToken, [switch]$Stop)

$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:LOCALAPPDATA 'codebloodhound-llm'
$gateway = Join-Path $PSScriptRoot 'llm_gateway.py'
$tokenFile = Join-Path $dir 'token.txt'
$port = 11500
New-Item -ItemType Directory -Force $dir | Out-Null

function Stop-OwnProcess([string]$pidFile, [scriptblock]$isOurs) {
    if (-not (Test-Path $pidFile)) { return }
    $id = (Get-Content $pidFile -Raw).Trim()
    Remove-Item $pidFile -Force
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$id)" -ErrorAction SilentlyContinue
    if ($process -and (& $isOurs $process)) { taskkill /PID $process.ProcessId /T /F 2>&1 | Out-Null }
}

# Stop only what this script started earlier: same PID and the command line it used
Stop-OwnProcess (Join-Path $dir 'gateway.pid') { param($p) $p.CommandLine -like "*$gateway*" -and $p.CommandLine -like "*--port $port*" }
Stop-OwnProcess (Join-Path $dir 'tunnel.pid') { param($p) $p.Name -eq 'ssh.exe' -and $p.CommandLine -like "*80:127.0.0.1:${port}*localhost.run*" }

if ($Stop) {
    Remove-Item (Join-Path $dir 'tunnel-url.txt') -ErrorAction SilentlyContinue
    Write-Output 'Stopped the model gateway and tunnel.'
    return
}

try { Invoke-RestMethod http://127.0.0.1:11434/api/tags -TimeoutSec 5 | Out-Null }
catch { throw 'Ollama is not running on 127.0.0.1:11434. Start the Ollama app first.' }

if ($RotateToken -and (Test-Path $tokenFile)) { Remove-Item $tokenFile -Force }
if (-not (Test-Path $tokenFile)) {
    New-Item -ItemType File $tokenFile | Out-Null
    # Only the current user may read the key: drop inherited permissions before writing it
    icacls $tokenFile /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:(R,W)" | Out-Null
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($tokenFile, $token)
}

$python = (Get-Command python -ErrorAction Stop).Source
$gatewayProcess = Start-Process -FilePath $python -PassThru -WindowStyle Hidden `
    -ArgumentList @('-I', "`"$gateway`"", '--token-file', "`"$tokenFile`"", '--port', $port) `
    -RedirectStandardOutput (Join-Path $dir 'gateway.log') -RedirectStandardError (Join-Path $dir 'gateway.err.log')
Set-Content (Join-Path $dir 'gateway.pid') $gatewayProcess.Id

$tunnelLog = Join-Path $dir 'tunnel.log'
Remove-Item $tunnelLog -ErrorAction SilentlyContinue
$tunnelProcess = Start-Process -FilePath 'ssh' -PassThru -WindowStyle Hidden -ArgumentList @(
    '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ServerAliveInterval=30', '-o', 'ExitOnForwardFailure=yes',
    '-R', "80:127.0.0.1:$port", 'nokey@localhost.run', '--', '--output', 'json'
) -RedirectStandardOutput $tunnelLog -RedirectStandardError (Join-Path $dir 'tunnel.err.log')
Set-Content (Join-Path $dir 'tunnel.pid') $tunnelProcess.Id

$url = $null
for ($i = 0; $i -lt 60 -and -not $url; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $tunnelLog) {
        $match = Select-String -Path $tunnelLog -Pattern 'https://[a-z0-9.-]+\.lhr\.life' | Select-Object -Last 1
        if ($match) { $url = $match.Matches[0].Value }
    }
}
if (-not $url) { throw "The tunnel did not report a URL. See $tunnelLog" }

[IO.File]::WriteAllText((Join-Path $dir 'tunnel-url.txt'), "$url/v1")  # no BOM, safe to copy
Remove-Item (Join-Path $dir 'connection.txt') -ErrorAction SilentlyContinue  # older versions kept the token there
Write-Output "LOCAL_LLM_BASE_URL = $url/v1"
Write-Output "LOCAL_LLM_API_KEY  = contents of $tokenFile"
