# Share the local Ollama model with a remote CodeBloodhound backend.
# Starts tools/llm_gateway.py (API key check, two allowed calls) and an SSH tunnel through
# localhost.run, then prints the URL and key to put into the remote backend's environment.
# Data lives in %LOCALAPPDATA%\codebloodhound-llm: token.txt, logs, connection.txt.
# The free tunnel gets a new URL on every start. Cloudflare quick tunnels were blocked on this
# network (TLS to the edge is dropped), so this script uses plain SSH instead.

$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:LOCALAPPDATA 'codebloodhound-llm'
$gateway = Join-Path $PSScriptRoot 'llm_gateway.py'
$tokenFile = Join-Path $dir 'token.txt'
$port = 11500
New-Item -ItemType Directory -Force $dir | Out-Null

# Stop what an earlier start left running
Get-CimInstance Win32_Process | Where-Object {
    ($_.Name -like 'python*' -and $_.CommandLine -like '*llm_gateway.py*') -or
    ($_.Name -eq 'ssh.exe' -and $_.CommandLine -like '*localhost.run*')
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -Confirm:$false }

try { Invoke-RestMethod http://127.0.0.1:11434/api/tags -TimeoutSec 5 | Out-Null }
catch { throw 'Ollama is not running on 127.0.0.1:11434. Start the Ollama app first.' }

$python = (Get-Command python -ErrorAction Stop).Source
Start-Process -FilePath $python -ArgumentList @('-I', "`"$gateway`"", '--token-file', "`"$tokenFile`"", '--port', $port) `
    -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir 'gateway.log') -RedirectStandardError (Join-Path $dir 'gateway.err.log')

$tunnelLog = Join-Path $dir 'tunnel.log'
Remove-Item $tunnelLog -ErrorAction SilentlyContinue
Start-Process -FilePath 'ssh' -ArgumentList @(
    '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ServerAliveInterval=30', '-o', 'ExitOnForwardFailure=yes',
    '-R', "80:127.0.0.1:$port", 'nokey@localhost.run', '--', '--output', 'json'
) -WindowStyle Hidden -RedirectStandardOutput $tunnelLog -RedirectStandardError (Join-Path $dir 'tunnel.err.log')

$url = $null
for ($i = 0; $i -lt 60 -and -not $url; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $tunnelLog) {
        $match = Select-String -Path $tunnelLog -Pattern 'https://[a-z0-9.-]+\.lhr\.life' | Select-Object -Last 1
        if ($match) { $url = $match.Matches[0].Value }
    }
}
if (-not $url) { throw "The tunnel did not report a URL. See $tunnelLog" }

$token = (Get-Content $tokenFile -Raw).Trim()
$text = @"
LOCAL_LLM_BASE_URL = $url/v1
LOCAL_LLM_API_KEY  = $token
"@
Set-Content -Path (Join-Path $dir 'connection.txt') -Value $text -Encoding utf8
Write-Output $text
