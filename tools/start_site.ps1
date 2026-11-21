# Host the whole CodeBloodhound site on this PC for a demo: PostgreSQL, FastAPI, the editor
# behind a password (tools/serve_site.py) and a public address: either a VPS relay with your
# domain (tools/vps/setup_relay.sh) or, without one, a free localhost.run tunnel.
#
#   powershell -ExecutionPolicy Bypass -File tools\start_site.ps1          # start or restart
#   powershell -ExecutionPolicy Bypass -File tools\start_site.ps1 -Stop    # stop everything it started
#   ... start_site.ps1 -Relay tunnel@203.0.113.5 -Domain example.org    # remember the VPS relay and use it
#   ... start_site.ps1 -Relay none                                       # forget it, back to localhost.run
#
# Expects portable PostgreSQL binaries in -PgBin and a database initialised in
# %LOCALAPPDATA%\codebloodhound-site\pgdata (user cyber_garden, password in db-password.txt).
# Files in %LOCALAPPDATA%\codebloodhound-site:
#   site-password.txt  password for user "team" (owner-only), db-password.txt  database password
#   site-url.txt       the current public URL, logs\  postgres, api, site and tunnel logs
#   relay.txt          "<user@vps> <domain>" when a VPS relay is configured
#   deepseek-key.txt   optional DeepSeek API key (made owner-only on start), deepseek-models.txt  optional model names
#   *.pid              processes this script started; restarts stop only these
# Passwords are never printed. The free tunnel gets a new URL on every start; the relay keeps the domain.
# The relay tunnel uses its own key, ~\.ssh\codebloodhound_relay, accepted only by the restricted VPS user.

param(
    [switch]$Stop,
    [switch]$Url,
    [string]$PgBin = (Join-Path $env:LOCALAPPDATA 'codebloodhound-site\pg17\pgsql\bin'),
    [string]$Model = 'qwen3:8b',
    [string]$Relay,
    [string]$Domain
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $env:LOCALAPPDATA 'codebloodhound-site'
$logs = Join-Path $dir 'logs'
$pgdata = Join-Path $dir 'pgdata'
New-Item -ItemType Directory -Force $logs | Out-Null
$relayFile = Join-Path $dir 'relay.txt'
$relayKey = Join-Path $env:USERPROFILE '.ssh\codebloodhound_relay'

if ($Relay -eq 'none') { Remove-Item $relayFile -ErrorAction SilentlyContinue }
elseif ($Relay) {
    if ($Relay -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$') { throw 'Pass -Relay as user@host, e.g. tunnel@203.0.113.5' }
    if ($Domain -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { throw 'Pass -Domain with the site domain, e.g. example.org' }
    [IO.File]::WriteAllText($relayFile, "$Relay $Domain")
}
$relayTarget, $relayDomain = if (Test-Path $relayFile) { (Get-Content $relayFile -Raw).Trim() -split '\s+' } else { $null, $null }

function Protect-NewSecret([string]$path, [int]$bytes) {
    if (Test-Path $path) { return }
    New-Item -ItemType File $path | Out-Null
    icacls $path /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:(R,W)" | Out-Null
    $buffer = New-Object byte[] $bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    [IO.File]::WriteAllText($path, ([Convert]::ToBase64String($buffer) -replace '[+/=]', ''))
}

function Stop-OwnProcess([string]$name, [scriptblock]$isOurs) {
    $pidFile = Join-Path $dir "$name.pid"
    if (-not (Test-Path $pidFile)) { return }
    $id = [int](Get-Content $pidFile -Raw).Trim()
    Remove-Item $pidFile -Force
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $id" -ErrorAction SilentlyContinue
    # taskkill /T: a venv python.exe is a launcher with a child process that must stop too
    if ($process -and (& $isOurs $process)) { taskkill /PID $id /T /F 2>&1 | Out-Null }
}

function Get-TunnelUrl {
    # localhost.run rotates anonymous domains; the log records every address it hands out
    $match = Select-String -Path (Join-Path $logs 'tunnel.log') -Pattern 'https://[a-z0-9.-]+\.lhr\.life' -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($match) { $match.Matches[0].Value }
}

if ($Url) {
    $current = if ($relayDomain) { "https://$relayDomain" } else { Get-TunnelUrl }
    if (-not $current) { throw 'The site tunnel is not running. Start it without -Url.' }
    [IO.File]::WriteAllText((Join-Path $dir 'site-url.txt'), $current)
    Write-Output "Site: $current"
    return
}

function Start-Logged([string]$name, [string]$file, [string[]]$arguments, [string]$workdir = $repo) {
    $process = Start-Process -FilePath $file -ArgumentList $arguments -WorkingDirectory $workdir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logs "$name.log") -RedirectStandardError (Join-Path $logs "$name.err.log")
    Set-Content (Join-Path $dir "$name.pid") $process.Id
    return $process
}

function Wait-Port([int]$port, [int]$seconds) {
    for ($i = 0; $i -lt $seconds * 2; $i++) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-Postgres([int]$seconds) {
    $isReady = Join-Path $PgBin 'pg_isready.exe'
    for ($i = 0; $i -lt $seconds * 2; $i++) {
        & $isReady -h 127.0.0.1 -p 5432 -q
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

Stop-OwnProcess 'tunnel' { param($p) $p.Name -eq 'ssh.exe' -and $p.CommandLine -like '*80:127.0.0.1:8080*localhost.run*' }
Stop-OwnProcess 'relay' { param($p) $p.CommandLine -like '*relay_tunnel.ps1*' }
Stop-OwnProcess 'site' { param($p) $p.CommandLine -like "*serve_site.py*" }
Stop-OwnProcess 'api' { param($p) $p.CommandLine -like "*uvicorn*backend.main:app*" }
if ($Stop) {
    if (Test-Path (Join-Path $pgdata 'postmaster.pid')) { & (Join-Path $PgBin 'pg_ctl.exe') -D $pgdata stop -m fast | Out-Null }
    Remove-Item (Join-Path $dir 'site-url.txt') -ErrorAction SilentlyContinue
    Write-Output 'Stopped the tunnel, site, API and PostgreSQL.'
    return
}

# PostgreSQL: pg_ctl tracks its own process through pgdata\postmaster.pid
if (-not (Get-NetTCPConnection -LocalPort 5432 -State Listen -ErrorAction SilentlyContinue)) {
    Start-Process (Join-Path $PgBin 'pg_ctl.exe') -ArgumentList @('-D', "`"$pgdata`"", '-l', "`"$(Join-Path $logs 'postgres.log')`"", 'start') -WindowStyle Hidden
    if (-not (Wait-Port 5432 20)) { throw "PostgreSQL did not start. See $logs\postgres.log" }
}
# The port opens before the database accepts queries: after an unclean shutdown PostgreSQL first
# replays its log and answers "the database system is starting up", which made FastAPI exit
if (-not (Wait-Postgres 60)) { throw "PostgreSQL is not ready to accept connections. See $logs\postgres.log" }

try { Invoke-RestMethod http://127.0.0.1:11434/api/tags -TimeoutSec 5 | Out-Null }
catch { Write-Warning 'Ollama is not running: scans work, AI answers will report that the model is unavailable.' }

# Two anonymous localhost.run tunnels from one PC can end up on the same domain: stop the model tunnel
$llmTunnel = Join-Path $env:LOCALAPPDATA 'codebloodhound-llm\tunnel.pid'
if (Test-Path $llmTunnel) {
    Write-Warning 'Stopping the model tunnel from start_remote_llm.ps1: the site reaches Ollama directly, and two anonymous tunnels collide.'
    & (Join-Path $PSScriptRoot 'start_remote_llm.ps1') -Stop | Out-Null
}

foreach ($port in 8000, 8080) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { throw "Port $port is already in use by another program." }
}

# FastAPI: the environment is set for this process only and inherited by uvicorn
$dbPassword = (Get-Content (Join-Path $dir 'db-password.txt') -Raw).Trim()
$env:DATABASE_URL = "postgresql://cyber_garden:$dbPassword@127.0.0.1:5432/cyber_garden"
$env:LLM_PROVIDER = 'local'
$env:LOCAL_LLM_MODEL = $Model
$env:LLM_TIMEOUT_SECONDS = '180'
$env:PYTHONIOENCODING = 'utf-8'
# DeepSeek stays optional: with a key in deepseek-key.txt it appears in the editor's model list,
# and each run still needs the user's consent to send findings outside this PC
$deepseekFile = Join-Path $dir 'deepseek-key.txt'
$deepseekModels = Join-Path $dir 'deepseek-models.txt'
if ((Test-Path $deepseekFile) -and (Get-Content $deepseekFile -Raw).Trim()) {
    icacls $deepseekFile /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:(R,W)" | Out-Null
    $env:DEEPSEEK_API_KEY = (Get-Content $deepseekFile -Raw).Trim()
    if (Test-Path $deepseekModels) {
        $names = ((Get-Content $deepseekModels -Raw) -split '[,\s]+' | Where-Object { $_ }) -join ','
        if ($names) { $env:DEEPSEEK_MODELS = $names; $env:DEEPSEEK_MODEL = ($names -split ',')[0] }
    }
}
$python = Join-Path $repo '.venv\Scripts\python.exe'
Start-Logged 'api' $python @('-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000') | Out-Null
Remove-Item Env:DATABASE_URL
Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
if (-not (Wait-Port 8000 30)) { throw "The API did not start. See $logs\api.err.log" }

$passwordFile = Join-Path $dir 'site-password.txt'
Protect-NewSecret $passwordFile 18
Start-Logged 'site' $python @('-I', "`"$(Join-Path $PSScriptRoot 'serve_site.py')`"", '--password-file', "`"$passwordFile`"", '--port', '8080') | Out-Null
if (-not (Wait-Port 8080 15)) { throw "The site proxy did not start. See $logs\site.err.log" }
# serve_site.py writes site-invite.txt; <site>/?key=<invite> opens the site without the password
$inviteFile = Join-Path $dir 'site-invite-link.txt'
function Save-InviteLink([string]$url) {
    $key = (Get-Content (Join-Path $dir 'site-invite.txt') -Raw).Trim()
    [IO.File]::WriteAllText($inviteFile, "$url/?key=$key")
}

if ($relayTarget) {
    if (-not (Test-Path $relayKey)) { throw "The relay key $relayKey is missing. Create it with ssh-keygen -t ed25519 -f $relayKey" }
    $relayLog = Join-Path $logs 'relay.log'
    Start-Logged 'relay' 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $PSScriptRoot 'relay_tunnel.ps1')`"",
        '-Target', $relayTarget, '-Key', "`"$relayKey`"", '-Log', "`"$relayLog`"") | Out-Null
    $siteUrl = "https://$relayDomain"
    $reached = $false
    for ($i = 0; $i -lt 20 -and -not $reached; $i++) {
        Start-Sleep -Seconds 1
        try { Invoke-WebRequest $siteUrl -UseBasicParsing -TimeoutSec 5 | Out-Null; $reached = $true }
        catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $reached = $true } }
    }
    [IO.File]::WriteAllText((Join-Path $dir 'site-url.txt'), $siteUrl)
    Save-InviteLink $siteUrl
    if (-not $reached) { Write-Warning "$siteUrl does not answer yet. Check DNS for $relayDomain and $relayLog" }
    Write-Output "Site:     $siteUrl"
    Write-Output "User:     team"
    Write-Output "Password: contents of $passwordFile"
    Write-Output "No-password link: contents of $inviteFile"
    Write-Output "Logs:     $logs (visitor addresses: /var/log/caddy/access.log on the VPS)"
    return
}

$tunnelLog = Join-Path $logs 'tunnel.log'
Remove-Item $tunnelLog -ErrorAction SilentlyContinue
Start-Logged 'tunnel' 'ssh' @('-o', 'StrictHostKeyChecking=accept-new', '-o', 'ServerAliveInterval=30', '-o', 'ExitOnForwardFailure=yes',
    '-R', '80:127.0.0.1:8080', 'nokey@localhost.run', '--', '--output', 'json') | Out-Null
$siteUrl = $null
for ($i = 0; $i -lt 60 -and -not $siteUrl; $i++) {
    Start-Sleep -Milliseconds 500
    $siteUrl = Get-TunnelUrl
}
if (-not $siteUrl) { throw "The tunnel did not report a URL. See $tunnelLog" }
[IO.File]::WriteAllText((Join-Path $dir 'site-url.txt'), $siteUrl)
Save-InviteLink $siteUrl

Write-Output "Site:     $siteUrl"
Write-Output "User:     team"
Write-Output "Password: contents of $passwordFile"
Write-Output "No-password link: contents of $inviteFile"
Write-Output "Logs:     $logs"
Write-Output 'The domain rotates from time to time: run this script with -Url to see the current one.'
