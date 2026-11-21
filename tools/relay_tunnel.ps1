# Keep an SSH reverse tunnel to the VPS relay open: VPS 127.0.0.1:18080 -> this PC 127.0.0.1:8080.
# Started hidden by start_site.ps1; reconnects after network drops, sleep or a VPS reboot.
# The key is accepted only by the restricted "tunnel" user (see tools/vps/setup_relay.sh).

param(
    [Parameter(Mandatory)][string]$Target,   # tunnel@<vps address>
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Log,
    [int]$LocalPort = 8080,
    [int]$RemotePort = 18080
)

function Write-TunnelLog([string]$text) {
    Add-Content -Path $Log -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $text" -Encoding utf8
}

$failures = 0
while ($true) {
    Write-TunnelLog "connecting to $Target"
    $started = Get-Date
    & ssh -N -T -i $Key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new `
        -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o ConnectTimeout=15 `
        -R "127.0.0.1:${RemotePort}:127.0.0.1:$LocalPort" $Target 2>&1 | ForEach-Object { Write-TunnelLog "ssh: $_" }
    $code = $LASTEXITCODE
    # a connection that lived for a while resets the backoff; quick failures wait longer, up to a minute
    $failures = if (((Get-Date) - $started).TotalSeconds -gt 60) { 0 } else { [Math]::Min($failures + 1, 6) }
    $delay = [Math]::Min(5 * [Math]::Pow(2, [Math]::Max($failures - 1, 0)), 60)
    Write-TunnelLog "ssh exited with code $code, reconnecting in $delay s"
    Start-Sleep -Seconds $delay
}
