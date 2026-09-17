$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$pidFile = Join-Path $root '.pids.json'
if (Test-Path $pidFile) {
    $pids = Get-Content $pidFile | ConvertFrom-Json
    foreach ($processId in @($pids.Backend, $pids.Frontend)) {
        if ($processId) {
            Stop-Process -Id ([int]$processId) -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

docker compose -f (Join-Path $root 'network/besu/docker-compose-active.yml') down
Write-Host 'Backend, frontend, and Besu stopped.' -ForegroundColor Green