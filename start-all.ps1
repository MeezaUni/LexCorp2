$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Start-LoggedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [string]$LogName
    )

    $stdout = Join-Path $logs "$LogName.log"
    $stderr = Join-Path $logs "$LogName.error.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    return $process
}

function Get-ListeningProcessId {
    param([int]$Port)
    $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($connection) { return [int]$connection.OwningProcess }
    return $null
}

Write-Host 'Starting LexCorp services...' -ForegroundColor Cyan

Push-Location $root
try {
    Write-Host '[1/4] Starting Besu...' -ForegroundColor Yellow
    docker compose -f network/besu/docker-compose-active.yml up -d

    Write-Host '[2/4] Waiting for Besu RPC...' -ForegroundColor Yellow
    $rpcReady = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
            $response = Invoke-RestMethod -Uri 'http://127.0.0.1:8545' -Method Post -ContentType 'application/json' -Body $body
            if ($response.result -eq '0x343b') {
                $rpcReady = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    if (-not $rpcReady) {
        throw 'Besu RPC did not become ready on http://127.0.0.1:8545. Check Docker and logs with: docker compose -f network/besu/docker-compose-active.yml logs'
    }

    Write-Host '[3/4] Checking smart contract...' -ForegroundColor Yellow
    $deploymentFile = Join-Path $root 'contracts\deployments\localhost.json'
    $shouldDeploy = $true
    if (Test-Path $deploymentFile) {
        $deployment = Get-Content $deploymentFile | ConvertFrom-Json
        try {
            $codeBody = @{jsonrpc = '2.0'; method = 'eth_getCode'; params = @($deployment.address, 'latest'); id = 1} | ConvertTo-Json -Compress
            $codeResponse = Invoke-RestMethod -Uri 'http://127.0.0.1:8545' -Method Post -ContentType 'application/json' -Body $codeBody
            $shouldDeploy = [string]::IsNullOrWhiteSpace($codeResponse.result) -or $codeResponse.result -eq '0x'
        } catch {
            $shouldDeploy = $true
        }
    }

    if ($shouldDeploy) {
        Write-Host 'No deployed contract found; deploying AssetNFT...' -ForegroundColor Yellow
        Push-Location (Join-Path $root 'contracts')
        try {
            npx hardhat run scripts/deploy.js --network localhost | Tee-Object -FilePath (Join-Path $logs 'deploy.log')
            if ($LASTEXITCODE -ne 0) { throw 'Smart contract deployment failed. See logs/deploy.log.' }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "Reusing AssetNFT at $($deployment.address)" -ForegroundColor Green
    }

    Write-Host '[4/4] Starting backend and frontend...' -ForegroundColor Yellow
    $backendId = Get-ListeningProcessId -Port 8000
    if ($backendId) {
        Write-Host "Reusing backend already listening on port 8000 (PID: $backendId)" -ForegroundColor Green
        $backend = $null
    } else {
        $backend = Start-LoggedProcess -FilePath 'python' -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000') -WorkingDirectory (Join-Path $root 'backend') -LogName 'backend'
        $backendId = $backend.Id
    }

    $frontendId = Get-ListeningProcessId -Port 5173
    if ($frontendId) {
        Write-Host "Reusing frontend already listening on port 5173 (PID: $frontendId)" -ForegroundColor Green
        $frontend = $null
    } else {
        $frontend = Start-LoggedProcess -FilePath 'npm.cmd' -ArgumentList @('run', 'dev', '--', '--host') -WorkingDirectory (Join-Path $root 'frontend') -LogName 'frontend'
        $frontendId = $frontend.Id
    }

    @{
        Backend = $backendId
        Frontend = $frontendId
    } | ConvertTo-Json | Set-Content -Path (Join-Path $root '.pids.json')

    Write-Host ''
    Write-Host 'LexCorp is running.' -ForegroundColor Green
    Write-Host 'Besu:    http://localhost:8545'
    Write-Host 'Backend: http://localhost:8000'
    Write-Host 'Frontend: http://localhost:5173'
    Write-Host 'Logs:    .\logs\backend.log and .\logs\frontend.log'
    Write-Host 'Stop:    .\stop-all.ps1'
} finally {
    Pop-Location
}