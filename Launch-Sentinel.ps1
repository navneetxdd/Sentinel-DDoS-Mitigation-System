#Requires -Version 5.0

param(
    [ValidateSet('start', 'status', 'stop')]
    [string]$Action = 'start',

    [ValidateSet('baseline', 'progressive', 'full', 'production')]
    [string]$LaunchMode = 'production',

    [string]$WSLDistro = 'kali-linux',
    [string]$RepoRoot = $PSScriptRoot,

    [switch]$NoBuild,
    [switch]$OpenDashboard
)

$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $RepoRoot '.sentinel'
$logDir = Join-Path $stateDir 'logs'
$stateFile = Join-Path $stateDir 'launcher-state.json'

$ports = @{
    sdn = 8080
    websocket = 8765
    explain = 5001
    frontend = 5173
}

function Initialize-Directories {
    if (!(Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir | Out-Null }
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
}

function Get-PortPid([int]$Port) {
    $line = netstat -ano | Select-String (":" + $Port + "\\s") | Select-Object -First 1
    if (!$line) { return $null }
    $parts = ($line.ToString().Trim() -split '\\s+')
    if ($parts.Length -lt 5) { return $null }
    $procId = 0
    if ([int]::TryParse($parts[-1], [ref]$procId)) { return $procId }
    return $null
}

function Test-PortOpen([int]$Port) {
    return $null -ne (Get-PortPid -Port $Port)
}

function Export-LauncherState($obj) {
    Initialize-Directories
    $obj | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $stateFile
}

function Import-LauncherState {
    if (!(Test-Path $stateFile)) { return $null }
    try { return Get-Content $stateFile -Raw | ConvertFrom-Json } catch { return $null }
}

function Start-BackgroundProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    if (Test-Path $StdoutPath) { Remove-Item $StdoutPath -Force }
    if (Test-Path $StderrPath) { Remove-Item $StderrPath -Force }

    return Start-Process -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath `
        -PassThru
}

function Write-ServiceStatus {
    $sdnPid = Get-PortPid -Port $ports.sdn
    $wsPid = Get-PortPid -Port $ports.websocket
    $explainPid = Get-PortPid -Port $ports.explain
    $frontendPid = Get-PortPid -Port $ports.frontend

    Write-Host ""
    Write-Host "Sentinel Service Status" -ForegroundColor Cyan
    Write-Host "-----------------------" -ForegroundColor Cyan
    Write-Host ("SDN        : " + ($(if ($sdnPid) {"UP (pid $sdnPid)"} else {"DOWN"})))
    Write-Host ("WebSocket  : " + ($(if ($wsPid) {"UP (pid $wsPid)"} else {"DOWN"})))
    Write-Host ("Explain API: " + ($(if ($explainPid) {"UP (pid $explainPid)"} else {"DOWN"})))
    Write-Host ("Frontend   : " + ($(if ($frontendPid) {"UP (pid $frontendPid)"} else {"DOWN"})))
    Write-Host ""
    Write-Host ("Logs: " + $logDir)
}

function Stop-ByPort([int]$Port) {
    $procId = Get-PortPid -Port $Port
    if ($procId) {
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            Write-Host ("Stopped pid " + $procId + " on port " + $Port)
        } catch {
            Write-Host ("Could not stop pid " + $procId + " on port " + $Port) -ForegroundColor Yellow
        }
    }
}

if (!(Test-Path (Join-Path $RepoRoot 'sentinel_pipeline.c'))) {
    Write-Host ("[FAIL] Repository not found at " + $RepoRoot) -ForegroundColor Red
    exit 1
}

if ($Action -eq 'status') {
    Write-ServiceStatus
    exit 0
}

if ($Action -eq 'stop') {
    Stop-ByPort -Port $ports.frontend
    Stop-ByPort -Port $ports.explain
    Stop-ByPort -Port $ports.websocket
    Stop-ByPort -Port $ports.sdn
    Write-Host "Done."
    exit 0
}

Initialize-Directories

$envVars = @{
    'SENTINEL_PROFILE' = $LaunchMode
    'SENTINEL_INTEGRATION_PROFILE' = $LaunchMode
}

$wslRepoPath = (($RepoRoot -replace '\\', '/' -replace '^([A-Za-z]):', '/mnt/$1')).ToLower().TrimEnd('.')

Write-Host ""
Write-Host "Sentinel Launcher (Single-Window Mode)" -ForegroundColor Cyan
Write-Host "Profile: $LaunchMode"
Write-Host "WSL Distro: $WSLDistro"
Write-Host "Repo: $RepoRoot"
Write-Host ""

if (!$NoBuild) {
    Write-Host "Building backend in WSL..."
    $buildOut = wsl -d $WSLDistro -u root -e bash -lc "cd '$wslRepoPath' && make pipeline" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed." -ForegroundColor Red
        Write-Host $buildOut
        exit 1
    }
    Write-Host "Build OK." -ForegroundColor Green
}

$started = @{}

if (!(Test-PortOpen -Port $ports.sdn)) {
    $sdn = Start-BackgroundProcess -Name 'sdn' -FilePath 'wsl.exe' -WorkingDirectory $RepoRoot `
        -Arguments @('-d', $WSLDistro, '-u', 'root', '-e', 'bash', '-lc', "cd '$wslRepoPath' && python3 scripts/start_ryu.py") `
        -StdoutPath (Join-Path $logDir 'sdn.out.log') -StderrPath (Join-Path $logDir 'sdn.err.log')
    $started.sdn = $sdn.Id
}

if (!(Test-PortOpen -Port $ports.websocket)) {
    $exports = ($envVars.GetEnumerator() | ForEach-Object { "export " + $_.Key + "=" + $_.Value }) -join '; '
    $backendCmd = "$exports; cd '$wslRepoPath' && ./sentinel_pipeline -i lo -q 0 -w 8765 --controller http://127.0.0.1:8080 -v"
    $backend = Start-BackgroundProcess -Name 'backend' -FilePath 'wsl.exe' -WorkingDirectory $RepoRoot `
        -Arguments @('-d', $WSLDistro, '-u', 'root', '-e', 'bash', '-lc', $backendCmd) `
        -StdoutPath (Join-Path $logDir 'backend.out.log') -StderrPath (Join-Path $logDir 'backend.err.log')
    $started.backend = $backend.Id
}

if (!(Test-PortOpen -Port $ports.explain)) {
    $pythonExe = if (Test-Path (Join-Path $RepoRoot '.venv-1\Scripts\python.exe')) {
        Join-Path $RepoRoot '.venv-1\Scripts\python.exe'
    } elseif (Test-Path (Join-Path $RepoRoot '.venv\Scripts\python.exe')) {
        Join-Path $RepoRoot '.venv\Scripts\python.exe'
    } else {
        'python'
    }
    $explain = Start-BackgroundProcess -Name 'explain' -FilePath $pythonExe -WorkingDirectory $RepoRoot `
        -Arguments @('explain_api.py', '--port', '5001') `
        -StdoutPath (Join-Path $logDir 'explain.out.log') -StderrPath (Join-Path $logDir 'explain.err.log')
    $started.explain = $explain.Id
}

if (!(Test-PortOpen -Port $ports.frontend)) {
    $frontend = Start-BackgroundProcess -Name 'frontend' -FilePath 'cmd.exe' -WorkingDirectory (Join-Path $RepoRoot 'frontend') `
        -Arguments @('/c', 'npm run dev -- --host 127.0.0.1 --port 5173') `
        -StdoutPath (Join-Path $logDir 'frontend.out.log') -StderrPath (Join-Path $logDir 'frontend.err.log')
    $started.frontend = $frontend.Id
}

$stateObj = [ordered]@{
    action = 'start'
    timestamp = (Get-Date).ToString('s')
    profile = $LaunchMode
    wslDistro = $WSLDistro
    repoRoot = $RepoRoot
    pids = $started
    logs = $logDir
}
Export-LauncherState -obj $stateObj

Write-Host ""
Write-Host "Started/attached services. Waiting for ports..."

$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    $ok = (Test-PortOpen -Port $ports.sdn) -and (Test-PortOpen -Port $ports.websocket) -and (Test-PortOpen -Port $ports.explain)
    if ($ok) { break }
    Start-Sleep -Milliseconds 500
}

Write-ServiceStatus
if ($OpenDashboard) {
    Write-Host "Waiting for frontend on port 5173..."
    $openDeadline = (Get-Date).AddSeconds(45)
    $ready = $false
    while ((Get-Date) -lt $openDeadline) {
        if (Test-PortOpen -Port $ports.frontend) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if ($ready) {
        try {
            Start-Process 'http://127.0.0.1:5173'
            Write-Host "Opened dashboard at http://127.0.0.1:5173" -ForegroundColor Green
        } catch {
            Write-Host "Frontend is up, but browser could not be opened automatically." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Frontend did not open in time. Check logs/frontend.out.log." -ForegroundColor Yellow
    }
}
Write-Host "Tip: run '.\\Launch-Sentinel.ps1 -Action stop' to stop everything." -ForegroundColor Yellow
