param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$frontendDir = Join-Path $RepoRoot "frontend"
if (-not (Test-Path -Path $frontendDir)) {
    Write-Host "[FAIL] Frontend directory not found: $frontendDir" -ForegroundColor Red
    return
}

Set-Location -LiteralPath $frontendDir
Write-Host "[SENTINEL FRONTEND] Working directory: $frontendDir"

if (-not (Test-Path -Path "node_modules")) {
    Write-Host "[SENTINEL FRONTEND] node_modules missing. Installing dependencies..."
    npm install
}

npm run dev -- --host 127.0.0.1 --port 5173
