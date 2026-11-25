$ErrorActionPreference = "Stop"

$RootDir = $PSScriptRoot
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# Resolve Python executable
$PythonExe = $null
$DefaultLocalPython = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
if (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonExe = (Get-Command python).Source
} elseif (Test-Path $DefaultLocalPython) {
    $PythonExe = $DefaultLocalPython
} else {
    Write-Error "Python 3.12 not found. Please install Python 3.12 or add it to PATH."
    exit 1
}

# Resolve Node.js / npm directory
$DefaultNodeDir = Join-Path $env:LOCALAPPDATA "Programs\nodejs"
$UseLocalNodeDir = $false
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    if (Test-Path (Join-Path $DefaultNodeDir "npm.cmd")) {
        $env:Path = "$DefaultNodeDir;$env:Path"
        $UseLocalNodeDir = $true
    } else {
        Write-Error "Node.js / npm not found. Please install Node.js 20+ or add it to PATH."
        exit 1
    }
}

Write-Host "Starting Supply Chain Sentinel Backend (Port 8000)..." -ForegroundColor Cyan
$BackendCmd = "Set-Location '$BackendDir'; `$env:PYTHONPATH = '$BackendDir'; & '$PythonExe' -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $BackendCmd

Write-Host "Starting Supply Chain Sentinel Frontend (Port 5173)..." -ForegroundColor Cyan
$NodePathPrefix = if ($UseLocalNodeDir -or (Test-Path $DefaultNodeDir)) { "`$env:Path = '$DefaultNodeDir;' + `$env:Path; " } else { "" }
$FrontendCmd = "Set-Location '$FrontendDir'; ${NodePathPrefix}npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $FrontendCmd

Write-Host ""
Write-Host "Supply Chain Sentinel is launching!" -ForegroundColor Green
Write-Host "  - Frontend Dashboard : http://localhost:5173"
Write-Host "  - Backend API Docs   : http://localhost:8000/docs"
Write-Host "  - Health Endpoint    : http://localhost:8000/health"
