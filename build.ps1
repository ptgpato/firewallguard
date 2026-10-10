$ErrorActionPreference = 'Stop'

Set-Location $PSScriptRoot

if (Get-Process -Name 'FirewallGuard' -ErrorAction SilentlyContinue) {
    throw 'FirewallGuard.exe is still running. Close it before building.'
}

if (-not (Test-Path '.\.venv\Scripts\python.exe')) {
    throw 'The .venv environment was not found. Create it with: python -m venv .venv'
}

$python = (Resolve-Path '.\.venv\Scripts\python.exe').Path

& $python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw 'Dependency installation failed.'
}

& $python -m PyInstaller `
    --clean `
    --noconfirm `
    --name FirewallGuard `
    --onedir `
    --windowed `
    --uac-admin `
    --add-data 'templates;templates' `
    --add-data 'static;static' `
    app.py
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE. Close FirewallGuard.exe and review the PyInstaller output above."
}

Copy-Item '.\firewallguard.db' '.\dist\FirewallGuard\firewallguard.db' -Force

Write-Host ''
Write-Host 'Build complete:'
Write-Host (Join-Path $PSScriptRoot 'dist\FirewallGuard\FirewallGuard.exe')
