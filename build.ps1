param([string]$PythonExe)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
if (-not $PythonExe) {
    $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundledPython) { $PythonExe = $bundledPython }
    else { $PythonExe = (Get-Command python -ErrorAction Stop).Source }
}
$previousPythonPath = $env:PYTHONPATH
$previousConfig = $env:PYINSTALLER_CONFIG_DIR
Push-Location $projectRoot
try {
    $env:PYTHONPATH = Join-Path $projectRoot 'packaging\build-tools'
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $projectRoot 'build\cache'
    & $PythonExe -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name SteamBPF --distpath dist --workpath build\work --specpath build steambpf_gui.py
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
    Write-Host "Built: $(Join-Path $projectRoot 'dist\SteamBPF.exe')"
}
finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYINSTALLER_CONFIG_DIR = $previousConfig
    Pop-Location
}
