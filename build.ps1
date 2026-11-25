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
    & (Join-Path $projectRoot 'native/build.ps1')
    if (-not $?) { throw 'Native module build failed.' }
    $env:PYTHONPATH = Join-Path $projectRoot 'packaging\build-tools'
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $projectRoot 'build\cache'
    $appIcon = Join-Path $projectRoot 'assets\steambpf.ico'
    $nativeDll = Join-Path $projectRoot 'native/bin/SteamBPFHook.dll'
    $nativeManifest = Join-Path $projectRoot 'native/bin/module.json'
    $thirdParty = Join-Path $projectRoot 'native/vendor/minhook/LICENSE.txt'
    & $PythonExe -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name SteamBPF --icon $appIcon --add-data "$appIcon;assets" --add-data "$nativeDll;native/bin" --add-data "$nativeManifest;native/bin" --add-data "$thirdParty;licenses" --distpath dist --workpath build\work --specpath build steambpf_gui.py
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
    Write-Host "Built: $(Join-Path $projectRoot 'dist\SteamBPF.exe')"
}
finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYINSTALLER_CONFIG_DIR = $previousConfig
    Pop-Location
}
