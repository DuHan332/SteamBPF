param([string]$ZigExe)
$ErrorActionPreference = 'Stop'
$nativeRoot = $PSScriptRoot
$projectRoot = Split-Path $nativeRoot -Parent
if (-not $ZigExe) { $ZigExe = Join-Path $projectRoot 'packaging/native-tools/ziglang/zig.exe' }
if (-not (Test-Path -LiteralPath $ZigExe)) { throw 'Install ziglang==0.13.0 into packaging/native-tools; see BUILD.md.' }
$ZigExe = (Resolve-Path -LiteralPath $ZigExe).Path
$output = Join-Path $nativeRoot 'bin'
$objects = Join-Path $projectRoot 'build/native'
New-Item -ItemType Directory -Force -Path $output,$objects | Out-Null
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $objects 'cache'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $objects 'global-cache'
try {
    $inputs = @('buffer.c','hook.c','trampoline.c','hde/hde64.c')
    $compiled = @()
    foreach ($source in $inputs) {
        $inputPath = Join-Path $nativeRoot "vendor/minhook/src/$source"
        $object = Join-Path $objects ((Split-Path $source -Leaf) + '.o')
        & $ZigExe cc -target x86_64-windows-gnu -O2 -c $inputPath -o $object
        if ($LASTEXITCODE -ne 0) { throw "Native compilation failed: $source" }
        $compiled += $object
    }
    $dll = Join-Path $output 'SteamBPFHook.dll'
    & $ZigExe c++ -target x86_64-windows-gnu -std=c++17 -O2 -s -shared -static (Join-Path $nativeRoot 'module.cpp') @compiled -ladvapi32 -o $dll
    if ($LASTEXITCODE -ne 0) { throw 'Module build failed.' }
    $manifest = @{ protocol = 2; sha256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() }
    [IO.File]::WriteAllText((Join-Path $output 'module.json'),($manifest | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $testExe = Join-Path $objects 'wire-tests.exe'
    & $ZigExe c++ -target x86_64-windows-gnu -std=c++17 -O2 -static (Join-Path $nativeRoot 'wire_tests.cpp') -o $testExe
    if ($LASTEXITCODE -ne 0) { throw 'Native test compilation failed.' }
    & $testExe
    if ($LASTEXITCODE -ne 0) { throw 'Native protocol tests failed.' }
    Write-Host "Built: $dll"
} finally {
    Remove-Item Env:ZIG_LOCAL_CACHE_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:ZIG_GLOBAL_CACHE_DIR -ErrorAction SilentlyContinue
}
