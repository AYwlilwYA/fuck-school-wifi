# build.ps1 -- build normalizer.exe with MSVC (VS18 Community), output to D:\hotspot-ttl\bin
# Pure ASCII on purpose.
$ErrorActionPreference = 'Stop'
$VCVARS = 'D:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'
$SRC = 'F:\hotspot-ttl\src'
$OUT = 'D:\hotspot-ttl\bin'
$WINDIVERT_DIR = 'D:\Python311\Lib\site-packages\pydivert\windivert_dll'

if (-not (Test-Path $VCVARS)) { throw "vcvars64 not found: $VCVARS" }
New-Item -ItemType Directory -Force $OUT | Out-Null

Push-Location $OUT
try {
    $cmd = 'call "' + $VCVARS + '" >nul 2>&1 && cl /nologo /O2 /W4 /EHsc /std:c++17 /utf-8 /MT /D_CRT_SECURE_NO_WARNINGS "' + (Join-Path $SRC 'normalizer.cpp') + '"'
    & cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "cl failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

# stop driver first: loaded driver locks WinDivert64.sys
& sc.exe stop WinDivert1.3 *> $null
Start-Sleep -Milliseconds 500

Copy-Item (Join-Path $WINDIVERT_DIR 'WinDivert64.dll') $OUT -Force
Copy-Item (Join-Path $WINDIVERT_DIR 'WinDivert64.sys') $OUT -Force

Write-Output ("built: " + (Join-Path $OUT 'normalizer.exe'))
Get-Item (Join-Path $OUT 'normalizer.exe') | Select-Object FullName, Length, LastWriteTime | Format-List
