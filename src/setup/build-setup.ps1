# build-setup.ps1 -- build hotspot-ttl-setup.exe (self-contained installer).
# Embeds: normalizer.exe + WinDivert64.dll + WinDivert64.sys + task XML template.
# License: GPL-3.0 (repo root LICENSE); Copyright (C) 2026 AYwlilwYA
# Pure ASCII on purpose (PS 5.1 + GBK console).

$ErrorActionPreference = 'Stop'
$src  = 'F:\hotspot-ttl\src\setup'
$bin  = 'D:\hotspot-ttl\bin'
$dist = 'D:\hotspot-ttl\dist'
$csc  = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$out  = Join-Path $dist 'hotspot-ttl-setup.exe'

New-Item -ItemType Directory -Force -Path $dist | Out-Null

# task XML template is versioned in src; never re-export from a live task
# (a running admin task would overwrite the SYSTEM principal template)
$xmlPath = Join-Path $src 'task-def.xml'
if (-not (Test-Path $xmlPath)) { throw "task-def.xml missing: $xmlPath" }
Write-Output ("task-def.xml: " + (Get-Item $xmlPath).Length + " bytes")

$cscArgs = @(
    '/nologo', '/target:exe', '/optimize+',
    "/out:$out",
    "/win32manifest:$src\app.manifest",
    '/codepage:65001',
    "/resource:$bin\normalizer.exe,normalizer.exe",
    "/resource:$bin\WinDivert64.dll,WinDivert64.dll",
    "/resource:$bin\WinDivert64.sys,WinDivert64.sys",
    "/resource:$xmlPath,task-def.xml",
    "$src\Setup.cs"
)
& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }

# portable launchers + readme in dist
$installCmd = Join-Path $dist 'install.cmd'
Set-Content -Path $installCmd -Encoding ASCII -Value "@echo off`r`n`"%~dp0hotspot-ttl-setup.exe`" %*`r`n"
$uninstallCmd = Join-Path $dist 'uninstall.cmd'
Set-Content -Path $uninstallCmd -Encoding ASCII -Value "@echo off`r`n`"%~dp0hotspot-ttl-setup.exe`" /uninstall`r`n pause`r`n"
Copy-Item (Join-Path $src 'README-dist.txt') (Join-Path $dist 'README.txt') -Force

# license files ride along with the binary distribution (GPL-3.0 + WinDivert LGPLv3)
$repoRoot = Join-Path $src '..\..'
Copy-Item (Join-Path $repoRoot 'LICENSE') (Join-Path $dist 'LICENSE.txt') -Force
$licDir = Join-Path $dist 'LICENSES'
New-Item -ItemType Directory -Force -Path $licDir | Out-Null
Copy-Item (Join-Path $repoRoot 'LICENSES\WinDivert-LGPLv3.txt') $licDir -Force

# portable zip (setup + launchers + readme + licenses)
$zip = Join-Path $dist 'hotspot-ttl-normalizer-portable.zip'
Compress-Archive -Path $out, $installCmd, $uninstallCmd, (Join-Path $dist 'README.txt'), (Join-Path $dist 'LICENSE.txt'), $licDir -DestinationPath $zip -Force

Get-Item $out | Format-List FullName, Length, LastWriteTime
Get-ChildItem $dist -File | Format-Table Name, Length, LastWriteTime -AutoSize
