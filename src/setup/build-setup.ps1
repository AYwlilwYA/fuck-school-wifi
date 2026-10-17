# build-setup.ps1 -- build hotspot-ttl-setup.exe (self-contained installer).
# Embeds: normalizer.exe + WinDivert64.dll + WinDivert64.sys + task XML template.
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

# portable zip (setup + launchers + readme)
$zip = Join-Path $dist 'hotspot-ttl-normalizer-portable.zip'
Compress-Archive -Path $out, $installCmd, $uninstallCmd, (Join-Path $dist 'README.txt') -DestinationPath $zip -Force

Get-Item $out | Format-List FullName, Length, LastWriteTime
Get-ChildItem $dist -File | Format-Table Name, Length, LastWriteTime -AutoSize
