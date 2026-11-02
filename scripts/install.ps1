# 把 dsh-coredump 链接进一个 DSH profile。
#
# 做三件事：
#   1. 备份 profile/package.json；
#   2. 写入 dependencies["dsh-coredump"]="link:<包目录>"，并把包名加进 dsh.profile.bundles；
#   3. 在 profile/node_modules 下建 junction（不复制源码，改代码重装即生效）。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
#   .\install.ps1 -ProfileName web -DshHome D:\dsh-home
#   .\install.ps1 -DryRun
#   .\install.ps1 -Force          # 覆盖已存在的 junction

[CmdletBinding()]
param(
    [string]$ProfileName = 'desktop',
    [string]$DshHome = (Join-Path $env:USERPROFILE '.dsh'),
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$packageRoot = Split-Path -Parent $PSScriptRoot
$packageName = 'dsh-coredump'
$manifestPath = Join-Path $packageRoot 'package.json'
if (-not (Test-Path $manifestPath)) {
    throw "找不到插件包清单：$manifestPath"
}

$profileDir = Join-Path $DshHome (Join-Path 'profiles' $ProfileName)
$profileManifest = Join-Path $profileDir 'package.json'
if (-not (Test-Path $profileManifest)) {
    throw "找不到 profile 清单：$profileManifest（先启动一次 DSH 生成 profile）"
}

Write-Host "[1/4] 插件包：$packageRoot"
Write-Host "[2/4] 目标 profile：$profileDir"

function Ensure-Property($object, $name, $initial) {
    if ($null -eq $object.PSObject.Properties[$name]) {
        $object | Add-Member -NotePropertyName $name -NotePropertyValue $initial
    }
    return $object.$name
}

$raw = Get-Content $profileManifest -Raw
$json = $raw | ConvertFrom-Json
if ($null -eq $json) { $json = [pscustomobject]@{} }

$dependencies = Ensure-Property $json 'dependencies' ([pscustomobject]@{})
$link = 'link:' + $packageRoot
$dependencies | Add-Member -NotePropertyName $packageName -NotePropertyValue $link -Force

$dsh = Ensure-Property $json 'dsh' ([pscustomobject]@{})
$profile = Ensure-Property $dsh 'profile' ([pscustomobject]@{})
$bundles = Ensure-Property $profile 'bundles' @()
if ($bundles -notcontains $packageName) {
    $bundles = @($bundles) + $packageName
    $profile | Add-Member -NotePropertyName 'bundles' -NotePropertyValue $bundles -Force
}

$nodeModules = Join-Path $profileDir 'node_modules'
$junction = Join-Path $nodeModules $packageName

if ($DryRun) {
    Write-Host "[dry-run] dependencies[$packageName] = $link"
    Write-Host "[dry-run] dsh.profile.bundles = $($bundles -join ', ')"
    Write-Host "[dry-run] junction: $junction -> $packageRoot"
    if (Test-Path $junction) { Write-Host "[dry-run] 已存在 junction（需要 -Force 才覆盖）" }
    return
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Copy-Item $profileManifest "$profileManifest.bak-$stamp" -Force
$json | ConvertTo-Json -Depth 40 | Set-Content -Path $profileManifest -Encoding UTF8
Write-Host "[3/4] 已更新 profile 清单（备份：package.json.bak-$stamp）"

New-Item -ItemType Directory -Force -Path $nodeModules | Out-Null
if (Test-Path $junction) {
    if (-not $Force) {
        throw "已存在 $junction；确认要覆盖请加 -Force。"
    }
    (Get-Item $junction).Delete()
}
New-Item -ItemType Junction -Path $junction -Target $packageRoot | Out-Null
Write-Host "[4/4] junction 已建立：$junction"

Write-Host ''
Write-Host '完成。请完全退出 DSH 进程后再启动，然后确认工具 coredump_parse 可用。'
Write-Host "如需回滚：还原 $profileManifest.bak-$stamp，并删除 $junction"
