#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DshExe,
  [Parameter(Mandatory=$true)][string[]]$Workspace,
  [string]$GuardDirectory = (Join-Path $env:LOCALAPPDATA 'DSH-Guard'),
  [string]$DshHome = (Join-Path $env:USERPROFILE '.dsh'),
  [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Profile = 'desktop',
  [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
function Absolute([string]$Value) {
  if (![IO.Path]::IsPathRooted($Value) -or $Value -match '^[\\/]{2}' -or $Value -match '[\x00-\x1f*?<>|"&^%!]') { throw "Expected an absolute plain local path: $Value" }
  $full = [IO.Path]::GetFullPath($Value)
  if ($full.Substring([IO.Path]::GetPathRoot($full).Length).Contains(':')) { throw 'Alternate data streams are forbidden.' }
  return $full.TrimEnd('\')
}
function Inside([string]$Parent, [string]$Child) {
  return $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or $Child.StartsWith($Parent.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase)
}
function NoLinks([string]$Target) {
  $part = $Target
  while ($part) {
    if (Test-Path -LiteralPath $part) {
      $item = Get-Item -LiteralPath $part -Force
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Links and reparse points are forbidden: $part" }
    }
    $parent = [IO.Path]::GetDirectoryName($part)
    if ($parent -eq $part) { break }
    $part = $parent
  }
}
function WriteUtf8([string]$File, [string]$Text) { [IO.File]::WriteAllText($File, $Text, [Text.UTF8Encoding]::new($false)) }
function FileHash([string]$File) {
  $stream=[IO.File]::OpenRead($File)
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash($stream)) } finally { $stream.Dispose(); $sha.Dispose() }
}
$source = Absolute $PSScriptRoot
$exe = Absolute $DshExe
$guard = Absolute $GuardDirectory
$homeDirectory = Absolute $DshHome
$app = [IO.Path]::GetDirectoryName($exe)
$cli = Join-Path $app 'resources\runtime\cli\bin\dsh.cmd'
$profileDirectory = Join-Path $homeDirectory "profiles\$Profile"
$manifestPath = Join-Path $profileDirectory 'package.json'
$roots = @($Workspace | ForEach-Object { Absolute $_ } | Select-Object -Unique)
$sourceFiles = @('index.mjs','engine.mjs','policy.mjs','restore.mjs','package.json','cordis.patch.yml','AGENTS-safety.md','README.md','LICENSE')
foreach ($file in $sourceFiles) { if (!(Test-Path -LiteralPath (Join-Path $source $file) -PathType Leaf)) { throw "Missing source file: $file" } }
foreach ($file in @($exe,$cli)) { if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "DSH file not found: $file" }; NoLinks $file }
foreach ($directory in @($source,$guard,$homeDirectory,$profileDirectory)) { NoLinks $directory }
if ($guard -eq [IO.Path]::GetPathRoot($guard).TrimEnd('\') -or (Inside $guard $exe) -or (Inside $guard $source) -or (Inside $source $guard) -or (Inside $guard $profileDirectory) -or (Inside $profileDirectory $guard)) { throw 'Guard directory overlaps application/source/profile, or is a drive root.' }
foreach ($root in $roots) {
  NoLinks $root
  if (!(Test-Path -LiteralPath $root -PathType Container)) { throw "Workspace does not exist: $root" }
  if ($root -eq [IO.Path]::GetPathRoot($root).TrimEnd('\') -or $root -eq (Absolute $env:USERPROFILE) -or $root -eq $homeDirectory) { throw "Workspace is too broad: $root" }
  foreach ($protected in @($guard,$source,$app,$homeDirectory)) { if ((Inside $root $protected) -or (Inside $protected $root)) { throw "Workspace overlaps protected installation/source paths: $root" } }
  NoLinks (Join-Path $root 'AGENTS.md')
}
NoLinks (Join-Path $homeDirectory 'AGENTS.md')
$plan = [pscustomobject]@{ mode='strict'; dshExe=$exe; cli=$cli; profile=$Profile; dshHome=$homeDirectory; guardDirectory=$guard; allowedWorkspaces=$roots; testedDshVersion='0.2.1-rc.2'; note='All arbitrary commands/scripts and unknown tools are blocked. Builds/tests/installations must be run manually outside DSH.' }
if ($PlanOnly) { $plan | ConvertTo-Json -Depth 5; return }
if (Test-Path -LiteralPath $guard) { throw 'Guard directory already exists. This installer handles a new installation only; it never overwrites an existing guard.' }
if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Open DSH once to initialize the selected profile, then fully quit DSH before installing.' }
NoLinks $manifestPath
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
if (@($manifest.dsh.profile.bundles) -contains 'dsh-local-safety-guard' -or $manifest.dependencies.'dsh-local-safety-guard') { throw 'This profile already has the guard. Do not install a second copy.' }
$running = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.Equals($exe,[StringComparison]::OrdinalIgnoreCase) })
if ($running.Count) { throw 'Fully quit DSH, including its tray process, before installing. No process is stopped by this installer.' }
$rulesTargets = @((Join-Path $homeDirectory 'AGENTS.md')) + @($roots | ForEach-Object { Join-Path $_ 'AGENTS.md' })
foreach ($file in $rulesTargets) {
  if ((Test-Path -LiteralPath $file) -and [IO.File]::ReadAllText($file).Contains('<!-- DSH-LOCAL-SAFETY-GUARD:BEGIN -->')) { throw "Existing guard rules require manual inspection: $file" }
}
$null = New-Item -ItemType Directory -Path $guard
$backup = Join-Path $guard ('install-backup\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Path $backup
foreach ($file in @('package.json','cordis.patch.yml','cordis.yml','pnpm-lock.yaml','pnpm-workspace.yaml')) {
  $original = Join-Path $profileDirectory $file
  if (Test-Path -LiteralPath $original -PathType Leaf) { Copy-Item -LiteralPath $original -Destination (Join-Path $backup $file) }
}
foreach ($file in $sourceFiles) { Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $guard $file) }
$policy = [ordered]@{ version=1; allowedWorkspaces=@($roots); maxBackupBytes=33554432; maxDestructivePerSession=1 }
WriteUtf8 (Join-Path $guard 'policy.json') (($policy | ConvertTo-Json -Depth 5)+"`n")
$template = [IO.File]::ReadAllText((Join-Path $source 'cordis.patch.yml'))
$anchor = '      name: dsh-local-safety-guard'
if ([regex]::Matches($template,[regex]::Escape($anchor)).Count -ne 1) { throw 'Invalid plugin patch template.' }
$dataConfig = $anchor+"`n      config:`n        dataDirectory: '"+$guard.Replace("'","''")+"'"
WriteUtf8 (Join-Path $guard 'cordis.patch.yml') $template.Replace($anchor,$dataConfig)
$ruleText = [IO.File]::ReadAllText((Join-Path $source 'AGENTS-safety.md'))
$rulesManifest = @()
$index = 0
foreach ($file in $rulesTargets) {
  $existed = Test-Path -LiteralPath $file -PathType Leaf
  $saved = $null
  $original = ''
  if ($existed) { $saved=Join-Path $backup "AGENTS-$index.original"; Copy-Item -LiteralPath $file -Destination $saved; $original=[IO.File]::ReadAllText($file) }
  if ($original.Length) { $original=$original.TrimEnd()+"`r`n`r`n" }
  WriteUtf8 $file ($original+$ruleText)
  $rulesManifest += [pscustomobject]@{ path=$file; existed=$existed; backup=$saved }
  $index++
}
WriteUtf8 (Join-Path $backup 'rules-manifest.json') (ConvertTo-Json -InputObject @($rulesManifest) -Depth 5)
$previousDshHome = [Environment]::GetEnvironmentVariable('DSH_HOME','Process')
try {
  $env:DSH_HOME = $homeDirectory
  & $cli plugin --profile $Profile add ('file:'+$guard.Replace('\','/'))
  if ($LASTEXITCODE -ne 0) { throw 'DSH plugin installation failed. Keep DSH closed and inspect install-backup before retrying.' }
} finally { [Environment]::SetEnvironmentVariable('DSH_HOME',$previousDshHome,'Process') }
$installedManifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
if (@($installedManifest.dsh.profile.bundles) -notcontains 'dsh-local-safety-guard') { throw 'Plugin bundle was not registered.' }
$installedDirectory = Join-Path $profileDirectory 'node_modules\dsh-local-safety-guard'
foreach ($file in @('index.mjs','engine.mjs','policy.mjs','cordis.patch.yml')) {
  if ((FileHash (Join-Path $guard $file)) -ne (FileHash (Join-Path $installedDirectory $file))) { throw "Installed file verification failed: $file" }
}
WriteUtf8 (Join-Path $guard 'installation.json') (($plan | ConvertTo-Json -Depth 5)+"`n")
Write-Output 'Installed. Start DSH, create a new session, and call safety_status. Runtime activation has not yet been verified.'
$plan | ConvertTo-Json -Depth 5
