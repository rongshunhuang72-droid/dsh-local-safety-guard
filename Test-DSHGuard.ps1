#requires -Version 5.1
[CmdletBinding()]
param([string]$GuardDirectory = (Join-Path $env:LOCALAPPDATA 'DSH-Guard'))
$ErrorActionPreference='Stop'
function FileHash([string]$File) {
  $stream=[IO.File]::OpenRead($File)
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash($stream)) } finally { $stream.Dispose(); $sha.Dispose() }
}
$directory=[IO.Path]::GetFullPath($GuardDirectory)
$installation=[IO.File]::ReadAllText((Join-Path $directory 'installation.json')) | ConvertFrom-Json
$receipt=[IO.File]::ReadAllText((Join-Path $directory 'records\active.json')) | ConvertFrom-Json
$hostProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$receipt.processId)
$live=$null -ne $hostProcess -and $hostProcess.ExecutablePath -eq $installation.dshExe -and $hostProcess.CommandLine -match 'dsh-desktop-host'
$profile=Join-Path $installation.dshHome ('profiles\'+$installation.profile)
$manifest=[IO.File]::ReadAllText((Join-Path $profile 'package.json')) | ConvertFrom-Json
$hashes=foreach ($file in @('index.mjs','engine.mjs','policy.mjs','cordis.patch.yml')) {
  (FileHash (Join-Path $directory $file)) -eq (FileHash (Join-Path $profile ('node_modules\dsh-local-safety-guard\'+$file)))
}
$policy=[IO.File]::ReadAllText((Join-Path $directory 'policy.json')) | ConvertFrom-Json
$policyValid=$policy.version -eq 1 -and @($policy.allowedWorkspaces).Count -gt 0 -and $policy.maxDestructivePerSession -eq 1 -and $policy.maxBackupBytes -gt 0
$registered=@($manifest.dsh.profile.bundles) -contains 'dsh-local-safety-guard'
$active=$receipt.active -eq $true -and $live -and $registered -and ($hashes -notcontains $false) -and $policyValid
[pscustomobject]@{ active=$active; receiptActive=$receipt.active; liveOfficialHost=$live; registered=$registered; installedFilesMatch=($hashes -notcontains $false); policyLooksValid=$policyValid; startedAt=$receipt.startedAt; guardDirectory=$directory; note='This checks loading and file consistency, not every possible bypass. Also run the harmless in-app probe documented in README.' } | ConvertTo-Json -Depth 5
if (!$active) { throw 'Guard runtime activation could not be confirmed.' }
