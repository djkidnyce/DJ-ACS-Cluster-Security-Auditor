<#
.SYNOPSIS
  Wrapper for acs_cli.js on Windows PowerShell and PowerShell 7.
.EXAMPLE
  .\acs.ps1 --path .\manifests --report --json
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Error @"
node is not on PATH. Node 18 or newer is required.
No Node available? The browser pages need no runtime at all:
  Invoke-Item '$here\dj_acs_auditor.html'
"@
  exit 2
}
# Pass arguments through untouched. PowerShell would otherwise try to interpret --path
# style switches as its own parameters.
& node "$here\acs_cli.js" @args
exit $LASTEXITCODE
