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
node is not on PATH. acs_cli.js needs Node 18 or newer.

If Node cannot be installed on this machine, two routes do not need it, and
between them they cover everything except headless CI:

  1. The page. No runtime, no server, no package manager. Scoring, violations,
     fix routes, drafted YAML and the full report all live here.
       Invoke-Item '$here\dj_acs_auditor.html'

  2. A shell summary of what ACS reported. Counts, not scores. Needs jq.
       Use scripts\acs_summary.sh from Git Bash or WSL, or read the pull output
       directly; the page is the better answer on Windows.

  If this host has a container runtime, the CLI runs without installing Node:
       podman run --rm -v "${here}:/w" -w /w docker.io/library/node:20-alpine ``
         node acs_cli.js --help
"@
  exit 2
}
# Pass arguments through untouched. PowerShell would otherwise try to interpret --path
# style switches as its own parameters.
& node "$here\acs_cli.js" @args
exit $LASTEXITCODE
