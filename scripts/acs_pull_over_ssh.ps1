<#
.SYNOPSIS
  Pull ACS and OpenShift data from PowerShell through an SSH jump host.

.DESCRIPTION
  The usual federal and enterprise shape: your workstation cannot reach the cluster or
  ACS Central, but a bastion can. So run the commands over SSH and bring the output back.

  PowerShell 7 ships an OpenSSH client, and Windows 10 and later have one as an optional
  feature, so no PuTTY and no extra tooling.

  WHAT RUNS WHERE
    On the bastion : oc, curl. It needs network reach and a kubeconfig or oc login.
    On your box    : this script, and afterwards acs_cli.js to build the report.

  Nothing is applied to any cluster. Every remote command is a read.

.PARAMETER JumpHost
  user@bastion, or a Host alias from your ~/.ssh/config.

.PARAMETER Mode
  workloads : oc get workloads as JSON. No ACS needed.
  vulns     : the ACS vulnerability export.
  alerts    : ACS policy violations, listed then hydrated so violation text is present.
  all       : all three.

.EXAMPLE
  .\acs_pull_over_ssh.ps1 -JumpHost dj@bastion.example.com -Mode workloads
  node ..\acs_cli.js --workloads .\acs_ssh_*\workloads.json --report

.EXAMPLE
  # ACS token supplied locally, sent to the bastion through stdin, never as an argument
  $env:ROX_API_TOKEN = '...'
  .\acs_pull_over_ssh.ps1 -JumpHost dj@bastion -Mode all -RoxEndpoint https://central-stackrox.apps.ocp.example.com
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$JumpHost,
  [ValidateSet('workloads', 'vulns', 'alerts', 'all')][string]$Mode = 'workloads',
  [string]$Namespace = '',
  [string]$RoxEndpoint = '',
  [string]$Query = '',
  [string]$OutDir = "acs_ssh_$(Get-Date -Format yyyyMMdd_HHmmss)",
  [string]$SshKey = '',
  [int]$Timeout = 600
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
  throw @"
ssh is not on PATH.

PowerShell 7 includes it. On Windows PowerShell 5.1 add the OpenSSH client:
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
"@
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$sshArgs = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new')
if ($SshKey) { $sshArgs += @('-i', $SshKey) }
$sshArgs += $JumpHost

# Run a remote command and capture stdout to a file, keeping stderr separate so a warning
# on the bastion does not end up inside your JSON.
function Invoke-Remote {
  param([string]$Command, [string]$OutFile, [string]$StdIn = $null)

  $errFile = "$OutFile.err"
  if ($StdIn) {
    # Secrets go over stdin, never in the argument vector. Arguments are visible in ps to
    # every user on the bastion and land in the remote shell history.
    $StdIn | & ssh @sshArgs $Command 1> $OutFile 2> $errFile
  } else {
    & ssh @sshArgs $Command 1> $OutFile 2> $errFile
  }
  $code = $LASTEXITCODE
  if ((Test-Path $errFile) -and (Get-Item $errFile).Length -eq 0) { Remove-Item $errFile }
  return $code
}

Write-Host "Pulling through $JumpHost"
Write-Host ('-' * 64)

# ---- reachability and prerequisites on the far side -------------------------
Write-Host '[0] Checking the bastion'
$probe = Join-Path $OutDir 'probe.txt'
$rc = Invoke-Remote -Command 'command -v oc >/dev/null 2>&1 && echo OC_OK; command -v curl >/dev/null 2>&1 && echo CURL_OK; oc whoami 2>/dev/null || echo NO_OC_SESSION' -OutFile $probe
if ($rc -ne 0) {
  Write-Host "  ssh failed with exit $rc"
  if (Test-Path "$probe.err") { Write-Host "  $(Get-Content "$probe.err" -Raw)" }
  Write-Host '  BatchMode is on, so this will not prompt. Set up key auth first:'
  Write-Host '    ssh-keygen -t ed25519; ssh-copy-id ' + $JumpHost
  exit 1
}
$probeText = Get-Content $probe -Raw
Write-Host "  oc present   : $(if ($probeText -match 'OC_OK') {'yes'} else {'NO'})"
Write-Host "  curl present : $(if ($probeText -match 'CURL_OK') {'yes'} else {'NO'})"
if ($probeText -match 'NO_OC_SESSION') {
  Write-Host '  oc session   : NOT logged in on the bastion.'
  Write-Host '                 Run oc login there first. This script will not send'
  Write-Host '                 cluster credentials over ssh for you.'
} else {
  $who = ($probeText -split "`n" | Where-Object { $_ -notmatch 'OK$' -and $_.Trim() }) -join ''
  Write-Host "  oc session   : $($who.Trim())"
}
Remove-Item $probe -ErrorAction SilentlyContinue

# ---- workloads ---------------------------------------------------------------
if ($Mode -eq 'workloads' -or $Mode -eq 'all') {
  Write-Host '[1] Workloads'
  $scope = if ($Namespace) { "-n $Namespace" } else { '--all-namespaces' }
  # -o json, because that is what people reach for and the auditor now reads it.
  $cmd = "oc get deployment,daemonset,statefulset,cronjob,job $scope -o json"
  $out = Join-Path $OutDir 'workloads.json'
  $rc = Invoke-Remote -Command $cmd -OutFile $out
  if ($rc -eq 0 -and (Get-Item $out).Length -gt 2) {
    try {
      $n = (Get-Content $out -Raw | ConvertFrom-Json).items.Count
      Write-Host "  $n object(s) -> $out"
    } catch { Write-Host "  written -> $out" }
  } else {
    Write-Host "  failed. $(if (Test-Path "$out.err") { Get-Content "$out.err" -Raw })"
  }
}

# ---- ACS ---------------------------------------------------------------------
if ($Mode -eq 'vulns' -or $Mode -eq 'alerts' -or $Mode -eq 'all') {
  if (-not $RoxEndpoint) {
    Write-Host '[2] ACS: no -RoxEndpoint given, asking the bastion to find it'
    $r = Join-Path $OutDir 'route.txt'
    Invoke-Remote -Command "oc get route central -n stackrox -o jsonpath='{.spec.host}' 2>/dev/null" -OutFile $r | Out-Null
    $host_ = (Get-Content $r -Raw).Trim()
    Remove-Item $r -ErrorAction SilentlyContinue
    if ($host_) { $RoxEndpoint = "https://$host_"; Write-Host "  found $RoxEndpoint" }
    else {
      Write-Host '  could not find the central route. Pass -RoxEndpoint explicitly.'
      Write-Host '  Remember: ACS Central is NOT the OpenShift API. Different host, different token.'
    }
  }

  if ($RoxEndpoint) {
    if (-not $env:ROX_API_TOKEN) {
      Write-Host '  ROX_API_TOKEN is not set locally. ACS will reject an OpenShift token,'
      Write-Host '  so create an ACS API token: Platform Configuration, Integrations,'
      Write-Host '  Authentication Tokens. Then: $env:ROX_API_TOKEN = ''...'''
    } else {
      $ep = $RoxEndpoint.TrimEnd('/')

      # The token is piped in over stdin and read into a variable on the far side. It is
      # never an ssh argument and never appears in the remote command line.
      $preamble = @"
read -r ROX_API_TOKEN
export ROX_API_TOKEN
"@
      if ($Mode -eq 'vulns' -or $Mode -eq 'all') {
        Write-Host '[3] ACS vulnerability export'
        $qs = "timeout=$Timeout"
        if ($Query -or $Namespace) {
          $q = if ($Query) { $Query } else { "Namespace:$Namespace" }
          # The + separating ACS search terms must go as %2B. A literal + in a query
          # string decodes to a space and silently changes the query.
          $enc = [uri]::EscapeDataString($q)
          $qs = "query=$enc&$qs"
        }
        $cmd = "$preamble curl -sS --fail-with-body -H `"Authorization: Bearer `$ROX_API_TOKEN`" `"$ep/v1/export/vuln-mgmt/workloads?$qs`""
        $out = Join-Path $OutDir 'vuln_workloads.ndjson'
        $rc = Invoke-Remote -Command $cmd -OutFile $out -StdIn $env:ROX_API_TOKEN
        if ($rc -eq 0) {
          $lines = @(Get-Content $out | Where-Object { $_.Trim() }).Count
          Write-Host "  $lines workload record(s) -> $out"
          if ($lines -eq 0) {
            Write-Host '  EMPTY is not CLEAN. Usually the token cannot read Image and Deployment,'
            Write-Host '  or nothing has been scanned yet.'
          }
        } else {
          Write-Host "  failed. $(if (Test-Path "$out.err") { Get-Content "$out.err" -Raw })"
        }
      }

      if ($Mode -eq 'alerts' -or $Mode -eq 'all') {
        Write-Host '[4] ACS policy violations, listed then hydrated'
        # /v1/alerts returns ListAlert, which has no violations[]. Only /v1/alerts/{id}
        # has the text, so hydrate on the bastion rather than shipping a useless list.
        $cmd = @"
$preamble
curl -sS --fail-with-body -H "Authorization: Bearer `$ROX_API_TOKEN" "$ep/v1/alerts?pagination.limit=1000" -o /tmp/acs_list.`$`$ 2>/dev/null
if command -v jq >/dev/null 2>&1; then
  jq -r '.alerts[].id' /tmp/acs_list.`$`$ | while read -r id; do
    curl -sS -H "Authorization: Bearer `$ROX_API_TOKEN" "$ep/v1/alerts/`$id"
  done | jq -s '{alerts: .}'
else
  echo '{"note":"jq is not installed on the bastion, returning the un-hydrated list"}' >&2
  cat /tmp/acs_list.`$`$
fi
rm -f /tmp/acs_list.`$`$
"@
        $out = Join-Path $OutDir 'alerts_full.json'
        $rc = Invoke-Remote -Command $cmd -OutFile $out -StdIn $env:ROX_API_TOKEN
        if ($rc -eq 0 -and (Test-Path $out)) {
          try {
            $n = (Get-Content $out -Raw | ConvertFrom-Json).alerts.Count
            Write-Host "  $n alert(s) -> $out"
          } catch { Write-Host "  written -> $out" }
          if (Test-Path "$out.err") { Write-Host "  note: $(Get-Content "$out.err" -Raw)" }
        } else {
          Write-Host "  failed. $(if (Test-Path "$out.err") { Get-Content "$out.err" -Raw })"
        }
      }
    }
  }
}

Write-Host ('-' * 64)
Write-Host "Written to $OutDir"
Get-ChildItem $OutDir | ForEach-Object { Write-Host "  $($_.Name)  ($($_.Length) bytes)" }
Write-Host ''
Write-Host 'Now build the report locally:'
$parts = @()
if (Test-Path (Join-Path $OutDir 'workloads.json'))       { $parts += "--workloads $OutDir\workloads.json" }
if (Test-Path (Join-Path $OutDir 'vuln_workloads.ndjson')) { $parts += "--vulns $OutDir\vuln_workloads.ndjson" }
if (Test-Path (Join-Path $OutDir 'alerts_full.json'))      { $parts += "--alerts $OutDir\alerts_full.json" }
Write-Host "  node acs_cli.js $($parts -join ' ') --report --json --worklist"
Write-Host ''
Write-Host 'Or drop those files straight onto dj_acs_auditor.html.'
