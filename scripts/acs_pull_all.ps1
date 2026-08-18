<#
.SYNOPSIS
  Pull EVERY finding ACS knows about, all severities low to critical, all states.

.DESCRIPTION
  ACS has several separate stores and no single endpoint returning all of them.
  Asking only /v1/alerts is the classic mistake: it returns policy violations, its
  list form carries no violation text, and it contains no image CVEs at all.

  Collects:
    1. Policy violations, every severity, stage and state, paged, then hydrated
       per alert so the violation text is actually present.
    2. Image CVEs for running workloads.
    3. Image CVEs for every image Central knows, including non running ones.
    4. Node CVEs.
    5. Snoozed and deferred CVEs, hidden from the default views.

  Every call is a GET. Nothing is ever written to a cluster.

.EXAMPLE
  $env:ROX_ENDPOINT  = 'https://central-stackrox.apps.example.com'
  $env:ROX_API_TOKEN = '...'
  .\acs_pull_all.ps1 -OutDir acs_findings
#>
[CmdletBinding()]
param(
  [string]$OutDir    = "acs_findings_$(Get-Date -Format yyyyMMdd_HHmmss)",
  [string]$Namespace = '',
  [string]$Cluster   = '',
  [int]   $Page      = 500,
  [int]   $Timeout   = 600,
  [switch]$Insecure
)

$ErrorActionPreference = 'Stop'

if (-not $env:ROX_ENDPOINT)  { throw 'Set $env:ROX_ENDPOINT, for example https://central-stackrox.apps.example.com' }
if (-not $env:ROX_API_TOKEN) { throw 'Set $env:ROX_API_TOKEN. Do not pass the token as a parameter, it lands in your history.' }

$base = $env:ROX_ENDPOINT.TrimEnd('/')
$hdr  = @{ Authorization = "Bearer $($env:ROX_API_TOKEN)"; Accept = 'application/json' }

# TLS verification stays ON by default. This request carries a bearer token that is
# effectively read access to your whole security posture; disabling verification hands
# it to anyone on the path. -Insecure exists for lab use, not for production.
$common = @{ Headers = $hdr; UseBasicParsing = $true }
if ($Insecure) {
  Write-Warning 'TLS verification disabled. Your API token is exposed to anyone who can intercept this connection.'
  if ($PSVersionTable.PSVersion.Major -ge 6) { $common['SkipCertificateCheck'] = $true }
  else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# No severity term, no state term, no lifecycle term. Omitting them returns every
# value, which is exactly what a full sweep needs. The ACS console defaults to active
# violations; this deliberately does not.
$scopeParts = @()
if ($Namespace) { $scopeParts += "Namespace:$Namespace" }
if ($Cluster)   { $scopeParts += "Cluster:$Cluster" }
$scope    = ($scopeParts -join '+')
$scopeEnc = [uri]::EscapeDataString($scope)

function Get-Json([string]$url) { Invoke-RestMethod @common -Uri $url -Method Get }
function Get-Text([string]$url) { (Invoke-WebRequest @common -Uri $url -Method Get).Content }

Write-Host "ACS full findings sweep"
Write-Host "  endpoint : $base"
Write-Host ("  scope    : " + $(if ($scope) { $scope } else { '<everything, no filter>' }))
Write-Host "  output   : $OutDir"
Write-Host ('-' * 64)

Write-Host '[0/6] Checking the token'
try { Get-Json "$base/v1/auth/status" | ConvertTo-Json -Depth 6 | Set-Content "$OutDir/00_auth_status.json"; Write-Host '  ok' }
catch {
  Write-Host "  FAILED: $($_.Exception.Message)"
  Write-Host '  401 the token is wrong or expired. 403 it authenticated but has no role.'
  Write-Host '  A connection error usually means an untrusted internal CA.'
  throw
}

Write-Host '[1/6] Policy violations, all severities, all states, all lifecycle stages'
try { $total = (Get-Json "$base/v1/alertscount?query=$scopeEnc").count } catch { $total = 0 }
Write-Host "  Central reports $total alert(s) in scope"

$all = New-Object System.Collections.ArrayList
$offset = 0
while ($true) {
  $u = "$base/v1/alerts?query=$scopeEnc&pagination.limit=$Page&pagination.offset=$offset"
  $r = Get-Json $u
  $batch = @($r.alerts)
  if ($batch.Count -eq 0) { break }
  [void]$all.AddRange($batch)
  Write-Host -NoNewline "`r  paged $($all.Count) alert(s)"
  $offset += $Page
  if ($batch.Count -lt $Page) { break }
}
Write-Host "`r  retrieved $($all.Count) alert(s)          "
@{ alerts = $all } | ConvertTo-Json -Depth 30 | Set-Content "$OutDir/01_alerts_list.json"
if ($total -gt 0 -and $all.Count -lt $total) {
  Write-Host "  NOTE: got $($all.Count) of $total. Usually the token can count them but cannot read every namespace."
}

# GET /v1/alerts returns storage.ListAlert, which has NO violations[] array. The
# violation text only exists on GET /v1/alerts/{id}. Skip this and you get a list of
# policy names with nothing explaining them, which reads as "no findings".
Write-Host '[2/6] Fetching violation detail per alert (this is what /v1/alerts omits)'
$full = New-Object System.Collections.ArrayList
$i = 0
foreach ($a in $all) {
  $i++
  if ($i % 50 -eq 0) { Write-Host -NoNewline "`r  hydrated $i of $($all.Count)" }
  try { [void]$full.Add((Get-Json "$base/v1/alerts/$($a.id)")) } catch { }
}
$withText = @($full | Where-Object { $_.violations -and $_.violations.Count -gt 0 }).Count
Write-Host "`r  hydrated $($full.Count) of $($all.Count), $withText carry violation text     "
@{ alerts = $full } | ConvertTo-Json -Depth 30 | Set-Content "$OutDir/02_alerts_full.json"

# These three stream NDJSON. Do not pipe them through ConvertFrom-Json as one document.
Write-Host '[3/6] Image CVEs for running workloads (vuln-mgmt export)'
$vq = "timeout=$Timeout"; if ($scope) { $vq = "query=$scopeEnc&$vq" }
try {
  Get-Text "$base/v1/export/vuln-mgmt/workloads?$vq" | Set-Content "$OutDir/03_vuln_workloads.ndjson"
  $n = @(Get-Content "$OutDir/03_vuln_workloads.ndjson" | Where-Object { $_.Trim() }).Count
  Write-Host "  $n workload record(s)"
  if ($n -eq 0) { Write-Host '  EMPTY. Usually the token lacks read on Image and Deployment, or nothing is scanned.' }
} catch {
  Write-Host "  FAILED: $($_.Exception.Message)"
  Write-Host '  403 here with a working step 1 means the token has Alert access but not Image.'
  Write-Host '  404 means Central is older than 3.74. Use roxctl or GraphQL instead.'
}

# Step 3 only covers images attached to a deployment. This covers watched images and
# images from deleted deployments too. For "everything", you need both.
Write-Host '[4/6] Image CVEs for every image Central knows (including non running)'
try {
  Get-Text "$base/v1/export/images?timeout=$Timeout" | Set-Content "$OutDir/04_all_images.ndjson"
  Write-Host "  $(@(Get-Content "$OutDir/04_all_images.ndjson" | Where-Object { $_.Trim() }).Count) image(s)"
} catch { Write-Host "  not available on this Central: $($_.Exception.Message)" }

Write-Host '[5/6] Node CVEs'
try {
  Get-Text "$base/v1/export/nodes?timeout=$Timeout" | Set-Content "$OutDir/05_nodes.ndjson"
  Write-Host "  $(@(Get-Content "$OutDir/05_nodes.ndjson" | Where-Object { $_.Trim() }).Count) node(s)"
} catch { Write-Host "  not available on this Central: $($_.Exception.Message)" }

# A CVE somebody deferred is still a finding. It is a decision, not an absence.
Write-Host '[6/6] Snoozed and deferred CVEs (hidden from the default views)'
try {
  $sn = [uri]::EscapeDataString('CVE Snoozed:true')
  Get-Text "$base/v1/export/images?query=$sn&timeout=$Timeout" | Set-Content "$OutDir/06_snoozed.ndjson"
  Write-Host "  $(@(Get-Content "$OutDir/06_snoozed.ndjson" | Where-Object { $_.Trim() }).Count) image(s) carrying snoozed CVEs"
} catch { Write-Host '  query not supported on this version, skipped' }

Write-Host ('-' * 64)
Write-Host 'Severity spread, low to critical'
$full | Group-Object { $_.policy.severity } |
  Sort-Object { @{ LOW_SEVERITY = 0; MEDIUM_SEVERITY = 1; HIGH_SEVERITY = 2; CRITICAL_SEVERITY = 3 }[$_.Name] } |
  ForEach-Object { Write-Host ("  policy  {0}  {1}" -f $_.Name, $_.Count) }

Write-Host ('-' * 64)
Write-Host "Written to $OutDir"
Get-ChildItem $OutDir | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ''
Write-Host 'Drop 02_alerts_full.json and 03_vuln_workloads.ndjson onto dj_acs_auditor.html.'
Write-Host 'Use 02, not 01. The list form has no violation text in it.'
