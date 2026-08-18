#!/usr/bin/env bash
#
# acs_pull_all.sh  --  pull EVERY finding ACS knows about, all severities, all states.
#
# Written for bash 3.2 so it runs on a stock macOS shell. No mapfile, no associative
# arrays, no process substitution into arrays.
#
# WHY THIS EXISTS
#   ACS has several separate stores and no single endpoint that returns all of them.
#   Asking only /v1/alerts is the classic mistake: it returns policy violations, it
#   defaults to active ones, its list form carries no violation text, and it contains
#   no image CVEs at all. This script sweeps every store and writes one file per store.
#
# WHAT IT COLLECTS
#   1. Policy violations, every severity, every lifecycle stage, every violation state
#      (ACTIVE, RESOLVED, ATTEMPTED), fully paginated, then hydrated per alert so the
#      violation text is actually present.
#   2. Image CVEs for running workloads, via the vuln-mgmt export.
#   3. Image CVEs for EVERY image Central knows, including images with no running
#      deployment, which store 2 does not cover.
#   4. Node CVEs.
#   5. Snoozed and deferred CVEs, which are excluded from the default views.
#
# WHAT IT DOES NOT DO
#   It never writes. Every call is a GET. Nothing is applied to a cluster.
#
# REQUIREMENTS
#   curl, jq. Both are usually already there.
#
# USAGE
#   export ROX_ENDPOINT=https://central-stackrox.apps.example.com
#   export ROX_API_TOKEN=...        # never pass this as an argument
#   ./acs_pull_all.sh [-o OUTDIR] [-n NAMESPACE] [-c CLUSTER] [-j JOBS] [--insecure]
#
set -u

OUTDIR="acs_findings_$(date +%Y%m%d_%H%M%S)"
NAMESPACE=""
CLUSTER=""
JOBS=4
PAGE=500
TIMEOUT=600
CURL_TLS=""
CACERT=""

while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTDIR="$2"; shift 2 ;;
    -n) NAMESPACE="$2"; shift 2 ;;
    -c) CLUSTER="$2"; shift 2 ;;
    -j) JOBS="$2"; shift 2 ;;
    --page) PAGE="$2"; shift 2 ;;
    --cacert) CACERT="$2"; shift 2 ;;
    --insecure) CURL_TLS="-k"; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

: "${ROX_ENDPOINT:?set ROX_ENDPOINT, for example https://central-stackrox.apps.example.com}"
: "${ROX_API_TOKEN:?set ROX_API_TOKEN. Do not pass the token as an argument, it lands in your shell history and in ps output}"

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

# Strip any trailing slash so we never build a //v1 URL.
ROX_ENDPOINT="${ROX_ENDPOINT%/}"

# TLS. Verification is ON by default and that is deliberate: this call carries a
# bearer token that is, in effect, read access to your entire security posture.
# --insecure disables verification and turns any host on the path into a position
# from which that token can be stolen. Prefer --cacert with your internal CA.
if [ -n "$CACERT" ]; then CURL_TLS="--cacert $CACERT"; fi
if [ "$CURL_TLS" = "-k" ]; then
  echo "WARNING: TLS verification disabled. Your API token is exposed to anyone who can" >&2
  echo "         intercept this connection. Use --cacert <file> instead where you can." >&2
fi

mkdir -p "$OUTDIR"

# Token goes in a header file, mode 600, not on the command line. Arguments are
# visible in ps to every user on the box; a header file is not.
HDR="$OUTDIR/.hdr"
( umask 077; printf 'Authorization: Bearer %s\n' "$ROX_API_TOKEN" > "$HDR" )
cleanup() { rm -f "$HDR"; }
trap cleanup EXIT INT TERM

CURL="curl -sS --fail-with-body $CURL_TLS -H @$HDR -H Accept:application/json"

# urlencode without python, so this works on a locked down box.
urlenc() {
  local s="$1" o="" c i
  i=0
  while [ $i -lt ${#s} ]; do
    c="${s:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) o="$o$c" ;;
      *) o="$o$(printf '%%%02X' "'$c")" ;;
    esac
    i=$((i+1))
  done
  printf '%s' "$o"
}

# Scope filter reused by every store. Left empty by default: no namespace filter, no
# cluster filter, no severity filter, no state filter. Empty means everything, which
# is the goal here. Narrow it only if a full sweep is too slow.
# Platform Component:true,false asks for BOTH your workloads and the platform's.
# The ACS console Violations page defaults to user workloads only (a selector added in
# 4.6), so anything you can see there under the platform view is absent from a default
# API pull. On ACS older than 4.6 the field does not exist and naming it rejects the
# whole query, so this is retried without it below.
PLATFORM_TERM="Platform Component:true,false"

SCOPE=""
[ -n "$NAMESPACE" ] && SCOPE="Namespace:$NAMESPACE"
if [ -n "$CLUSTER" ]; then
  [ -n "$SCOPE" ] && SCOPE="$SCOPE+Cluster:$CLUSTER" || SCOPE="Cluster:$CLUSTER"
fi
SCOPE_ENC="$(urlenc "$SCOPE")"

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "----------------------------------------------------------------"; }

say "ACS full findings sweep"
say "  endpoint : $ROX_ENDPOINT"
say "  scope    : ${SCOPE:-<everything, no filter>}"
say "  output   : $OUTDIR"
hr

# --- 0. Prove the token works and say what it can see -----------------------
say "[0/6] Checking the token"
if ! $CURL "$ROX_ENDPOINT/v1/auth/status" -o "$OUTDIR/00_auth_status.json" 2>"$OUTDIR/00_auth_status.err"; then
  say "  FAILED. $(head -c 300 "$OUTDIR/00_auth_status.err")"
  say ""
  say "  401 means the token is wrong or expired."
  say "  403 means it authenticated but lacks a role."
  say "  A connection error usually means an untrusted internal CA. Use --cacert."
  exit 1
fi
say "  ok"

# --- 1. Policy violations, every state, fully paginated ---------------------
# Deliberately NO 'Violation State' term. The ACS console defaults to ACTIVE; omitting
# the term returns ACTIVE, RESOLVED and ATTEMPTED. Same for severity and lifecycle
# stage: no filter means every value, which is what "low to high" asks for.
say "[1/6] Policy violations, all severities, all states, all lifecycle stages"
# Build the alert query: scope, plus both platform and user. No state term, so every
# state comes back: ACTIVE, RESOLVED and ATTEMPTED.
AQ="$PLATFORM_TERM"
[ -n "$SCOPE" ] && AQ="$SCOPE+$PLATFORM_TERM"
AQ_ENC="$(urlenc "$AQ")"

# Probe once. If this Central rejects the field it predates 4.6, so drop the term.
PROBE=$($CURL "$ROX_ENDPOINT/v1/alertscount?query=$AQ_ENC" 2>/dev/null | jq -r '.count // "ERR"')
if [ "$PROBE" = "ERR" ] || [ -z "$PROBE" ]; then
  say "  this Central rejected the Platform Component filter, so it predates ACS 4.6"
  say "  retrying without it, which returns whatever Central gives by default"
  AQ="$SCOPE"
  AQ_ENC="$SCOPE_ENC"
fi

TOTAL=$($CURL "$ROX_ENDPOINT/v1/alertscount?query=$AQ_ENC" 2>/dev/null | jq -r '.count // 0')
say "  Central reports $TOTAL alert(s) in scope"
say "  query: ${AQ:-<no filter, everything>}"

: > "$OUTDIR/01_alerts_list.json"
OFFSET=0
GOT=0
echo '{"alerts":[]}' > "$OUTDIR/01_alerts_list.json"
while : ; do
  Q="query=$AQ_ENC&pagination.limit=$PAGE&pagination.offset=$OFFSET"
  if ! $CURL "$ROX_ENDPOINT/v1/alerts?$Q" -o "$OUTDIR/.page.json" 2>"$OUTDIR/.page.err"; then
    say "  page at offset $OFFSET failed: $(head -c 200 "$OUTDIR/.page.err")"
    break
  fi
  N=$(jq -r '(.alerts // []) | length' "$OUTDIR/.page.json")
  [ "$N" = "0" ] && break
  jq -s '{alerts: (.[0].alerts + (.[1].alerts // []))}' \
     "$OUTDIR/01_alerts_list.json" "$OUTDIR/.page.json" > "$OUTDIR/.merged.json" \
     && mv "$OUTDIR/.merged.json" "$OUTDIR/01_alerts_list.json"
  GOT=$((GOT+N))
  OFFSET=$((OFFSET+PAGE))
  printf '\r  paged %s alert(s)' "$GOT"
  [ "$N" -lt "$PAGE" ] && break
done
rm -f "$OUTDIR/.page.json" "$OUTDIR/.page.err"
printf '\r  retrieved %s alert(s)          \n' "$GOT"

if [ "$TOTAL" != "0" ] && [ "$GOT" -lt "$TOTAL" ]; then
  say "  NOTE: got $GOT of $TOTAL. The gap is almost always scoped access:"
  say "        your token can count them but cannot read every namespace."
fi

# --- 2. Hydrate. This is the step people miss. -------------------------------
# GET /v1/alerts returns storage.ListAlert, which has NO violations[] array. The
# violation text only exists on GET /v1/alerts/{id}. Without this loop you get a
# list of policy names with nothing explaining them, which reads as "no findings".
say "[2/6] Fetching violation detail per alert (this is what /v1/alerts omits)"
jq -r '.alerts[]?.id' "$OUTDIR/01_alerts_list.json" | sort -u > "$OUTDIR/.ids"
IDCOUNT=$(wc -l < "$OUTDIR/.ids" | tr -d ' ')
if [ "$IDCOUNT" != "0" ]; then
  mkdir -p "$OUTDIR/.full"
  # Bounded concurrency. Central is a security control; do not flood it.
  export ROX_ENDPOINT OUTDIR
  CURL_ARGS="$CURL_TLS"
  export CURL_ARGS HDR
  cat "$OUTDIR/.ids" | xargs -P "$JOBS" -I{} sh -c \
    'curl -sS --fail-with-body $CURL_ARGS -H "@$HDR" -H Accept:application/json \
       "$ROX_ENDPOINT/v1/alerts/{}" -o "$OUTDIR/.full/{}.json" 2>/dev/null || true'
  find "$OUTDIR/.full" -name '*.json' -size +0 -print0 \
    | xargs -0 cat 2>/dev/null \
    | jq -s '{alerts: .}' > "$OUTDIR/02_alerts_full.json"
  HYD=$(jq -r '.alerts | length' "$OUTDIR/02_alerts_full.json")
  WITHTEXT=$(jq -r '[.alerts[] | select((.violations // []) | length > 0)] | length' "$OUTDIR/02_alerts_full.json")
  say "  hydrated $HYD of $IDCOUNT, $WITHTEXT carry violation text"
  rm -rf "$OUTDIR/.full"
else
  echo '{"alerts":[]}' > "$OUTDIR/02_alerts_full.json"
  say "  no alerts to hydrate"
fi
rm -f "$OUTDIR/.ids" "$OUTDIR/00_auth_status.err"

# --- 3. Image CVEs on running workloads --------------------------------------
# Streams NDJSON, one {"result":{deployment,images,livePods}} per line. Do not pipe
# this through anything expecting a single JSON document.
say "[3/6] Image CVEs for running workloads (vuln-mgmt export)"
VQ="timeout=$TIMEOUT"
[ -n "$SCOPE" ] && VQ="query=$SCOPE_ENC&$VQ"
if $CURL "$ROX_ENDPOINT/v1/export/vuln-mgmt/workloads?$VQ" -o "$OUTDIR/03_vuln_workloads.ndjson" 2>"$OUTDIR/.v.err"; then
  L=$(grep -c . "$OUTDIR/03_vuln_workloads.ndjson" 2>/dev/null || echo 0)
  C=$(jq -s '[.[].result.images[]?.scan.components[]?.vulns[]?.cve] | unique | length' \
        "$OUTDIR/03_vuln_workloads.ndjson" 2>/dev/null || echo "?")
  say "  $L workload(s), $C distinct CVE(s)"
  [ "$L" = "0" ] && say "  EMPTY. Usually the token lacks read on Image and Deployment, or nothing is scanned."
else
  say "  FAILED: $(head -c 200 "$OUTDIR/.v.err")"
  say "  403 here with a working step 1 means the token has Alert access but not Image."
  say "  404 means Central is older than 3.74. Use roxctl or GraphQL instead."
fi
rm -f "$OUTDIR/.v.err"

# --- 4. Every image Central knows, not just the running ones -----------------
# Step 3 only covers images attached to a deployment. This covers watched images,
# images from deleted deployments, and anything scanned but not running. If you want
# "all possible findings", you need both.
say "[4/6] Image CVEs for every image Central knows (including non running)"
if $CURL "$ROX_ENDPOINT/v1/export/images?timeout=$TIMEOUT" -o "$OUTDIR/04_all_images.ndjson" 2>"$OUTDIR/.i.err"; then
  L=$(grep -c . "$OUTDIR/04_all_images.ndjson" 2>/dev/null || echo 0)
  C=$(jq -s '[.[].result.scan.components[]?.vulns[]?.cve] | unique | length' \
        "$OUTDIR/04_all_images.ndjson" 2>/dev/null || echo "?")
  say "  $L image(s), $C distinct CVE(s)"
else
  say "  not available on this Central: $(head -c 160 "$OUTDIR/.i.err")"
fi
rm -f "$OUTDIR/.i.err"

# --- 5. Node CVEs -------------------------------------------------------------
say "[5/6] Node CVEs"
if $CURL "$ROX_ENDPOINT/v1/export/nodes?timeout=$TIMEOUT" -o "$OUTDIR/05_nodes.ndjson" 2>"$OUTDIR/.n.err"; then
  L=$(grep -c . "$OUTDIR/05_nodes.ndjson" 2>/dev/null || echo 0)
  say "  $L node(s)"
else
  say "  not available on this Central: $(head -c 160 "$OUTDIR/.n.err")"
fi
rm -f "$OUTDIR/.n.err"

# --- 6. Snoozed and deferred, which the default views hide -------------------
# A CVE somebody deferred is still a finding. It is a decision, not an absence. If
# you are asking for everything, you want these too, clearly labelled.
say "[6/6] Snoozed and deferred CVEs (hidden from the default views)"
SNZ="$(urlenc 'CVE Snoozed:true')"
if $CURL "$ROX_ENDPOINT/v1/export/images?query=$SNZ&timeout=$TIMEOUT" \
     -o "$OUTDIR/06_snoozed.ndjson" 2>/dev/null; then
  L=$(grep -c . "$OUTDIR/06_snoozed.ndjson" 2>/dev/null || echo 0)
  say "  $L image(s) carrying snoozed CVEs"
else
  say "  query not supported on this version, skipped"
  : > "$OUTDIR/06_snoozed.ndjson"
fi

# --- Summary ------------------------------------------------------------------
hr
say "Platform split"
# jq's // is an ALTERNATIVE operator, not a null coalesce: it treats false as empty and
# falls through. So `.platformComponent // null` turns every false into null, and every
# user workload gets reported as "flag not present". Test with has() instead.
jq -r '
  [.alerts[]? | if has("platformComponent") then .platformComponent
                elif has("platform_component") then .platform_component
                else null end] |
  {reported: (map(select(. != null)) | length),
   platform: (map(select(. == true)) | length),
   user:     (map(select(. == false)) | length),
   unknown:  (map(select(. == null)) | length)} |
  "  platform components : \(.platform)\n  your workloads      : \(.user)" +
  (if .unknown > 0 then "\n  flag not reported   : \(.unknown)  (this Central predates ACS 4.6)" else "" end)
' "$OUTDIR/02_alerts_full.json" 2>/dev/null || true
say ""

say "Violation states (the console shows ACTIVE only)"
jq -r '[.alerts[]? | .state] | group_by(.) | map({s: .[0], n: length}) | .[] | "  \(.s)  \(.n)"' \
  "$OUTDIR/02_alerts_full.json" 2>/dev/null || true
say ""

say "Severity spread, low to critical"
jq -r '
  [.alerts[]? | .policy.severity] | group_by(.) |
  map({sev: .[0], n: length}) |
  sort_by(if   .sev=="LOW_SEVERITY"      then 0
          elif .sev=="MEDIUM_SEVERITY"   then 1
          elif .sev=="HIGH_SEVERITY"     then 2
          elif .sev=="CRITICAL_SEVERITY" then 3
          else 4 end) |
  .[] | "  policy  \(.sev)  \(.n)"
' "$OUTDIR/02_alerts_full.json" 2>/dev/null || true

jq -s -r '
  [.[].result.images[]?.scan.components[]?.vulns[]? | {cve, severity}] | unique_by(.cve) |
  group_by(.severity) | map({sev: .[0].severity, n: length}) |
  sort_by(if   .sev=="LOW_VULNERABILITY_SEVERITY"       then 0
          elif .sev=="MODERATE_VULNERABILITY_SEVERITY"  then 1
          elif .sev=="IMPORTANT_VULNERABILITY_SEVERITY" then 2
          elif .sev=="CRITICAL_VULNERABILITY_SEVERITY"  then 3
          else 4 end) |
  .[] | "  cve     \(.sev)  \(.n)"
' "$OUTDIR/03_vuln_workloads.ndjson" 2>/dev/null || true

hr
say "Written to $OUTDIR:"
ls -1 "$OUTDIR" | sed 's/^/  /'
say ""
say "Drop 02_alerts_full.json and 03_vuln_workloads.ndjson onto dj_acs_auditor.html."
say "Use 02, not 01. The list form has no violation text in it."
