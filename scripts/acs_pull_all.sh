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
#   ./acs_pull_all.sh [-o PARENT_DIR] [-n NAMESPACE] [-c CLUSTER] [-j JOBS]
#                     [--no-timestamp] [--no-summary] [--cacert FILE]
#                     [--pin sha256//KEY] [--insecure]
#
#   -o names the parent. Each run lands in PARENT/acs_findings_<timestamp>/ so
#   runs never overwrite each other. --no-timestamp writes straight into -o.
#
set -u
SCRIPTDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Where the run goes.
#
# -o names the PARENT. Each run gets its own timestamped directory inside it, so a second
# run never overwrites the first and you keep a history you can diff. An export you cannot
# compare against last week's is worth much less than one you can.
#
# --no-timestamp writes straight into -o instead, for a pipeline that wants a fixed path.
OUTPARENT="."
RUNDIR="acs_findings_$(date +%Y%m%d_%H%M%S)"
NO_TS=0
NO_SUMMARY=0
PIN=""
NAMESPACE=""
CLUSTER=""
JOBS=4
PAGE=500
TIMEOUT=600
CURL_TLS=""
CACERT=""

while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTPARENT="$2"; shift 2 ;;
    --no-timestamp) NO_TS=1; shift ;;
    --no-summary) NO_SUMMARY=1; shift ;;
    --pin) PIN="${2:-}"; shift 2 ;;
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
# The preflight reads ROX_CA from the environment. Accept the same variable here so a
# CA is exported once and both scripts use it. An explicit --cacert still wins.
if [ -z "$CACERT" ] && [ -n "${ROX_CA:-}" ]; then CACERT="$ROX_CA"; fi
if [ -n "$CACERT" ]; then
  if [ ! -r "$CACERT" ]; then
    echo "ERROR: CA bundle not readable: $CACERT" >&2
    exit 2
  fi
  CURL_TLS="--cacert $CACERT"
fi
if [ "$CURL_TLS" = "-k" ]; then
  echo "WARNING: TLS verification disabled. Your API token is exposed to anyone who can" >&2
  echo "         intercept this connection. Use --cacert <file> instead where you can." >&2
fi

if [ "$NO_TS" = "1" ]; then OUTDIR="$OUTPARENT"; else OUTDIR="$OUTPARENT/$RUNDIR"; fi
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

# curl exit 60 on an OpenShift cluster is almost always the same thing: Central sits
# behind an .apps route whose wildcard certificate is signed by the cluster's own
# ingress CA, and your workstation has no reason to trust that CA. The answer is to
# obtain the CA over a channel you already trust, which is your authenticated oc
# session, and NOT to turn verification off on a request carrying a bearer token.
ca_help() {
  say "  TLS verification failed: the CA presenting this certificate is not trusted here."
  say ""
  say "  Do NOT reach for --insecure. This request carries a token that reads your whole"
  say "  security posture, and disabling verification hands it to anyone on the path."
  say ""
  say "  Find out which CA is actually presenting, so you fetch the right one:"
  say ""
  say "    openssl s_client -connect ${ROX_ENDPOINT#https://}:443 -showcerts </dev/null 2>/dev/null \\"
  say "      | openssl x509 -noout -issuer -subject"
  say ""
  say "  Then get that CA from your authenticated oc session, not from the handshake."
  say ""
  say "  If Central is behind a normal .apps route, which is the usual case:"
  say ""
  say "    oc -n openshift-config-managed get configmap default-ingress-cert \\"
  say "      -o jsonpath='{.data.ca-bundle\\.crt}' > ~/ocp-ingress-ca.pem"
  say ""
  say "  If the route is passthrough and Central presents its own certificate:"
  say ""
  say "    oc -n stackrox get secret central-tls \\"
  say "      -o jsonpath='{.data.ca\\.pem}' | base64 -d > ~/central-ca.pem"
  say ""
  say "  Then set it once and re-run. Both scripts read this variable:"
  say ""
  say "    export ROX_CA=~/ocp-ingress-ca.pem"
  say "    ./acs_preflight.sh \"$ROX_ENDPOINT\""
  say "    ./acs_pull_all.sh"
  say ""
  say "  Verify it worked before trusting the output:"
  say ""
  say "    curl --cacert \"\$ROX_CA\" -sS -o /dev/null -w '%{http_code}\\n' \\"
  say "      \"$ROX_ENDPOINT/v1/metadata\""
}

say "ACS full findings sweep"
say "  endpoint : $ROX_ENDPOINT"
say "  scope    : ${SCOPE:-<everything, no filter>}"
say "  output   : $OUTDIR"
hr

# --- 0. Prove the token works and say what it can see -----------------------
# --- TLS: get to a verified connection without reaching for -k ---------------
#
# Central's certificate is self signed by default. That is not a misconfiguration, it is
# what the operator installs, and it means the system trust store will never verify it.
# The wrong answer is --insecure, because this request carries a token that reads your
# entire security posture. The right answer is to obtain the issuer over a channel you
# already trust and pin to it.
#
# Order of preference, most trustworthy first:
#   1. A CA you supplied. You decided where it came from.
#   2. The central-tls secret, read through your authenticated oc session. The cluster
#      tells us its own CA over a connection kubectl already verified.
#   3. A public key pin you confirmed out of band. Verifies the exact key with no chain.
#   4. Nothing. The run stops and tells you which of the above to do.
resolve_tls() {
  [ -n "$CACERT" ] && return 0
  [ "$CURL_TLS" = "-k" ] && return 0
  if [ -n "$PIN" ]; then
    # -k is required here and is not a weakening.
    #
    # --pinnedpubkey is an ADDITIONAL check, not a replacement for chain verification.
    # Against a self signed certificate curl fails with error 60 before it ever looks at
    # the pin, so the pin alone can never work. -k turns off the chain and hostname
    # checks, and the pin then requires the exact public key you named. Wrong key fails
    # closed: verified against a self signed endpoint, a mismatched pin returns no
    # response at all.
    #
    # The security of this rests entirely on you having confirmed the fingerprint through
    # some channel other than this connection. Pinned to whatever answered first, it is
    # trust on first use and worth saying so plainly.
    CURL_TLS="-k --pinnedpubkey $PIN"
    say "  chain verification off, pinned to the public key you supplied"
    say "  every request must present exactly that key or it fails"
    return 0
  fi

  # Does the system trust store already work? Most of the time with a self signed cert it
  # will not, but a cluster behind a corporate CA that is already installed will pass.
  if curl -sS -o /dev/null --max-time 10 "$ROX_ENDPOINT/v1/metadata" 2>/dev/null; then
    say "  verified against the system trust store"
    return 0
  fi

  # Try the cluster. This is the good path and it is why oc being logged in matters.
  if command -v oc >/dev/null 2>&1; then
    CA_AUTO="$OUTDIR/central-ca.pem"
    # --request-timeout is not optional here.
    #
    # oc will happily block for a long time against a cluster it cannot reach, and this
    # runs on a workstation whose kubeconfig may point anywhere, or nowhere. Without a
    # bound, a script whose whole job is to fetch findings sits silently on an unrelated
    # API call, and the operator has no idea which step they are waiting on.
    say "  trying the central-tls secret through your oc session"
    if oc --request-timeout=10s -n stackrox get secret central-tls \
         -o jsonpath='{.data.ca\.pem}' 2>/dev/null \
         | base64 -d > "$CA_AUTO" 2>/dev/null && [ -s "$CA_AUTO" ]; then
      if curl -sS --cacert "$CA_AUTO" -o /dev/null --max-time 10 "$ROX_ENDPOINT/v1/metadata" 2>/dev/null; then
        CURL_TLS="--cacert $CA_AUTO"
        say "  CA read from the central-tls secret over your oc session, and it verifies"
        say "  saved to $CA_AUTO for the next run: --cacert that file, or export ROX_CA"
        return 0
      fi
      say "  read a CA from central-tls but it does not verify this endpoint."
      say "  Central is probably behind a route with a different certificate than its own."
      rm -f "$CA_AUTO"
    else
      say "  no CA available that way: not logged in, no read on the secret, or the"
      say "  request timed out. Falling through to the options below."
      rm -f "$CA_AUTO" 2>/dev/null || true
    fi
  fi

  # Nothing automatic worked. Show the key so it can be confirmed out of band.
  say ""
  say "  TLS verification failed and no trusted CA could be obtained automatically."
  say ""
  if command -v openssl >/dev/null 2>&1; then
    HOSTPORT=$(echo "$ROX_ENDPOINT" | sed -e 's|^https\{0,1\}://||' -e 's|/.*$||')
    case "$HOSTPORT" in *:*) : ;; *) HOSTPORT="$HOSTPORT:443" ;; esac
    SPKI=$(echo | openssl s_client -connect "$HOSTPORT" -servername "${HOSTPORT%%:*}" 2>/dev/null \
      | openssl x509 -pubkey -noout 2>/dev/null \
      | openssl pkey -pubin -outform der 2>/dev/null \
      | openssl dgst -sha256 -binary 2>/dev/null | openssl base64 2>/dev/null)
    FP=$(echo | openssl s_client -connect "$HOSTPORT" 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
    ISS=$(echo | openssl s_client -connect "$HOSTPORT" 2>/dev/null \
      | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    # sha256 of nothing is 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=. If the handshake
    # produced no certificate, every step of that pipeline still succeeds and hashes an
    # empty string, so the check below is on the certificate rather than on the hash.
    # Printing a pin command built from an empty handshake would be worse than printing
    # nothing: it looks authoritative and pins to a value that means the opposite.
    if [ -n "$FP" ] && [ -n "$SPKI" ] && \
       [ "$SPKI" != "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" ]; then
      say "  The endpoint is presenting a certificate issued by:"
      say "    $ISS"
      say "  SHA-256 fingerprint:"
      say "    $FP"
      say ""
      say "  Confirm that fingerprint against the cluster through a channel other than this"
      say "  connection before trusting either option below. That confirmation is the whole"
      say "  security of both of them."
      say ""

      # A self signed certificate is its own issuer, so the certificate itself works as a
      # CA bundle. That keeps full verification, chain and hostname, and is the better of
      # the two. It only fails when the name you are connecting to is not in the
      # certificate, which is common with a port forward and rare with a real route.
      LEAF="$OUTPARENT/central-cert.pem"
      echo | openssl s_client -connect "$HOSTPORT" 2>/dev/null | openssl x509 > "$LEAF" 2>/dev/null
      if [ -s "$LEAF" ] && curl -sS --cacert "$LEAF" -o /dev/null --max-time 10 \
           "$ROX_ENDPOINT/v1/metadata" 2>/dev/null; then
        say "  A: verify against the certificate itself. Full verification, keeps the"
        say "     hostname check. This one works against your endpoint:"
        say ""
        say "       ./acs_pull_all.sh --cacert $LEAF -o $OUTPARENT"
        say ""
      else
        say "  A: verifying against the certificate itself did not work here, which"
        say "     usually means the name you are connecting to is not in the certificate."
        say "     The certificate is saved at $LEAF if you want to inspect it."
        say ""
      fi

      say "  B: pin the public key. Works regardless of the name, and fails closed if the"
      say "     key ever changes:"
      say ""
      say "       ./acs_pull_all.sh --pin 'sha256//$SPKI' -o $OUTPARENT"
      say ""
      say "     This turns the chain check off and requires that exact key instead. It is"
      say "     trust on first use unless you confirmed the fingerprint above."
      say ""
    else
      say "  Could not read a certificate from $HOSTPORT to show you its fingerprint."
      say "  Nothing answered the TLS handshake, so the endpoint or the port is wrong,"
      say "  or something between you and it is refusing the connection."
      say ""
    fi
  fi
  say "  Or read the CA from the cluster yourself and pass it:"
  say ""
  say "    oc -n stackrox get secret central-tls -o jsonpath='{.data.ca\\.pem}' \\"
  say "      | base64 -d > central-ca.pem"
  say "    ./acs_pull_all.sh --cacert central-ca.pem -o $OUTPARENT"
  say ""
  say "  Both of these verify. --insecure does not, and this request carries a token that"
  say "  reads your whole security posture, so it is not offered as a shortcut here."
  return 1
}

say "[0/7] TLS"
if ! resolve_tls; then
  # Leave nothing that could be mistaken for a pull. A directory named
  # acs_findings_<timestamp> containing one stray file looks like a run that returned
  # almost nothing, which is a very different thing from a run that never started.
  #
  # cleanup() removes the token header file, but it runs on EXIT, which is after this.
  # Call it first or the directory is never empty and the rmdir quietly does nothing.
  cleanup
  rmdir "$OUTDIR" 2>/dev/null || true
  say ""
  say "  Nothing was pulled, so no findings directory was created."
  exit 1
fi

# CURL is built from CURL_TLS, and resolve_tls is what decides CURL_TLS. Building it
# before that ran meant the decision was discarded: the pin was computed, announced, and
# then never passed to curl. Rebuild here, once, after the decision is final.
CURL="curl -sS --fail-with-body $CURL_TLS -H @$HDR -H Accept:application/json"

say "[0/7] Checking the token"
if ! $CURL "$ROX_ENDPOINT/v1/auth/status" -o "$OUTDIR/00_auth_status.json" 2>"$OUTDIR/00_auth_status.err"; then
  say "  FAILED. $(head -c 300 "$OUTDIR/00_auth_status.err")"
  say ""
  say "  401 means the token is wrong or expired."
  say "  403 means it authenticated but lacks a role."
  say ""
  if grep -qiE "certificate|SSL|self.signed|unable to get local issuer" "$OUTDIR/00_auth_status.err" 2>/dev/null; then
    ca_help
  else
    say "  A connection error usually means an untrusted internal CA. Use --cacert."
  fi
  # Mark the directory so it cannot be mistaken for a pull that came back empty.
  {
    echo "This run FAILED at the token check and pulled nothing."
    echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') against $ROX_ENDPOINT"
    echo ""
    echo "The only other file here is 00_auth_status.err, which is what curl said."
    echo "There are no findings in this directory. Do not load it and conclude the"
    echo "cluster is clean."
  } > "$OUTDIR/RUN_FAILED.txt"
  say ""
  say "  Marked $OUTDIR/RUN_FAILED.txt so this is not mistaken for an empty result."
  exit 1
fi
say "  ok"

# --- 1. Policy violations, every state, fully paginated ---------------------
# Deliberately NO 'Violation State' term. The ACS console defaults to ACTIVE; omitting
# the term returns ACTIVE, RESOLVED and ATTEMPTED. Same for severity and lifecycle
# stage: no filter means every value, which is what "low to high" asks for.
say "[1/7] Policy violations, all severities, all states, all lifecycle stages"
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
say "[2/7] Fetching violation detail per alert (this is what /v1/alerts omits)"
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
say "[3/7] Image CVEs for running workloads (vuln-mgmt export)"
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
say "[4/7] Image CVEs for every image Central knows (including non running)"
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
say "[5/7] Node CVEs"
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
say "[6/7] Snoozed and deferred CVEs (hidden from the default views)"
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
# --- 7. The live workloads, captured beside the findings -----------------------
#
# ACS tells you a workload is in violation. It does not hand you the manifest. Capturing
# the running objects into the same directory, at the same moment, is what makes the pair
# useful: the findings and the thing they are about, from the same instant.
#
# It also gives you a before and after. Run this, make changes, run it again, and the two
# workloads.json files diff cleanly. Without that you are comparing a finding count to a
# finding count and hoping the cluster did not move underneath you.
say "[7/7] Live workloads"
WL="$OUTDIR/workloads.json"
if command -v oc >/dev/null 2>&1; then
  # Same time bound as the trust bootstrap, and for the same reason: this runs on a
  # workstation whose kubeconfig may point anywhere, or nowhere.
  if oc --request-timeout=60s get deployment,daemonset,statefulset,cronjob,job \
       --all-namespaces -o json > "$WL" 2>"$OUTDIR/.wl.err"; then
    if command -v jq >/dev/null 2>&1; then
      N=$(jq -r '.items | length' "$WL" 2>/dev/null || echo "?")
      say "  $N workload object(s) written to workloads.json"
    else
      say "  written to workloads.json"
    fi
    say "  drop this on the page with the rest to audit what is running, not what git says"
  else
    # An oc that is present but cannot reach the cluster leaves you in exactly the same
    # place as no oc at all, so give the same instruction rather than only the error.
    say "  could not read workloads: $(head -c 160 "$OUTDIR/.wl.err" 2>/dev/null)"
    say "  Not fatal. The ACS findings above are unaffected; the workloads were not"
    say "  captured, so violations will show as needing a manifest you do not have."
    say "  Capture them anywhere your oc session works and drop the file on the page:"
    say ""
    say "    oc get deployment,daemonset,statefulset,cronjob,job -A -o json > workloads.json"
    rm -f "$WL"
  fi
else
  say "  oc is not on PATH, so the running workloads were not captured."
  say "  Without them the page can show you the violations but has no manifest to fix."
  say "  Capture them anywhere you have oc and drop the file on the page alongside these:"
  say ""
  say "    oc get deployment,daemonset,statefulset,cronjob,job -A -o json > workloads.json"
fi
rm -f "$OUTDIR/.wl.err"
hr

# --- the summary, written and shown --------------------------------------------
#
# A directory of seven JSON files is not a result anybody can read. Writing the summary
# here means the run ends with something you can look at, send on, or attach to a ticket
# without opening anything else. It is jq only, so it works on the machines where the
# rest of the tooling does not.
SUMMARY="$OUTDIR/findings.md"
if [ "$NO_SUMMARY" = "0" ] && command -v jq >/dev/null 2>&1 \
   && [ -x "$SCRIPTDIR/acs_summary.sh" ]; then
  hr
  if "$SCRIPTDIR/acs_summary.sh" "$OUTDIR" -o "$SUMMARY" >/dev/null 2>&1 && [ -s "$SUMMARY" ]; then
    # Show it. A file written and not shown is a file nobody reads.
    cat "$SUMMARY"
    hr
    say "Summary written to $SUMMARY"
  else
    say "Could not write the summary. The exported files are still in $OUTDIR."
  fi
elif [ "$NO_SUMMARY" = "0" ] && ! command -v jq >/dev/null 2>&1; then
  hr
  say "jq is not installed, so no summary was written. The exports are in $OUTDIR."
fi

hr
say "Next: open dj_acs_auditor.html in a browser and drop these files on it."
say "Drop all of them at once. They merge rather than replacing each other."
say ""
say "Use 02_alerts_full.json, not 01. The list form has no violation text in it,"
say "which is a limit of the ACS API rather than of this script."
say ""
say "The page needs no runtime, no package manager and no server. Open the file."
say ""
if command -v node >/dev/null 2>&1; then
  say "Or headless, same engine:"
  say "  node acs_cli.js --alerts $OUTDIR/02_alerts_full.json --vulns $OUTDIR/03_vuln_workloads.ndjson --report"
else
  say "Node is not on this machine, so acs_cli.js is unavailable here. For a summary you"
  say "can read or hand over without leaving the shell, jq is enough:"
  say ""
  say "  ./scripts/acs_summary.sh $OUTDIR -o findings.md"
  say ""
  say "That counts what ACS reported. It is not a posture score and does not draft fixes,"
  say "because both need the policy engine. For those, open the page on any machine and"
  say "drop this directory on it."
fi
