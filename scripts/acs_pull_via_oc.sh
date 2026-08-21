#!/usr/bin/env sh
#
# acs_pull_via_oc.sh -- pull ACS vulnerability data using your existing oc session.
#
# THE THING TO UNDERSTAND FIRST
#   oc cannot fetch this data. oc talks to the Kubernetes API server, and ACS findings
#   are not Kubernetes objects. There is no CRD holding CVEs: the ACS operator installs
#   Central and SecuredCluster custom resources, and those are install configuration.
#   `oc get central -o yaml` returns replica counts and a route hostname, never a CVE.
#
#   What oc IS good for is everything around the call:
#     * finding which namespace ACS is in and what its route is
#     * getting the CA so TLS verification actually works
#     * port forwarding when the route is not reachable from your workstation
#     * retrieving the admin credential from a secret
#
#   This script does all four, then makes the one HTTP call that oc cannot make.
#
# AUTHENTICATION
#   ACS does not accept OpenShift tokens for its API. `oc whoami -t` will be rejected.
#   Two things work:
#     ROX_API_TOKEN   an ACS API token. Preferred. Scoped, revocable, expiring.
#     --admin         read the auto generated admin password from the central-htpasswd
#                     secret and use basic auth. Convenient, and it is the account with
#                     the most privilege in the product, so treat it accordingly.
#
# POSIX sh. Read only: every call is a GET, nothing is applied to anything.
#
set -u

NS=""
OUT="acs_via_oc_$(date +%Y%m%d_%H%M%S)"
QUERY=""
TIMEOUT=600
USE_ADMIN=0
FORCE_PF=0
PF_PORT=18443

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="$2"; shift 2 ;;
    -o|--out) OUT="$2"; shift 2 ;;
    -q|--query) QUERY="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --admin) USE_ADMIN=1; shift ;;
    --port-forward) FORCE_PF=1; shift ;;
    --port) PF_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v oc >/dev/null 2>&1 || { echo "oc not found on PATH" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl not found on PATH" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

oc whoami >/dev/null 2>&1 || { echo "Not logged in. Run: oc login <cluster>" >&2; exit 1; }

mkdir -p "$OUT"
PF_PID=""
VIA_TUNNEL=0
cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null
  rm -f "$OUT/.hdr" "$OUT/.tmp"
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "----------------------------------------------------------------"; }

say "Pulling ACS vulnerability data using your oc session"
say "  user    : $(oc whoami 2>/dev/null)"
say "  cluster : $(oc whoami --show-server 2>/dev/null)"
hr

# ---- 1. Where is ACS installed? ---------------------------------------------
# The namespace is stackrox on most installs and rhacs-operator on some. Rather than
# guessing, ask for the Central custom resource wherever it lives.
say "[1] Locating ACS"
if [ -z "$NS" ]; then
  NS=$(oc get central --all-namespaces -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
fi
if [ -z "$NS" ]; then
  # No operator install, or no permission on the CR. Fall back to finding the Deployment.
  NS=$(oc get deployment --all-namespaces -o jsonpath='{range .items[?(@.metadata.name=="central")]}{.metadata.namespace}{end}' 2>/dev/null)
fi
if [ -z "$NS" ]; then
  say "  Could not find ACS on this cluster."
  say ""
  say "  Either it is not installed, or your account cannot see it. Try:"
  say "    oc get central --all-namespaces"
  say "    oc get deploy --all-namespaces | grep -w central"
  say ""
  say "  If those are empty but you know ACS exists, you are probably on the wrong"
  say "  cluster, or ACS Central runs on a different cluster from the one you are"
  say "  logged in to. That is a normal topology: one Central watching many clusters."
  exit 1
fi
say "  namespace: $NS"
say "  version  : $(oc -n "$NS" get central -o jsonpath='{.items[0].status.productVersion}' 2>/dev/null || echo 'not readable')"

# What oc CAN tell you, and what it cannot. Worth printing so nobody goes hunting for
# vulnerability data in a place that structurally does not have it.
say "  note     : the Central custom resource is install configuration. It carries"
say "             replica counts, exposure settings and a version. It does not carry"
say "             findings, and there is no CRD that does."

# ---- 2. How do we reach Central? --------------------------------------------
say "[2] Reaching Central"
HOST=""
if [ "$FORCE_PF" -eq 0 ]; then
  HOST=$(oc -n "$NS" get route central -o jsonpath='{.spec.host}' 2>/dev/null)
fi

BASE=""
if [ -n "$HOST" ]; then
  say "  route: https://$HOST"
  # Probe it. A route existing does not mean your workstation can reach it: split DNS,
  # an egress proxy or a firewall between you and the apps domain are all common.
  if curl -sS -k -o /dev/null --max-time 10 "https://$HOST/v1/metadata" 2>/dev/null; then
    BASE="https://$HOST"
    say "  reachable from here"
  else
    say "  route exists but is not reachable from this workstation, falling back to port forward"
  fi
fi

if [ -z "$BASE" ]; then
  say "  starting: oc -n $NS port-forward svc/central $PF_PORT:443"
  oc -n "$NS" port-forward "svc/central" "$PF_PORT:443" >"$OUT/portforward.log" 2>&1 &
  PF_PID=$!
  i=0
  while [ $i -lt 30 ]; do
    sleep 1
    curl -sS -k -o /dev/null --max-time 3 "https://127.0.0.1:$PF_PORT/v1/metadata" 2>/dev/null && break
    i=$((i+1))
  done
  if [ $i -ge 30 ]; then
    say "  port forward did not come up. See $OUT/portforward.log"
    exit 1
  fi
  BASE="https://127.0.0.1:$PF_PORT"
  VIA_TUNNEL=1
  say "  tunnel up on $BASE"
fi

# ---- 3. TLS ------------------------------------------------------------------
# Get the CA out of the cluster so verification works properly, rather than reaching for
# -k. This is the whole reason to do it through oc: you have a trusted channel to the
# cluster already, so you can bootstrap trust for the second channel from it.
say "[3] TLS"
CA="$OUT/central-ca.pem"
CURL_TLS=""
if oc -n "$NS" get secret central-tls -o jsonpath='{.data.ca\.pem}' 2>/dev/null | base64 -d > "$CA" 2>/dev/null && [ -s "$CA" ]; then
  say "  CA extracted from the central-tls secret"
  if [ "$VIA_TUNNEL" -eq 1 ]; then
    # Through a port forward the hostname will not match the certificate. Pin to the
    # service name the certificate is actually issued for, rather than disabling checks.
    #
    # --noproxy is not optional here. The moment the URL stops being 127.0.0.1 and
    # becomes central.<ns>.svc, curl consults http_proxy and HTTPS_PROXY and tries to
    # CONNECT through the corporate proxy to a name that only exists inside the cluster.
    # It fails with "403 from proxy after CONNECT", which reads like an authentication
    # problem and is not one. Federal and enterprise networks almost always have a proxy
    # set, so without this the tunnel path breaks in exactly the environments that need
    # it most.
    CURL_TLS="--cacert $CA --resolve central.$NS.svc:$PF_PORT:127.0.0.1 --noproxy central.$NS.svc"
    BASE="https://central.$NS.svc:$PF_PORT"
    say "  verifying against central.$NS.svc through the tunnel, proxy bypassed"
  else
    CURL_TLS="--cacert $CA"
  fi
else
  say "  could not read central-tls. Falling back to no verification for this run."
  say "  That exposes the credential below to anyone on the path. Prefer granting read"
  say "  on the central-tls secret, or supply your own CA with ROX_CA."
  CURL_TLS="-k"
  [ "$VIA_TUNNEL" -eq 1 ] && CURL_TLS="-k --noproxy 127.0.0.1"
fi
[ -n "${ROX_CA:-}" ] && CURL_TLS="--cacert $ROX_CA"

# ---- 4. Credential -----------------------------------------------------------
say "[4] Credential"
AUTH=""
if [ -n "${ROX_API_TOKEN:-}" ]; then
  ( umask 077; printf 'Authorization: Bearer %s\n' "$ROX_API_TOKEN" > "$OUT/.hdr" )
  AUTH="-H @$OUT/.hdr"
  say "  using ROX_API_TOKEN"
elif [ "$USE_ADMIN" -eq 1 ]; then
  PW=$(oc -n "$NS" get secret central-htpasswd -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null)
  if [ -z "$PW" ]; then
    say "  could not read central-htpasswd. Your account may not have get on secrets there."
    exit 1
  fi
  ( umask 077; printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$PW" | base64 | tr -d '\n')" > "$OUT/.hdr" )
  AUTH="-H @$OUT/.hdr"
  PW=""
  say "  using the admin account from central-htpasswd"
  say "  WARNING: this is the highest privilege account in the product. Prefer a scoped"
  say "  API token for anything you run more than once, and never put it in a pipeline."
else
  say "  No credential."
  say ""
  say "  oc whoami -t will NOT work: ACS does not accept OpenShift tokens for its API."
  say ""
  say "  Either create an ACS API token with read on Image and Deployment:"
  say "    ACS console, Platform Configuration, Integrations, Authentication Tokens"
  say "    export ROX_API_TOKEN=<token>"
  say "  or rerun with --admin to use the auto generated admin password."
  exit 1
fi

CURL="curl -sS --fail-with-body $CURL_TLS $AUTH -H Accept:application/json"

if ! $CURL "$BASE/v1/auth/status" -o "$OUT/.tmp" 2>"$OUT/auth.err"; then
  say "  authentication failed: $(head -c 200 "$OUT/auth.err")"
  exit 1
fi
say "  authenticated"
hr

# ---- 5. The pull -------------------------------------------------------------
say "[5] Pulling vulnerability data"
QS="timeout=$TIMEOUT"
if [ -n "$QUERY" ]; then
  # Percent encode. The + that separates ACS search terms MUST be sent as %2B, because a
  # literal + in a query string decodes to a space and silently changes the query.
  # ${var:offset:length} is a bash extension, not POSIX. On dash or busybox ash it is a
  # syntax error, and this script claims to be POSIX sh, so walk the string with cut.
  enc=""
  rest="$QUERY"
  while [ -n "$rest" ]; do
    ch=$(printf '%s' "$rest" | cut -c1)
    rest=$(printf '%s' "$rest" | cut -c2-)
    case "$ch" in
      [a-zA-Z0-9.~_-]) enc="$enc$ch" ;;
      *) enc="$enc$(printf '%%%02X' "'$ch")" ;;
    esac
  done
  QS="query=$enc&$QS"
  say "  query: $QUERY"
fi

if $CURL "$BASE/v1/export/vuln-mgmt/workloads?$QS" -o "$OUT/vuln_workloads.ndjson" 2>"$OUT/vuln.err"; then
  L=$(grep -c . "$OUT/vuln_workloads.ndjson" 2>/dev/null || echo 0)
  say "  $L workload record(s)"
  if [ "$HAVE_JQ" -eq 1 ] && [ "$L" != "0" ]; then
    C=$(jq -s '[.[].result.images[]?.scan.components[]?.vulns[]?.cve] | unique | length' "$OUT/vuln_workloads.ndjson" 2>/dev/null)
    say "  $C distinct CVE(s)"
  fi
  [ "$L" = "0" ] && say "  EMPTY is not CLEAN. Usually nothing is scanned yet, or the credential cannot read Image."
else
  say "  failed: $(head -c 250 "$OUT/vuln.err")"
  say "  403 here with a working step 4 means the credential lacks read on Image and Deployment."
fi

# Alerts too, since we are already connected and authenticated.
if $CURL "$BASE/v1/alerts?pagination.limit=1000" -o "$OUT/alerts_list.json" 2>/dev/null; then
  if [ "$HAVE_JQ" -eq 1 ]; then
    say "  $(jq -r '(.alerts // []) | length' "$OUT/alerts_list.json") alert(s) listed"
    say "  reminder: this list has no violation text. Hydrate with /v1/alerts/{id},"
    say "            or use ./acs_pull_all.sh which does it for you."
  fi
fi

# Empty error and log files are noise that makes an operator think something failed.
find "$OUT" -maxdepth 1 -type f -empty -delete 2>/dev/null

hr
say "Written to $OUT:"
ls -1 "$OUT" | grep -v '^\.' | sed 's/^/  /'
say ""
say "Next:"
say "  open dj_acs_auditor.html and drop $OUT/vuln_workloads.ndjson on it"
say ""
say "  Or, if Node is available here:"
say "  node acs_cli.js --path ./manifests --vulns $OUT/vuln_workloads.ndjson --report --worklist"
