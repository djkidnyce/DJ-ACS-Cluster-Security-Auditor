#!/usr/bin/env sh
#
# acs_preflight.sh -- work out which server you are actually talking to, whether your
# token works there, and what it is allowed to read. Then print the exact vuln-mgmt call.
#
# WHY THIS EXISTS
#   ACS Central and the OpenShift API server are two different servers, on two different
#   hostnames, with two different token systems. They are easy to confuse because both
#   live on the same cluster and both take a bearer token.
#
#     OpenShift API   https://api.<cluster>:6443
#                     paths look like /apis/user.openshift.io/v1/users/~
#                     token from: oc whoami -t
#
#     ACS Central     https://central-stackrox.apps.<cluster>   (port 443)
#                     paths look like /v1/export/vuln-mgmt/workloads
#                     token from: ACS console, Platform Configuration >
#                                 Integrations > Authentication Tokens
#
#   If you send an ACS path to the OpenShift API you get a 403 or a 404 that looks like
#   an authorisation problem and is actually a wrong host problem. This script names it.
#
# POSIX sh, so it runs on a stock macOS shell, dash or busybox ash.
#
set -u

URL="${1:-${ROX_ENDPOINT:-}}"
TOKEN="${ROX_API_TOKEN:-}"
CURL_TLS=""
[ "${2:-}" = "--insecure" ] && CURL_TLS="-k"
[ -n "${ROX_CA:-}" ] && CURL_TLS="--cacert $ROX_CA"

if [ -z "$URL" ]; then
  echo "usage: ROX_API_TOKEN=... ./acs_preflight.sh <url> [--insecure]" >&2
  echo "   or: export ROX_ENDPOINT=... ROX_API_TOKEN=... && ./acs_preflight.sh" >&2
  exit 2
fi
URL="${URL%/}"

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

hr() { echo "----------------------------------------------------------------"; }
echo "ACS preflight"
echo "  target : $URL"
hr

TMP=$(mktemp -t acspf.XXXXXX) || exit 1
trap 'rm -f "$TMP" "$TMP.h"' EXIT INT TERM

# Token goes in a header file, not an argument. Arguments show up in ps.
HDRF="$TMP.h"
( umask 077; printf 'Authorization: Bearer %s\n' "$TOKEN" > "$HDRF" )

# Echo a clean three digit status, or 000 when the connection never completed.
# Getting this wrong matters: on connection refused curl still prints a status via -w,
# and an "|| echo 000" appends a second value, producing something like 000000 that
# then fails every equality test and lands in whatever branch is last. That is how a
# dead endpoint gets misreported as a live one.
req() {  # req <path> ; echoes the HTTP status, body lands in $TMP
  code=$(curl -sS $CURL_TLS -o "$TMP" -w '%{http_code}' \
    -H "@$HDRF" -H 'Accept: application/json' "$URL$1" 2>"$TMP.err")
  rc=$?
  case "$code" in
    [1-5][0-9][0-9]) printf '%s' "$code" ;;
    *) printf '000' ;;
  esac
  return $rc
}

# ---- 1. Which server is this? ------------------------------------------------
# Probe one path that only ACS Central serves and one that only the Kubernetes or
# OpenShift API server serves. Whichever answers tells you where you are, with no
# guessing from the hostname.
echo "[1] Identifying the server"
ACS_CODE=$(req /v1/metadata)
K8S_CODE=$(req /version)
OCP_CODE=$(req /apis/user.openshift.io/v1/users/~)

# Identify by which probe ANSWERS, not by which one fails. A 401 or 403 still proves
# the endpoint exists and is serving that API surface; only 000 and 404 mean absent.
KIND="unknown"
if [ "$ACS_CODE" = "000" ] && [ "$K8S_CODE" = "000" ] && [ "$OCP_CODE" = "000" ]; then
  KIND="unreachable"
elif [ "$ACS_CODE" = "200" ] || [ "$ACS_CODE" = "401" ] || [ "$ACS_CODE" = "403" ]; then
  KIND="acs"
elif [ "$OCP_CODE" = "200" ] || [ "$OCP_CODE" = "401" ] || [ "$OCP_CODE" = "403" ]; then
  KIND="openshift"
elif [ "$K8S_CODE" = "200" ] || [ "$K8S_CODE" = "401" ] || [ "$K8S_CODE" = "403" ]; then
  KIND="kubernetes"
fi

case "$KIND" in
  acs)
    echo "  This is ACS Central. Correct server for vulnerability data."
    req /v1/metadata >/dev/null
    if [ $HAVE_JQ -eq 1 ]; then
      V=$(jq -r '.version // "unknown"' "$TMP" 2>/dev/null)
      echo "  Central version: $V"
    fi
    ;;
  openshift|kubernetes)
    echo "  *** This is the ${KIND} API server, NOT ACS Central. ***"
    echo ""
    echo "  That is why you are seeing paths like /apis/user.openshift.io/v1/users/~."
    echo "  Those belong to the cluster API. ACS endpoints do not exist here, and never"
    echo "  will: ACS Central is a separate service on a separate route."
    echo ""
    echo "  Find the real Central URL:"
    echo "    oc get route central -n stackrox -o jsonpath='{.spec.host}'"
    echo "  If that namespace is empty, try rhacs-operator, or:"
    echo "    oc get route --all-namespaces | grep -i central"
    echo ""
    echo "  Then rerun against https://<that host>  (port 443, not 6443)."
    echo ""
    echo "  Note the tokens are different too. oc whoami -t is an OpenShift token and"
    echo "  ACS will reject it. Generate an ACS API token in the ACS console under"
    echo "  Platform Configuration, Integrations, Authentication Tokens."
    exit 1
    ;;
  unreachable)
    echo "  Nothing answered at $URL."
    [ -s "$TMP.err" ] && echo "  curl said: $(head -c 200 "$TMP.err")"
    echo ""
    echo "  Connection refused, DNS failure, or a TLS handshake the client rejected."
    echo "  If it is the certificate, export ROX_CA=/path/to/ca.pem and rerun rather"
    echo "  than reaching for --insecure, which exposes your token on the wire."
    exit 1
    ;;
  *)
    echo "  Reached something, but it is not an API this script recognises."
    echo "  /v1/metadata gave $ACS_CODE, /version gave $K8S_CODE, users/~ gave $OCP_CODE"
    echo "  A proxy or ingress in front of the real endpoint would look like this."
    [ -s "$TMP.err" ] && echo "  curl said: $(head -c 200 "$TMP.err")"
    echo ""
    echo "  A connection error here is usually an untrusted internal CA."
    echo "  Export ROX_CA=/path/to/ca.pem and rerun, rather than reaching for --insecure:"
    echo "  that flag exposes your token to anyone on the network path."
    exit 1
    ;;
esac
hr

# ---- 2. Does the token authenticate? ----------------------------------------
echo "[2] Token"
if [ -z "$TOKEN" ]; then
  echo "  ROX_API_TOKEN is not set."
  exit 1
fi
CODE=$(req /v1/auth/status)
case "$CODE" in
  200) echo "  Authenticated."
       [ $HAVE_JQ -eq 1 ] && jq -r '"  expires: " + (.expires // "not reported")' "$TMP" 2>/dev/null
       ;;
  401) echo "  401. The token is wrong or expired."
       echo "  If you pasted an OpenShift token (oc whoami -t), that is the problem:"
       echo "  ACS does not accept them. Generate an ACS API token instead."
       exit 1 ;;
  403) echo "  403. Authenticated but the token has no usable role." ; exit 1 ;;
  *)   echo "  Unexpected status $CODE" ; exit 1 ;;
esac
hr

# ---- 3. What can it actually read? ------------------------------------------
# This is the check worth having. A token scoped only to Alert sails through step 2,
# works fine for /v1/alerts, and returns 403 on the vulnerability export. That reads as
# "no vulnerabilities" if nobody is watching the status code.
echo "[3] Permissions that matter for a full pull"
probe() {  # probe <label> <path>
  c=$(req "$2")
  case "$c" in
    200) echo "  ok    $1" ;;
    403) echo "  DENY  $1   (403, the token lacks this resource)" ;;
    404) echo "  n/a   $1   (404, not present on this Central version)" ;;
    *)   echo "  ?     $1   (status $c)" ;;
  esac
}
probe "Alert        /v1/alerts"                        "/v1/alerts?pagination.limit=1"
probe "Image+Deploy /v1/export/vuln-mgmt/workloads"    "/v1/export/vuln-mgmt/workloads?timeout=15"
probe "Image        /v1/export/images"                 "/v1/export/images?timeout=15"
probe "Node         /v1/export/nodes"                  "/v1/export/nodes?timeout=15"
hr

# ---- 4. The call ------------------------------------------------------------
echo "[4] The vulnerability call, ready to run"
echo ""
cat <<EOF
  export ROX_ENDPOINT=$URL
  export ROX_API_TOKEN=<your ACS API token>
  export ROX_CA=/path/to/internal-ca.pem      # if Central uses an internal CA

  curl -sS --fail-with-body \${ROX_CA:+--cacert "\$ROX_CA"} \\
    -H "Authorization: Bearer \$ROX_API_TOKEN" \\
    -H "Accept: application/json" \\
    "\$ROX_ENDPOINT/v1/export/vuln-mgmt/workloads?timeout=600" \\
    -o acs_vulns.ndjson

  wc -l acs_vulns.ndjson      # 0 lines means empty, not clean

Scoped to one namespace. Note the + between terms must be sent as %2B: a literal
plus sign in a query string decodes to a space, which silently changes the query.

  "\$ROX_ENDPOINT/v1/export/vuln-mgmt/workloads?query=Namespace%3Aprod&timeout=600"

Two terms, Namespace AND Cluster:

  "\$ROX_ENDPOINT/v1/export/vuln-mgmt/workloads?query=Namespace%3Aprod%2BCluster%3Aocp-prod&timeout=600"

Then feed it in:

  node acs_cli.js --path ./manifests --vulns acs_vulns.ndjson --report --worklist
EOF
hr
echo "Sweep every store at once instead:  ./scripts/acs_pull_all.sh -o findings"
