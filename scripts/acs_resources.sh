#!/usr/bin/env bash
#
# acs_resources.sh  --  work out what to set CPU and memory requests and limits to, from what
# the workloads actually used, rather than from a guess.
#
# IT NEVER WRITES. Every call is a read: a Thanos query, or oc adm top. It prints YAML
# fragments and a table. It does not patch a workload, and it does not apply anything.
#
# WHY THIS EXISTS
#
#   ACS.013 and ACS.014 report a missing request or limit, and the automatic fix inserts a
#   placeholder flagged PLACEHOLDER precisely because the tool cannot know the right number.
#   A placeholder that reaches production is worse than the finding: set memory too low and
#   the kernel OOM kills the container, which converts a tidy compliance score into an
#   outage. The right number comes from measurement.
#
# TWO SOURCES, IN ORDER
#
#   thanos   OpenShift monitoring already retains this. One PromQL query returns two weeks
#            of history immediately. Needs the cluster-monitoring-view cluster role.
#   sample   oc adm top, appended to a file on a schedule. Works on any cluster with
#            metrics-server and no monitoring access, and you wait for the window to fill.
#
#   It tries Thanos and falls back to sampling, saying which it used. A recommendation from
#   forty minutes of samples and one from fourteen days look identical on the page, so the
#   output always states the window and the sample count.
#
# WHAT IT REPORTS, AND WHY CPU AND MEMORY DIFFER
#
#   Memory is not compressible. Exceed the limit and the container is killed, so the limit
#   has to sit above the real peak, not above a percentile that clips it.
#
#   CPU is compressible. Exceed the limit and the container is throttled, not killed, which
#   is survivable but is its own outage for anything latency sensitive. So the script also
#   reads container_cpu_cfs_throttled_seconds_total and tells you whether the workload is
#   ALREADY being throttled before you put a ceiling on it.
#
#   Percentiles for both with headroom, which is what was asked for. HEADROOM below is a
#   multiplier you can change, at the top of the file rather than buried in a formula.
#
# USAGE
#   ./acs_resources.sh recommend -n NAMESPACE [--days 14] [--source thanos|sample|auto]
#   ./acs_resources.sh sample -n NAMESPACE [-o FILE]        # one sample, for cron
#   ./acs_resources.sh report -n NAMESPACE [-o FILE]        # read the samples back
#
# REQUIREMENTS
#   oc (or kubectl via OC=kubectl) and jq. curl for the Thanos path.
#
# WRITTEN FOR bash 3.2 and /bin/sh. No mapfile, no associative arrays, no process
# substitution. This repository has shipped a script that worked under bash and silently
# dropped arguments under dash.
set -eu

# Tunables. Requests come from the working percentile, limits from the peak percentile times
# the headroom. Raise HEADROOM_MEM if your workloads are spiky; it is the number standing
# between a tight limit and an OOM kill.
REQ_PCT=50
LIM_PCT=99
HEADROOM_MEM=1.5
HEADROOM_CPU=2.0
DAYS=14
SOURCE=auto
OC="${OC:-oc}"
NS=""
OUTFILE=""
SAMPLE_FILE="${ACS_SAMPLE_FILE:-./acs_resource_samples.tsv}"

usage() {
  cat <<'TXT'
acs_resources.sh  --  CPU and memory requests and limits from measured use, not a guess.

IT PRINTS. IT NEVER WRITES. Every call it makes is a read.

USAGE
  acs_resources.sh <subcommand> -n NAMESPACE [options]

SUBCOMMANDS
  recommend     query the data and print requests and limits per container
  sample        take one oc adm top sample and append it to a file, for cron
  report        compute the recommendation from samples already collected

OPTIONS
  -n, --namespace NS   the namespace. Required
      --days N         window to look back over. Default 14
      --source WHICH   thanos, sample, or auto. Default auto, which tries Thanos first
  -o, --out FILE       where to write. Default is standard output, or
                       ./acs_resource_samples.tsv for the sample subcommand
  -h, --help           this text

HOW THE NUMBERS ARE DERIVED
  requests   the 50th percentile of observed use
  limits     the 99th percentile, times a headroom multiplier
             memory 1.5x, cpu 2.0x, both editable at the top of this file

  Memory is not compressible: exceeding the limit is an OOM kill, so the limit sits above
  the peak. CPU is compressible: exceeding it throttles. The report tells you whether a
  container is already being throttled before you put a ceiling on it.

COLLECTING WITHOUT MONITORING ACCESS
  Every fifteen minutes for a fortnight, then read it back:

    */15 * * * * cd /path && ./acs_resources.sh sample -n prod >/dev/null 2>&1
    ./acs_resources.sh report -n prod

A recommendation from forty minutes of samples and one from fourteen days look the same on
the page, so the output always states the window and how many samples it rests on.
TXT
  exit "${1:-2}"
}

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "$1 not found on PATH." >&2
  [ "$1" = "$OC" ] && echo "If you use kubectl, set OC=kubectl and run it again." >&2
  exit 2
}

CMD="${1:-}"
[ -n "$CMD" ] || usage
case "$CMD" in
  -h|--help|help) usage 0 ;;
  -*) echo "Unknown option: $CMD" >&2
      echo "A subcommand comes first. Run with --help for the list." >&2
      exit 2 ;;
esac
shift || true

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="${2:-}"; shift 2 || usage ;;
    -o|--out)       OUTFILE="${2:-}"; shift 2 || usage ;;
    --days)         DAYS="${2:-}"; shift 2 || usage ;;
    --source)       SOURCE="${2:-}"; shift 2 || usage ;;
    -h|--help)      usage 0 ;;
    -*)             echo "Unknown option: $1" >&2; usage ;;
    *)              echo "Unexpected argument: $1" >&2; usage ;;
  esac
done

need jq
need "$OC"
[ -n "$NS" ] || { echo "A namespace is required. Use -n NAMESPACE." >&2; usage; }
case "$SOURCE" in thanos|sample|auto) : ;; *) echo "Unknown source: $SOURCE" >&2; usage ;; esac

# ---------------------------------------------------------------- units
#
# Kubernetes quantities in, Kubernetes quantities out. A recommendation of 134217728 is
# correct and unusable in a review; 128Mi is the same number somebody can check by eye.

to_mi() {  # bytes -> NNNMi, rounded up so a limit is never below what was measured
  awk -v b="$1" 'BEGIN { if (b <= 0) { print "16Mi"; exit }
    m = b / 1048576; m = (m == int(m)) ? m : int(m) + 1; if (m < 16) m = 16;
    printf "%dMi\n", m }'
}

to_milli() {  # cores -> NNNm
  awk -v c="$1" 'BEGIN { if (c <= 0) { print "10m"; exit }
    m = c * 1000; m = (m == int(m)) ? m : int(m) + 1; if (m < 10) m = 10;
    printf "%dm\n", m }'
}

# ---------------------------------------------------------------- Thanos
#
# The route is the supported way in. port-forward to thanos-querier is the fallback for a
# workstation that cannot reach the route, and it is the operator's call to set that up
# rather than this script opening tunnels on its own.

thanos_url() {
  $OC get route thanos-querier -n openshift-monitoring \
    -o jsonpath='{.spec.host}' 2>/dev/null || true
}

# Trust, handled the same way as the ACS scripts. The Thanos route presents the cluster
# ingress certificate, which is the identical untrusted internal CA problem, so the identical
# rules apply: ROX_CA from the environment, refuse a CA path that cannot be read rather than
# falling back to the system trust store, and never --insecure by default.
CURL_TLS=""
if [ -n "${ROX_CA:-}" ]; then
  if [ ! -r "$ROX_CA" ]; then
    echo "ERROR: ROX_CA is set but not readable: $ROX_CA" >&2
    echo "  Refusing rather than falling back to the system trust store, which would verify" >&2
    echo "  against a different set of CAs than you asked for." >&2
    exit 2
  fi
  CURL_TLS="--cacert $ROX_CA"
fi

ca_help() {
  echo "  TLS verification failed against the Thanos route. Nothing here trusts the CA that" >&2
  echo "  signed its certificate." >&2
  echo "" >&2
  echo "  Do NOT use --insecure. This request carries a token that can read cluster metrics," >&2
  echo "  and turning verification off exposes the token to anyone on the path." >&2
  echo "" >&2
  echo "  See which CA is actually presenting:" >&2
  echo "    openssl s_client -connect $1:443 -showcerts </dev/null 2>/dev/null \\" >&2
  echo "      | openssl x509 -noout -issuer -subject -dates" >&2
  echo "" >&2
  echo "  Then fetch it through your oc session and point ROX_CA at it:" >&2
  echo "    $OC -n openshift-config-managed get configmap default-ingress-cert \\" >&2
  echo "      -o jsonpath='{.data.ca-bundle\\.crt}' > ~/ocp-ingress-ca.pem" >&2
  echo "    export ROX_CA=~/ocp-ingress-ca.pem" >&2
}

thanos_query() {  # thanos_query <host> <promql> ; prints the raw JSON, or nothing
  _host="$1"; _q="$2"
  _tok="$($OC whoami -t 2>/dev/null || true)"
  [ -n "$_tok" ] || return 1
  # The token goes in a header file, not an argument. Arguments show up in ps.
  _hdr="$(mktemp "${TMPDIR:-/tmp}/acsres-hdr.XXXXXX")" || return 1
  ( umask 077; printf 'Authorization: Bearer %s\n' "$_tok" > "$_hdr" )
  _err="$_hdr.err"
  curl -sS --max-time 60 $CURL_TLS -H "@$_hdr" \
    --data-urlencode "query=$_q" \
    "https://$_host/api/v1/query" 2>"$_err"
  _rc=$?
  if [ $_rc -ne 0 ] && grep -qiE "certificate|SSL|self.signed|unable to get local issuer" "$_err" 2>/dev/null; then
    ca_help "$_host"
  fi
  rm -f "$_hdr" "$_err"
  return $_rc
}

thanos_reachable() {
  _host="$(thanos_url)"
  [ -n "$_host" ] || return 1
  _out="$(thanos_query "$_host" 'up' || true)"
  printf '%s' "$_out" | jq -e '.status == "success"' >/dev/null 2>&1
}

# quantile_over_time rather than a plain max, so one scrape spike during a node problem does
# not set the ceiling for a fortnight. The peak percentile is high enough to still sit above
# real traffic.
PROMQL_MEM='quantile_over_time(%s, container_memory_working_set_bytes{namespace="%s",container!="",container!="POD"}[%dd])'
PROMQL_CPU='quantile_over_time(%s, rate(container_cpu_usage_seconds_total{namespace="%s",container!="",container!="POD"}[5m])[%dd:5m])'
PROMQL_THROTTLE='sum by (container) (increase(container_cpu_cfs_throttled_periods_total{namespace="%s",container!=""}[%dd])) / clamp_min(sum by (container) (increase(container_cpu_cfs_periods_total{namespace="%s",container!=""}[%dd])), 1)'

series_to_tsv() {  # stdin: prometheus JSON -> "container<TAB>value"
  jq -r '.data.result[]? | [(.metric.container // "?"), .value[1]] | @tsv' 2>/dev/null || true
}

# ---------------------------------------------------------------- sampling
#
# oc adm top prints human units: 5m, 20Mi. Parsed back to cores and bytes here, because a
# percentile over a column of mixed suffixes is arithmetic on strings.

parse_cpu() {  # 5m | 1 -> cores
  awk -v v="$1" 'BEGIN { if (v ~ /m$/) { sub(/m$/, "", v); printf "%.6f\n", v / 1000 }
    else printf "%.6f\n", v + 0 }'
}

parse_mem() {  # 20Mi | 1Gi | 512Ki | 1024 -> bytes
  awk -v v="$1" 'BEGIN {
    if (v ~ /Ki$/) { sub(/Ki$/, "", v); printf "%d\n", v * 1024 }
    else if (v ~ /Mi$/) { sub(/Mi$/, "", v); printf "%d\n", v * 1048576 }
    else if (v ~ /Gi$/) { sub(/Gi$/, "", v); printf "%d\n", v * 1073741824 }
    else printf "%d\n", v + 0 }'
}

cmd_sample() {
  _dest="${OUTFILE:-$SAMPLE_FILE}"
  [ -f "$_dest" ] || printf 'epoch\tnamespace\tpod\tcontainer\tcores\tbytes\n' > "$_dest"
  _now="$(date -u +%s)"
  _raw="$($OC adm top pods --containers --no-headers -n "$NS" 2>/dev/null || true)"
  if [ -z "$_raw" ]; then
    echo "No metrics returned for namespace $NS." >&2
    echo "metrics-server or the monitoring stack has to be serving oc adm top for this to" >&2
    echo "work. Try: $OC adm top pods -n $NS" >&2
    exit 1
  fi
  _n=0
  printf '%s\n' "$_raw" | while read -r pod container cpu mem _rest; do
    [ -n "$container" ] || continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$_now" "$NS" "$pod" "$container" \
      "$(parse_cpu "$cpu")" "$(parse_mem "$mem")" >> "$_dest"
    _n=$((_n + 1))
  done
  _total="$(grep -c . "$_dest" || true)"
  echo "appended to $_dest  (file now holds $((_total - 1)) sample row(s))" >&2
}

# Percentiles out of the collected samples. Nearest rank on a sorted list, which is the
# honest method for a few hundred points: no interpolation inventing a value that was never
# observed, and the maximum is reported alongside so the peak is visible rather than implied.
percentiles_from_samples() {  # <file> <namespace>
  awk -F'\t' -v ns="$2" -v rp="$REQ_PCT" -v lp="$LIM_PCT" '
    NR == 1 { next }
    $2 == ns && $4 != "" { c[$4] = 1; n[$4]++; cpu[$4 "|" n[$4]] = $5; mem[$4 "|" n[$4]] = $6
      if ($6 + 0 > peak[$4]) peak[$4] = $6 + 0
      if ($5 + 0 > cpeak[$4]) cpeak[$4] = $5 + 0
      if (first == 0 || $1 + 0 < first) first = $1 + 0
      if ($1 + 0 > last) last = $1 + 0 }
    END {
      for (k in c) {
        cnt = n[k]
        for (i = 1; i <= cnt; i++) { a[i] = cpu[k "|" i] + 0; b[i] = mem[k "|" i] + 0 }
        for (i = 1; i < cnt; i++) for (j = i + 1; j <= cnt; j++) {
          if (a[j] < a[i]) { t = a[i]; a[i] = a[j]; a[j] = t }
          if (b[j] < b[i]) { t = b[i]; b[i] = b[j]; b[j] = t } }
        ri = int(cnt * rp / 100); if (ri < 1) ri = 1
        li = int(cnt * lp / 100); if (li < 1) li = 1
        printf "%s\t%.6f\t%.6f\t%d\t%d\t%d\t%.6f\t%d\n", k, a[ri], a[li], b[ri], b[li], cnt, cpeak[k], peak[k]
      }
      printf "WINDOW\t%d\t%d\n", first, last
    }' "$1"
}

# MEM_PEAK_MARGIN is the floor under the memory limit, as a multiple of the highest value
# actually observed. A p99 limit can sit BELOW the peak when the distribution has a long
# tail, and a memory limit below the peak is an OOM kill on the next spike, which is the one
# outcome this whole exercise exists to avoid. So the limit is whichever is larger: the
# percentile times its headroom, or the observed peak times this margin.
MEM_PEAK_MARGIN=1.15

emit_recommendation() {  # container cpuReq cpuLim memReq memLim n cpuPeak memPeak
  _any=0
  while IFS="$(printf '\t')" read -r container creq clim mreq mlim n cpeak mpeak; do
    [ "$container" = "WINDOW" ] && continue
    [ -n "$container" ] || continue
    _any=1
    echo "  # container $container, from $n observation(s)"
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: $(to_milli "$creq")"
    echo "      memory: $(to_mi "$mreq")"
    echo "    limits:"
    echo "      cpu: $(to_milli "$(awk -v v="$clim" -v h="$HEADROOM_CPU" 'BEGIN{printf "%.6f", v*h}')")"
    echo "      memory: $(to_mi "$(awk -v v="$mlim" -v h="$HEADROOM_MEM" -v pk="${mpeak:-0}" -v m="$MEM_PEAK_MARGIN" \
        'BEGIN { a = v * h; b = pk * m; printf "%d", (a > b ? a : b) }')")"
    echo "  # observed cpu peak $(to_milli "$cpeak"), p${LIM_PCT} $(to_milli "$clim")"
    if [ -n "${mpeak:-}" ] && [ "${mpeak:-0}" != "0" ]; then
      echo "  # observed memory peak $(to_mi "$mpeak"), p${LIM_PCT} $(to_mi "$mlim")"
      awk -v v="$mlim" -v h="$HEADROOM_MEM" -v pk="$mpeak" -v m="$MEM_PEAK_MARGIN" \
        'BEGIN { if (pk * m > v * h) print "  # memory limit raised to clear the observed peak, which p'"${LIM_PCT}"' did not" }'
    fi
    echo ""
  done
  [ "$_any" -eq 1 ] || echo "  (no containers matched in that namespace)"
}

cmd_report() {
  _src="${OUTFILE:-$SAMPLE_FILE}"
  [ -f "$_src" ] || { echo "No sample file at $_src. Run the sample subcommand first." >&2; exit 1; }
  _rows="$(percentiles_from_samples "$_src" "$NS")"
  _win="$(printf '%s\n' "$_rows" | awk -F'\t' '$1=="WINDOW"{print $2" "$3}')"
  _first="$(printf '%s' "$_win" | awk '{print $1}')"
  _last="$(printf '%s' "$_win" | awk '{print $2}')"
  _span=0
  [ -n "$_first" ] && [ -n "$_last" ] && _span=$(( (_last - _first) / 3600 ))
  _count="$(printf '%s\n' "$_rows" | awk -F'\t' '$1!="WINDOW"{s+=$6} END{print s+0}')"

  echo "# Resource recommendation for namespace $NS"
  echo "# Source: oc adm top samples from $_src"
  echo "# Window: ${_span} hour(s) of wall clock, $_count observation(s)"
  echo "# requests at p${REQ_PCT}, limits at p${LIM_PCT} times headroom (mem ${HEADROOM_MEM}x, cpu ${HEADROOM_CPU}x)"
  echo "#"
  # A recommendation from forty minutes of samples and one from a fortnight look identical
  # once they are YAML, so the thinness of the evidence is stated where it cannot be missed.
  if [ "$_span" -lt 24 ]; then
    echo "# WARNING: this rests on less than a day of samples. A daily or weekly peak has"
    echo "#          almost certainly not happened yet, so the memory limit below is likely"
    echo "#          lower than the workload will eventually need. Keep sampling."
    echo "#"
  elif [ "$_span" -lt 168 ]; then
    echo "# NOTE: under a week of samples. A weekly peak, such as a Monday batch run, may"
    echo "#       not be represented yet."
    echo "#"
  fi
  printf '%s\n' "$_rows" | emit_recommendation
  echo "# Nothing here was applied. Memory limits are the dangerous ones: too low is an OOM"
  echo "# kill, not a throttle. Check these against what you know of the workload."
}

cmd_recommend() {
  _used=""
  if [ "$SOURCE" = "thanos" ] || [ "$SOURCE" = "auto" ]; then
    if thanos_reachable; then
      _used=thanos
    elif [ "$SOURCE" = "thanos" ]; then
      echo "Thanos is not reachable, and --source thanos was asked for explicitly." >&2
      echo "  The route is thanos-querier in openshift-monitoring, and reading it needs the" >&2
      echo "  cluster-monitoring-view cluster role:" >&2
      echo "    $OC adm policy add-cluster-role-to-user cluster-monitoring-view \$($OC whoami)" >&2
      echo "  Or collect samples instead: $0 sample -n $NS" >&2
      exit 1
    fi
  fi

  if [ "$_used" != "thanos" ]; then
    echo "# Thanos not used, falling back to collected samples." >&2
    cmd_report
    return 0
  fi

  _host="$(thanos_url)"
  _qm_req="$(printf "$PROMQL_MEM" "0.$REQ_PCT" "$NS" "$DAYS")"
  _qm_lim="$(printf "$PROMQL_MEM" "0.$LIM_PCT" "$NS" "$DAYS")"
  _qc_req="$(printf "$PROMQL_CPU" "0.$REQ_PCT" "$NS" "$DAYS")"
  _qc_lim="$(printf "$PROMQL_CPU" "0.$LIM_PCT" "$NS" "$DAYS")"
  _qt="$(printf "$PROMQL_THROTTLE" "$NS" "$DAYS" "$NS" "$DAYS")"

  _tmp="$(mktemp "${TMPDIR:-/tmp}/acsres.XXXXXX")"
  trap 'rm -f "$_tmp" "$_tmp".*' EXIT INT TERM
  thanos_query "$_host" "$_qm_req" | series_to_tsv > "$_tmp.mreq"
  thanos_query "$_host" "$_qm_lim" | series_to_tsv > "$_tmp.mlim"
  thanos_query "$_host" "$_qc_req" | series_to_tsv > "$_tmp.creq"
  thanos_query "$_host" "$_qc_lim" | series_to_tsv > "$_tmp.clim"
  thanos_query "$_host" "$_qt"     | series_to_tsv > "$_tmp.thr"

  echo "# Resource recommendation for namespace $NS"
  echo "# Source: Thanos, $DAYS day(s) of history via route $_host"
  echo "# requests at p${REQ_PCT}, limits at p${LIM_PCT} times headroom (mem ${HEADROOM_MEM}x, cpu ${HEADROOM_CPU}x)"
  echo "#"
  if [ ! -s "$_tmp.mreq" ]; then
    echo "# No series returned. Either the namespace has no running workloads, or the token"
    echo "# lacks cluster-monitoring-view, which returns success with an empty result rather"
    echo "# than an error. Check with: $OC auth can-i get pods --subresource=metrics -n $NS"
    return 0
  fi

  # Throttling first. Putting a CPU ceiling on a container that is already being throttled
  # makes an existing problem worse, and that is worth knowing before reading the numbers.
  _thr="$(awk -F'\t' '$2+0 > 0.01 { printf "%s %.1f%%\n", $1, $2*100 }' "$_tmp.thr" || true)"
  if [ -n "$_thr" ]; then
    echo "# ALREADY BEING THROTTLED over this window:"
    printf '%s\n' "$_thr" | sed 's/^/#   /'
    echo "#   A CPU limit on these will throttle them harder. Consider raising the limit, or"
    echo "#   omitting the CPU limit and setting only a request."
    echo "#"
  fi

  join -t"$(printf '\t')" -a1 -e 0 -o 0,1.2,2.2 "$_tmp.creq" "$_tmp.clim" 2>/dev/null \
    | join -t"$(printf '\t')" -a1 -e 0 -o 0,1.2,1.3,2.2 - "$_tmp.mreq" 2>/dev/null \
    | join -t"$(printf '\t')" -a1 -e 0 -o 0,1.2,1.3,1.4,2.2 - "$_tmp.mlim" 2>/dev/null \
    | awk -F'\t' -v d="$DAYS" '{ printf "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", $1, $2, $3, $4, $5, d " days", $3 }' \
    | emit_recommendation
  echo "# Nothing here was applied. Memory limits are the dangerous ones: too low is an OOM"
  echo "# kill, not a throttle. Check these against what you know of the workload."
}

case "$CMD" in
  recommend) cmd_recommend ;;
  sample)    cmd_sample ;;
  report)    cmd_report ;;
  *)         echo "Unknown subcommand: $CMD" >&2; usage ;;
esac
