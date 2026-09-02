#!/usr/bin/env sh
#
# Summarise a pull directory without Node.
#
# WHY THIS EXISTS
#   The browser page and acs_cli.js both run the policy engine. The page needs no runtime,
#   but it needs a browser and a human. acs_cli.js needs Node, and Node cannot be installed
#   everywhere: a hardened RHEL host in a controlled enclave is exactly the machine where
#   you can run curl and jq and nothing else.
#
#   This script closes that gap for the case it honestly can. It reads what
#   acs_pull_all.sh wrote and reports what ACS said, using jq only.
#
# WHAT IT IS NOT
#   It is not the policy engine and it does not produce a posture score. A posture score
#   is computed over scanned manifests, and this script has no manifests and no scanner.
#   Everything below is a faithful count of what ACS reported, nothing inferred.
#
#   For scoring, fix routes and drafted YAML you need the page or the CLI.
#
# USAGE
#   ./acs_summary.sh <pull-directory> [-o out.md]
#
set -u

DIR="${1:-}"
OUT=""
[ "${2:-}" = "-o" ] && OUT="${3:-}"

if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
  echo "usage: ./acs_summary.sh <pull-directory> [-o out.md]" >&2
  echo "" >&2
  echo "  The directory acs_pull_all.sh wrote, for example:" >&2
  echo "    ./acs_summary.sh findings/acs_findings_20260821_143022" >&2
  exit 2
fi
command -v jq >/dev/null 2>&1 || { echo "jq is required and is not on PATH." >&2; exit 2; }

A="$DIR/02_alerts_full.json"
[ -r "$A" ] || A="$DIR/01_alerts_list.json"
V="$DIR/03_vuln_workloads.ndjson"

emit() { if [ -n "$OUT" ]; then printf '%s\n' "$*" >> "$OUT"; else printf '%s\n' "$*"; fi; }
[ -n "$OUT" ] && : > "$OUT"

emit "# ACS findings summary"
emit ""
emit "Source: \`$DIR\`"
emit "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
emit ""
emit "> Counts of what ACS reported. This is not a posture score: no manifests were"
emit "> scanned and no policy engine ran. A score over nothing would read as 100 out of"
emit "> 100, which means unmeasured rather than clean. For scoring, fix routes and drafted"
emit "> YAML, open \`dj_acs_auditor.html\` and drop this directory on it."
emit ""

# ---- violations ------------------------------------------------------------
if [ -r "$A" ]; then
  # Both shapes carry .alerts; the list form has no violations[] but the same identity.
  ALL='[.alerts[]? // .[]? | select(type=="object")]'

  TOTAL=$(jq -r "$ALL | length" "$A" 2>/dev/null || echo 0)
  emit "## Violations: $TOTAL"
  emit ""

  emit "### By severity"
  emit ""
  emit "| Severity | Count |"
  emit "|---|---|"
  jq -r "$ALL"' | group_by(.policy.severity) | map({s:.[0].policy.severity, n:length})
        | sort_by(if .s=="CRITICAL_SEVERITY" then 0 elif .s=="HIGH_SEVERITY" then 1
                  elif .s=="MEDIUM_SEVERITY" then 2 else 3 end)
        | .[] | "| \(.s // "unknown" | sub("_SEVERITY";"")) | \(.n) |"' "$A" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""

  # Platform split. has() rather than // because the field is a boolean and // treats
  # false as empty, which would silently turn every user workload into "not reported".
  PLAT=$(jq -r "$ALL"' | map(select(has("platformComponent") and .platformComponent == true)) | length' "$A" 2>/dev/null || echo 0)
  USER=$(jq -r "$ALL"' | map(select(has("platformComponent") and .platformComponent == false)) | length' "$A" 2>/dev/null || echo 0)
  NOFLAG=$(jq -r "$ALL"' | map(select(has("platformComponent") | not)) | length' "$A" 2>/dev/null || echo 0)
  emit "### Ownership"
  emit ""
  emit "| Reported as | Count |"
  emit "|---|---|"
  emit "| Your workloads | $USER |"
  emit "| Platform components | $PLAT |"
  emit "| No platformComponent field sent | $NOFLAG |"
  emit ""
  if [ "$NOFLAG" != "0" ]; then
    emit "$NOFLAG violation(s) arrived without the \`platformComponent\` field, so ACS did not"
    emit "tell us who owns them. The page infers it from the namespace and says when it is"
    emit "guessing. That guess is wrong in both directions, so check them."
    emit ""
  fi

  emit "### By policy, worst first"
  emit ""
  emit "| Count | Policy | Severity |"
  emit "|---|---|---|"
  jq -r "$ALL"' | group_by(.policy.name) | map({p:.[0].policy.name, s:.[0].policy.severity, n:length})
        | sort_by(-.n) | .[:15][]
        | "| \(.n) | \(.p // "unknown") | \(.s // "" | sub("_SEVERITY";"")) |"' "$A" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""

  emit "### By namespace, worst first"
  emit ""
  emit "| Count | Namespace |"
  emit "|---|---|"
  jq -r "$ALL"' | map(.commonEntityInfo.namespace // .namespace // .deployment.namespace // "unknown")
        | group_by(.) | map({ns:.[0], n:length}) | sort_by(-.n) | .[:15][]
        | "| \(.n) | \(.ns) |"' "$A" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""

  emit "### By violation state"
  emit ""
  jq -r "$ALL"' | group_by(.state) | map({s:.[0].state, n:length}) | sort_by(-.n) | .[]
        | "- \(.s // "not reported"): \(.n)"' "$A" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""
else
  emit "## Violations"
  emit ""
  emit "No alert export found in this directory. Expected \`02_alerts_full.json\`, or"
  emit "\`01_alerts_list.json\` as a fallback."
  emit ""
fi

# ---- CVEs ------------------------------------------------------------------
if [ -r "$V" ]; then
  emit "## Image vulnerabilities"
  emit ""
  emit "| Severity | Distinct CVEs |"
  emit "|---|---|"
  jq -s -r '[.[].result.images[]?.scan.components[]?.vulns[]? | {cve, severity}]
        | unique_by(.cve) | group_by(.severity) | map({s:.[0].severity, n:length})
        | sort_by(if   .s=="CRITICAL_VULNERABILITY_SEVERITY"  then 0
                  elif .s=="IMPORTANT_VULNERABILITY_SEVERITY" then 1
                  elif .s=="MODERATE_VULNERABILITY_SEVERITY"  then 2 else 3 end)
        | .[] | "| \(.s | sub("_VULNERABILITY_SEVERITY";"")) | \(.n) |"' "$V" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""

  FIXABLE=$(jq -s -r '[.[].result.images[]?.scan.components[]?.vulns[]?
      | select((.fixedBy // "") != "")] | unique_by(.cve) | length' "$V" 2>/dev/null || echo 0)
  ALLC=$(jq -s -r '[.[].result.images[]?.scan.components[]?.vulns[]?]
      | unique_by(.cve) | length' "$V" 2>/dev/null || echo 0)
  emit "$FIXABLE of $ALLC distinct CVEs have a published fix. The rest cannot be cleared by"
  emit "rebuilding, so they are a different conversation from the ones that can."
  emit ""

  KEV=$(jq -s -r '[.[].result.images[]?.scan.components[]?.vulns[]?
      | select(.cisaKev == true or .cisa_kev == true)] | unique_by(.cve) | length' "$V" 2>/dev/null || echo 0)
  if [ "$KEV" != "0" ]; then
    if [ "$KEV" = "1" ]; then
      emit "1 of them is on the CISA Known Exploited Vulnerabilities catalog. Somebody is"
      emit "using it in the wild right now, which is the strongest signal in this file."
    else
      emit "$KEV of them are on the CISA Known Exploited Vulnerabilities catalog. Somebody is"
      emit "using those in the wild right now, which is the strongest signal in this file."
    fi
    emit ""
  fi

  emit "### Images to rebuild, worst CVSS first"
  emit ""
  emit "| Worst CVSS | Critical | KEV | Fixable | CVEs | Image |"
  emit "|---|---|---|---|---|---|"
  jq -s -r '[.[].result | select(.images != null) | .images[]
        | {img: (.name.fullName // .name.remote // .id),
           worst: ([.scan.components[]?.vulns[]?.cvss // 0] | max // 0),
           crit: ([.scan.components[]?.vulns[]? | select(.severity=="CRITICAL_VULNERABILITY_SEVERITY")] | unique_by(.cve) | length),
           kev:  ([.scan.components[]?.vulns[]? | select(.cisaKev == true or .cisa_kev == true)] | unique_by(.cve) | length),
           fix:  ([.scan.components[]?.vulns[]? | select((.fixedBy // "") != "")] | unique_by(.cve) | length),
           all:  ([.scan.components[]?.vulns[]?] | unique_by(.cve) | length)}]
        | unique_by(.img) | sort_by(-.worst, -.crit) | .[:20][]
        | "| \(.worst) | \(.crit) | \(.kev) | \(.fix) | \(.all) | \(.img) |"' "$V" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""

  emit "### Highest scoring CVEs"
  emit ""
  emit "| CVSS | KEV | Severity | CVE | Fixed in | Image |"
  emit "|---|---|---|---|---|---|"
  jq -s -r '[.[].result | select(.images != null) | .images[] as $i
        | $i.scan.components[]?.vulns[]?
        | {cve, cvss: (.cvss // 0), sev: (.severity // ""),
           kev: (if (.cisaKev == true or .cisa_kev == true) then "yes" else "" end),
           fix: (.fixedBy // ""), img: ($i.name.fullName // $i.name.remote // $i.id)}]
        | unique_by(.cve) | sort_by(-.cvss) | .[:20][]
        | "| \(.cvss) | \(.kev) | \(.sev | sub("_VULNERABILITY_SEVERITY";"")) | \(.cve) | \(if (.fix // "") == "" then "none yet" else .fix end) | \(.img) |"' "$V" 2>/dev/null \
    | while IFS= read -r l; do emit "$l"; done
  emit ""
  emit "CVSS is the score ACS supplied for each CVE. It is not the priority this tool ranks"
  emit "by: that adds the CISA catalog, EPSS exploitation probability, whether a fix exists"
  emit "and whether pods are actually running the image, and it runs to 15 rather than 10."
  emit "That model lives in the policy engine, so it comes from the page or the CLI, not"
  emit "from here. Reimplementing it in this script would give you a second ranking that"
  emit "drifts from the first, which is worse than not having one."
  emit ""
  emit "Grouped by image because that is the unit of work: you rebuild an image once and"
  emit "every fixable CVE inside it clears together. A list ordered by CVE looks like"
  emit "progress and cannot be actioned."
  emit ""
else
  emit "## Image vulnerabilities"
  emit ""
  emit "No vulnerability export found. Expected \`03_vuln_workloads.ndjson\`."
  emit "Note that CVEs never appear in the alert endpoint, so an empty alert list proves"
  emit "nothing about them."
  emit ""
fi

emit "## What this summary cannot tell you"
emit ""
emit "- Your posture score. That needs manifests and the policy engine."
emit "- Which violations are fixable, and by which route."
emit "- The corrected YAML."
emit ""
emit "All three come from \`dj_acs_auditor.html\`, which needs a browser and no runtime,"
emit "or from \`acs_cli.js\`, which needs Node. Drop this directory on the page."

[ -n "$OUT" ] && echo "Written to $OUT" >&2
exit 0
