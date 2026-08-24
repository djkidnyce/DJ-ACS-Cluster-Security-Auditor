#!/usr/bin/env sh
# Wrapper for acs_cli.js. Written for POSIX sh so it runs on a stock macOS bash 3.2,
# dash, or busybox ash without change.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v node >/dev/null 2>&1; then
  echo "node is not on PATH. acs_cli.js needs Node 18 or newer." >&2
  echo "" >&2
  echo "If Node cannot be installed on this machine, you have two routes that do not" >&2
  echo "need it, and between them they cover everything except headless CI:" >&2
  echo "" >&2
  echo "  1. The page. No runtime, no server, no package manager. Scoring, violations," >&2
  echo "     fix routes, drafted YAML and the full report all live here." >&2
  echo "       open $DIR/dj_acs_auditor.html" >&2
  echo "" >&2
  echo "  2. A shell summary of what ACS reported, using jq only. Counts, not scores." >&2
  echo "       $DIR/scripts/acs_summary.sh <pull-directory> -o findings.md" >&2
  echo "" >&2
  echo "  If this host has a container runtime, the CLI runs without installing Node:" >&2
  echo "       podman run --rm -v \"$DIR\":/w:Z -w /w docker.io/library/node:20-alpine \\" >&2
  echo "         node acs_cli.js --help" >&2
  exit 2
fi
exec node "$DIR/acs_cli.js" "$@"
