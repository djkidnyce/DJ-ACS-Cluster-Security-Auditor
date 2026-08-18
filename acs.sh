#!/usr/bin/env sh
# Wrapper for acs_cli.js. Written for POSIX sh so it runs on a stock macOS bash 3.2,
# dash, or busybox ash without change.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v node >/dev/null 2>&1; then
  echo "node is not on PATH. Node 18 or newer is required." >&2
  echo "No Node available? The browser pages need no runtime at all:" >&2
  echo "  open $DIR/dj_acs_auditor.html" >&2
  exit 2
fi
exec node "$DIR/acs_cli.js" "$@"
