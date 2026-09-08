#!/usr/bin/env bash
#
# check_docx.sh -- verify the committed Word guides still match their generators.
#
# WHY THIS EXISTS
#
#   The .docx guides are committed so the repository contains readable, formatted
#   documentation you can open, print, or hand to somebody. The cost of committing
#   generated output is that it silently stops matching its source: someone edits
#   docs/doc1.js, forgets to rebuild, and the file in git describes a version of the tool
#   that no longer exists. Nothing fails, and the reader has no way to tell.
#
#   So the guides are checked the same way the SBOM is: rebuild from source, compare with
#   what is committed, fail if they differ.
#
# WHY IT COMPARES TEXT RATHER THAN BYTES
#
#   A .docx is a ZIP, and the docx library writes non-deterministic content into it: two
#   builds of an unchanged source produce different bytes every time. Verified here
#   before this was written, twice in a row, different SHA-256 both times. A byte
#   comparison would therefore fail on every run and get switched off within a week, and
#   a check nobody runs is worse than no check because it looks like coverage.
#
#   The extracted TEXT is stable across builds. That is the property worth asserting: it
#   catches every content change, which is the thing that actually goes stale, and
#   ignores the packaging noise that never mattered.
#
# USAGE
#
#   ./docs/check_docx.sh            fail if a committed guide is out of date
#   ./docs/check_docx.sh --rebuild  rebuild and leave the new files in place
#
# REQUIREMENTS
#
#   pandoc for the text extraction, and Node with the docx package to rebuild.
#   Neither is needed to READ the guides. That is the whole point of committing them.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$DIR/.." && pwd)
REBUILD=0
[ "${1:-}" = "--rebuild" ] && REBUILD=1

GUIDES="DJ_ACS_Auditor_User_Guide.docx DJ_Security_Tooling_Administration_Guide.docx"

for g in $GUIDES; do
  [ -f "$ROOT/docs/$g" ] || {
    echo "MISSING: docs/$g is not in the checkout." >&2
    echo "The guides are committed on purpose. Rebuild with:" >&2
    echo "  npm install --no-save docx && node docs/doc1.js && node docs/doc2.js" >&2
    exit 1
  }
done

if [ "$REBUILD" = "1" ]; then
  ( cd "$ROOT" && node docs/doc1.js && node docs/doc2.js )
  echo "rebuilt. Commit the result."
  exit 0
fi

command -v pandoc >/dev/null 2>&1 || {
  echo "pandoc not found, so the guides cannot be compared against their source." >&2
  echo "  Debian or Ubuntu : apt-get install -y pandoc" >&2
  echo "  macOS            : brew install pandoc" >&2
  echo "" >&2
  echo "This does not stop you reading or rebuilding them, only verifying them." >&2
  exit 2
}

TMP=$(mktemp -d)

# Restoring in the trap rather than at the end, because "at the end" is not reached when
# the script dies early. Piping this into head sends SIGPIPE partway through, which
# skipped the restore and left the rebuilt guides sitting in the tree looking committed.
# Found by piping it into head. A cleanup that only runs on the happy path is not
# cleanup.
restore() {
  for g in $GUIDES; do
    [ -f "$TMP/committed_$g" ] && cp "$TMP/committed_$g" "$ROOT/docs/$g"
  done
  rm -rf "$TMP"
}
trap restore EXIT INT TERM HUP PIPE

# Keep the committed copies aside, rebuild, compare text, then put them back exactly as
# they were. This script verifies; it does not modify the tree.
for g in $GUIDES; do cp "$ROOT/docs/$g" "$TMP/committed_$g"; done

( cd "$ROOT" && node docs/doc1.js >/dev/null && node docs/doc2.js >/dev/null ) || {
  echo "The generators failed to run. Install the docx package first:" >&2
  echo "  npm install --no-save docx" >&2
  exit 2
}

STATUS=0
for g in $GUIDES; do
  pandoc "$TMP/committed_$g" -t plain --wrap=none -o "$TMP/old_$g.txt" 2>/dev/null
  pandoc "$ROOT/docs/$g"     -t plain --wrap=none -o "$TMP/new_$g.txt" 2>/dev/null
  if diff -q "$TMP/old_$g.txt" "$TMP/new_$g.txt" >/dev/null 2>&1; then
    echo "ok  docs/$g matches its source ($(wc -l < "$TMP/new_$g.txt" | tr -d ' ') lines of text)"
  else
    echo "OUT OF DATE: docs/$g does not match what its generator produces." >&2
    echo "Run ./docs/check_docx.sh --rebuild and commit the result." >&2
    diff -u "$TMP/old_$g.txt" "$TMP/new_$g.txt" 2>/dev/null | head -30 >&2 || true
    STATUS=1
  fi
done

exit $STATUS
