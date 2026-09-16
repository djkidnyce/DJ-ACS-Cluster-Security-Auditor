# Handoff

For whoever picks this up next, human or agent, with no memory of how it got here.
Read this before changing anything. It is short on purpose and every line in it cost
something to learn.

## What this is

A browser page and a CLI that audit Kubernetes and OpenShift manifests against Red Hat
ACS policy logic, score the findings, and produce corrected YAML. One policy engine,
`acs_policies.js`, shared by every surface so they cannot disagree about a manifest.

    dj_acs_auditor.html   the whole browser surface, three tabs: Audit, Remediate, Diff
    acs_policies.js       the engine: policy catalogue, scanning, scoring, fixes, diffing
    acs_cli.js            the same engine, headless, for CI
    scripts/              pull data out of ACS without a browser: bash, curl, jq
    docs/                 two .docx guides, generated and committed, plus their generators
    test/                 17 suites, plain Node, no framework
    vendor/               js-yaml and JSZip, committed, hashed in the SBOM

## Hard constraints. Violating one of these is a defect, not a tradeoff.

**Nothing executes a command to remediate a finding.** Not the page, not the CLI, not in
any mode. Fixes are text edits to YAML handed back as files. The single subprocess in the
whole tool is `git status --porcelain`, used by `--in-place` to refuse a dirty tree, and
CI pins that fact.

**The report / manual / auto mode gate is a security control, not a convenience.** Report
is the default everywhere. The mode is never inferred from what you asked for, an unknown
mode is an error rather than a silent downgrade, and asking for something applyable in
report mode is refused with an explanation. Do not weaken it. Read only analysis such as
the Diff tab is allowed in report mode, because a rendered table is not an artifact.

**No package manager at runtime.** The page loads its dependencies from `vendor/` with
plain script tags. The operator this is built for cannot install Node or npm. `jsdom` is
the only npm dependency anywhere and it is test only and optional.

**The browser is not a preview of the fix, it is what produces it.** The scan runs on one
machine and the review happens on another, neither with Node.

## Build, test, package

    npm install --no-save jsdom docx     # test and docs only, never shipped
    node test/run_tests.js               # ~847 without jsdom
    NODE_PATH=... node test/run_tests.js # ~1278 with jsdom

    node scripts/make_sbom.js            # regenerate after touching vendor/
    node scripts/make_sbom.js --check    # CI runs this
    ./docs/check_docx.sh                 # guides still match their generators
    ./docs/check_docx.sh --rebuild       # after editing docs/doc1.js or doc2.js

Version lives in exactly one place, `ACS_VERSION` in `acs_policies.js`. `test/version.cjs`
fails the build if it disagrees with the newest CHANGELOG heading or with the git tag.
`BUILD.txt` carries the test counts, written from the run that produced the build. Do not
type test counts into prose anywhere; `test/ci.cjs` fails the build if you do, because
they went stale three times.

## The thing that keeps going wrong

**Verification that reports success while asserting nothing.** Eight confirmed instances
so far. A CI step grepping a deleted file. Thirty one TLS assertions skipping silently. A
tag check that could not see tags. An injection test whose server never started. A
path traversal assertion checking the wrong directory and the wrong filename. A query
encoder test that shelled out to `jq` and never touched this repository. A race test that
waited 120ms for a timer set at 3000ms. An export assertion counting files matched by
`/\.ya?ml$/`, which could not see the file named `undefined` it was writing.

So: **prove every new assertion can fail.** Break the code it covers, watch it go red, put
the code back. If a mutation produces no failure, either the test is vacuous or the
mutation was not a real defect, and you have to work out which before moving on. Several
of the above were found exactly that way and several were written by someone who thought
they were being careful.

Assert the setup too. A test that cannot reach the code it is testing reports a pass.

## Traps that have cost real time

**GitHub and its CDN serve stale copies.** Three times a page or a raw file showed content
several versions old and nearly produced a false claim about the repository. Always append
a cache buster, `?cb=1`, and prefer `raw.githubusercontent.com` over the rendered page.

**Pasting multi line shell into a terminal loses the newlines.** A script whose lines
collapse becomes `#!/bin/sh for R in ...`, which is one comment and does nothing. Long jq
gets a quote eaten and reports something unhelpful. Prefer short commands, or a file.

**`.docx` is not byte reproducible.** Two builds of unchanged source differ every time, so
`check_docx.sh` compares extracted text, not bytes. A byte comparison would fail on every
run and be switched off within a week.

**`grep -c` prints its count and then exits 1 when the count is zero**, so
`$(grep -c . f || echo 0)` yields `0\n0`, which is an illegal number that kills the rest of
a step under dash without failing the run. Use the `countlines` helper.

**Fixture ports must be requested from the OS.** A hardcoded port plus a readiness probe
that accepts any certificate meant a stale server from a previous run answered, and the
resulting expired certificate looked exactly like a macOS TLS limitation. It was not.

## Where things stand

Released through 1.7.0. Every finding from the internal review, F1 through F10, is closed.
A command injection through ACS alert ids and a path traversal in the same place are fixed
and regression tested end to end against a hostile server.

Open and not blocking:

- The findings table at 750 rows has never been checked in a real browser. jsdom performs
  no layout, so no assertion can see it. This is a manual check and it is the one thing
  that should happen before calling the table work done.
- `actions/checkout@v4` and `actions/setup-node@v4` target Node 20, which GitHub has
  deprecated. Two line change when something else touches CI.
- `scripts/acs_rollback_helper.sh` exists as a delivered artifact but is not in the repo
  or under test. It prints rollback commands and never runs them. Add it properly or drop
  it, do not leave it half in.

## Conventions worth keeping

Comments explain why, not what, and name the defect that motivated the code. Several of
them are the only record of a bug that took hours to find.

Prose in this project uses no hyphens or dashes anywhere, including code comments.

When a review finding says a thing is cosmetic, check whether it is hiding something
structural. F8 looked like deduplicating a toggle and was actually a chance to silently
change what one tab displays.

Do not put anything about a specific cluster, namespace, endpoint or environment in this
repository. It is public.
