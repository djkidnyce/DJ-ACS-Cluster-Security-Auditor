# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
public interface for versioning purposes is the CLI flags, the exit codes, the shape of
the JSON and SARIF exports, and the policy ids. A change to any of those is a minor bump
at least; removing or renaming one is a major.

Every release is tagged. `git tag -l` is the list, and the tag matches the version this
tool stamps into every report and patch header it writes.

## 1.7.0 - 2026-09-16

### Added

- **A Diff tab.** Left is the YAML you loaded, right is the same objects with the fixes
  applied to a copy, side by side, the way a diff reads on GitHub. A file list down the
  side with added and removed counts, click a file to see it, and unchanged lines collapse
  to "N unchanged line(s)" so a one line fix does not render four hundred lines of context.

  It renders in every mode, including report, on purpose. A diff is analysis, not an
  artifact: you cannot apply a rendered table, nothing is written, and seeing what a fix
  would do is exactly what helps somebody decide whether to leave report mode. The gate
  stays where it belongs, on the things that produce files.

  Two views: everything the fixes would change, or only the findings you have ticked. The
  filter says which one you are looking at, and when the filtered view is empty it says
  why rather than going blank.

- **`buildFixedCopy`, one function both the Diff tab and the corrected YAML export call.**
  A diff that showed something the export does not write would be worse than no diff,
  because you would review the wrong thing and believe otherwise. Same reasoning as the
  page and the CLI sharing one policy engine.

- **`handoff.md`.** What the next person needs before touching anything: the constraints
  that are defects rather than tradeoffs, the build and test commands, the eight confirmed
  instances of this project's recurring failure mode with the instruction to prove every
  new assertion can fail, the traps that have cost real time, and what is genuinely open.

  It is checked. `test/ci.cjs` fails the build if the file goes missing or stops carrying
  the no command guarantee, the mode gate, the no package manager constraint, how to run
  the tests, the failure mode, or the manual check that no assertion can cover. A handoff
  nothing verifies is a handoff that quietly stops being true, which is the same defect as
  everything else in this list.

### Fixed

- **The corrected YAML export wrote a file called `undefined` containing the word
  `undefined`, and had done since 1.5.0.** Selecting any Generate finding, which is the
  default deny NetworkPolicy, triggered it. `defaultDenyPolicy` returns a Kubernetes
  object, and the export read `.name` and `.yaml` off it, neither of which exists.
  `previewFix` had built the name correctly all along, so the two paths disagreed.

  It surfaced the moment a second caller existed, which is the argument for the refactor
  above rather than a coincidence alongside it.

  The test that should have caught it asserted `yamls.length === 2` on a list filtered by
  `/\.ya?ml$/`. A file named `undefined` does not match that filter, so the count was
  right past it for four releases. An equality check on a filtered count cannot see what
  the filter excludes. It now asserts that every written file has a real name and real
  content, and that a Generate finding produces a named NetworkPolicy.

- **`showTab` treated any unrecognised name as the Audit tab**, because it encoded "not
  remediate means audit" as a boolean. With a third tab that would have made Diff
  unreachable by a single typo. It is a lookup now, and an unknown name still falls back
  to Audit deliberately rather than by accident.

## 1.6.0 - 2026-09-08

The findings a review left open, closed. Nothing here changes what the tool does to your
manifests; it closes the gaps between what the code does and what it says it does.

### Fixed

- **A flash message's dwell was changed for every caller as a rider on an unrelated fix
  (F4).** Making refusals visible on the tab you are standing on was correct. Moving the
  timeout from 3000 to 6000ms for all twenty two call sites, without saying so, was not.
  "ZIP downloaded" and "Report only, choose Manual or Auto to write files" are not the same
  kind of message and should not share a number by accident.

  The default is back to 3000. The refusals an operator has to read and then act on ask
  for 6000 explicitly, through named constants with the reasoning beside them. Review
  caught that the first pass named three of them and left four more on the shortened
  default, halving the dwell those had in 1.5.1; all of them are explicit now.

  Fixing it exposed a second defect: a short acknowledgement landing after a refusal wiped
  the refusal early, which is the exact failure the longer dwell exists to prevent.

  The first fix for that was itself wrong, and review found it by pressing a button twice.
  Comparing the message TEXT cannot tell "still mine" from "the same message posted
  again", so the first press's timer wiped the second press's refusal early. Pressing
  twice is exactly what an operator does when a control appears to do nothing. Each call
  now carries a sequence token and clears only if its element still holds that token.

- **The comment describing the query encoder was wrong (F5).** It claimed jq's `@uri` is
  exactly the RFC 3986 unreserved set. Measured across every printable byte, it also passes
  `!`, `(`, `)` and `*` through. Harmless, since those are legal in a query string and mean
  nothing to ACS, and wrong as documentation.

  The comment now says what was measured, and the claim that matters is a check rather than
  a sentence: eight assertions pin that `+`, `:`, space, comma, `&`, `=` and `#` all encode,
  each with the reason it matters. `+` is the one that would silently change the query,
  because ACS reads a bare `+` as a term separator.

  The first version of those assertions shelled out to `jq` directly and never touched
  this repository. Review replaced `urlenc` with a passthrough and all eight stayed green:
  they were testing jq. That is the seventh instance of this project's recurring failure
  mode, and it had already been written into this file as the proof the problem was fixed.
  They now lift the function out of the script and call it, and gutting `urlenc` turns all
  eight red.

- **One `try` around ten test suites, so a single throw skipped the rest (F6).** A
  regression that removed one element reported `1 failed` when the true number was
  seventeen, and eight suites never ran. The count under-reported exactly on the run where
  an accurate list matters most.

  Each suite is isolated now, a crash is attributed to it by name with the failing frame,
  and crashes are counted separately from false assertions, because they are different
  problems: a false assertion is usually a defect in the product, a throw is usually a
  missing element the harness assumed. Demonstrated by making a suite throw: 357 of 380
  assertions still ran, against 0 under the old runner.

- **Two copies of the lazy detail row, one per table (F8).** Merged, carefully. The two
  tables render deliberately different advisories: Audit shows the runtime risk wording,
  Remediate shows Severity and Live in ACS. The mechanism is shared now and the content is
  not, so neither tab's output changed. That is the real risk in this finding and it is the
  part with the most coverage: two mutations, one giving both tables the same column count
  and one pointing Audit at the Remediate advisory, both go red.

- **Cosmetics that were quietly wrong (F7).** `table-layout:auto` removed, because `auto`
  is the CSS initial value and the declaration did nothing. The 340px cell ceiling now says
  where the number came from. `#fModeWhy` lost its inline layout and is styled with the
  other notes, with room under it so it reads as an explanation of the button above rather
  than a caption for the table below.

- **The release notes told every downloader something false.** They said the Word guides
  are "attached here rather than committed", which stopped being true in 1.5.1 when the
  guides were committed. A published false statement in a security tool is small and still
  worth removing, so it is corrected and now asserted.

- **A flake found while verifying this release, and not shipped past.** One CA assertion
  failed inside the full suite and passed five times standalone. The cause was the harness
  timeout firing on a loaded machine, not the script: that code path exits before it ever
  reaches authentication, so the assertion could not have failed for the reason it
  reported. A kill presented as a content mismatch sends you reading the wrong file.

  The block now asserts the run completed before asserting anything about its output, and
  says so when it did not. The pull timeout is a named constant with room for a loaded box,
  and the timeout message reports that constant rather than a number typed into a string
  next to it. Five full runs clean afterwards.

- **Three stale test counts in the documentation, found by asking rather than assuming.**
  The README claimed 1173 in two places, the Administration Guide claimed 177 for a suite
  that had grown to 399, and the User Guide claimed 899 from two releases back. Nothing
  caught any of it, because the only freshness check in this project was for version
  strings.

  The numbers are not corrected, they are removed. A count typed into prose is stale the
  release after it is written, and this is the third time it has happened. `BUILD.txt`
  carries the counts, written from the run that produced the build, and the per suite
  count column is gone from the Administration Guide because it rotted fastest and told
  the reader least.

  A check now fails the build on any three digit test count in the README, either guide,
  the docs index or the page itself. It found the User Guide's 899 within a second of
  being written, which is the argument for it. Its first version exempted any line
  mentioning `BUILD.txt`, so "1242 tests, see BUILD.txt" passed, which is the exact
  sentence somebody writes to keep the number and look compliant. Point at the file or
  state the number, not both.

### Already done in 1.5.1, confirmed rather than redone

- F9, the same disproved claim about the two injection controls, removed from the CHANGELOG.
- F10, `LC_ALL=C` on the allowlist grep. Re-measured this release: the grep and the `case`
  guard agree on every byte from 0x20 to 0xFF, so the two controls cannot disagree at the
  margins about what an alert id may contain.

## 1.5.1 - 2026-09-04

A security fix and three defects that all shipped for the same reason: the tests read the
code as text instead of running it and watching what happened.

### Fixed

- **Command execution through an ACS alert id.** `acs_pull_all.sh` passed alert ids from
  Central into a shell script body via `xargs -I{}`, inside a double quoted string, where
  `$()` and backticks are live. An id of ``aaa`touch FILE`bbb`` created FILE on the machine
  running the pull, in a process holding `ROX_API_TOKEN` and a working kubeconfig, and the
  run reported success. Confirmed end to end against a hostile server before and after.

  Two controls, and they cover different vectors rather than being redundant. Passing the
  id as an argument stops it being parsed as script, which closes the backtick and `$()`
  execution path. The `^[A-Za-z0-9._-]+$` allowlist is what stops the id being used as a
  path, and it is the only thing standing between a `/` in an id and an arbitrary file
  write, because the id is interpolated into the `-o` target. Review demonstrated that:
  with the allowlist removed and argument passing intact, a traversal payload still landed
  a file outside the run directory. There is now also a guard inside the fetch body,
  independent of the allowlist, so the redundancy is real rather than assumed. A rejected id is counted, named and explained rather than
  dropped quietly, because a Central sending something that is not an id is itself worth
  knowing about.

  This predates 1.5.0. If you have run a pull against an endpoint you do not control,
  that is the run to look at.

- **The query encoder returned nothing under dash.** `urlenc` used bash substring syntax.
  The shebang says bash so that was legal, but the suite invoked the script as `sh`, and
  the encoder returned the empty string there. `-n` and `-c` were silently ignored and the
  alert query lost its platform scope: same exit code, same files, different question. It
  is jq `@uri` now, which behaves identically under both shells.

- **`$(grep -c . f || echo 0)` produced `0\n0`.** `grep -c` prints its count and then exits
  1 when the count is zero, so the fallback appended a second zero. Arithmetic on that is
  an illegal number, which under dash killed the rest of the step without failing the run.
  Six occurrences, replaced with one `countlines` helper.

- **The findings table had no row checkboxes.** `renderTable` emitted seven `<td>` under
  eight `<th>`, so the checkbox cell the header declared was never filled. Every value
  rendered one column left of its heading, the Action column was empty in every row, and
  the only way to select anything was the header box, which operated on a model nothing on
  screen reflected. The Audit tab had the same fault the other way round: eight cells under
  seven headers, the extra one holding a checkbox bound to no handler anywhere in the file.
  Remediate gets its cell back; Audit, which is read only and has nothing to act on a
  selection with, loses its orphan.

- **Two containers of one object could not be selected apart.** Selection was keyed on
  `findingKey`, which is `file|obj|policy.id` with no namespace and no container. A
  two container Deployment where both containers run privileged is two findings with one
  key; on a trivial fixture, 8 of 19 findings collide that way. Ticking one would tick the
  other and the export would take both. The selection is now keyed on `findingRowKey`,
  which adds namespace, path and detail. `findingKey` itself is unchanged, because
  `STATE.applied`, the CLI and the test suite are keyed on it.

- **`Fix this` looked live and did nothing in report mode.** It was never disabled, so it
  was pressed, `requireMode` refused it, and the refusal was written to `#exportMsg` at the
  bottom of the page, below a 750 row table, where nobody scrolled down to look for it. It
  is disabled when the mode forbids writing, and it says which control to move in its own
  tooltip.

- **`Download corrected YAML for 750 selected` was greyed out with no reason beside it.**
  The label came from the selection and the disabled state came from the mode, and the only
  explanation lived in a different section far above the table. The gate is unchanged and
  still correct. A permanent note now sits directly above the table naming the Mode
  selector as the thing holding the button, and the button carries the same reason as a
  tooltip. Report only is still the default and is still enforced.

- **The findings table was quadratic.** It built two elements per finding, set `innerHTML`
  on each, attached two listeners and appended into a live table, and a single checkbox
  tick re-ran the whole thing. At 75 findings that was 440ms and nobody noticed. At 750, an
  ordinary first run, the page was unusable: clicks queued behind a render and every button
  looked dead. It was not dead, it was waiting.

  One string assignment instead of 2n, no advisory row built until somebody opens one, one
  delegated listener instead of per row listeners rebuilt every render, `findingRows()`
  evaluated once per render instead of three times, the filter pickers rebuilt once per
  scan instead of once per sort, and ticking a box repaints the boxes rather than
  rebuilding the table.

  There is deliberately no cap on how many rows are drawn. A cap would hide part of what
  the operator came to look at, break in-page find and print for the hidden part, and make
  "Select all shown" act on rows that are not shown, which is the same defect as a button
  whose number disagrees with the screen. Above 2,000 rows the count line says the filters
  will make it quicker and leaves the choice where it belongs.

- **The section header counted an opened advisory as an extra finding.** `refreshCounts`
  counted `tr:not(.hidden)` in the DOM, so reading one row made the header say 751 of 750.
  It reads the row set the table was built from instead.

- **A selection could outlive the findings in it.** Applying a fix and rescanning left keys
  in the set for findings that were no longer fixable, so the button promised work the
  export would not do. Stale keys are dropped on every rescan.

### Changed

- **Long values wrap inside their own cell instead of pushing the table off screen.** Every
  data table sits in a wrapper that takes any remainder as its own horizontal scrollbar, so
  a wide table never gives `<body>` one and takes the header and the controls with it. The
  findings table is fixed layout with explicit column widths, so one 180 character path
  widens its own column rather than every column. Values break rather than being clipped:
  an operator deciding whether a finding applies has to read the path, two clipped paths
  under one namespace are indistinguishable, and a tooltip is not on the printed page.

- **Selection survives a mode change.** Ticking costs nothing and produces nothing, so
  nothing about switching to Report only throws 750 ticks away. The gate sits on the two
  controls that act -- the export and `Fix this` -- and both now say so where they are.

### Fixed, after the suite failed on macOS and would not say why

- **Three hardcoded ports in the test fixture, and the failure they caused.** The TLS
  suite bound a fixed port on every run, and its readiness probe connected with
  `rejectUnauthorized: false`, so any listener satisfied it. On a machine that had run the
  suite before, a python server left over from an earlier run still held the port. The new
  server failed to bind, that failure was swallowed, and every assertion afterwards talked
  to the stale process.

  The pin route still passed, because a pin runs with `-k` and never checks expiry. The CA
  route did full verification and reported `certificate has expired`, which was exactly
  right and described a certificate generated days earlier by a run nobody remembered.

  Ports are now requested from the OS at runtime, and the fixture asserts that the
  certificate answering the port is the one this run generated, comparing SHA-256
  fingerprints and printing both when they differ. That check was written first and proved
  against a deliberate squatter holding the port with an unrelated expired certificate.

- **A probe before the token moves.** `--cacert` was taken at face value: if curl could not
  use the file, the run carried on and failed later as `authentication failed`, which sends
  you to look at the token when the problem is the certificate. It now makes one
  unauthenticated request with the CA first and quotes curl's own verdict.

  The advice follows that verdict rather than the platform. Expired, a chain that does not
  reach the CA, and a hostname mismatch are three different problems with three different
  answers, and the script now distinguishes them.

- **A wrong diagnosis, corrected.** The first version of that guidance decided what to say
  from `curl -V`, on the theory that Apple's Secure Transport ignores `--cacert`. The probe
  disproved it: on stock macOS curl the CA was read, the chain was evaluated, and the
  answer was a specific and correct `certificate has expired`. The theory reached the
  script, the README and the User Guide before the evidence arrived, and all three are
  corrected. Diagnosing from a build string rather than from the error is guessing with
  extra confidence.

- **A test that failed with no diagnosis, sitting above a test that could not fail.** The
  suite reported `verifying against the certificate itself also completes the pull  FAIL`
  and nothing else. The assertion directly below passed, because it checks that a phrase is
  *absent* from the output and a run that died early prints nothing at all.

  The first now prints curl's exit code, its stderr, the tail of the run and `curl -V`. The
  second is conditional on the first having succeeded, so they go red together. Those five
  printed lines are the only reason the real cause was found, rather than the plausible one.

### Documentation

- **The two Word guides are committed to the repository.** They were gitignored for
  several versions, on the reasoning that a binary change reads as
  `Bin 1128727 -> 1129347 bytes` and no reviewer can read that. True, and it cost more
  than it saved: browsing the repository showed a `docs/` folder of generators, figures
  and a proposal, and not one readable document. The README named two `.docx` paths that
  were not in git, and the route it offered for building them was
  `npm install --no-save docx`, which is exactly what an operator on a hardened host
  cannot run. The documentation existed and the person most likely to need it could not
  reach it.

  A guide is meant to be opened, printed and handed to somebody, formatted. That is worth
  more than a reviewable diff on a file almost nobody edits by hand.

- **`docs/check_docx.sh` keeps them honest.** The real risk with committed generated
  output is that it silently stops matching its source. This rebuilds from the generators
  and fails if a committed guide has drifted. CI runs it on every push.

  It compares extracted text rather than bytes, deliberately: a `.docx` is a ZIP and the
  generator writes non-deterministic content into it, so two builds of an unchanged source
  differ every time, verified twice here before the script was written. A byte comparison
  would fail on every run and be switched off within a week, and a check nobody runs is
  worse than no check because it looks like coverage.

  Its own restore step ran only on the happy path at first, so piping the output into
  `head` sent SIGPIPE and left rebuilt guides sitting in the tree looking committed. Found
  by doing exactly that. The restore is in the trap now.

- **The User Guide said "Version 1.0" while the tool stamped 1.5.0 into every report it
  wrote,** and both guides were dated 11 August 2026 regardless of when they were built.
  Version now comes from `ACS_VERSION` and the date from the newest CHANGELOG heading, so
  neither can be wrong without the build being wrong. The Administration Guide already
  read the version this way; the User Guide never did.

- **`docs/README.md`** explains what is in the folder, how to rebuild any of it, and why
  the guides are committed.

- CI previously failed the build if a `.docx` was tracked. That rule is why there was no
  readable documentation, so it is inverted: the build now fails if a guide goes missing.

- The README's test counts were stale in two places and its verification example named a
  1.4.0 artifact. Corrected.

### A note on the tests

Every defect above was found by running something and looking, and every one of them had
a test nearby that passed. The token check walked one line at a time, so a `-k` assigned
on one line and expanded on another was invisible to it. The script checks asserted that
the source mentioned the right strings, so a function returning nothing passed. The first
version of the injection regression test passed because its server never started.

The new tests assert observed behaviour: the URL the server received, the canary file that
was or was not created, the DOM element that survived a click. Several of them assert the
setup first, because a test that cannot reach the code it is testing reports a pass and
means nothing.

## 1.5.0 - 2026-09-02

Written for the workflow this is actually used in: scan on a Linux box, copy the files to a
Windows machine, review there, apply through your own change process. No Node on either
end, so the browser has to be the whole path rather than a preview of it.

### Added

- **Corrected YAML for a chosen subset of findings, from the browser.** Filter and tick
  what you want, press Download corrected YAML, and you get a ZIP of your manifests with
  those fixes applied, in the folder layout you loaded them in, plus a `READ_THIS_FIRST.md`
  recording every change, the ones that can stop a workload, any placeholder values, and
  anything that could not be applied.

  It applies to a copy. Nothing in the page moves, the undo history is untouched, and you
  can export one severity band, then another, without the two interfering. Exporting is not
  applying: these are files, and putting them on a cluster remains your decision.

- **Filters on the findings table.** Severity, fix kind, weakness class and policy id, with
  the pickers built from what was actually found rather than from the whole catalogue. At
  four figures of findings a single flat list is not a work queue, it is a wall.

- **Selection, by filter and by row.** Tick individual findings, or take everything
  currently shown. Selection is held per finding rather than per row, so filtering and
  sorting never move a tick onto something else. A finding with no mechanical fix gets a
  disabled box naming the reason instead of no box.

- **`acs_pull_all.sh` captures the running workloads.** `oc get
  deployment,daemonset,statefulset,cronjob,job -A -o json` lands as `workloads.json` in the
  same timestamped run directory as the findings, so the violations and the manifests they
  are about come from the same instant. Run it, make changes, run it again, and the two
  directories diff cleanly. Without it ACS tells you a workload is in violation and you
  have nothing to fix.

  Time bounded like the trust bootstrap, and not fatal if `oc` is missing: it says what to
  run elsewhere and carries on.

### Changed

- **The heavy sections collapse, with counts in the header.** Cross check, Violations from
  ACS, and Findings, on the page and in the exported report. The count is what makes
  collapsing useful rather than merely tidy: `1100 open, 40 critical` in a closed header
  tells you where to start, and a critical count turns the badge red.

- **A disabled export button now says what is holding it.** Report mode greying out the
  patch and corrected YAML controls was silent, so it read as the tool being broken rather
  than as a deliberate gate.

## 1.4.0 - 2026-09-02

Provenance and reviewability. Nothing in the tool's behaviour changes; what changes is
whether you can check that the thing you downloaded is the thing that was built.

### Added

- **A release pipeline that produces something verifiable.** Pushing a version tag now
  builds the archives, generates `SHA256SUMS`, attests build provenance through GitHub's
  signing infrastructure, and attaches everything to a GitHub Release. Anyone can check a
  download:

      sha256sum -c SHA256SUMS
      gh attestation verify dj-acs-auditor-1.4.0.zip --repo djkidnyce/DJ-ACS-Cluster-Security-Auditor

  The attestation is a signed statement that those exact bytes came from that workflow at
  that commit. The release notes say plainly that it is not a claim the tool is correct,
  because a verified signature on bad software is still bad software.

  The pipeline refuses to publish unless the version, the CHANGELOG and the tag agree, the
  whole suite passes on that exact commit, and the SBOM matches what is vendored.

- **An SBOM, generated rather than written.** `sbom.cdx.json`, CycloneDX 1.5, listing the
  entire dependency surface: js-yaml 4.1.0 and JSZip 3.10.1, both vendored, both hashed.
  `scripts/make_sbom.js` reads the bytes on disk, so the document cannot describe a
  dependency that is not there. It refuses to run if `vendor/` contains a file it does not
  recognise, because an SBOM that silently omits a dependency is worse than none. It has no
  timestamp, so it changes only when a dependency does and a diff on it always means
  something. CI verifies it still matches.

- **Signed tags documented.** `RELEASING.md` covers SSH tag signing, how to verify one, and
  says to admit it when you cannot sign rather than letting people assume you did.

### Changed

- **The generated Word guides are no longer committed.** They were 1.1MB and 465KB of
  binary in the tree, diffing as `Bin X -> Y bytes`, so a documentation change could not be
  reviewed, and the repository carried both the source and the output of the same thing.
  They are built in CI and attached to each release. A documentation change is now a diff
  of `docs/doc1.js`.

  Two new CI jobs hold what that gives up: one proves the generators still run and the
  figures still render, and one fails the build if a generated `.docx` is committed again.
  Building them is now checked on every push rather than discovered at release time.

## 1.3.0 - 2026-08-24

Everything here was written after 1.2.0 was tagged and pushed, so it gets its own version
rather than being folded into a release that is already out.

### Fixed

- **`test/version.cjs` failed while preparing a release, and then gave two different
  answers on two identical runs.** It compared the git tag against the code whenever HEAD
  sat on a tag, so applying the next version's files on top of the previous tag turned the
  suite red for doing exactly the right thing.

  Guarding that with "unless the tree is dirty" made it worse rather than better. `unzip`
  preserves the archive's timestamps, so git's stat cache reported a freshly replaced tree
  as clean on the first `git status` and dirty on the second, once the index had been
  refreshed. Two identical commands, two different results, which is worse than either
  answer alone.

  The comparison now binds in CI, where the checkout is a fresh clone and the tag, the
  commit and the files are the same thing by construction. Locally it reports what it sees
  and does not fail. Verified: fails in CI on a wrong tag, passes on the right one, skips
  when there is no tag, and three identical local runs agree.
- **The self signed TLS tests skipped silently where a local TLS server could not start.**
  Thirty one assertions disappeared, the total dropped, and everything still said passed.
  The skip now names the reason and checks python3, openssl and `-addext` support
  individually, so a machine that is not exercising that coverage says so. The readiness
  loop no longer uses `seq`, which is not POSIX, and probes with node's own TLS client
  rather than shelling out to openssl, which is one less external tool to disagree.

  The first version of that diagnostic still discarded the test server's stderr, so it
  reported "could not start a local TLS server" and withheld the reason: the same defect
  one level down. The server's stderr is now captured and printed with the skip.
- **A CI check that could not fail, and was masking real violations.** The guarantee job
  greps three files for `eval(`, `new Function(` and `child_process`, and one of them was
  the remediation page, deleted in 1.2.0. grep exits 2 on a missing path, `if grep` reads
  non zero as "no match", and the step printed "clean" and passed. The error also masked
  matches in the files that did still exist: a planted `eval()` in the surviving page went
  undetected. Every green build since 1.2.0 asserted nothing there.

  The workflow now globs rather than naming files, asserts the files exist before checking
  them, runs each step under `set -e`, pins the CLI to exactly one subprocess and asserts
  what that subprocess is, fails the build when a suite crashes before reporting, and has a
  self test job that plants an `eval()` and a password field and requires the checks to
  catch them. `test/ci.cjs` asserts all of that from the suite, so the workflow is covered
  the same way the code is.

- **"Automatic" described the edit and was read as a promise about the workload.** Four of
  the fourteen automatic fixes remove something an application may be relying on:
  `readOnlyRootFilesystem` on anything that writes to disk, dropping all capabilities from
  an image that needs one, `runAsNonRoot` against an image with no numeric non root user,
  and unmounting the service account token from a pod that calls the Kubernetes API. They
  were presented identically to genuinely inert changes like removing `hostPID`.

  Each now carries a note naming the specific failure and the remedy, and it appears in the
  confirmation dialog, the change log, the drafted patch header, the CLI output and its own
  section in the report. The classification stays `auto`, because the edit really is
  unambiguous; what changed is that the tool no longer implies that makes it safe to apply
  without looking at the workload.

- **`docs/index.html`, the GitHub Pages site, still described the tool as it was before
  1.1.0.** Two pages, live connect panels, a test count from the first commit. It is the
  public face of the project and had not been updated since it was written. Rewritten
  against what actually ships, including the coverage number and the automatic fix caveat.


- **The pull could not reach a Central with a self signed certificate**, which is what the
  RHACS operator installs by default. It stopped at the token check having written only an
  error file, leaving a directory that looked like a pull returning almost nothing. TLS is
  now resolved before the token is touched, in order of trustworthiness: a CA you supplied,
  then the `central-tls` secret read through your authenticated `oc` session, and failing
  both it stops and prints the certificate's issuer, its SHA-256 fingerprint, and two
  commands that work.
- `--pinnedpubkey` alone can never verify a self signed certificate. It is an additional
  check rather than a replacement, so curl rejects the chain before it looks at the pin.
  `--pin` now turns the chain check off and enforces the key, which is the combination that
  works. A wrong key fails closed with `curl (90)`, asserted against a real self signed TLS
  server rather than by reading the script.
- The curl command was assembled before the TLS decision was made, so whatever
  `resolve_tls` chose was discarded. One branch rebuilt it by hand and the others did not.
  It is rebuilt once now, after the decision is final.
- **The `oc` call that bootstraps trust had no timeout.** On a workstation `oc` usually
  exists and points at a real cluster, so a script whose job is to fetch findings could sit
  silently on an unrelated API server. It now passes `--request-timeout=10s` and announces
  that it is trying that route, so a wait is explained rather than mysterious.
- A failed run no longer leaves a findings directory. TLS failures leave nothing, and a
  token rejection writes `RUN_FAILED.txt` saying not to read the directory as a clean
  cluster. `cleanup` runs before the `rmdir` it would otherwise defeat.
- **ACS violations had no score, so there was nothing to rank them by.** Every matched
  violation already carried a CVSS style score from the catalogue and the table never
  rendered it. With an ACS export and no manifests the findings table is empty by
  definition, so the violations table was the only thing on screen and it offered four
  severity buckets and no ordering inside them. There is now a sortable Score column on the
  page and in the report, and the report lists violations worst first. An unmatched
  violation shows an em dash rather than a zero, because zero would sort it below every real
  finding and read as harmless rather than as not assessed.
- With ACS data and no manifests the top of the page was an explanation and nothing else.
  It now shows the counts that are real, total violations, the severity split and how many
  are on platform components, under a heading saying these are counts and not a posture
  score.
- `renderRemediateTab` also wrote the summary cards and, being the later of the two
  writers, silently replaced whatever the Audit half had put there. Two owners for one
  element is the failure the page merge existed to remove; it survived because that half
  was lifted wholesale.

### Added

- **The exported HTML report is sortable.** Click any column header. Numeric columns are
  detected from their values rather than declared, the arrow moves to whichever column is
  active, and it is applied to every table generically so one added later is sortable
  without anybody remembering to wire it. The report outlives the session and gets attached
  to tickets; the first thing anybody does with a findings table is reorder it, and without
  this they export to a spreadsheet and circulate that instead.
- **The README states coverage as a number.** Twenty policies, against roughly seventy ACS
  defaults, with a table of what cannot be judged from a manifest at all: build stage rules,
  runtime behaviour, image CVE policies, and your own tuned policies. A clean score here
  means clean against twenty checks and should never be quoted as compliance with the ACS
  default set.
- **The pull ends with a summary, written and shown.** `acs_pull_all.sh` writes
  `findings.md` into the run directory and prints it. Seven JSON files in a folder is not a
  result anybody can read, and a summary written but never displayed is one nobody reads.
  `--no-summary` skips it.
- **The summary scores the images.** Worst CVSS per image alongside critical, KEV and
  fixable counts, and a table of the highest scoring CVEs with the version each is fixed in.
  It states that CVSS is not the priority the engine ranks by, which additionally weighs the
  CISA catalog, EPSS, whether a fix exists and whether pods are running the image, and runs
  to 15 rather than 10. That model lives in the engine and is deliberately not reimplemented
  in jq, because a second ranking that drifts from the first is worse than one ranking.
- `--pin` on `acs_pull_all.sh`, and automatic CA bootstrap from the `central-tls` secret.
- The script tests now run against a real self signed TLS server, and are hermetic: a stub
  `oc` on PATH makes the trust bootstrap branch deterministic. Without it the branch was
  never reached where `oc` is absent, so the suite passed while only testing half the code,
  and hung where `oc` was present. Every external call in those tests is time bounded, so a
  future hang fails an assertion instead of wedging the run.

## 1.2.0 - 2026-08-24

### Fixed

- **ACS violations had no score, so there was nothing to rank them by.** Every matched
  violation already carried a CVSS style score from the policy catalogue and the table
  simply never rendered it. With an ACS export and no manifests the findings table is
  empty by definition, so the violations table was the only thing on screen and it offered
  four severity buckets and no ordering inside them. There is now a sortable Score column
  on the page and in the HTML report, and the report lists violations worst first. An
  unmatched violation shows an em dash rather than a zero, because zero would sort it
  below every real finding and read as harmless rather than as not assessed.
- **With ACS data and no manifests the top of the page was an explanation and nothing
  else.** It now shows the counts that are real, total violations, the severity split and
  how many are on platform components, under a heading that says these are counts and not
  a posture score. Refusing to invent a score should not mean refusing to show the numbers
  that exist.
- `renderRemediateTab` also wrote the summary cards, and being the later of the two writers
  it silently replaced whatever the Audit half had put there. Two owners for one element is
  the failure the page merge existed to remove, and it survived the merge because that half
  was lifted wholesale.

- **The pull script could not reach a Central with a self signed certificate, which is
  what the operator installs by default.** It stopped at the token check having written
  only an error file, leaving a directory that looked like a pull returning almost
  nothing. It now resolves TLS before touching the token, in order of trustworthiness: a
  CA you supplied, then the `central-tls` secret read through your authenticated `oc`
  session, and failing both it stops and prints the certificate's issuer, its SHA-256
  fingerprint, and two commands that work.
- `--pinnedpubkey` alone can never verify a self signed certificate. It is an additional
  check rather than a replacement, so curl rejects the chain before it looks at the pin.
  The `--pin` option now disables the chain check and enforces the key, which is the
  combination that actually works. A wrong key fails closed with `curl (90)`, asserted
  against a real self signed TLS server rather than by reading the script.
- The curl command was assembled before the TLS decision was made, so whatever
  `resolve_tls` chose was silently discarded. One branch rebuilt it by hand and the others
  did not. It is rebuilt once now, after the decision is final.
- A failed run left a findings directory behind. TLS failures now leave nothing, and a
  token rejection writes `RUN_FAILED.txt` saying not to read the directory as a clean
  cluster. `cleanup` is called before the `rmdir` it would otherwise defeat, since the
  trap runs on exit and the directory is never empty until it has.

### Added

- **`scripts/acs_summary.sh`, so a machine without Node is not a dead end.** Node cannot be
  installed everywhere, and a hardened host in a controlled enclave is exactly the machine
  where curl and jq are all you get. This reads a pull directory and reports what ACS said:
  violations by severity, policy and namespace, the split between your workloads and
  platform components, how many arrived with no `platformComponent` field at all, CVEs by
  Red Hat severity, how many have a published fix, and the images to rebuild ranked by
  critical count. jq only.

  It does not compute a posture score and does not draft fixes, and it says so in its own
  output. Both need the policy engine. A score is measured over scanned manifests and this
  script has neither manifests nor a scanner, so any number it printed would be invented,
  which is the same defect as scoring an empty scan.

- The wrapper scripts detect a missing Node and print the routes that do not need it: the
  page, the summary script, and running the CLI in a container. Previously they said Node
  was required and stopped.

### Changed

- **The auditor and remediation pages are now one file with two tabs.** `dj_acs_auditor.html`
  is the whole browser surface: an **Audit** tab that reads, scores, cross checks and
  exports, and a **Remediate** tab that edits the YAML you loaded with a diff, a
  confirmation and undo. `dj_acs_remediation.html` is removed.

  This was not cosmetic. Eighteen function names existed in both files, ten of them
  byte identical, and they were kept in step by hand. That is how a fix reached one
  surface and not the other, which happened more than once during development. There is
  now one file list, one visibility gate, one violations table and one mode gate. The mode
  selector sits above the tabs, because a control that decides whether the tool may write
  has to be visible from wherever you are standing when you ask it to.

- `-o` on `acs_pull_all.sh` now names the **parent**. Each run lands in
  `PARENT/acs_findings_<timestamp>/`, so a second run never overwrites the first and you
  keep a history you can diff. `--no-timestamp` writes straight into `-o` for a pipeline
  that wants a fixed path.

### Fixed

- **The HTML report contained no ACS violations at all.** A run with a violation export and
  no manifests produced about five kilobytes of headings and method notes while the page it
  came from was listing dozens of findings. The report now carries every violation, split
  into your workloads and platform components, each with its fix route and the reason the
  platform split was drawn where it was. The report is the artifact that outlives the
  session, so anything visible in the page has to reach it.
- **The report also scored an empty scan as 100 out of 100, Grade A**, the same defect
  fixed in the pages in 1.1.0 but left in the one output people file against a ticket.
- **The file picker would not offer `.ndjson` files.** `accept` listed only
  `.yaml,.yml,.json`, so three of the seven files `acs_pull_all.sh` writes were invisible
  in the browse dialog. Drag and drop always worked, which is why it went unnoticed.
- **Three controls existed in the markup with nothing bound to them.** The four CVE filter
  checkboxes were read inside the render function but never wired to a change event, so
  ticking one did nothing until an unrelated render happened to run. Both CVE download
  buttons were referenced nowhere in the script at all. Found by merging the two files and
  now covered by the page tests, which drive the controls rather than calling the render
  function directly.
- `buildHtmlReport` read `cats` before it was declared, a temporal dead zone that only
  fired when manifests were present. The report worked on ACS only data and threw on a real
  scan. The suite caught it, but as a crashed process rather than a failed assertion.
- The test runner reported `TOTAL: N passed, 0 failed` when a suite crashed before printing
  its summary, because a crashed suite contributes no numbers. It now names the crash in the
  total line.

## 1.1.0 - 2026-08-21

### Fixed

- **The pages reported a posture of 100 out of 100, Grade A, when no manifests had been
  scanned.** The score's denominator comes from what was scanned. Load an ACS export and
  no YAML and that denominator is empty, so the arithmetic returns a perfect score. An
  operator reading it would see a green A on a cluster the tool had not measured, which is
  the most misleading output this tool could produce. The CLI already refused to print a
  score in that case; neither page did. Both now say so and explain that scoring nothing
  means unmeasured rather than clean, and the violations stay fully usable without a score.
- **Privilege escalation findings dead ended at "Platform" with no fix offered.** The
  policy (ACS.003) exists, is auto fixable and has a patch template, so nothing was missing
  from the policy side. The refusal came entirely from the platform classification, which
  is sometimes a guess: when ACS does not send `platformComponent`, the tool falls back to
  matching the namespace. A workload you own sitting in `openshift-operators` was refused
  forever with no way to say so. See Added below.
- `buildViolationPatch` re-derived fixability without the caller's options, so an
  overridden platform record was re-judged as platform and silently produced no patch. The
  override appeared to do nothing at all.
- The first version of the posture guard returned early and hid the violations panel along
  with the score, turning "refuse to show a meaningless number" into "hide what you came
  for". Caught by the page tests.
- `acs_preflight.sh` accepted a `ROX_CA` pointing at a file that does not exist and fell
  back to the system trust store, so a run believed to be pinned to an internal CA was
  verifying against a different set of CAs. Now exits 2. `acs_pull_all.sh` had the same
  gap for `--cacert`.
- `acs_pull_all.sh` did not read `ROX_CA`, which `acs_preflight.sh` has always read. Two
  scripts meant to run back to back disagreed about where trust comes from.
- The scripts ended by telling you to run the Node CLI, which is not installable
  everywhere. They now lead with the browser, which needs no runtime at all.

### Added

- **The platform classification records how it was reached, and can be overridden per
  finding.** `platformComponent` from ACS is authoritative; a namespace match is a guess.
  Rows and `--list-violations` now say which (`ACS said so` or `guessed from namespace`),
  because they are different claims and should not look identical. Every platform refusal
  carries an override control. Overriding a guess applies the normal fix routes; overriding
  something ACS itself flagged asks for confirmation first. It is per object, never global,
  it does not bypass the mode gate, and the drafted YAML carries the warning in its header.
- `--override-platform` on the CLI, taking the same identifiers as `--select`.
- A TLS failure in either script now prints the commands to obtain the CA, rather than the
  word `--cacert`: `openssl s_client` to identify the issuer, then `default-ingress-cert`,
  `router-ca` or the `central-tls` secret depending on how Central is exposed.
- `test/scripts.cjs`, which asserts the shell scripts agree with each other: same trust
  source, no token over an unverified connection, insecure never the default, credentials
  by header file rather than argv, and a TLS failure that names a real command. It found
  the unreadable-CA gap on its first run.
- `test/posture_platform.cjs`, covering both defects above.
- A "what needs what" table in the README. The audit path is browser only and needs no
  runtime; Node is required for the headless CLI and the tests, and nothing else.

### Removed

- **The in browser connect panels, on both pages.** A page opened from a file has a null
  origin, and neither ACS Central nor the OpenShift API sends a header that permits it, so
  the browser blocked every request before the page saw it. The feature asked for a live
  ACS API token in exchange for a request that could not succeed. Removing it deletes the
  risk class rather than managing it. Neither page now contains a password field, a token
  identifier, a URL field, or a network call of any kind, and the test suite asserts their
  absence. Use `scripts/acs_pull_all.sh`, which runs where the cluster is reachable, keeps
  the token out of shell history and out of `ps`, and verifies TLS.

### Fixed

- **Three of the six files the pull script writes were rejected on load.** The vulnerability
  parser required a deployment or an images array, and `/v1/export/images` and
  `/v1/export/nodes` return a bare `storage.Image` and `storage.Node` which have neither.
  All six shapes now load. An image with no running workload is labelled as not deployed
  rather than attributed to a Deployment that does not exist, and a node CVE is labelled
  as a node.
- **Dropping several files loaded only one.** Each import replaced the previous one, so
  whichever file landed last was the only one you saw. Imports now merge. A violation that
  arrives twice, once slim from `/v1/alerts` and once hydrated from `/v1/alerts/{id}`, is
  deduplicated with the hydrated copy kept. Per image CVE counts are recomputed from the
  merged set rather than summed, so an image present in two exports does not double count.
- **The Download button under the violation fix panel had no click handler.** The bundle it
  should have produced was correct and the button did nothing. This is the defect class the
  whole page tests exist to catch, and the suite now covers it.
- **"Nothing was fixable" was reported for violations that were fixable.** A violation whose
  manifest is loaded routes to the in place fix rather than to a patch, which is correct
  behaviour described by an incorrect message. It now says which route it took.
- **A rejected file said what it was not, never what it was.** Dropping the tool's own
  findings export back in produced "expected Kubernetes or OpenShift objects", which
  describes everything the file is not. The tool now recognises its own output, a SARIF
  report, a Kubernetes API error, an ACS error envelope and an empty result, and says so.
- Report mode listed patches it withheld by filename only. Flattened names use the same
  separator between fields as within them, so you could not tell where the namespace ended
  and the object began. It now names the object, the namespace and the policies covered.
- CLI output paths printed as `../../../../..` when the output directory was outside the
  working directory. Absolute paths are printed in that case.

### Added

- **Checkboxes. You choose which violations to fix.** Every row in the violations panel has
  one. Nothing is selected until you select it and the draft button stays disabled until
  something is, for the same reason report mode is the default: the state you get by doing
  nothing should be the state that does nothing. The header box takes every fixable
  violation currently shown rather than everything imported, because selecting rows you
  filtered out of view is how a patch reaches a namespace you deliberately excluded. A
  violation with no fix route gets a disabled checkbox rather than none, so the absence of
  an option reads as an answer instead of an oversight. Selection is held per violation, so
  filtering and sorting do not move your ticks, and a violation imported later does not
  arrive pre selected.
- **`--list-violations` and `--select` on the CLI**, the command line equivalent of the
  checkboxes. `--select` takes an alert id, an object name or a policy id. A term matching
  nothing exits non zero and writes nothing rather than warning and continuing, because a
  typo in a narrowing option does not narrow less, it fails to narrow at all.
- **The written account now records its scope.** Draft fixes for four violations out of
  thirty and it says so at the top, and states that the other twenty six are not described
  anywhere in it. A report covering a subset otherwise reads identically to one covering the
  whole cluster, and the person reading it later is usually not the person who ran it.
- **A violations panel on both pages.** Every violation in the export gets a row: severity,
  policy, object, namespace, state, violation text, and a fix route. Filters cover your
  workloads against platform components, matched against unmatched, and fixable only.
  Clicking a row shows the rationale, the standards mapping, and the reasoning behind the
  route it was given. Counts are not findings.
- **Drafting violation fixes to YAML, in the browser and from the CLI.** The output is YAML
  files and a written account, and nothing else. No command is run, no cluster is contacted,
  nothing is applied. Each file names the object, the namespace and the policies it covers,
  and states on its face that it was built from a violation rather than from a manifest and
  therefore needs verifying. Violations on platform components are always listed and never
  patched. `node acs_cli.js --alerts 02_alerts_full.json --violation-fixes --mode manual`.
### Changed

- **The administration guide covers this repository only.** It previously documented DJ's
  KYSA alongside the ACS Auditor and referenced `kysa_cli.js`, `ci_templates/`,
  `fetch_vendor_libs.sh`, `dj_kysa_source_watcher.py`, `kysa_waivers.yaml` and
  `GETTING_STARTED.md`, none of which exist here. A maintainer following it could not find
  the files it named. It now describes only what ships, notes that KYSA is a separate tool
  intended to merge later, and the CI, vendoring, exceptions and maintenance sections were
  rewritten around what this tool actually does. Figures 5 and 6 were redrawn for one
  toolset. A note describing the state of a local working folder was removed; it did not
  belong in a published repository.

- 237 more tests. `test/exports.cjs` loads all six pull script outputs and asserts merging
  and deduplication. `test/cli_violations.cjs` runs the CLI as a real process and inspects
  what lands on disk, chiefly that report mode leaves nothing applyable behind, and that a
  selection is honoured on both surfaces.
- Figure 2 in the user guide replaced with the pull workflow. Figure 8 added for the
  violations panel and the fix routes. Both Word guides updated throughout.

## 1.0.0 - 2026-08-19

Initial release.

Audit Kubernetes and OpenShift manifests against Red Hat Advanced Cluster Security policy
logic, score and rank every finding, and fix it in YAML with a preview and an explicit
confirmation.

- Explicit report, manual and auto modes. Report is the default everywhere and the mode is
  never inferred, so nothing applyable is produced by accident.
- Twenty ACS policy replicas with CIS, NIST 800-53, PSS and DISA STIG citations.
- Weighted posture scoring whose denominator comes from what was scanned rather than what
  was found, so the projection survives a rescan.
- Policy violations and image CVEs read from the two separate ACS endpoints, including
  platform components and every violation state.
- Violations render as rows with a fix route each, and checkboxes decide which are acted on.
- Fixes are drafted as YAML you review and apply yourself. No command is ever run to
  remediate, on any surface, in any mode.
- The pages contact nothing. The scripts do, GET only, from a shell where the token stays
  out of `ps` and out of shell history.
- No package manager and no network at rest. The browser path needs no runtime at all.
