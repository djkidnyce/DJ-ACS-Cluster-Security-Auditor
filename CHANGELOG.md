# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
public interface for versioning purposes is the CLI flags, the exit codes, the shape of
the JSON and SARIF exports, and the policy ids. A change to any of those is a minor bump
at least; removing or renaming one is a major.

Every release is tagged. `git tag -l` is the list, and the tag matches the version this
tool stamps into every report and patch header it writes.

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
