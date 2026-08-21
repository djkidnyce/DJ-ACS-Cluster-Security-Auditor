# Changelog

## Unreleased

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

- 163 more tests. `test/exports.cjs` loads all six pull script outputs and asserts merging
  and deduplication. `test/cli_violations.cjs` runs the CLI as a real process and inspects
  what lands on disk, chiefly that report mode leaves nothing applyable behind, and that a
  selection is honoured on both surfaces.
- Figure 2 in the user guide replaced with the pull workflow. Figure 8 added for the
  violations panel and the fix routes. Both Word guides updated throughout.
