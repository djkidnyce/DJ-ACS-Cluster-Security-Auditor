# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
public interface for versioning purposes is the CLI flags, the exit codes, the shape of
the JSON and SARIF exports, and the policy ids. A change to any of those is a minor bump
at least; removing or renaming one is a major.

Every release is tagged. `git tag -l` is the list, and the tag matches the version this
tool stamps into every report and patch header it writes.

## 1.14.0 - 2026-11-10

### Added

- **`acs_rollout.sh drift`: hardening an earlier revision had and the running one does not.**

  Reported from production. A fix was applied, landed at one revision, and three revisions
  later the running template no longer had it. The finding came back, the YAML on disk was
  still correct, and the auditor annotation was still on the object because whatever
  replaced the template had written its own. Nothing in the tool could tell that apart from
  a fix that was never applied, and the two have completely different remedies.

  `drift` does not read the annotation to decide what hardening to expect. The annotation
  records a run, not a list of policies, so inferring expectations from it would report
  drift on a policy the operator deliberately left alone. It compares the live pod template
  against the template stored in every revision the cluster still keeps, and reports only
  what the cluster can prove was lost: a property that held in an earlier revision and does
  not hold now. It then names the newest revision that still had it, which is the rollback
  target, and prints that rollback command without running it.

  It also says which of two things happened, once per workload. If the revision that still
  had the fix carries the same auditor reference as the live object, the auditor was not
  what replaced it and something edited the template afterwards. If it carries a different
  reference, a later auditor apply replaced it, which happens because a full manifest apply
  writes the whole pod template: an export generated without a given fix removes that fix.
  The per fix patches do not have this problem.

  `managedFields` is printed with it, since that is the only record the API keeps of who
  wrote the object last, with a legend: `kubectl-edit` and `oc-edit` are a person at a
  console, `client-side-apply` is somebody applying a manifest, and Terraform, Helm, Argo CD
  or an operator name means that tool owns the field and will undo the fix again, so the
  value belongs in its config rather than in the cluster.

  Covers Deployments through ReplicaSets, StatefulSets and DaemonSets through
  ControllerRevisions, and DeploymentConfigs through ReplicationControllers. Five reads for
  the whole scope regardless of cluster size. `--all` widens it past annotated workloads.
  `snapshot` now captures a `drift.txt` too, for a machine that cannot reach the cluster.

  The output states its own limits: a fix that was never applied never held in any revision
  and so cannot appear, and a pruned revision cannot be compared, which matters because
  `revisionHistoryLimit` defaults to 10.

  The script remains self contained, shell and jq only, no Node and no dependency on
  anything else in the repository, so this one file can be carried to an air gapped box
  running an older release. Verified by dropping it onto a pristine v1.11.0 checkout.

### Fixed

- **An empty field in the middle of a record silently shifted every field after it.** The
  subcommand loops split records on a tab, and tab is IFS whitespace, so `read` collapses
  two consecutive tabs into one. A StatefulSet has no `deployment.kubernetes.io/revision`
  annotation, so its revision field is empty, and the drift report printed its auditor
  reference where the revision number belonged and the revision count where the reference
  belonged. The drift loop now splits on a unit separator, which is not whitespace.

### Notes

- 38 new assertions in `test/scripts.cjs`, driven against fake `oc` binaries that record
  every call, asserting among other things that every call made is a `get`. All were
  mutation tested. Three did not fail when they should have: two because the fixture had
  only one good revision, so picking the oldest instead of the newest and sorting revisions
  lexically both went unnoticed, and one because it counted a per workload verdict across
  the whole report. The fixture now carries a workload whose good revisions are 9 and 10,
  either side of ten so that a lexical sort names the wrong one.

## 1.13.0 - 2026-11-04

### Fixed

- **Per fix patch files contained every fix applied to the object, not just their own.**
  `buildMergePatch` was called with the file's original state and its final state, so a
  Deployment with a CPU fix and a memory fix produced two patch files that were byte for
  byte identical, each named after one of the two. Anyone applying a subset of the patches
  got fields from fixes they had not chosen. Each patch is now built from that one fix's
  own before and after. Reported from production.
- Patch files and the patch README now give the exact `oc patch` command and state that it
  has to be a strategic patch. Strategic is already the default for `oc patch` and
  `kubectl patch`, so the command spells out what you would get anyway; it spells it out
  because `--type=merge` does something else entirely. These patches name a single
  container inside `spec.template.spec.containers`, and a JSON merge patch replaces the
  entire container list with the patch contents, deleting the image, ports, env and every
  container not named in it.
- Patch files are numbered in the order the fixes were applied.
- `formatMem` could return a correct but unreadable quantity such as `2000000Ki`. A unit is
  now only chosen if the quotient also stays under four digits.

### Changed

- **ACS.013 and ACS.014 derive the limit from the request instead of inserting a frozen
  placeholder.** A value already present on the container is never overwritten, for either
  requests or limits: only a missing value is filled in. Raising a request changes what the
  scheduler reserves across every replica, and overwriting a tuned limit is not this tool's
  decision to make.
  - The limit is the request times the multiplier, or the floor, whichever is larger.
    Defaults are 5x for CPU with a 500m floor, and 4x for memory with a 512Mi floor, so a
    10Mi memory request yields 512Mi rather than 40Mi.
  - Where a container has no request to derive from, the request itself is a placeholder
    and the change note says so in those words.
  - Where only a limit is present, the request is set to match it, which is what Kubernetes
    already defaults it to.
  - A Guaranteed mode sets the limit equal to the request. It is also inferred, per
    container, when the other resource on that container is already pinned request equal to
    limit. That inference is stated in the change note as INFERRED every time it fires; it
    reads intent from the sibling resource and will occasionally be wrong.
  - Guaranteed cannot honour the floor, because clearing it would mean raising the request.
    When the request is below the floor the change note carries a WARNING naming the floor
    it could not reach and what to do about it.
  - Every change note distinguishes derived, raised to the floor, and genuine placeholder.
    A derived limit is only as good as the request it came from; `scripts/acs_resources.sh`
    is still the way to get a measured number.

### Added

- Resource limits panel on the Remediate tab: mode, both multipliers, both floors and both
  default requests, with a worked example showing the arithmetic on real numbers. A value
  that is not a usable quantity is refused and named rather than silently defaulted.
- CLI flags `--cpu-multiplier`, `--mem-multiplier`, `--cpu-floor`, `--mem-floor`,
  `--cpu-request`, `--mem-request` and `--guaranteed`. A bad value exits 2 with the value
  quoted back.
- `test/page.cjs` suite `resourceLimits`, 49 assertions. Every one was mutation tested;
  two of them failed to fail on the first attempt and were rewritten.

## 1.12.0 - 2026-10-30

> No `1.12.0` tag exists. This version was never released on its own: its changes shipped inside **`v1.13.0`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

### Added

- **A manual finding can be marked resolved, and then it is fixable.** ACS.012 and ACS.017
  were manual because the right answer needed an input the scanner cannot see: which claim,
  which service account. The edit itself was never the hard part. Apply the matching file out
  of `recommended/`, press Mark applied on the row, and the checkbox enables. The fix then
  rewrites the volume to that claim, or sets `serviceAccountName`, using the name from the
  file you applied rather than one you retyped.

  A recommended ServiceAccount is now generated too, deliberately bare with no RoleBindings,
  which is strictly better than the namespace default that every other workload shares.

  ACS.011 and ACS.020 stay manual. They are resolved by removing something, not by editing a
  field, and a resolution would not help.

- **A third posture card.** Current, after auto fixes, and after auto fixes plus the
  resolutions recorded. A workload hardened in every respect but one `hostPath` read 91 and
  94, while actually resolving it reached 100, and those points were invisible: manual
  findings always count against the projected score, so the tool offered no feedback for
  doing the hard work and the same feedback for waiving it as for fixing it.

- **Resolutions ride in the exceptions file as a second entry type**, with the policy, object,
  the value, the artifact it came from and a timestamp. One document to hand up the chain
  showing both what was fixed and what was accepted, rather than two.

  The prerequisite ordering is the same as the Secret work: the export prints
  `oc get pvc <name> -n <ns>` ahead of the apply instructions, warns that Pending means the
  pod waits too, and repeats that nothing was copied out of the host path. The tool has no
  cluster access, so a resolution is your assertion and the verification is yours to run.

### Fixed

- **`renderRemediateTab()` was still writing the posture cards.** It runs after `render()`, so
  it silently replaced whatever the Audit half had put there, which is why a third card added
  in `render()` never appeared at all. The comment directly above that block claimed the
  problem had been removed in the page merge; it had not. `render()` is now the only writer
  and the remediate specific numbers moved into it.

- **A resolutions only exceptions file could not be loaded back.** The shape check accepted a
  file carrying `entries` or `rules` and rejected anything else as not ours, so an export
  holding only resolutions was discarded whole.

### Changed

- `manual policies have no fix function` was asserted in the suite and is now deliberately
  false. Replaced with the property that actually matters: a manual policy's fix must do
  nothing when called without a resolution, so a manual finding can never be swept into a
  bulk apply.

## 1.11.0 - 2026-10-11

### Added

- **The Secret that the ACS.010 fix points at is now generated.** The fix rewrites a literal
  credential to a `secretKeyRef` and the Secret did not exist, so applying the corrected YAML
  produced `CreateContainerConfigError: secret not found`. A Secrets selector on the
  Remediate tab chooses what travels with the corrected manifests:

  `Secret stub` is the default and needs nothing installed: a Secret with every key present
  and the values deliberately empty, safe to commit, filled by the `oc create secret` command
  the export already prints. `ExternalSecret` emits an External Secrets Operator manifest with
  a `secretStoreRef` for a Vault backed store. `Do not generate one` for estates that manage
  Secrets elsewhere.

  Neither artifact carries a credential. A generated manifest holding a real secret would be
  the same leak this policy exists to close, one directory further along.

- **Recommended PersistentVolumeClaims for hostPath mounts.** Every hostPath volume gets a
  claim written to `recommended/` in the export, named from the object and the volume, checked
  against claims already declared in what you loaded. Drop `oc get pvc -A -o json` on the page
  alongside the manifests and the collision check becomes real; without it the export says so.

  ACS.012 stays manual and nothing is applied, because a PVC is not a mechanical equivalent of
  a hostPath. The warnings travel with each claim: nothing is copied, so mounting it gives the
  container an empty volume while the host directory stays on the node; a replica count above
  one will not work with ReadWriteOnce; the size is a placeholder; the storage class is
  deliberately absent so the cluster default applies. And when the workload is a DaemonSet the
  first thing it says is that a hostPath there is usually the point, because a log shipper on
  `/var/log` cannot be given the node filesystem by a claim.

- **`scripts/acs_resources.sh`**, for the ACS.013 and ACS.014 placeholders. Thanos over
  fourteen days where the `cluster-monitoring-view` role is available, `oc adm top` sampled
  from cron where it is not, and it says which it used. Requests from the 50th percentile,
  limits from the 99th times a headroom multiplier, both editable at the top of the file.

  The memory limit is never left below the observed peak. A long tailed distribution puts the
  99th percentile under the real maximum, so 99 samples at 100Mi and one at 800Mi yields a
  150Mi limit by the obvious calculation and an OOM kill on the next spike. It clamps above
  the peak and prints that it did. CPU is treated differently because exceeding a CPU limit
  throttles rather than kills, so the Thanos path reports which containers are already being
  throttled before you put a ceiling on them.

  Every run states the window and the observation count, and under a day of samples it warns
  that the memory limit is probably lower than the workload will need.

### Fixed

- **The new resources script passed its bearer token as a command line argument**, where
  `ps` exposes it to anyone on the box, and treated a leading dash as a subcommand so a
  mistyped flag reported a missing namespace instead of naming the flag. Both were caught by
  the existing script suite the moment the file was added: the token now goes in a header file
  at `umask 077` and trust is handled the same way as the ACS scripts, honouring `ROX_CA` and
  refusing a CA path it cannot read.

- **The generated Secret name did not match the manifest reference.** The fix stripped
  hyphens, producing `paymentsapi-secrets`, while the artifact kept them, producing
  `payments-api-secrets`. Both now come from one function, `secretArtifactName`, and the
  tests pin the literal name so an unintended rename fails rather than two sides agreeing on
  something wrong together.

- **A second credential on the same container was lost.** The ACS.010 fix rewrites every
  matching env var in a container at once, so a Deployment with two leaked credentials
  produces two findings but only the first reaches `applied`; the second reports no change
  because the work was already done. Deriving the Secret's keys from the findings therefore
  generated one key while the manifest referenced two, and the second credential became a
  reference to a key that did not exist. The keys are now read out of the corrected manifest,
  which is the only authority on what it needs.

- One Secret is generated per object rather than per credential. Three leaked env vars on one
  Deployment produce one Secret with three keys, not three Secrets with the same name where
  the last apply wins.

### Changed

- A fix that generates a companion artifact now shows that artifact in the Diff tab as a new
  file, so a reviewer sees both halves of the change.

## 1.10.0 - 2026-10-11

> No `1.10.0` tag exists. This version was never released on its own: its changes shipped inside **`v1.11.0`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

Minor rather than patch: the `cis` field on every policy is replaced by `cisK8s` and
`cisOcp`, which changes the shape of the findings JSON.

### Fixed

- **Every CIS citation named no benchmark, and the numbers were the OpenShift benchmark's
  while the report said Kubernetes.** The two publications number the same controls
  differently. CIS Kubernetes Benchmark v2.0.1 inserted a new 5.2.1, "Ensure that the cluster
  has at least one active policy control mechanism in place", which shifts 5.2.2 through
  5.2.8 down by one; the CIS Red Hat OpenShift Container Platform Benchmark v2.0.0 keeps the
  older numbering. Nothing in the output could have revealed which one a number came from.

  Both are now carried per policy and the citation line says which is which, for example
  `CIS K8s 5.2.2 | CIS OCP 5.2.1` for privileged containers. Read out of the v2.0.1 and
  v2.0.0 PDFs and checked control by control.

- **Nine policies carried prose in the CIS field** such as "CIS General container hardening",
  which rendered in the citation line looking like a citation. Those that have a real section
  now carry it: ACS.010 is 5.4.1, "Prefer using secrets as files over secrets as environment
  variables", in both benchmarks; ACS.011 and ACS.012 are Kubernetes 5.2.11, HostPath
  volumes; ACS.019 is Kubernetes 5.2.12, HostPorts. The five with no CIS section anywhere
  now say n/a and produce no CIS citation at all rather than prose.

- **ACS.019 cited the wrong Docker control.** It was labelled "Docker CIS 5.7", which in CIS
  Docker Benchmark v1.9.0 is "Ensure sshd is not run within containers". Privileged ports is
  5.8. The policy is renamed and the correction is recorded.

### Added

- **A dated standards table**, rendered in the report above the Method section and in the
  JSON as data. Per standard: the release the section numbers belong to, how the entry was
  established, a checkable URL, and notes. Eight entries, including both CIS benchmarks, the
  Docker benchmark, both DISA STIGs, and the current Kubernetes release.

- **Staleness is computed from a review date rather than asserted.** Past 180 days the report
  warns the reader to re-check the numbers before quoting them in an accreditation package,
  and the JSON exposes `stale` for a pipeline to fail on. Supersession is tracked separately,
  because reviewing a table does not un-supersede a benchmark.

- Kubernetes 1.37.1 is recorded in the table, verified against kubernetes.io, so the distance
  between a cited benchmark and the supported release window is visible.

### Notes

- No CIS rule text is reproduced anywhere in this repository. Section numbers are references;
  the benchmark prose is not redistributable.
- The DISA STIG fields remain control family pointers rather than V numbers. That mapping
  still needs doing and is the obvious next piece.

## 1.9.3 - 2026-10-06

> No `1.9.3` tag exists. This version was never released on its own: its changes shipped inside **`v1.11.0`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

### Fixed, in the policy catalogue

Prompted by one false positive report, every policy was audited against the secure pattern
as well as the insecure one. Four more defects, two of them false negatives.

- **ACS.010 flagged the secure pattern and its fix broke it.** The check matched the variable
  NAME and never looked at the value, so `APP_PASSWORD_FILE=/etc/secrets/app/password` was
  reported as a leaked credential and the auto fix replaced that path with a `secretKeyRef`.
  The application then opens a file named after its own password. It also flagged the service
  account token path that Kubernetes mounts itself. An absolute path, a `file://` URL and a
  `$(VAR)` substitution are now recognised as references, while `PASSWORD_FILE=hunter2` is
  still a finding because the value is not a path.

- **ACS.007 missed `CAP_SYS_ADMIN`.** Capability names were compared without normalising the
  `CAP_` prefix, so the prefixed form passed as clean. A false negative on a node takeover
  capability is the worst kind this catalogue can produce.

- **ACS.019 flagged every hostPort and its fix deleted them.** The policy is about privileged
  ports, below 1024. It reported `hostPort: 8080` and then deleted it, so an ingress
  controller or a node local agent was one automatic fix away from losing its binding. Now
  only ports below 1024 are flagged or touched.

- **ACS.009 reported a non zero `runAsUser` as possibly root.** An explicit non zero
  `runAsUser` overrides the image USER, so the container does not run as root. True to the
  letter and noise in practice: a team that sets `runAsUser` everywhere saw a finding on
  every workload it owns.

### Added

- **`test/falsepos.cjs`.** Every policy with a check, driven against both a hardened
  configuration and an insecure one, plus a fully hardened pod that must produce no findings
  at all. A false positive wastes a reviewer's afternoon; a false negative leaves the thing
  in production, so both directions are asserted.

- **ACS.010 now ships the commands.** The policy stays automatic and the export gained a
  section, placed before the apply instructions, giving the ordered steps per credential:
  read the current value, create the Secret, verify what landed matches, apply the manifest,
  watch the rollout, rotate. The order is the fix. Applying the corrected YAML before the
  Secret exists is what produces `CreateContainerConfigError: secret not found`, which is one
  of the two errors from the original incident.

### Notes

- Whether the kubelet accepts `capabilities.drop: ["all"]` in lowercase could not be verified
  against a live cluster. The tool treats it as compliant, which matches how other scanners
  compare it. Treat as unverified.
- ACS.012 reports every `hostPath`, not only sensitive ones, and the detail names the path
  rather than claiming it is sensitive. That is deliberate.
- The catalogue carries no `PodSecurityPolicy` references, so it is not sitting on guidance
  removed in Kubernetes 1.25, and it does cite Pod Security Admission.

### Fixed

- **The exported diff showed changes that had been opted out.** It read a `DIFF_BUILT` cache
  written only by `renderDiffTab()`, and `render()` does not call `renderDiffTab()`. So
  recording an exception on the Remediate tab left the export holding the build from before
  it, and the file both showed the excepted change and listed it as a documented exception,
  contradicting itself inside one document. The corrected YAML export was always right,
  which is how the discrepancy was noticed. Reported from production.

  The cache existed so the exported file would match what the operator had been looking at.
  Computing it twice from the same state achieves that; caching one of the two computations
  is precisely what made them differ. There is no cache now: `buildDiffModel()` is called
  fresh by the tab and by the export, so neither can be stale and the two cannot disagree.

  The same staleness applied to taking a namespace out of scope while not on the Diff tab.

- A test now asserts the property rather than the symptom: nothing listed in the export as a
  documented exception may appear in the reference register as an applied policy. It drives
  the reported order, rendering the Diff tab first and recording the exception afterwards,
  and reintroducing the cache fails it.

## 1.9.2 - 2026-09-29

Every script audited after a production report that one of them "did not run". Three of the
five had the same defect and two had others. Found by running each script rather than
reading it.

### Fixed

- **`acs_pull_all.sh --help` and `acs_pull_via_oc.sh --help` printed the file's comment
  header**, through `sed -n '2,40p' "$0"` and `sed -n '2,32p' "$0"`, hash marks and all.
  Same defect fixed in `acs_rollout.sh` in 1.9.1. All three now print real help with
  options, examples and environment variables.

- **`acs_preflight.sh -h` tried to connect to a server called "-h".** The first argument was
  taken as the Central URL unconditionally, so `-h`, `--help` and any mistyped flag became
  the endpoint and the run failed looking like a connectivity problem rather than a usage
  error. It now prints help, and an unrecognised option is named and refused.

- **`acs_preflight.sh --insecure` only worked as the second argument.** Passed first it
  became the URL. Position no longer matters.

- **`acs_summary.sh` treated `--help` as an error**, exiting 2 with a usage message on
  stderr, the same response as a mistake. It also took an unrecognised flag as the directory
  name, so a typo reported a missing directory instead of a bad option. Both fixed.

### Added

- A regression suite over **every** `.sh` in `scripts/`, rather than the ones somebody
  remembered to cover, so a script added later is covered the day it lands. Per script, under
  both bash and dash: it parses, it has a shebang, it has no CRLF endings, `-h` and
  `--help` exit 0 and print no raw comment line and document their own options, an unknown
  option is named and refused, and the source contains no self printing pattern and no
  executable cluster write verb.

  The write verb check is heredoc aware. `acs_rollout.sh` names both `oc rollout undo` and
  `oc rollback` in its help text on purpose, and a check that cannot tell printed text from
  an executed command would either flag that or be useless.

  PowerShell scripts were audited too. They use comment based help with param blocks, so
  `Get-Help` works natively and they never had the defect.

## 1.9.1 - 2026-09-29

> No `1.9.1` tag exists. This version was never released on its own: its changes shipped inside **`v1.9.2`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

### Fixed

- **`acs_rollout.sh` looked like it was not running.** With no subcommand it printed its own
  comment header through `sed -n '2,50p' "$0"`, hash marks and all, which reads exactly like
  a script that failed to execute and echoed its source. It now prints real help: the
  subcommands, the options, worked examples, and the note that it prints commands rather
  than running them. Reported from use.

  The hardcoded line range had gone stale as well. The header grew past line 50 when
  `restore` was added in 1.8.0, so that subcommand was cut off mid sentence and went
  undocumented in the output for a release. A fixed line number pointing into a file that
  grows is the same trap as indexing a table column by position, which this project also
  shipped once.

- **`acs_rollout.sh -h` did not show help.** As the first argument it was read as the
  subcommand name and fell through to "unknown subcommand", which is unhelpful for the most
  likely thing anybody types first. `-h`, `--help` and `help` now all print the help and
  exit 0, while a missing or wrong subcommand still exits 2.

- A test now asserts that every subcommand the case statement dispatches on appears in the
  SUBCOMMANDS list, which is what the stale line range defeated. The first version of that
  test matched the whole output and passed with a subcommand deleted from the list, because
  its name still appeared under EXAMPLES.

## 1.9.0 - 2026-09-22

### Added

- **Exception rules.** An exception can now say what it means instead of pinning one exact
  finding. A rule names a policy and a reason, plus optional `namespace`, `object` and
  `file` patterns where `*` matches any run of characters and `?` matches one:

      { "policy": "ACS.016", "namespace": "openshift-*",
        "reason": "Operators call the Kubernetes API. Removing the token stops them." }

  That is one line covering every operator namespace, including ones loaded after it was
  written. The previous format keyed on the whole finding row, which meant an exception was
  authored by typing
  `m/op.yaml|Deployment/oas-op|ACS.016|openshift-apiserver-operator|spec.automount...|Pod automounts a service account token`
  by hand, and it stopped matching silently when a file moved or the finding text changed.
  Exact entries still import and still win over a rule, because pressing Opt out on one row
  is a decision about that row.

- **Optional expiry.** A rule can carry `"expires": "YYYY-MM-DD"`. After that date the
  finding returns to scope marked as an expired exception rather than quietly reappearing,
  it becomes fixable again, and the report lists it separately: a decision that lapsed is
  not the same as a decision nobody made. The report also counts how many exceptions have
  no expiry at all.

- **Opt out all shown.** Set the policy filter, optionally a namespace, press one button,
  give one reason, and it writes a rule covering everything the filters describe. Refused
  without a policy filter, because a rule with no policy would except every finding in
  scope including ones not on screen.

- **An exceptions template.** A commented starter file, generated by the same build that
  reads it, documenting every field with two worked examples. It loads as it stands, and
  the test suite imports it to prove the examples are valid rather than aspirational.

- **A rule that matches nothing is reported.** On import, rules matching no loaded finding
  are counted and named. A rule pointing at a renamed namespace used to look exactly like
  one that was working.

- **The diff as a standalone HTML file.** One self contained page with every changed file
  side by side, the reference register, and any documented exceptions. No script tag, no
  external stylesheet, nothing fetched, so it opens on a machine that can reach nothing.
  Built for attaching to a ticket instead of screenshotting findings one at a time.

### Changed

- **The click through shows the change side by side.** It was one column of plus and minus
  lines, which reads fine to somebody who already knows what changed and is hard to show to
  anybody else. Left is what you have, right is what you would get, same as the Diff tab and
  the exported HTML. All three now share one pairing implementation.

- Import now reports what it took, what it refused and why, naming the offending rule
  rather than printing a count.

## 1.8.0 - 2026-09-18

### Added

- **Opt out of a fix, with a reason on the record.** Any finding can be excepted from the
  corrected YAML, one policy against one object at a time. Excepting
  `automountServiceAccountToken` on a batch job says nothing about the same policy on the
  deployment next to it. The reason is required: an empty one, a reason too short to be an
  audit record, and a list of non answers (`n/a`, `none`, `by design`, `wont fix`) are
  refused in place, next to the box, rather than accepted and filed. An exception with no
  reason cannot be told apart from a finding nobody looked at, which is the state this
  exists to prevent.

  An excepted finding is excluded from the corrected YAML and from Select all, and it is
  still in the report, still in the JSON, and now carries its reason there. It is
  recorded, not hidden.

- **Exceptions travel as a file.** `Save exceptions` writes `acs_exceptions_<stamp>.json`,
  which the corrected YAML export also carries. `Load exceptions` reads one back on any
  machine running the auditor, and entries whose reason was deleted by hand are rejected
  on the way in rather than imported blank. The browser copy is a convenience; this file
  is the record, and it can sit in the same repository as the manifests and be reviewed
  like anything else.

- **Every fixed object says which run changed it.** Two annotations are written: the
  object gets `kubernetes.io/change-cause`, which is the column `oc rollout history`
  prints, and the pod template gets `acs-auditor/applied`, which is what travels into the
  ReplicaSet or ControllerRevision for that revision. The object level annotation alone
  does not survive into a revision, so both are required.

  The value reads `2026-09-18 14:40Z / DJ ACS Auditor 1.8.0 / ACS-20260918-1440-001`.
  Short enough for the column that prints it. The reference resolves to a register in
  `READ_THIS_FIRST.md` and in the change log, which says which object it was, which
  policies were applied, and which of them can stop the workload. Objects that were not
  changed are not annotated: stamping them would alter the pod template hash and restart a
  workload to record that nothing happened to it.

- **The loaded file list folds.** Twelve files or fewer it stays open, past that it folds
  itself, and the summary carries the file count, the document count and the finding count
  so folding it costs nothing. The choice is remembered where the browser allows it. A
  file that failed to parse forces the list open and is counted in the summary: a parse
  error behind a fold reads as a clean scan of a file that was never scanned.

- **Suite filter in the page tests.** `node test/page.cjs annotations optOuts` runs those
  suites and says `PARTIAL RUN` so a filtered run cannot be mistaken for a full one. An
  unknown name exits 2 with the list of real ones instead of quietly running everything.

- **Namespace scope on the Audit tab.** Every loaded namespace is listed with its object
  and finding counts, and unticking one takes it out of scope: out of the findings, out of
  the posture score, out of the report and out of the JSON. Both halves are scoped
  together. Scoping the findings but not the objects would leave every excluded object in
  the denominator with none of its failures in the numerator, so deselecting a namespace
  would raise the score. The test for this excludes one of two identical namespaces and
  asserts the score does not move.

  The report says so where a reader cannot miss it. The HTML report opens with a note
  naming every excluded namespace and how many findings and objects went with it, above
  the score rather than below it, and the JSON carries the same under `scope`. A posture
  number for part of an estate is fine to publish and dishonest to publish silently.

- **Deselect platform namespaces in one click.** openshift, kube, stackrox, rhacs and the
  rest, out of scope together.

- **A Namespace column on both tables, sortable, with a platform mark.** Platform
  namespaces carry a pill on every row explaining that operators and control plane
  components there need the Kubernetes API and that a fix removing their access will stop
  them. Fixes on them remain available: the mark is advisory, and the namespace selector
  is the control that actually removes them from reach.

- **Namespace filter on the Remediate tab.** Work one namespace at a time. Select all
  shown then takes only that namespace.

- **Namespace coverage in the export.** `READ_THIS_FIRST.md` and the change log now carry
  a row for every namespace that was in scope, whether or not anything was applied to it,
  with how many findings were fixed, excepted, left for a human and left. The namespaces
  that received no fixes are named again underneath, because a reader scanning a long
  table will not do the subtraction. Namespaces excluded before the scan get their own
  section saying they were not examined.

- **`scripts/acs_rollout.sh`.** The other half of the annotations: what is running, which
  revision it is on, what changed it, and the command to put it back.

  It never writes. Every call is a read, and the test suite drives it against a fake `oc`
  that refuses every write verb and asserts none was ever issued. Making it execute the
  command instead of printing it fails six assertions.

  `plan` prints two lists and their overlap. `broken` is triage by symptom whatever the
  cause, and reports the workload that owns an unhealthy pod rather than the ReplicaSet in
  between. `touched` reads the `acs-auditor/applied` annotation, so it catches a workload
  that took a bad fix and has not restarted yet. `history`, `snapshot`, `undo` and
  `restore` do what they say.

  Deployment, StatefulSet, DaemonSet and DeploymentConfig are each given the command they
  actually take: `oc rollout undo` for the first three, `oc rollback --to-version` for a
  DeploymentConfig. `restore` handles the kinds with no rollout at all, reads a capture
  rather than the cluster, strips the fields the server owns, and needs no `oc` on PATH.

  Written for dash as well as bash, and the suite runs it under both. This repository has
  already shipped a script that worked under bash and silently dropped arguments under
  dash.

- **Contents pages derived from the headings.** Both guides built their contents from a
  hand kept list beside the document. The administration guide's had already drifted: it
  listed fifteen sections against a document with nineteen, and the last three numbers
  pointed at the wrong sections.

### Fixed

- **A posture score of 100, Grade A, over an empty scope.** The guard that refuses to
  score zero manifests was checking the loaded file list. Namespace scoping reopened the
  defect through a new door: files loaded, every namespace deselected, denominator empty,
  Grade A. The guard now runs on the scoped file set and the page says which of the two
  empties it is.

### Changed

- A finding with no mechanical fix now has something in its action cell: the opt out
  button. It has no Fix this button, which is what the spec says and what the test now
  checks, rather than checking that the cell is empty.

### Notes

- Opened from a `file://` URL the page has an opaque origin and `localStorage` throws
  rather than returning nothing. Every read and write of it is wrapped, and the features
  that would use it fall back to their defaults. This is the normal case for this tool,
  not an edge case, which is why the exceptions register is also a file.

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

- **`handoff.md`, gitignored and deliberately unpublished.** What the next person needs
  before touching anything: the constraints that are defects rather than tradeoffs, the
  build and test commands, the eight confirmed instances of this project's recurring
  failure mode with the instruction to prove every new assertion can fail, the traps that
  have cost real time, and what is genuinely open.

  It is a working document, not a release artifact, so it stays out of the repository and
  out of the release. That split what CI can check. It asserts the policy, that the file
  remains ignored, which holds in a fresh checkout. It asserts the content only where the
  file exists, which is a working tree, and it prints which checks it skipped and why.
  A check that silently examines nothing is the defect this project keeps finding in
  itself, so it does not get to be silent here either.

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

> No `1.1.0` tag exists. This version was never released on its own: its changes shipped inside **`v1.2.0`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

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

> No `1.0.0` tag exists. This version was never released on its own: its changes shipped inside **`v1.2.0`**. The version number was bumped while the work was in progress, and the next tag cut carried it.

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
