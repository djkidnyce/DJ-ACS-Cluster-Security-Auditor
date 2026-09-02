# DJ's ACS Auditor

Audit Kubernetes and OpenShift manifests against Red Hat Advanced Cluster Security policy logic, score and rank every finding, then apply the safe fixes to your YAML with a full preview and an explicit confirmation before anything changes.

**No command is ever run to remediate a finding.** Fixes are made to YAML text in your browser and handed back to you as files. Nothing touches a cluster, nothing calls `oc`, `kubectl` or `roxctl`, and nothing is applied behind your back.

## The two pages

| File | What it is for |
|---|---|
| `dj_acs_auditor.html` | The whole browser surface. Two tabs: **Audit** reads, scores and reports; **Remediate** edits the YAML you loaded with a diff, a confirmation and undo. One mode gate governs both |
| `acs_policies.js` | The policy engine both pages share, so they can never disagree about a manifest |
| `vendor/` | js-yaml and JSZip, committed so the tool needs no package manager and no network |
| `acs_cli.js` + `acs.sh` / `.cmd` / `.ps1` | The same audit, report and fixes from a terminal or a pipeline |
| `scripts/acs_preflight.sh` | Tells you which server you are pointed at and what your token can read |
| `scripts/acs_pull_all.sh` and `.ps1` | Pull every finding ACS has, all severities and states, from outside the browser |
| `scripts/acs_pull_via_oc.sh` | Same, but reaches Central through your existing `oc` session |
| `scripts/acs_pull_over_ssh.ps1` | PowerShell, when only a bastion can reach the cluster |
| `test/run_tests.js` | 929 tests against the real engine, the page, the scripts and the CLI |

Open either HTML file directly. There is nothing to install and no server to run.

## Two ACS data planes, and why an empty alert list proves nothing

**An image CVE is not a policy violation.** It only produces an alert if somebody wrote a policy that fires on it, and most teams have not. A cluster full of critical, actively exploited CVEs can return an empty `/v1/alerts` list. Empty is not clean, it means you asked the wrong endpoint.

| Plane | Endpoint | The catch |
|---|---|---|
| Policy violations | `GET /v1/alerts` | Returns `storage.ListAlert`, a slim projection with **no `violations[]` at all**, and namespace under `commonEntityInfo` rather than `deployment`. Only `GET /v1/alerts/{id}` returns the full alert with violation text. This tool lists, then hydrates. |
| Image vulnerabilities | `GET /v1/export/vuln-mgmt/workloads` | Streams NDJSON, one `{"result": {...}}` per line, so `res.json()` fails on it. The token needs read on **Image and Deployment**, not just Alert, which is the most common reason a CVE pull comes back empty while alerts keep working. |

Shapes verified against the upstream StackRox definitions: `api/v1/alert_service.proto`, `storage/alert.proto`, `api/v1/vuln_mgmt_service.proto`, `storage/image.proto`, `storage/vulnerability.proto`, `storage/cve.proto`. Check them against your own ACS version.

## Where findings come from

Three sources, and you can use any combination.

**Local scan.** Drop in YAML and the engine evaluates it against replicas of twenty ACS default policies. Works with no ACS access at all, which makes it usable in development, in CI, and on a disconnected network.

**Your ACS violations.** Run `scripts/acs_pull_all.sh`, then drop what it writes onto the page. A roxctl JSON report works too. Each violation is matched back to a policy by name, so findings present in both are marked **live in ACS**, which tells you the problem is not theoretical: it exists in a running cluster right now.

**Your ACS vulnerability export.** Same route, then drop the `.ndjson` on the page. Every CVE is ranked, tied back to the manifest and container line that pulls the image, and checked for drift between what git says and what ACS actually scanned.

Drop as many of those files as you like, in any order. They accumulate rather than replace each other, and a violation that arrives twice, once slim from the list endpoint and once hydrated from the detail endpoint, is deduplicated with the hydrated copy kept.

**The pages never connect to anything.** There is no URL field, no token field, and no `fetch` call in either of them. A page opened from a file has a null origin and neither ACS Central nor the OpenShift API sends a header that permits it, so an in browser connector could never have worked. Building one anyway meant asking for a live API token in exchange for a request the browser then blocked. The scripts run where the cluster is actually reachable, keep the token out of shell history and out of `ps`, and verify TLS properly.

## Seeing and fixing violations

Every violation in the export gets a row: severity, score, policy, object, namespace, state, the violation text, and what can be done about it. Severity is what your ACS reported and may be tuned; the score is this tool's own ranking of the weakness class, so sort by it to order work inside a severity band. An unmatched violation shows an em dash rather than a zero, because zero would rank it as harmless rather than as not assessed. Filters cover your workloads against platform components, matched against unmatched, and fixable only. Click a row for the rationale, the standards it maps to, and the reasoning behind the fix route.

The Fix column is the point. A count you cannot act on is not a finding.

| Route | What it means |
|---|---|
| **In your YAML** | The manifest is loaded, so the fix is applied to it directly on the remediation page and you download the corrected file. |
| **Patch** | No manifest for this object, so a strategic merge patch is drafted from the violation itself. |
| **Need manifest** | Fixable in principle, but the violation does not carry enough to draft a patch safely. |
| **Human decision** | The policy has no mechanical fix. Somebody has to decide. |
| **Platform** | A platform component. Listed, never patched. |
| **Not modelled** | No policy in the catalogue matches. Reported rather than dropped. |

Each row has a checkbox. Nothing is selected until you select it, and the draft button stays disabled until something is, for the same reason report mode is the default. The header box takes every fixable violation **currently shown**, which is not the same as everything imported. A violation with no fix route gets a disabled checkbox rather than none, so the absence of an option reads as an answer instead of an oversight. The selection follows the violation, not the row, so filtering and sorting do not move your ticks.

Drafted fixes are YAML files and nothing else. No command is run and no cluster is touched, on any surface, in any mode. Each file carries a header naming the object, the namespace, the policies it covers, and the fact that it was built from a violation rather than from a manifest and therefore needs verifying. Test it against a namespace you do not care about, then apply it yourself.

### Platform components

Violations on platform components are listed and refused by default, because the owning operator reverts manual edits and the resulting drift is harder to find than the original finding.

But that classification is not always ACS's. When ACS does not send `platformComponent`, the tool falls back to matching the namespace, and that guess is wrong in both directions: your own workload in `openshift-operators` gets refused forever, and the operator never sees the fix because the tool decided on their behalf that it was not theirs.

So the tool now says which signal decided, `ACS said so` or `guessed from namespace`, and every refusal carries an **override**. Overriding a guess applies the normal fix routes. Overriding something ACS itself flagged asks for confirmation first. It is per object, never global, it does not bypass the mode gate, and the drafted YAML says on its face that it was overridden and that an operator may revert it.

From the CLI: `--override-platform Deployment/cert-manager-webhook`.

Violations on platform components are never patched without that explicit override. The owning operator reverts manual edits, so a patch there changes nothing except how hard the drift is to find. Raise a policy exception with an expiry, change the cluster configuration through the supported path, or open a case with Red Hat.

From the CLI:

```bash
# the default: an account of what could be fixed, and no YAML at all
node acs_cli.js --alerts 02_alerts_full.json --violation-fixes

# the YAML itself, for everything
node acs_cli.js --alerts 02_alerts_full.json --violation-fixes --mode manual --out fixes

# see what is there, then act on a subset
node acs_cli.js --alerts 02_alerts_full.json --list-violations
node acs_cli.js --alerts 02_alerts_full.json --violation-fixes --mode manual \
  --select Deployment/payments-api,ACS.004 --out fixes
```

`--select` takes an alert id, an object name, or a policy id. A term that matches nothing exits non zero and writes nothing, rather than warning and continuing: a typo in a narrowing option does not narrow less, it fails to narrow at all, and a run you believed was scoped to one Deployment would quietly cover the cluster. Omitting `--select` still means everything, which is how it behaved before the option existed.

The written account records the scope. If you drafted fixes for four violations out of thirty it says so at the top and states that the other twenty six are not described anywhere in it, because a report covering a subset otherwise reads identically to one covering the whole cluster.

## Vulnerabilities

Severity uses the Red Hat scale, kept verbally distinct from policy severity so nobody conflates an **Important** CVE with a **High** policy violation: Critical, Important, Moderate, Low.

Priority runs **0 to 15**, not 0 to 10. Clamping to 10 lands every critical on exactly 10 and destroys the ordering at the top of the queue, which is the only place ordering matters. It is CVSS plus named, bounded adjustments:

| Signal | Adds |
|---|---|
| On the CISA KEV catalog | 2.0 |
| EPSS 50% or higher | 1.5 |
| EPSS 10 to 50% | 0.7 |
| A fix is published | 1.0 |
| Pods running the image | 0.5 |

Every adjustment is listed in the UI next to the row. A ranking nobody can audit is a ranking nobody should trust, including this one. It is not a CVSS score and should not be quoted as one.

**There is no auto fix for a CVE, deliberately.** ACS reports that a package is fixed in version X. It cannot tell you which image tag ships version X, because only your build knows that. Deriving one from the other means guessing, and a wrong guess points a production Deployment at a tag that does not exist or that clears the CVE and breaks the app. What you get instead: a rebuild worklist grouped by image (you rebuild once and every fixable CVE inside clears together), the file and container that declares it, git against cluster drift, and a **Replace this image** action that applies a reference *you* supply through the same preview, confirm and undo as every other fix.

CVE data is kept **out of the posture score**. The configuration posture has a fixed denominator derived from what was scanned, which is what makes before and after comparable. CVE counts move every time a feed updates with nothing in your manifests changing. Folding them together would produce a score that moves for reasons you did not cause and cannot act on.

## Report, manual, or auto. You choose, every time.

Three modes, and the tool never picks one for you.

| Mode | Produces | Modifies anything |
|---|---|---|
| `report` | The analysis. Report, JSON, SARIF. **Nothing that could be applied.** | No |
| `manual` | Patches and written guidance for a human to review and apply | No |
| `auto` | Applies the safe fixes and writes corrected YAML | Yes, with preview and confirmation |

**`report` is the default on every surface.** The safe state is the one you get by doing
nothing, not the one you get by remembering a flag.

**The mode is never inferred.** Asking for `--patches` does not put you in manual mode.
You choose the mode, then ask for the output. Asking for something applyable while in
report mode is refused with an explanation rather than silently upgraded or downgraded:

```
--patches produce material that can be applied, and this run is in
report mode, which by definition produces none.

Choose the path you actually want:
  --mode manual   patches and guidance, nothing modified
  --mode auto     apply the safe fixes

Refusing rather than picking one for you. An auto fix nobody selected is a
new risk, not a mitigation.
```

**An unknown mode is an error**, never a silent fall back to something permissive.
`--mode atuo` exits 2.

**The mode is recorded in every artifact.** A reviewer holding a patch should not have to
ask which path produced it. Manual mode writes `PROPOSED_CHANGES.md`; auto writes
`CHANGES.md`. Both carry a `Mode:` line.

### Why this is a security control and not a convenience

A remediation tool that can write before the operator has chosen to write is a new risk,
not a mitigation. The failure mode is not the tool doing something malicious. It is
someone at the end of a long incident clicking the obvious button, producing a change to
a production manifest they did not intend, and then defending it in review with a
plausible looking diff attached.

So on the remediation page the mode gates the buttons **and** the handlers. Calling
`startStepping()` or `reviewApplyAll()` directly from the console in report mode still
refuses: a disabled attribute is a UI hint, not a control. Apply-all is reachable only in
auto, because manual means looking at each change. Skipping the confirmation prompt is
offered only in auto, and switching back to report clears it, so a mode change cannot
leave a permissive setting behind.

## Command line

Same engine, same policy set, same report. Nothing is reimplemented, so the CLI and the
pages cannot disagree about a manifest.

```bash
# report only, the default
node acs_cli.js --path ./manifests

# the full picture: report, findings JSON, CVE worklist
node acs_cli.js --path ./manifests \
  --alerts acs_alerts_full.json --vulns acs_vulns.ndjson \
  --report --json --worklist

# manual: patches for a human to apply, nothing modified
node acs_cli.js --path ./manifests --mode manual --patches --out ./proposed

# auto: apply the safe fixes to a copy
node acs_cli.js --path ./manifests --mode auto --patches --out ./remediated

# CI gate, SARIF into the security tab
node acs_cli.js --path ./manifests --sarif --fail-on high
```

Wrappers for each shell: `./acs.sh`, `acs.cmd`, `.\acs.ps1`. Identical switches.

**Report until you say otherwise.** `--mode auto` writes to `--out`, never over your
sources. `--in-place` is auto only and refuses outside a clean git tree, because without
version control there is no undo. `--fix` still works as an alias for `--mode auto` and
warns, so old scripts do not break silently. `--fail-on` defaults to `none`: start there, work the backlog
down, then tighten. A gate that blocks every merge on day one gets switched off inside a
week, and a switched off gate leaves you worse off than before you installed it.

## Auditing what is actually running

Point the tool at a cluster export and it scans what is deployed rather than what git says
should be deployed. Those two drift, and the gap is frequently where the finding lives.

```sh
oc get deployment,daemonset,statefulset,cronjob,job --all-namespaces -o json > workloads.json
```

`scripts/acs_pull_all.sh` runs that same command as its last step and drops
`workloads.json` into the timestamped run directory beside the ACS findings, so the
violations and the objects they are about come from the same moment. Run the script, make
your changes, run it again, and the two directories diff cleanly. If `oc` is missing or
cannot reach the cluster the run still succeeds and prints the command to run elsewhere.

Drop `workloads.json` on the page, or:

```sh
node acs_cli.js --workloads workloads.json --report
```

JSON and YAML both work, as does a `List` wrapper, a single object, or a file of
concatenated objects from a shell loop. Server side fields are stripped on load
(`status`, `managedFields`, `uid`, `resourceVersion`, `ownerReferences`, the
last applied configuration annotation), so what you scan is what you could commit.

## Can I use oc for this?

Not for the findings. `oc` talks to the Kubernetes API server and ACS findings are not
Kubernetes objects. There is no CRD holding CVEs, and `oc get central -o yaml` returns
install configuration, never a finding.

`oc` is how you reach Central though, and `scripts/acs_pull_via_oc.sh` automates it:
locate the namespace, use the route or fall back to `oc port-forward`, pull the CA out of
the `central-tls` secret so verification actually works, authenticate, and fetch. Note
`oc whoami -t` is an OpenShift token and ACS will reject it; use an ACS API token or
`--admin` to read `central-htpasswd`.

## Pulling everything from the API

There is no single ACS endpoint that returns all findings. `scripts/acs_pull_all.sh`
(and the PowerShell equivalent) sweeps all of them: alerts paged and hydrated, image
CVEs for running workloads, image CVEs for images with no running workload, node CVEs,
and the snoozed CVEs the default views hide.

```bash
export ROX_ENDPOINT=https://central-stackrox.apps.example.com
export ROX_API_TOKEN=<token>
./scripts/acs_pull_all.sh -o findings
```

Everything is achieved by leaving filters out rather than adding them: no severity
term, no `Violation State` term, no `Lifecycle Stage` term. Omitting a term returns
every value for it, and it does not go stale when ACS adds a new one. See
`scripts/README.md`.

## The cross check

The cross check earns its keep in both directions. A finding in the manifest but not in ACS may be in a namespace ACS does not cover, or excluded by a policy exception. A violation in ACS but not in your manifests means either the manifest is not in the set you loaded or the cluster has drifted from git, and drift is worth knowing about on its own.

Violations that cannot map to a manifest, runtime policies in particular, are reported separately rather than quietly dropped. A scanner that discards what it does not understand is indistinguishable from a scanner that found nothing.

## Applying fixes

Three ways to work, all on the remediation page.

**Step through one by one.** The most careful option. It shows one fix at a time with the policy, why it matters, exactly what will change as a diff, and the standards behind it. Apply and continue, skip this one, or stop here. A progress bar tracks how far through you are.

**Review and apply all.** Previews the entire batch as a combined diff, grouped by file, with a summary of every change. One confirmation applies the lot.

**Fix this, per row.** Each auto fixable finding has its own button in the findings table, with the same confirm dialog.

Every route shows a real diff computed against your actual file, not a description of what might happen. There is a checkbox to skip the confirmation once you trust it, off by default.

**Undo** works one step at a time or all the way back to how the files were loaded. Verified byte for byte by the test suite.

## What gets fixed, and what deliberately does not

Fixes are classified, and the classification is the most important judgment in the tool.

**Auto** describes the edit, not your application. It means the change to the YAML is unambiguous: there is one correct value and the tool knows it. It does **not** mean the workload will survive the change.

Four of them can stop a workload that was relying on what gets removed: `readOnlyRootFilesystem` on anything that writes to disk, dropping all capabilities from an image that needs one, `runAsNonRoot` against an image with no numeric non-root user, and unmounting the service account token from a pod that calls the Kubernetes API. Each carries a specific note naming the failure and the remedy, and it appears in the confirmation dialog, the change log, the drafted patch header, the CLI output and the report. Test them in a namespace you do not care about first.

Auto covers: `privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, host namespaces, capabilities, `runAsNonRoot`, resource requests and limits, `automountServiceAccountToken`, host ports, and rewriting a hardcoded credential to a `secretKeyRef`.

**Generate** creates a new object rather than editing one, currently the default deny NetworkPolicy with DNS egress already allowed.

**Manual** means the right answer depends on context the scanner cannot see, so it is explained and left alone. Pinning an image digest needs to know which build is blessed. Removing a `hostPath` needs a storage decision. Replacing the default service account needs the replacement to exist first. Guessing at these breaks working systems, and a security tool that breaks production gets switched off, which leaves you less secure than before it was installed.

Two fixes insert placeholder resource values. They are flagged as PLACEHOLDER in the confirmation dialog and in the change log, and they need tuning to your workload before deploy. The secret rewrite is flagged too, because it cannot un-leak a credential that is already in git history: rotate it.

## Taking the result

* **Patched YAML as a ZIP**, preserving your folder structure, with a change log
* **One combined YAML file**, if you prefer
* **Strategic merge patches**, one per applied fix, for manifests templated by Helm or Kustomize that cannot be edited directly. Each patch carries only the changed fields, keyed on the container name the way Kubernetes merges those arrays, so it will not clobber a field that drifted since the scan
* **The full diff**, copied to the clipboard
* **A change log** in markdown recording every change, why it was made, and the standards behind it, plus everything still needing a human decision

## Working through a large finding list

A first run against a real cluster returns findings in the hundreds or thousands. A flat
list that long is not a work queue, so the findings table filters and the rows are
selectable.

Filter by severity, by fix kind (auto, generate, manual, already applied), by weakness
class, or by ACS policy. The class and policy pickers are built from what was actually
found rather than from the whole catalogue, so an empty option never appears. Taking
privilege escalation on its own is the class filter set to Privileges; taking the top of
the list is Critical and High with everything else unticked.

The header count says what is behind a collapsed section and what a filter is hiding:
`showing 84 of 1104, 1104 open, 40 critical`. That matters more than the collapsing does.
A narrowed list looks like a shorter one, and a shorter one reads as a cleaner cluster.

Selection is held per finding, not per row, so filtering and sorting never move a tick
onto something else. `Select all shown` takes every fixable finding currently visible,
which is not the same as everything loaded. A finding with no mechanical fix gets a
disabled checkbox naming the reason, so the absence of an option reads as an answer
rather than an oversight.

## Getting corrected YAML out of the browser

The scan runs on a Linux box, the files get copied to a Windows machine, and the review
happens there. Neither end has Node and neither can be given it. So the browser is not a
preview of the fix, it is what produces it.

Tick what you want, choose Manual or Auto, and press **Download corrected YAML**. You get
a ZIP holding `corrected/` with your manifests rewritten in the folder layout you loaded
them in, plus `READ_THIS_FIRST.md` recording every change applied, every fix that can stop
a workload, every placeholder value that still needs tuning, and anything that could not be
applied and why.

The export runs against a copy. Nothing in the page moves, the undo history is untouched,
and you can export one severity band, review it, then export another without the two
interfering.

Exporting is not applying. No command runs, from the browser or anywhere else, and nothing
in the ZIP touches a cluster until you put it there through your own change process:

```sh
oc apply -f corrected/ --dry-run=server   # see what the API server would do
oc apply -f corrected/                    # or commit them and let your pipeline do it
```

The server side dry run is worth the extra step. It catches an admission controller
rejecting the change before you find out during a rollout.

In `report` mode the export controls are disabled, and the page says which control is
holding them rather than leaving a grey button that reads like a bug.

## Scoring

Every finding carries the ACS severity, a CVSS v3.1 style score for ranking, and citations to CIS Kubernetes Benchmark, NIST SP 800-53 Rev 5, Pod Security Standards and DISA STIG.

Posture is a weighted compliance rate. Every applicable policy and object pair is one check, weighted Critical 18, High 10, Medium 5, Low 2. Your score is the percentage of that total weight you pass. Grades: A at 90, B at 80, C at 70, D at 60, F below.

The denominator is derived only from what was scanned, never from what was found. That is what makes the current and projected numbers comparable: a check that starts passing has to stay in the total rather than disappearing from it, otherwise the projection would not survive a rescan.

## Accuracy and limits

Policy names, severities and remediation text are modelled on the ACS defaults, with the structure verified against the [upstream StackRox definitions](https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files). **Check them against your own ACS version.** Defaults shift between releases and most teams tune them, which is why the importer falls back through exact match, a table of known naming variants, then token scoring, rather than dropping a violation it does not recognise.

This is static analysis of manifest text plus whatever ACS hands you. It does no vulnerability scanning of its own: if ACS has not scanned an image, this tool has nothing to say about it and says so rather than showing a reassuring zero. It does not query a cluster, and it is not a replacement for ACS, for admission control such as Pod Security Admission or Kyverno, or for runtime enforcement. ACS policies that evaluate image CVEs, build metadata or runtime process behaviour cannot be judged from YAML at all.

STIG references are mapping aids. Verify them against the current DISA release before citing them in an accreditation package.

## What needs what

Nothing in the audit path needs a package manager, and the part most people actually use needs no runtime at all.

| To do this | You need | Node? |
|---|---|---|
| Read, score, cross check, see violations, draft fixes | A browser. Open `dj_acs_auditor.html` from disk | **No** |
| Apply fixes with preview, confirm and undo | A browser. Open `dj_acs_auditor.html` from disk | **No** |
| Pull data out of ACS | `bash`, `curl`, `jq` | **No** |
| Pull via an `oc` port forward | The above plus `oc` | **No** |
| Pull from PowerShell or over SSH | PowerShell 5.1 or newer, no extra modules | **No** |
| Summarise a pull from the shell | `bash`, `jq` | **No** |
| Run the same audit headless, in a pipeline | `acs_cli.js` | Yes, Node 18+, or a container |
| Run the test suite | `test/run_tests.js` | Yes, Node 18+ |
| Rebuild the Word guides and figures | `docs/` generators | Yes, plus Python |

The page loads `vendor/js-yaml.min.js` and `vendor/jszip.min.js` with plain `<script src>` tags from the folder it sits in. No server, no build step, no install.

### If Node cannot be installed at all

This is the normal case on a hardened host in a controlled enclave, so it is a supported path rather than a caveat.

| What you need | How to get it without Node |
|---|---|
| Pull data out of ACS | `scripts/acs_pull_all.sh`. bash, curl and jq |
| Posture score, violations, fix routes, drafted YAML, the full HTML report | `dj_acs_auditor.html`. A browser, nothing else. Open the file |
| Corrected YAML for the findings you chose, as a ZIP | `dj_acs_auditor.html`, Remediate tab, Download corrected YAML |
| A summary you can read or hand over from the shell | `scripts/acs_summary.sh <pull-dir> -o findings.md`. jq only |
| The headless CLI, for CI | A container: `podman run --rm -v "$PWD":/w:Z -w /w docker.io/library/node:20-alpine node acs_cli.js --help` |

`acs_pull_all.sh` runs this for you at the end of every pull, writing `findings.md` into the run directory and printing it. `--no-summary` turns that off.

`acs_summary.sh` counts what ACS reported: violations by severity, policy and namespace, the split between your workloads and platform components, which violations arrived with no `platformComponent` field at all, CVEs by Red Hat severity, how many are actually fixable, how many are on the CISA Known Exploited Vulnerabilities catalog, the images to rebuild ranked by worst CVSS, and the highest scoring CVEs with the version each is fixed in.

It reports CVSS, which is the score ACS supplied. It does not reproduce the tool's own 0 to 15 priority ranking, which additionally weighs the CISA catalog, EPSS, fixability and whether pods are running the image: that model lives in the engine, and a second ranking in jq would drift from it. It does not produce a posture score and does not draft fixes, and it says so in its own output. Both need the policy engine, and the engine needs the page or the CLI. A summary that implied a score it had not computed would be the same defect as scoring an empty scan.

The wrapper scripts (`acs.sh`, `acs.ps1`, `acs.cmd`) detect a missing Node and print these routes rather than failing with `command not found`. Run `./acs.sh` rather than `node acs_cli.js` and you get the routes instead of a bare `bash: node: command not found`.

Nothing in the browser path is degraded. Every fix the CLI can write, the page can write, and the corrected YAML the page exports is produced by the same engine file the CLI loads. The CLI exists for headless CI, not for capability.

## Central's certificate is self signed, and that is normal

The RHACS operator installs a self signed certificate for Central. Your system trust store will never verify it, so `curl (60) SSL certificate problem` on the first run is the expected outcome, not a misconfiguration.

`--insecure` is not the answer. That request carries a token that reads your entire security posture, and disabling verification hands it to anyone on the path. The script does not offer it as a shortcut.

Run the pull and it works out the best available route by itself, in this order:

1. **A CA you supplied**, via `--cacert` or `ROX_CA`. You decided where it came from.
2. **The `central-tls` secret, read through your `oc` session.** The cluster tells us its own CA over a connection `oc` already verified. If `oc` is logged in this usually just works, and the CA is saved for next time.
3. **Nothing automatic worked**, so it stops and shows you the certificate's issuer and SHA-256 fingerprint, plus two commands that will work.

Confirm that fingerprint against the cluster through some channel other than the connection you are trying to trust. That confirmation is the entire security of what follows.

```bash
# A: verify against the certificate itself. A self signed certificate is its own
# issuer, so it works as a CA bundle. Full verification, hostname check included.
./scripts/acs_pull_all.sh --cacert findings/central-cert.pem -o findings

# B: pin the public key. Works even when the hostname does not match the
# certificate, which is common through a port forward.
./scripts/acs_pull_all.sh --pin 'sha256//<the hash it printed>' -o findings
```

A is better where it works, because it keeps hostname verification. The script tests A against your endpoint before recommending it, so it only offers it when it actually works.

B turns the chain check off and requires that exact public key instead. `--pinnedpubkey` on its own cannot help here: it is an additional check rather than a replacement, so curl rejects a self signed certificate before it ever looks at the pin. The pin is enforced, and a wrong key fails closed with `curl (90)`.

A failed run leaves no findings directory. If TLS never resolved there is nothing to keep, and if the token was rejected the directory is marked `RUN_FAILED.txt` so it cannot be mistaken for a pull that came back clean.

## When the pull script fails on TLS

`curl (60) SSL certificate problem: self-signed certificate in certificate chain` means Central sits behind a route whose certificate is signed by a CA your machine has no reason to trust. On OpenShift that is usually the cluster's own ingress CA, which signs the wildcard for `.apps`.

Do not reach for `--insecure`. That request carries a token that reads your entire security posture, and disabling verification hands it to anyone on the path.

Get the CA over a channel you already trust, which is your authenticated `oc` session rather than the handshake that just failed:

```bash
# see which CA is actually presenting
openssl s_client -connect central.apps.example.com:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates

# usual case: Central behind an .apps route signed by the cluster ingress CA
oc -n openshift-config-managed get configmap default-ingress-cert \
  -o jsonpath='{.data.ca-bundle\.crt}' > ~/ocp-ingress-ca.pem

# OpenShift older than 4.8, where default-ingress-cert does not exist yet
oc -n openshift-ingress-operator get secret router-ca \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > ~/ocp-ingress-ca.pem

# passthrough route, Central presenting its own certificate
oc -n stackrox get secret central-tls \
  -o jsonpath='{.data.ca\.pem}' | base64 -d > ~/central-ca.pem
```

Then set it once. Both scripts read `ROX_CA`, and `acs_pull_all.sh` also takes `--cacert`:

```bash
export ROX_CA=~/ocp-ingress-ca.pem
./scripts/acs_preflight.sh https://central.apps.example.com
./scripts/acs_pull_all.sh -o findings
```

The ingress operator publishes its default certificate as the `default-ingress-cert` ConfigMap in `openshift-config-managed` on OpenShift 4.8 and newer; it superseded `router-ca` ([OpenShift enhancement](https://github.com/openshift/enhancements/blob/master/enhancements/ingress/default-ingress-cert-configmap.md), [certificate types](https://docs.redhat.com/en/documentation/openshift_container_platform/4.8/html/security_and_compliance/certificate-types-and-descriptions)).

If your organisation already publishes a CA bundle, use that instead of extracting one. A bundle from your PKI team is a better answer than a bundle from the cluster you are auditing.

Both scripts now detect this failure and print these commands rather than the word `--cacert`. A CA path that does not exist is refused with a non zero exit rather than quietly falling back to no verification.

## Coverage, stated as a number

This tool models **twenty** policies. Red Hat ACS ships roughly seventy defaults, and most teams add their own. So a clean posture score here means clean against twenty checks, not compliant with the ACS default policy set, and it should never be quoted as the latter.

What the twenty cover: the Deploy stage configuration weaknesses that are visible in a manifest and mechanically checkable. Privilege, host namespaces, capabilities, root, resource limits, service account tokens, host ports, secrets in environment variables, and a default deny NetworkPolicy.

What they do not, and cannot:

| Not covered | Why |
|---|---|
| Build stage policies, image provenance, signature and registry rules | Nothing in a manifest tells you where the image was built or by whom |
| Runtime policies: process execution, network baselines, file integrity | These describe behaviour of a running container, not declared state |
| Image CVE policies | CVEs come from the ACS vulnerability export and are reported separately; they are deliberately kept out of the posture score |
| Your own tuned or custom policies | This tool does not know they exist. They arrive through the ACS export and are shown as **unmatched** rather than dropped |

A violation this tool cannot match to a policy appears in the violations table under its own filter, with the fix route `Not modelled`. That is the honest answer, and it is why the unmatched count is worth watching after an ACS upgrade: a jump in it means the catalogue has drifted from your ACS version.

**Use this alongside ACS, not instead of it.** ACS sees the cluster, the build pipeline and the runtime. This sees the manifest, and fixes it.

## The posture score, and when there isn't one

The denominator comes from what was scanned, never from what was found. That is what makes the projected score comparable to a real rescan.

It also means scoring zero manifests returns 100 out of 100, Grade A. That is arithmetically correct and completely misleading: nothing was scanned, so nothing was found. If you load an ACS export and no YAML, both pages and the CLI refuse to show a number and say why. Unmeasured is not the same as clean, and a green A on a cluster you have not looked at is the worst output a security tool can give you.

Your violations and CVEs are fully usable without a score.

## Tests

```bash
node test/run_tests.js

# optional: the whole page tests need jsdom, and skip cleanly without it
npm install jsdom && node test/run_tests.js
```

775 engine, CLI and script tests, no install required, plus 154 whole page tests that need jsdom and skip without it. 929 in total. Suites that need something the machine lacks say what is missing rather than skipping silently.

They cover the policy catalogue, scanning and scoring, fix application and YAML validity, diff correctness, merge patch minimality, ACS import across every export shape the pull script writes plus renamed policy matching, the full remediation flow including that preview mutates nothing and undo restores byte for byte, and the vulnerability path end to end: NDJSON parsing, CVE deduplication, priority reasoning, manifest correlation and drift.

Four of them fail against the pre fix alert entity resolution and pass against the current one, which is the evidence that the ListAlert bug is actually fixed rather than merely reported as fixed.

`test/exports.cjs` loads all six files `acs_pull_all.sh` writes and asserts each is understood, that dropping several merges rather than overwrites, that merging the same file twice changes nothing, and that a file which cannot be loaded is told what it is rather than what it is not.

`test/cli_violations.cjs` runs the CLI as a real process and inspects what lands on disk. The strongest assertion in it is the negative one: report mode leaves nothing behind that anyone could apply.

`test/page.cjs` loads each HTML file in a real DOM and drives it. It catches what engine tests structurally cannot: an element id that does not exist, a handler never bound, a panel that never unhides. The violation fix button shipped once with no click handler at all, which is exactly that shape of defect. It needs jsdom, so it is optional and skips rather than fails.

## Security

The tool has been reviewed against itself. Findings, and what was done:

| Finding | Status |
|---|---|
| CVE links from an ACS export reached an `href` with no scheme check, so `javascript:` and `data:` executed in a page holding a live token | **Fixed.** `safeUrl` allowlists http and https, everything else renders as inert text. 19 cases in `test/hardening.cjs`. |
| Generated commands used `curl -sk`, teaching operators to disable TLS verification on a request carrying a bearer token | **Fixed.** Verification on by default, `--cacert` guidance shown, insecure is opt in and warns. |
| Token clearing sat inside `try`, so it was skipped on failure, and failure is the common path with CORS | **Superseded.** The in browser connectors were removed entirely, so there is no longer a token to clear. |
| The browser asked for a live ACS API token in exchange for a request the browser then blocked | **Fixed by removal.** A page opened from a file has a null origin and neither ACS Central nor the OpenShift API sends a header that permits it, so the feature could never work from there. The risk was real and the benefit was zero. Use `scripts/acs_pull_all.sh`, which runs where the cluster is reachable, keeps the token out of shell history and out of `ps`, and verifies TLS. |
| No CSP on the page or the generated report | **Proposed**, see `docs/PROPOSAL_page_hardening.md`. |
| CDN fallback with no SRI, which also contradicts the offline claim | **Proposed**, same document. Recommendation is to fail closed. |

Every fix has a regression test that was confirmed to fail against the pre fix code.

Standing guarantees, asserted on every run: no `exec`, `eval` or `Function` constructor in
any shipped file; no token in browser storage; no password field, no token identifier and
no `fetch` call anywhere in either page; GET only, no write method to any cluster; and
nothing in the remediation path runs a command, on any surface, in any mode.

One process is spawned anywhere in the tool, and it is worth naming rather than leaving the
guarantee looking broader than it is. `--in-place --mode auto` runs `git status --porcelain`
via `execFileSync` with an argument array and no shell, in the directory you pointed at, and
refuses to overwrite your files if the tree is dirty or is not a repository. It reads. It
remediates nothing. Everything else the tool produces is a file.

## Verifying a download

Releases carry checksums and a signed build provenance attestation, so you do not have to
take the archive on trust:

```bash
sha256sum -c SHA256SUMS
gh attestation verify dj-acs-auditor-1.4.0.zip \
  --repo djkidnyce/DJ-ACS-Cluster-Security-Auditor
```

That proves those bytes came from this repository's release workflow, at that commit. It
does not prove the tool is correct. A verified signature on bad software is still bad
software, and the two claims are worth keeping apart.

`sbom.cdx.json` lists the whole dependency surface, which is two libraries:

| Component | Version | Licence | Why |
|---|---|---|---|
| js-yaml | 4.1.0 | MIT | YAML parsing, shared by every surface so they cannot disagree |
| JSZip | 3.10.1 | MIT or GPL-3.0 | Builds the ZIP of patched YAML in the browser |

Both are committed to the repository and verified by hash in CI. Nothing is fetched at
build or run time, which is why this works on a disconnected network. The SBOM is generated
from the bytes on disk by `scripts/make_sbom.js`, so it cannot describe a dependency that
is not there, and it refuses to run if `vendor/` gains a file it does not recognise.

## The Word guides are built, not committed

They are generated from `docs/doc1.js` and `docs/doc2.js` and attached to each release.
Committing them meant a documentation change arrived as `Bin 1128727 -> 1129347 bytes`,
which nobody can review, and the repository carried both the source and the output of the
same thing.

To read them without waiting for a release:

```bash
npm install --no-save docx
node docs/doc1.js && node docs/doc2.js
```

CI builds them on every push, so a broken generator is caught then rather than at release
time.

## Releasing

Every change that ships gets a version and a tag. Semantic versioning, where the public
interface is the CLI flags, the exit codes, the JSON and SARIF shapes, and the policy ids.

The version lives in exactly one place, `ACS_VERSION` in `acs_policies.js`. The banner, the
HTML report, the findings JSON, the SARIF run and every drafted patch header derive from
it, and `test/version.cjs` fails the build if it disagrees with the newest CHANGELOG
heading or with the git tag on a tagged commit. A report whose version does not match a tag
cannot be used as evidence, because you cannot tell which build produced it.

See [RELEASING.md](RELEASING.md) for the procedure.

## Documentation

| Document | For |
|---|---|
| `docs/DJ_ACS_Auditor_User_Guide.docx` | Operators. How to scan, connect to a live cluster, apply fixes, and export. Illustrated. |
| `docs/DJ_Security_Tooling_Administration_Guide.docx` | Maintainers. Architecture, tests, adding policies, vendoring, exceptions, CI, release. |

Figures are generated from source: `python3 docs/make_figures.py` and `python3 docs/make_admin_figures.py`.
The documents are built with `node docs/doc1.js` and `node docs/doc2.js`.

## Contact

Questions, bugs, or policy suggestions: **[github.com/djkidnyce](https://github.com/djkidnyce)**

Built by DJ.
