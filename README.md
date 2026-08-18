# DJ's ACS Auditor

Audit Kubernetes and OpenShift manifests against Red Hat Advanced Cluster Security policy logic, score and rank every finding, then apply the safe fixes to your YAML with a full preview and an explicit confirmation before anything changes.

**No command is ever run to remediate a finding.** Fixes are made to YAML text in your browser and handed back to you as files. Nothing touches a cluster, nothing calls `oc`, `kubectl` or `roxctl`, and nothing is applied behind your back.

## The two pages

| File | What it is for |
|---|---|
| `dj_acs_auditor.html` | Scan, score, rank, cross check against ACS violations and image CVEs, export the report. Read only, it never modifies anything |
| `dj_acs_remediation.html` | Apply fixes interactively, with preview, confirmation, one at a time stepping, and undo |
| `acs_policies.js` | The policy engine both pages share, so they can never disagree about a manifest |
| `vendor/` | js-yaml and JSZip, committed so the tool needs no package manager and no network |
| `acs_cli.js` + `acs.sh` / `.cmd` / `.ps1` | The same audit, report and fixes from a terminal or a pipeline |
| `scripts/acs_preflight.sh` | Tells you which server you are pointed at and what your token can read |
| `scripts/acs_pull_all.sh` and `.ps1` | Pull every finding ACS has, all severities and states, from outside the browser |
| `scripts/acs_pull_via_oc.sh` | Same, but reaches Central through your existing `oc` session |
| `scripts/acs_pull_over_ssh.ps1` | PowerShell, when only a bastion can reach the cluster |
| `test/run_tests.js` | 531 tests against the real engine, pages and CLI |

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

**Local scan.** Drop in YAML and the engine evaluates it against replicas of the ACS default Deploy stage policies. Works with no ACS access at all, which makes it usable in development, in CI, and on a disconnected network.

**Your ACS violations.** Pull live from Central, or drop in an export or a roxctl JSON report alongside the YAML. Each violation is matched back to a policy by name, so findings present in both are marked **live in ACS**, which tells you the problem is not theoretical: it exists in a running cluster right now.

**Your ACS vulnerability export.** Pull live, or drop the `.ndjson` on the page. Every CVE is ranked, tied back to the manifest and container line that pulls the image, and checked for drift between what git says and what ACS actually scanned.

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

Drop `workloads.json` on either page, or:

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

**Auto** means one correct change with no plausible downside: `privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, host namespaces, capabilities, `runAsNonRoot`, resource requests and limits, `automountServiceAccountToken`, host ports, and rewriting a hardcoded credential to a `secretKeyRef`.

**Generate** creates a new object rather than editing one, currently the default deny NetworkPolicy with DNS egress already allowed.

**Manual** means the right answer depends on context the scanner cannot see, so it is explained and left alone. Pinning an image digest needs to know which build is blessed. Removing a `hostPath` needs a storage decision. Replacing the default service account needs the replacement to exist first. Guessing at these breaks working systems, and a security tool that breaks production gets switched off, which leaves you less secure than before it was installed.

Two fixes insert placeholder resource values. They are flagged as PLACEHOLDER in the confirmation dialog and in the change log, and they need tuning to your workload before deploy. The secret rewrite is flagged too, because it cannot un-leak a credential that is already in git history: rotate it.

## Taking the result

* **Patched YAML as a ZIP**, preserving your folder structure, with a change log
* **One combined YAML file**, if you prefer
* **Strategic merge patches**, one per applied fix, for manifests templated by Helm or Kustomize that cannot be edited directly. Each patch carries only the changed fields, keyed on the container name the way Kubernetes merges those arrays, so it will not clobber a field that drifted since the scan
* **The full diff**, copied to the clipboard
* **A change log** in markdown recording every change, why it was made, and the standards behind it, plus everything still needing a human decision

## Scoring

Every finding carries the ACS severity, a CVSS v3.1 style score for ranking, and citations to CIS Kubernetes Benchmark, NIST SP 800-53 Rev 5, Pod Security Standards and DISA STIG.

Posture is a weighted compliance rate. Every applicable policy and object pair is one check, weighted Critical 18, High 10, Medium 5, Low 2. Your score is the percentage of that total weight you pass. Grades: A at 90, B at 80, C at 70, D at 60, F below.

The denominator is derived only from what was scanned, never from what was found. That is what makes the current and projected numbers comparable: a check that starts passing has to stay in the total rather than disappearing from it, otherwise the projection would not survive a rescan.

## Accuracy and limits

Policy names, severities and remediation text are modelled on the ACS defaults, with the structure verified against the [upstream StackRox definitions](https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files). **Check them against your own ACS version.** Defaults shift between releases and most teams tune them, which is why the importer falls back through exact match, a table of known naming variants, then token scoring, rather than dropping a violation it does not recognise.

This is static analysis of manifest text plus whatever ACS hands you. It does no vulnerability scanning of its own: if ACS has not scanned an image, this tool has nothing to say about it and says so rather than showing a reassuring zero. It does not query a cluster, and it is not a replacement for ACS, for admission control such as Pod Security Admission or Kyverno, or for runtime enforcement. ACS policies that evaluate image CVEs, build metadata or runtime process behaviour cannot be judged from YAML at all.

STIG references are mapping aids. Verify them against the current DISA release before citing them in an accreditation package.

## Tests

```bash
node test/run_tests.js

# optional: the whole page tests need jsdom, and skip cleanly without it
npm install jsdom && node test/run_tests.js
```

247 engine tests, no install required, plus 33 whole page tests that need jsdom and skip without it. 280 in total. They cover the policy catalogue, scanning and scoring, fix application and YAML validity, diff correctness, merge patch minimality, ACS import across all three export shapes plus renamed policy matching, the full remediation flow including that preview mutates nothing and undo restores byte for byte, and the vulnerability path end to end: NDJSON parsing, CVE deduplication, priority reasoning, manifest correlation and drift.

Four of them fail against the pre fix alert entity resolution and pass against the current one, which is the evidence that the ListAlert bug is actually fixed rather than merely reported as fixed.

`test/page.cjs` adds 33 more that load each HTML file in a real DOM and drive it. They catch what engine tests structurally cannot: an element id that does not exist, a handler never bound, a panel that never unhides. It needs jsdom, so it is optional and skips rather than fails.

## Security

The tool has been reviewed against itself. Findings, and what was done:

| Finding | Status |
|---|---|
| CVE links from an ACS export reached an `href` with no scheme check, so `javascript:` and `data:` executed in a page holding a live token | **Fixed.** `safeUrl` allowlists http and https, everything else renders as inert text. 19 cases in `test/hardening.cjs`. |
| Generated commands used `curl -sk`, teaching operators to disable TLS verification on a request carrying a bearer token | **Fixed.** Verification on by default, `--cacert` guidance shown, insecure is opt in and warns. |
| Token clearing sat inside `try`, so it was skipped on failure, and failure is the common path with CORS | **Fixed.** Moved to `finally` across all six connectors. |
| No CSP on the pages or the generated report | **Proposed**, see `docs/PROPOSAL_page_hardening.md`. |
| CDN fallback with no SRI, which also contradicts the offline claim | **Proposed**, same document. Recommendation is to fail closed. |

Every fix has a regression test that was confirmed to fail against the pre fix code.
Standing guarantees, asserted on every run: no `exec`, `eval` or `Function` constructor
in any shipped file; no token in browser storage; every token field a password input;
GET only, no write method to any cluster.

## Documentation

| Document | For |
|---|---|
| `docs/DJ_ACS_Auditor_User_Guide.docx` | Operators. How to scan, connect to a live cluster, apply fixes, and export. Illustrated. |
| `docs/DJ_Security_Tooling_Administration_Guide.docx` | Maintainers. Architecture, tests, adding policies, vendoring, waivers, CI, release. Covers KYSA too. |

Figures are generated from source: `python3 docs/make_figures.py` and `python3 docs/make_admin_figures.py`.
The documents are built with `node docs/doc1.js` and `node docs/doc2.js`.

## Contact

Questions, bugs, or policy suggestions: **[github.com/djkidnyce](https://github.com/djkidnyce)**

Built by DJ.
