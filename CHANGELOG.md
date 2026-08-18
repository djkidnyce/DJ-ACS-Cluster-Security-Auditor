# Changelog

Notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Initial public release.

### What it does

* Audits Kubernetes and OpenShift manifests against replicas of the twenty Red Hat ACS
  default Deploy stage policies, with CIS, NIST SP 800-53 Rev 5, Pod Security Standards
  and DISA STIG citations on every finding.
* Scores posture with a weighted compliance rate whose denominator is derived from what
  was scanned rather than what was found, so the projected score survives a rescan.
* Applies the safe fixes to YAML with a preview, a confirmation, one at a time stepping,
  and undo. Emits patched files, strategic merge patches for Helm and Kustomize, a change
  log, and a CVE rebuild worklist grouped by image.
* Pulls from ACS: policy violations from `/v1/alerts`, image CVEs from
  `/v1/export/vuln-mgmt/workloads`, and workloads from the OpenShift API. Browser pages,
  a CLI, and scripts for direct, `oc` and SSH bastion access.
* Runs from a browser with nothing installed, or headless from a pipeline with SARIF
  output and a severity gate.

### Design decisions worth knowing about

These are the ones most likely to surprise you, and each exists for a reason.

* **`report` is the default mode everywhere.** Nothing applyable is produced unless you
  choose `manual` or `auto`. The mode is never inferred from another option, an unknown
  mode is an error rather than a quiet fall back to something permissive, and the mode is
  recorded in every artifact. A remediation tool that can write before the operator has
  chosen to write is a new risk, not a mitigation.
* **There is no auto fix for a CVE.** ACS reports fixed package versions, not fixed image
  tags, and deriving one from the other means guessing about how your image is built.
* **Platform component violations are never auto patched.** The owning operator reverts a
  manual edit on its next reconcile, so a patch there changes nothing except how hard the
  drift is to see.
* **CVE counts are kept out of the posture score.** They move whenever a vulnerability
  feed updates, with nothing in your manifests changing.
* **Priority runs 0 to 15, not 0 to 10.** Clamping to 10 lands every critical on exactly
  10 and destroys the ordering at the top of the queue.
* **No command is ever run to remediate a finding.** Fixes are text edits to YAML. The
  tool is read only against clusters: `GET` requests only, and only when you ask.

### Security properties, asserted on every test run

* No `exec`, `eval` or `Function` constructor in any shipped file.
* No API token reaches browser storage. Every token field is a password input and is
  cleared in a `finally` block, so a failed request does not leave a credential in the DOM.
* URLs arriving from an ACS export are scheme allowlisted to `http` and `https` before
  reaching an `href`.
* Generated commands never disable TLS verification by default.
* Dependencies are vendored with published SHA-256 values. No package manager, no network
  access at rest.

531 tests across the engine, both pages driven in a real DOM, and the command line.
