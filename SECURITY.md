# Security policy

## Reporting

Report anything security relevant privately first, through GitHub Security Advisories on
this repository, or by contacting [github.com/djkidnyce](https://github.com/djkidnyce).
Please do not open a public issue for a vulnerability.

Useful things to include: what you did, what happened, and the smallest input that
reproduces it. **Redact any token before sending anything.** If a credential appeared
somewhere it should not have, rotate it first and report second.

## What this tool does and does not do

Understanding the boundary makes it much easier to judge whether something is a
vulnerability.

* **It never executes a command to remediate a finding.** Fixes are text edits to YAML.
  No `oc`, `kubectl`, `roxctl`, `helm`, or shell.
* **It never writes to a cluster.** Live connect issues HTTP `GET` only, and only when
  you ask.
* **Nothing applyable is produced without an explicit mode.** `report` is the default on
  every surface.
* **It performs no vulnerability scanning of its own.** CVE data comes from ACS.

## Properties asserted on every test run

If you can break any of these, that is a vulnerability and worth reporting:

* No `exec`, `eval`, or `Function` constructor in any shipped file.
* No API token is written to `localStorage`, `sessionStorage`, IndexedDB, or a cookie.
  Every token field is a password input and is cleared in a `finally` block, so a failed
  request does not leave a credential sitting in the DOM.
* URLs arriving from an ACS export are scheme allowlisted to `http` and `https` before
  they reach an `href`. `javascript:`, `data:`, `vbscript:`, `blob:` and `filesystem:`
  are rejected and rendered as inert text.
* Generated commands never disable TLS verification by default, and the insecure variant
  warns that the token is exposed.
* The engine issues no `POST`, `PUT`, `PATCH` or `DELETE` to any cluster.

## Known limitations, deliberately accepted

These are documented rather than fixed, and are not currently treated as vulnerabilities:

* **No Content Security Policy** on the pages or the generated report. See
  `docs/PROPOSAL_page_hardening.md` for what is proposed and why the tool pages cannot
  use a hash based policy without a build step.
* **A CDN fallback exists** if `vendor/` is missing, with no subresource integrity. The
  same proposal recommends removing it and failing closed instead.
* **The `vendor/` directory is the trust boundary.** Anyone who can write to it can
  replace the YAML parser, which is the component that decides what your manifests say.
  Hashes are published in the release; verify them.
* **Live connect requires a token in a browser tab.** Use a short lived, least privilege,
  read only token. For ACS, generate a dedicated API token rather than reusing an admin
  one, and revoke it when finished.

## Do not run this from a hosted page

The project page is documentation only and deliberately does not host a runnable copy.
Pasting a live ACS API token into a page served from anyone's web infrastructure widens
the blast radius of a repository or CDN compromise from "bad code" to "your cluster
credentials". Download a release, verify it, and open the HTML from your own disk.

## Supported versions

The latest release. This is a single maintainer project; older versions are not patched.
