# Proposal: content security policy and removing the CDN fallback

Status: proposed, not implemented
Author: DJ
Date: 15 August 2026
Covers findings 2 and 3 from the security review

These two were held back from the immediate fixes because they change how the pages
load. Findings 1, 4 and 5 were small and unambiguous and are already in, with regression
tests in `test/hardening.cjs`.

Every number below was measured against the current code, not estimated.

---

## Finding 2: no content security policy anywhere

### What is true today

| Surface | Inline `<script>` blocks | Largest block | CSP |
|---|---|---|---|
| `dj_acs_auditor.html` | 2 | 32,495 bytes | none |
| `dj_acs_remediation.html` | 2 | 43,704 bytes | none |
| Generated HTML report | 1 | 401 bytes | none |

### Threat

The generated report is the real exposure, and it is worth separating from the tool
pages because the risk profile is completely different.

The report gets emailed, attached to change tickets, dropped in a shared drive, and
opened weeks later by people who did not generate it and have no idea what is in it. It
is a file that travels. Any injection that reaches it becomes stored cross site
scripting with a long shelf life and an audience of exactly the people you least want
compromised: whoever reviews security findings.

The tool pages are the lesser exposure. They are opened by one person, on purpose, with
input they chose. Still worth hardening, but the report is where the leverage is.

Finding 1 closed the one injection path I could actually demonstrate. A CSP is defence
in depth for the paths nobody has found yet, which in a tool that ingests third party
JSON is not a hypothetical category.

### Be honest about what CSP can and cannot do here

A nonce based CSP is not available. Nonces must be generated per response by a server,
and these pages are opened from `file://`. There is no server.

That leaves hashes, and the two surfaces come out differently.

**The report: a hash works cleanly, with no build step.** It has exactly one inline
script, the light and dark toggle, and it is 401 bytes that have not changed and have no
reason to. Measured:

```
sha256-NHuSn1pUTym4fz7JZo6EbmBn5hsmVVvBcRuvREgcvwg=
```

```
default-src 'none';
script-src 'sha256-NHuSn1pUTym4fz7JZo6EbmBn5hsmVVvBcRuvREgcvwg=';
style-src 'unsafe-inline';
img-src data:;
base-uri 'none';
form-action 'none';
frame-ancestors 'none'
```

Cost: 241 bytes added to a 16 KB report. `default-src 'none'` means an injected
`<script src>`, `<img>` beacon, `<iframe>`, `fetch` or form post has nowhere to go. The
report has no legitimate need to talk to anything, so denying everything costs nothing.

Verified: the hash survives write and read back, and the CSP meta tag is preserved.

**The tool pages: a hash is a maintenance trap.** Hashing a 32 KB inline block means the
hash changes on every edit to the page logic. Get it wrong and the page silently goes
blank, which is the worst possible failure for a tool somebody opens under time
pressure. That needs a build step to stay correct, and a build step contradicts the
"double click the file, nothing to install" property that makes this usable on a locked
down network.

So `script-src 'unsafe-inline'` on the tool pages, which is a real limitation and should
be written down rather than glossed over.

**And `connect-src` cannot save us on the tool pages either.** The obvious win would be
restricting outbound connections so an injection cannot exfiltrate a token. It does not
work here: the pages legitimately connect to whatever Central and API host the operator
types, which is unknown when the page is authored. `connect-src https:` permits every
https host on the internet, so it stops nothing that matters. Claiming it as a mitigation
would be security theatre.

What is left for the tool pages is still worth having, because each directive closes a
specific real channel:

```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
object-src 'none';
base-uri 'none';
form-action 'none';
frame-src 'none';
frame-ancestors 'none'
```

| Directive | What it actually stops |
|---|---|
| `object-src 'none'` | Plugin and embed based execution |
| `base-uri 'none'` | A `<base>` tag hijacking every relative URL on the page |
| `form-action 'none'` | An injected form posting the DOM, including a token field, to an attacker |
| `frame-src` and `frame-ancestors 'none'` | Injected iframes, and this page being framed by another |
| `img-src 'self' data:` | Beacon exfiltration through an image URL |

### Recommendation

1. **Ship the strict CSP on the generated report now.** Highest value, lowest cost, no
   build step, and it protects the artifact that travels. Add a test asserting the hash
   matches the emitted script, so a future edit to the toggle fails the suite loudly
   instead of shipping a blank report.
2. **Ship the partial CSP on the tool pages**, with `'unsafe-inline'` and a comment
   stating plainly why, and why `connect-src` is not in the list.
3. **Do not pursue nonces or a build step** unless the tool moves to being served from a
   real origin. If that happens, revisit all of this: a served origin makes nonces,
   meaningful `connect-src`, and real SRI all available at once.

Effort: roughly half a day including tests. Risk of breaking the tool: low for the
report, low for the pages given `'unsafe-inline'` is retained.

---

## Finding 3: the CDN fallback contradicts the offline claim and has no integrity check

### What is true today

```js
if (typeof jsyaml === 'undefined')
  document.write('<scr' + 'ipt src="https://cdnjs.cloudflare.com/.../js-yaml.min.js"><\/scr' + 'ipt>');
```

Three occurrences across the two pages, two libraries. No `integrity`, no `crossorigin`.
The CLI has no equivalent path: it already fails closed with instructions, which is the
behaviour being proposed for the pages.

### Threat

Two distinct problems, and the second is the one that actually gets people fired.

**Supply chain.** A compromised or intercepted CDN response is arbitrary JavaScript
executing in a page that holds a live ACS bearer token and every manifest the operator
loaded. No integrity attribute means nothing detects it. This is the textbook case SRI
exists for.

**The claim is false when the fallback fires.** The README, both Word documents and the
tool's own copy say this runs with no network access. That is true right up until
`vendor/js-yaml.min.js` is missing, at which point the tool silently reaches the
internet. It goes missing in ordinary ways: a rename, a partial unzip, a `.gitignore`
pattern catching `*.min.js`, a corporate scanner quarantining a minified file.

On a classified or air gapped network, an unexpected outbound request from a security
tool is not a degraded experience. It is an incident, with a write up, and the tool gets
banned. The failure is silent and the consequence is disproportionate, which is the worst
combination.

### Options

**A. Add SRI to the fallback.** Keeps the convenience. Two problems. It still makes the
outbound request, so the air gap problem is untouched. And the documented hashes are for
the **unpkg** build; cdnjs may serve a different build of the same version, so the
existing `vendor/README.md` values cannot simply be reused. They would have to be
computed against cdnjs specifically and re-verified whenever cdnjs rebuilds. That is
ongoing maintenance for a path that should not exist.

**B. Remove the fallback, fail closed.** The page detects the missing library and stops
with a message naming the file, the URL to fetch it from, and the SHA-256 to verify it
against, matching what `acs_cli.js` already does. No network call in any circumstance.
The operator gets a clear, actionable error instead of a silent degradation.

**C. Ship a genuine single file build.** A small script inlines `vendor/*.js` into the
HTML and emits `dj_acs_auditor.standalone.html`. One file, no `vendor/` directory, no
dependency on relative paths surviving a copy. Best distribution story for locked down
environments, where "one file you can email" beats "a folder you must keep intact."
Needs a build step, but an optional one that does not affect normal use.

### Recommendation

**B now, C as a follow up.**

Failing closed is the correct posture for a security tool. A scanner that silently
degrades is worse than one that stops, because the operator carries on believing the
result. That is the same principle already applied to unparseable YAML, to unmatched ACS
violations and to images with no scan data: say what you could not do, never present a
gap as a clean result.

C is the better end state for air gapped distribution and is worth doing once B is in,
because it removes the failure mode entirely rather than reporting it well.

Effort: B is about an hour including a test that the failure message appears and that no
`document.write` of a remote script remains. C is roughly half a day.

---

## Suggested order

| Step | Change | Effort | Risk |
|---|---|---|---|
| 1 | CSP on the generated report, with a hash test | 2 hours | low |
| 2 | Remove the CDN fallback, fail closed | 1 hour | low |
| 3 | Partial CSP on the tool pages | 2 hours | low |
| 4 | Optional single file build | 4 hours | low |

Steps 1 and 2 are independent and can ship together. Step 3 is worth doing in the same
release so the CSP story is consistent. Step 4 can wait for a version bump.

## What is deliberately not proposed

**Subresource integrity on `vendor/`.** SRI does not apply to `file://` script tags, and
even where it did, an attacker who can write to `vendor/` can equally edit the HTML that
carries the hash. The honest control here is that the folder's integrity is the trust
boundary: verify the hashes at release time, document them, and treat write access to
that directory as equivalent to write access to the tool. That is already stated in
`vendor/README.md` and section 8 of the administration guide.

**Runtime hashing of the vendored libraries in the browser.** Technically possible with
`crypto.subtle`, but it would run after the library has already been parsed and executed,
which means it detects tampering strictly too late to prevent it. It would produce a
reassuring green tick that proves nothing. Not worth the code.
