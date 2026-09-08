# Documentation

Two guides, committed to this repository as Word documents so they are formatted,
printable, and readable without building anything. The same files are attached to every
[release](https://github.com/djkidnyce/DJ-ACS-Cluster-Security-Auditor/releases).

| Document | For | Covers |
|---|---|---|
| **[DJ_ACS_Auditor_User_Guide.docx](DJ_ACS_Auditor_User_Guide.docx)** | Operators | Loading manifests, reading the audit, pulling data out of ACS, working a large finding list, applying fixes, and getting corrected YAML back out. Illustrated. |
| **[DJ_Security_Tooling_Administration_Guide.docx](DJ_Security_Tooling_Administration_Guide.docx)** | Maintainers | Architecture, the fix mode gate, the two ACS data planes, running and extending the test suites, adding a policy, vendoring, waivers, CI and the release procedure. |
| [PROPOSAL_page_hardening.md](PROPOSAL_page_hardening.md) | Reviewing the security posture | Content Security Policy and subresource integrity, written up as a proposal rather than applied. |

GitHub will not render a `.docx` in the browser. Click the file, then **Download**, or
clone the repository and open them normally.

## How this folder fits together

```
doc1.js  doc2.js  common.js     the source of both guides
figures/                        diagrams, committed as .png and .svg
make_figures.py                 rebuilds the user guide figures
make_admin_figures.py           rebuilds the administration guide figures
make_vuln_figure.py             rebuilds the vulnerability panel figure
check_docx.sh                   verifies the committed guides match their source
*.docx                          generated, committed, verified in CI
index.html                      a browsable index of the figures
```

The `.docx` files are generated, not written. Edit `doc1.js` or `doc2.js`, then rebuild.

## Rebuilding

```bash
python3 docs/make_figures.py          # user guide figures
python3 docs/make_admin_figures.py    # administration guide figures
python3 docs/make_vuln_figure.py      # the vulnerability panel figure

npm install --no-save docx            # the only npm dependency in the project
./docs/check_docx.sh --rebuild        # or: node docs/doc1.js && node docs/doc2.js
```

Then commit the rebuilt `.docx`. None of this is needed to read the guides or to use the
tool; it is here for whoever changes the documentation next.

## Why the guides are committed, and how they are kept honest

Generated output in a repository has one well known failure: it stops matching its source.
Somebody edits `doc1.js`, forgets to rebuild, and the file in git describes a version of
the tool that no longer exists. Nothing fails, and the reader has no reason to doubt it.

These were gitignored for several versions for exactly that reason, and it cost more than
it saved. Browsing the repository showed generators, figures and a proposal, and not one
readable document. The README named two `.docx` paths that were not there. The
documentation existed and the person most likely to need it could not reach it.

So they are committed, and `./docs/check_docx.sh` closes the gap that made ignoring them
attractive in the first place. CI runs it on every push and fails the build when a guide
no longer matches its generator.

It compares extracted text rather than bytes, deliberately. A `.docx` is a ZIP and the
generator writes non-deterministic content into it, so two builds of an unchanged source
produce different bytes every time. A byte comparison would fail on every run and be
switched off within a week, and a check nobody runs is worse than no check because it
looks like coverage. The text is stable, and the text is what goes stale.

The guides also carry the version they describe, read from `ACS_VERSION`, and a date taken
from the newest CHANGELOG heading. Neither is typed in, so neither can be wrong without
the build being wrong. The User Guide previously said "Version 1.0" while the tool stamped
1.5.0 into every report it wrote.
