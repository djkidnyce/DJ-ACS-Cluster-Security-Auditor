# Releasing

Every change that ships gets a version and a tag. The version is written in one place and
checked by the suite, so the tag, the CHANGELOG and the string stamped into every report
cannot drift apart.

## Deciding the number

Semantic versioning. The public interface, for versioning purposes, is:

- the CLI flags and their meanings
- the exit codes
- the shape of the findings JSON and the SARIF output
- the policy ids

| Change | Bump |
|---|---|
| A new flag, a new policy, a new panel, a new fix route | **Minor** |
| A fix that changes what the tool reports or refuses | **Minor**, because output people rely on moved |
| A fix with no visible change to output or interface | **Patch** |
| Removing or renaming a flag, a policy id, or a JSON field | **Major** |
| Changing a default that makes the tool do more than it did | **Major**, and reconsider |

That last row is deliberate. Report mode is the default and auto is opt in. Any change that
narrows that gap is a breaking change to the safety model, whatever it does to the code.

## The procedure

1. Make the change. Add or update tests, and prove any regression test fails against the
   broken behaviour before you rely on it.

2. Bump `ACS_VERSION` in `acs_policies.js`. Nothing else in code holds a version; the
   banner, the report, the JSON, the SARIF and every patch header derive from it.

3. Add a CHANGELOG section at the top, `## X.Y.Z - YYYY-MM-DD`, newest first. Write what
   changed and why it mattered, not what files moved. If a defect reached a user, say what
   they would have seen, because that is what makes it recognisable next time.

4. Regenerate anything derived.

   The SBOM names the version, so it changes on every release:

       node scripts/make_sbom.js

   Figures, only if you changed them. The Word guides are built in CI and attached to the
   release, so you do not need to build them here unless you want to read them:

       cd docs && python3 make_figures.py && python3 make_admin_figures.py

5. Run the suite. Both ways, because the page tests are the ones that catch a dead button
   or a panel that never unhides:

       node test/run_tests.js
       npm install jsdom && node test/run_tests.js

   `test/version.cjs` will fail if the version, the CHANGELOG and the tag disagree.

6. Commit, tag, push. The tag is `v` plus the version:

       git add -A
       git commit -F- <<'MSG'
       <subject>

       <body>
       MSG
       git tag -a v1.4.0 -m "v1.4.0: <one line>"
       git push origin main --follow-tags

   Pushing the tag triggers the release workflow. Watch it: it refuses to publish if the
   version, the CHANGELOG and the tag disagree, if the suite fails, or if the SBOM does not
   match what is vendored.

   `--follow-tags` pushes annotated tags reachable from the commits being pushed, so the
   tag and the code arrive together. Pushing them separately is how a tag ends up on
   GitHub pointing at a commit nobody has.

7. Verify what landed:

       git describe --tags --exact-match
       node test/version.cjs

   On a tagged commit `version.cjs` compares the tag against the code instead of skipping.

## Sign the tag

An annotated tag records who made it. A signed tag lets somebody else verify that
independently, which is the difference between a claim and evidence. For a tool people are
invited to run against production manifests, that distinction is the whole point.

SSH signing is the least friction if you already have a key on GitHub:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global tag.gpgsign true
```

Then `git tag -a` signs automatically. Verify with:

```bash
git tag -v v1.4.0
```

GitHub shows a Verified badge once the same public key is registered as a signing key in
your account settings, which is a separate list from your authentication keys.

If you cannot sign, say so rather than implying otherwise. An unsigned tag is not a
failure; quietly letting people assume it is signed would be.

## What a release produces

Pushing a version tag runs `.github/workflows/release.yml`, which will not publish
anything until the version, the CHANGELOG and the tag agree, the whole suite passes on
that exact commit, and the SBOM matches what is vendored. It then builds:

| Artifact | What it is for |
|---|---|
| `dj-acs-auditor-X.Y.Z.zip` and `.tar.gz` | The tool, without the development-only files |
| `SHA256SUMS` | So a download can be checked before it is trusted |
| A build provenance attestation | A signed statement that these bytes came from this workflow, from this commit |
| `sbom.cdx.json` | The entire dependency surface: two vendored libraries |
| The two Word guides | Built from source at release time rather than committed |

Anyone can verify a download:

```bash
sha256sum -c SHA256SUMS
gh attestation verify dj-acs-auditor-1.4.0.zip \
  --repo djkidnyce/DJ-ACS-Cluster-Security-Auditor
```

The attestation says where the bytes came from. It does not say the tool is correct, and
the release notes are explicit about that, because a verified signature on bad software is
still bad software.

## Annotated, not lightweight

Use `git tag -a`. An annotated tag carries a tagger, a date and a message, and it is a real
object in the repository. A lightweight tag is a bare pointer with no record of who made it
or when. For anything used as evidence, and a security audit tool is, that record is the
point.

## Fixing a tag you got wrong

Before pushing, delete and remake it: `git tag -d v1.1.0`.

After pushing, do not move it. A tag that means one thing on your machine and another on
someone's checkout is worse than a wrong number. Cut the next patch version and note the
correction in the CHANGELOG.
