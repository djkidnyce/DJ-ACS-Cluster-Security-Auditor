/* The CI workflow, checked the way any other guarantee is checked.
 *
 * This exists because the guarantee job silently stopped working. It listed
 * dj_acs_remediation.html by name, 1.2.0 deleted that file, and grep began exiting 2 on
 * the missing path. `if grep` reads a non zero exit as "no match", so the step printed
 * "clean" and passed. Worse, the error masked real matches in the files that did still
 * exist: a planted eval() went undetected. Every green build after 1.2.0 asserted nothing
 * there and reported success.
 *
 * A check that cannot fail is worse than no check, because it is counted.
 */
'use strict';
const fs = require('fs'), path = require('path');
const ROOT = path.join(__dirname, '..');
const CI = path.join(ROOT, '.github', 'workflows', 'ci.yml');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

console.log('\nThe workflow exists and is shipped with the tool');
t('the workflow is in the package, not only in the repository', fs.existsSync(CI));
if (!fs.existsSync(CI)) { console.log('\n' + P + ' passed, ' + (F + 1) + ' failed'); process.exit(1); }
const y = fs.readFileSync(CI, 'utf8');

console.log('\nIt never names a file that may not exist');
/* Naming files is what broke it. Every grep target must be a glob or a path the workflow
   has already asserted the existence of. */
const named = (y.match(/dj_acs_[a-z_]+\.html/g) || []).filter((n) => n.indexOf('*') === -1);
t('no page file is named literally in a grep target',
  named.every((n) => n === 'dj_acs_auditor.html'));
t('the deleted remediation page is not referenced at all',
  y.indexOf('dj_acs_remediation') === -1);
t('there is a step that asserts the files exist before the checks run',
  /expected \$f and it is not here/.test(y));

console.log('\nThe guarantee steps fail loudly rather than passing on an error');
const steps = y.split(/\n      - name: /).slice(1);
const grepSteps = steps.filter((s) => /run: \|/.test(s) && /grep/.test(s));
t('there are guarantee steps that grep', grepSteps.length >= 4);
/* -e for the steps that must abort on any error, -o pipefail for the one that pipes into
   grep and would otherwise mask a failure in the command feeding it. Either is a
   deliberate choice; shell defaults are not. */
t('none of them runs under bare shell defaults',
  grepSteps.every((s) => /set -[euo]/.test(s)));

console.log('\nThe claims the README makes are the claims CI asserts');
for (const [claim, needle] of [
  ['no exec, eval or Function constructor', /eval\\\(\|new Function/],
  ['no credential can enter the page', /type="password"/],
  ['the page makes no network call', /fetch/],
  ['the engine issues no cluster writes', /POST\|PUT\|PATCH\|DELETE/],
  ['vendored dependencies match their published hashes', /sha256sum -c/],
  ['the shell scripts parse', /sh -n/],
  ['the version agrees with the CHANGELOG', /test\/version\.cjs/],
]) {
  t('  CI asserts: ' + claim, needle.test(y));
}

console.log('\nThe CLI is allowed exactly one subprocess, and CI pins it');
t('it counts the child_process requires rather than exempting the file',
  /child_process/.test(y) && /-eq 1/.test(y));
t('and pins what that one subprocess is', /status.*--porcelain/.test(y));
t('and forbids a shell capable spawn', /shell: \*true|spawn\\\(/.test(y));

console.log('\nCI proves its own checks can fail');
t('there is a self test job', /selftest:/.test(y));
t('it plants an eval and requires the check to catch it',
  /planted eval/.test(y) && /does not detect a planted eval/.test(y));
t('and plants a credential field too', /planted field/.test(y));

console.log('\nThe version to tag check is enforced where it can be trusted');
t('CI runs the version suite', /test\/version\.cjs/.test(y));
/* It binds in CI only, because a local tree can be mid release and because git's stat
   cache made a dirty tree look clean on the first status after an unzip. CI is a fresh
   checkout, so tag, commit and files are the same thing there. */
t('and CI is where the tag comparison actually binds',
  fs.readFileSync(path.join(ROOT, 'test', 'version.cjs'), 'utf8').indexOf('GITHUB_ACTIONS') !== -1);

console.log('\nA crashed suite cannot be read as a pass');
t('CI fails the build when a suite crashes before reporting',
  /CRASHED BEFORE REPORTING/.test(y));

/* ------------------------------------------------- the release pipeline */

const REL = path.join(ROOT, '.github', 'workflows', 'release.yml');

console.log('\nA release produces something verifiable, not just a git tag');
t('there is a release workflow', fs.existsSync(REL));
const r = fs.existsSync(REL) ? fs.readFileSync(REL, 'utf8') : '';

t('it triggers on a version tag rather than on every push',
  /tags: \['v\[0-9\]/.test(r));
t('it fetches tags, so the version check can bind', /fetch-depth: 0/.test(r));

console.log('\n  It refuses to publish something that does not hold together');
t('the version, the CHANGELOG and the tag must agree first',
  /node test\/version\.cjs/.test(r));
t('the whole suite must pass on the exact commit',
  /node test\/run_tests\.js/.test(r));
t('the SBOM must match what is vendored', /make_sbom\.js --check/.test(r));

console.log('\n  And what it publishes can be checked by whoever downloads it');
t('checksums are generated', /sha256sum/.test(r));
t('build provenance is attested', /attest-build-provenance/.test(r));
t('the SBOM ships with the release', /sbom\.cdx\.json/.test(r));
t('the release notes say how to verify', /gh attestation verify/.test(r));
t('and say plainly what the attestation does not mean',
  /not a claim that the tool is correct/.test(r));

console.log('\nThe generated documentation is built, not committed');
t('the .docx files are gitignored',
  /docs\/\*\.docx/.test(fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8')));
t('CI proves the generators still run', /node docs\/doc1\.js/.test(y));
t('and fails if a generated document gets committed again',
  /a generated \.docx is tracked/.test(y));
t('the release builds them and attaches them', /node docs\/doc1\.js/.test(r));

console.log('\nThe SBOM is generated from the files, not maintained by hand');
const gen = path.join(ROOT, 'scripts', 'make_sbom.js');
t('there is a generator', fs.existsSync(gen));
const g = fs.existsSync(gen) ? fs.readFileSync(gen, 'utf8') : '';
t('it hashes the actual bytes on disk', /createHash\('sha256'\)/.test(g));
t('it refuses to omit a vendored file it does not recognise',
  /does not know about/.test(g));
t('it has no timestamp, so it only changes when a dependency does',
  !/new Date\(\)/.test(g));
t('CI verifies it still matches', /make_sbom\.js --check/.test(y));

const sbom = path.join(ROOT, 'sbom.cdx.json');
t('the SBOM is committed', fs.existsSync(sbom));
if (fs.existsSync(sbom)) {
  const b = JSON.parse(fs.readFileSync(sbom, 'utf8'));
  t('it is CycloneDX', b.bomFormat === 'CycloneDX');
  t('it names the whole dependency surface, which is two libraries',
    b.components.length === 2);
  t('every component carries a hash', b.components.every((c) => c.hashes && c.hashes.length));
  t('every component carries a licence', b.components.every((c) => c.licenses && c.licenses.length));
  t('every component says where it came from',
    b.components.every((c) => (c.externalReferences || []).some((e) => e.type === 'distribution')));
  t('and the version matches the engine',
    b.metadata.component.version === require('../acs_policies.js').ACS_VERSION);
}

console.log('\nSigning is documented honestly');
const rel = fs.readFileSync(path.join(ROOT, 'RELEASING.md'), 'utf8');
t('RELEASING explains how to sign a tag', /gpg\.format ssh|tag\.gpgsign/.test(rel));
t('and how to verify one', /git tag -v/.test(rel));
t('and says to admit it when you cannot sign, rather than implying you did',
  /quietly letting people assume/.test(rel));

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
