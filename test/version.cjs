/* The version has to mean something, or it is decoration.
 *
 * This tool writes its version into every report, every JSON and SARIF export, and the
 * header of every patch it drafts. Somebody reading a patch six months from now uses that
 * string to work out which build produced it, and to go and read what that build did.
 * That only works if three things agree: the constant in the engine, the newest heading in
 * the CHANGELOG, and the git tag.
 *
 * They have drifted before on this project in the smaller way: a commit message claiming
 * 531 tests against a tree that ran 469, and a README whose summary contradicted its own
 * table. Numbers written by hand in two places diverge. This is the check that stops the
 * version doing the same.
 */
'use strict';
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const ROOT = path.join(__dirname, '..');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

console.log('\nThe version is a real semantic version, in one place');
t('ACS_VERSION is exported', typeof E.ACS_VERSION === 'string' && E.ACS_VERSION.length > 0);
t('and it is semver, not a marketing number (' + E.ACS_VERSION + ')', SEMVER.test(E.ACS_VERSION));
t('the banner is derived from it, not typed out again',
  E.ACS_TOOL === "DJ's ACS Auditor v" + E.ACS_VERSION);

const engine = fs.readFileSync(path.join(ROOT, 'acs_policies.js'), 'utf8');
const literals = (engine.match(/DJ's ACS Auditor v\d/g) || []);
t('no second hardcoded copy of the banner exists in the engine', literals.length === 0);

console.log('\nThe CHANGELOG agrees, and describes this version');
const cl = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
const headings = (cl.match(/^## .+$/gm) || []).map((h) => h.replace(/^##\s*/, '').trim());
const releases = headings.filter((h) => SEMVER.test(h.split(/\s|-/)[0]));
t('there is at least one released version in the CHANGELOG', releases.length > 0);
const newest = releases[0].split(/\s|-/)[0];
t('the newest CHANGELOG entry matches the code (' + newest + ' vs ' + E.ACS_VERSION + ')',
  newest === E.ACS_VERSION);
t('every release heading carries a date',
  releases.every((r) => /\d{4}-\d{2}-\d{2}/.test(r)));

/* Versions must go up. A release older than the one below it means somebody edited the
   middle of the file rather than the top. */
const nums = releases.map((r) => r.split(/\s|-/)[0].split('.').map(Number));
let descending = true;
for (let i = 1; i < nums.length; i++) {
  const a = nums[i - 1], b = nums[i];
  const cmp = (a[0] - b[0]) || (a[1] - b[1]) || (a[2] - b[2]);
  if (cmp <= 0) descending = false;
}
t('releases are listed newest first and strictly decreasing', descending);
t('the newest release section is not empty',
  cl.split('## ' + releases[0])[1].trim().length > 40);

console.log('\nNothing else hardcodes a version that could fall behind');
for (const f of ['README.md', 'acs_cli.js', 'docs/doc1.js', 'docs/doc2.js']) {
  const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
  const stale = (src.match(/ACS Auditor v(\d+\.\d+(\.\d+)?)/g) || [])
    .filter((m) => !m.endsWith('v' + E.ACS_VERSION));
  t('  ' + f + ' carries no stale version string', stale.length === 0);
  if (stale.length) console.log('        found: ' + Array.from(new Set(stale)).join(', '));
}

console.log('\nThe git tag agrees with the version');

/* Where this binds, and why it is not "whenever a tag is checked out".
 *
 * The obvious rule is: if HEAD sits on a tag, the tag must match the version. That rule
 * fails in two ways on a working machine.
 *
 * It fires while preparing a release, which is the one time it should not: sitting on the
 * previous tag with the next version's files applied is exactly what preparing looks like.
 *
 * And the obvious guard for that, "unless the tree is dirty", is not reliable. unzip
 * preserves the archive's timestamps, so git's stat cache can report a freshly replaced
 * tree as clean on the first status and dirty on the second, once the index has been
 * refreshed. That produced two different results from two identical runs, which is worse
 * than either answer on its own.
 *
 * So it binds in CI, where the checkout is fresh and the tag, the commit and the files are
 * the same thing by construction. Locally it reports what it sees and does not fail.
 */
const inCI = !!(process.env.CI || process.env.GITHUB_ACTIONS);
let tag = null;
try {
  tag = execFileSync('git', ['describe', '--tags', '--exact-match'],
    { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
} catch (e) { /* not on a tagged commit, or not a git tree at all */ }

if (!tag) {
  console.log('  skip  no exact tag on this commit, so there is nothing to compare');
} else if (!inCI) {
  const agrees = tag === 'v' + E.ACS_VERSION;
  console.log('  note  HEAD is on ' + tag + ' and the code says ' + E.ACS_VERSION +
    (agrees ? ', which agree.' : ', which do not agree.'));
  if (!agrees) {
    console.log('        That is expected while preparing a release and is not failed here.');
    console.log('        It is asserted in CI, where the checkout is a fresh clone of the tag.');
  }
} else {
  t('the tag matches the version (' + tag + ' vs ' + E.ACS_VERSION + ')',
    tag === 'v' + E.ACS_VERSION);
  t('and the CHANGELOG documents that exact version', releases[0].indexOf(E.ACS_VERSION) === 0);
}

console.log('\nThe stamp actually reaches the artifacts');
const st = { files: [], findings: [], acs: null, onlyInAcs: [], vulns: null, vulnCorr: null };
/* The report HTML escapes the apostrophe in the tool name, so compare on the part that
   cannot be escaped rather than on the raw banner. */
t('the HTML report carries the version',
  E.buildHtmlReport(st).indexOf('ACS Auditor v' + E.ACS_VERSION) !== -1);
t('the findings JSON carries it', E.buildFindingsJson(st).tool === E.ACS_TOOL);

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
