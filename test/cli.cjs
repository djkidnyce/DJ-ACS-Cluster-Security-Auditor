/* CLI tests. These run the real binary as a subprocess against real files on disk,
 * because the things that break in a CLI are exit codes, argument handling and what
 * actually lands in the output directory, none of which are visible from unit tests.
 *
 * Two of these guard defects found during development and worth naming:
 *
 *   The --fail-on gate was inverted. sevRank returns 0 for Critical and 3 for Low, so a
 *   naive >= comparison produced a gate that passed builds containing criticals and
 *   blocked them on lows. A CI gate that is confidently wrong is worse than no gate,
 *   because people trust it.
 *
 *   buildMergePatch takes (beforeDoc, afterDoc). The CLI was calling it with (docs,
 *   finding). JavaScript did not complain: it walked the finding object and emitted the
 *   entire finding structure as if it were a patch, including the policy text. Silent,
 *   wrong, and it would have been applied to a cluster.
 */
'use strict';
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };
const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'acs_cli.js');
const yaml = require(path.join(ROOT, 'vendor', 'js-yaml.min.js'));

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'acscli-'));
const MAN = path.join(WORK, 'manifests');
fs.mkdirSync(path.join(MAN, 'app'), { recursive: true });
fs.mkdirSync(path.join(MAN, 'legacy'), { recursive: true });

fs.writeFileSync(path.join(MAN, 'app', 'deployment.yaml'), [
  'apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: payments-api',
  '  namespace: prod', 'spec:', '  template:', '    spec:', '      hostNetwork: true',
  '      containers:', '      - name: api',
  '        image: quay.io/acme/payments:latest', '        env:',
  '        - name: DB_PASSWORD', '          value: hunter2',
  '        securityContext:', '          privileged: true', ''].join('\n'));
fs.writeFileSync(path.join(MAN, 'legacy', 'ds.yaml'), [
  'apiVersion: apps/v1', 'kind: DaemonSet', 'metadata:', '  name: shipper',
  '  namespace: tools', 'spec:', '  template:', '    spec:', '      containers:',
  '      - name: s', '        image: quay.io/acme/fluentd:1.16', ''].join('\n'));

const V = (cve, sev, cvss, fixedBy, extra) => Object.assign({
  cve, severity: sev, cvss, summary: cve, link: 'https://access.redhat.com/security/cve/' + cve,
  fixedBy: fixedBy || '', state: 'OBSERVED' }, extra || {});
fs.writeFileSync(path.join(WORK, 'vulns.ndjson'), JSON.stringify({ result: {
  deployment: { name: 'payments-api', namespace: 'prod', type: 'Deployment' }, livePods: 2,
  images: [{ id: 'sha256:a', name: { fullName: 'quay.io/acme/payments:latest' },
    scan: { scanTime: 't', operatingSystem: 'rhel:9', components: [{ name: 'openssl', version: '3.0.7', vulns: [
      V('CVE-2026-1000', 'CRITICAL_VULNERABILITY_SEVERITY', 9.8, '3.0.14', { cisaKev: true, epss: { epssProbability: 0.62 } }),
      V('CVE-2026-1001', 'LOW_VULNERABILITY_SEVERITY', 2.1, '')] }] } }] } }) + '\n');
fs.writeFileSync(path.join(WORK, 'alerts.json'), JSON.stringify({ alerts: [{
  id: 'a1', state: 'ACTIVE', lifecycleStage: 'DEPLOY',
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY', categories: ['Privileges'] },
  deployment: { name: 'payments-api', deploymentType: 'Deployment' },
  commonEntityInfo: { namespace: 'prod', clusterName: 'ocp-prod' },
  violations: [{ message: 'Container "api" is privileged' }] }] }));

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI].concat(args), {
    cwd: cwd || WORK, encoding: 'utf8', env: Object.assign({}, process.env, { NO_COLOR: '1' }),
  });
}

/* ---- read only by default ------------------------------------------------ */

console.log('\nRead only unless you ask otherwise');
const ro = run(['--path', MAN]);
t('a plain run exits 0', ro.status === 0);
t('it says nothing applyable was produced', /Nothing applyable was produced/.test(ro.stdout));
const untouched = fs.readFileSync(path.join(MAN, 'app', 'deployment.yaml'), 'utf8');
t('the source manifest is untouched', /privileged: true/.test(untouched));
t('it reports a posture score', /Posture \d+\/100/.test(ro.stdout));
t('it separates auto fixable from needs a decision', /automatically fixable/.test(ro.stdout));

console.log('\nWorst first ordering');
const lines = ro.stdout.split('\n').filter((l) => /^  (Critical|High|Medium|Low)\s/.test(l));
const ranks = { Critical: 0, High: 1, Medium: 2, Low: 3 };
let ordered = true;
for (let i = 1; i < lines.length; i++) {
  if (ranks[lines[i].trim().split(/\s+/)[0]] < ranks[lines[i - 1].trim().split(/\s+/)[0]]) ordered = false;
}
t('findings are listed worst first, not best first', ordered && lines.length > 0);
t('the first finding is Critical', /^  Critical/.test(lines[0] || ''));

/* ---- the fail-on gate ---------------------------------------------------- */

console.log('\nThe --fail-on gate, which was inverted and is the reason these exist');
console.log('  sevRank returns 0 for Critical and 3 for Low. Getting the comparison');
console.log('  backwards produces a gate that lets criticals through and blocks on lows.');
t('--fail-on none exits 0', run(['--path', MAN, '--quiet', '--fail-on', 'none']).status === 0);
const critRun = run(['--path', MAN, '--quiet', '--fail-on', 'critical']);
t('--fail-on critical blocks when a critical is present', critRun.status === 1);
t('and it names the blocking findings', /Critical/.test(critRun.stderr));
t('--fail-on low blocks (everything is at or above low)',
  run(['--path', MAN, '--quiet', '--fail-on', 'low']).status === 1);
t('--fail-on high blocks (criticals are above high)',
  run(['--path', MAN, '--quiet', '--fail-on', 'high']).status === 1);
t('an unknown level exits 2 rather than silently passing',
  run(['--path', MAN, '--quiet', '--fail-on', 'bogus']).status === 2);

/* The discriminating case: a tree whose worst finding is Medium. --fail-on critical must
   PASS it and --fail-on medium must BLOCK it. An inverted gate gets both backwards. */
const CLEAN = path.join(WORK, 'mediumonly');
fs.mkdirSync(CLEAN, { recursive: true });
fs.writeFileSync(path.join(CLEAN, 'ok.yaml'), [
  'apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: ok', '  namespace: prod',
  'spec:', '  template:', '    spec:', '      automountServiceAccountToken: false',
  '      securityContext:', '        runAsNonRoot: true', '      containers:',
  '      - name: c', '        image: quay.io/acme/app@sha256:' + 'a'.repeat(64),
  '        securityContext:', '          privileged: false',
  '          allowPrivilegeEscalation: false', '          readOnlyRootFilesystem: true',
  '          capabilities:', '            drop: [ALL]', '        resources:',
  '          requests: {cpu: 100m, memory: 128Mi}', '          limits: {cpu: 500m, memory: 512Mi}', ''].join('\n'));
const mOnly = run(['--path', CLEAN, '--quiet', '--fail-on', 'critical']);
t('a tree with no criticals passes --fail-on critical', mOnly.status === 0);
t('the same tree still blocks on --fail-on medium',
  run(['--path', CLEAN, '--quiet', '--fail-on', 'medium']).status === 1);

/* ---- the mode gate ------------------------------------------------------- */

console.log('\nThe mode gate: nothing applyable without an explicit choice');
console.log('  An auto fix the operator did not select is a new risk, not a mitigation.');
const modeDefault = run(['--path', MAN]);
t('the default mode is report', /mode\s+report/.test(modeDefault.stdout));
t('report mode says plainly that nothing applyable was produced',
  /Report mode\. Nothing applyable was produced/.test(modeDefault.stdout));

const refused = run(['--path', MAN, '--patches', '--out', path.join(WORK, 'refused')]);
t('--patches in report mode is REFUSED, not silently downgraded', refused.status === 2);
t('and it explains the choice rather than picking one', /--mode manual/.test(refused.stderr) && /--mode auto/.test(refused.stderr));
t('it says why, in one line a reviewer would accept',
  /new risk, not a mitigation/.test(refused.stderr));
t('nothing was written by the refused run', !fs.existsSync(path.join(WORK, 'refused')));

t('an unknown mode exits 2 rather than defaulting to something permissive',
  run(['--path', MAN, '--mode', 'atuo']).status === 2);
t('and names the valid values', /report, manual, auto/.test(run(['--path', MAN, '--mode', 'atuo']).stderr));
t('an unknown mode never falls back to a writing mode',
  /Refusing to guess/.test(run(['--path', MAN, '--mode', 'atuo']).stderr));
t('--in-place outside auto is refused', run(['--path', MAN, '--mode', 'manual', '--in-place']).status === 2);

console.log('\nManual computes the fix and emits it, but modifies nothing');
const MAN_OUT = path.join(WORK, 'manual');
const man = run(['--path', MAN, '--mode', 'manual', '--patches', '--out', MAN_OUT]);
t('manual exits 0', man.status === 0);
t('it says the fixes were computed, not applied', /computed across/.test(man.stdout));
t('and that nothing was modified', /Nothing was modified/.test(man.stdout));
t('patches are emitted', fs.existsSync(path.join(MAN_OUT, 'patches')) &&
  fs.readdirSync(path.join(MAN_OUT, 'patches')).length > 0);
t('NO corrected YAML is written in manual mode', !fs.existsSync(path.join(MAN_OUT, 'fixed')));
t('the proposal is named as a proposal, not a change log',
  fs.existsSync(path.join(MAN_OUT, 'PROPOSED_CHANGES.md')) &&
  !fs.existsSync(path.join(MAN_OUT, 'CHANGES.md')));
t('the proposal states nothing was modified',
  /NOTHING WAS MODIFIED/.test(fs.readFileSync(path.join(MAN_OUT, 'PROPOSED_CHANGES.md'), 'utf8')));
t('the mode is recorded in the artifact itself',
  /Mode: manual/.test(fs.readFileSync(path.join(MAN_OUT, 'PROPOSED_CHANGES.md'), 'utf8')));
t('the source manifest is untouched after a manual run',
  /privileged: true/.test(fs.readFileSync(path.join(MAN, 'app', 'deployment.yaml'), 'utf8')));

console.log('\nAuto computes the same fix and writes it');
const AUTO_OUT = path.join(WORK, 'auto');
const au = run(['--path', MAN, '--mode', 'auto', '--patches', '--out', AUTO_OUT]);
t('auto exits 0', au.status === 0);
t('corrected YAML IS written in auto mode', fs.existsSync(path.join(AUTO_OUT, 'fixed')));
t('and it is called a change log, not a proposal', fs.existsSync(path.join(AUTO_OUT, 'CHANGES.md')));
t('the mode is recorded there too', /Mode: auto/.test(fs.readFileSync(path.join(AUTO_OUT, 'CHANGES.md'), 'utf8')));
t('the source is STILL untouched without --in-place',
  /privileged: true/.test(fs.readFileSync(path.join(MAN, 'app', 'deployment.yaml'), 'utf8')));
t('manual and auto compute the same number of fixes',
  (man.stdout.match(/(\d+) fix\(es\) computed/) || [])[1] ===
  (au.stdout.match(/(\d+) fix\(es\) applied/) || [])[1]);

console.log('\n--fix still works, but says what it now means');
const alias = run(['--path', MAN, '--mode', 'auto', '--out', path.join(WORK, 'alias')]);
t('an explicit --mode auto does not warn', !/deprecated alias/.test(alias.stderr));
const aliasRun = run(['--path', MAN, '--fix', '--out', path.join(WORK, 'alias2')]);
t('--fix warns that it is an alias', /deprecated alias for --mode auto/.test(aliasRun.stderr));
t('and it still behaves as auto', fs.existsSync(path.join(WORK, 'alias2', 'fixed')));

console.log('\nViolation fixes obey the same gate');
/* This alert names an object that is NOT in the manifest set, so it can only be fixed by
   emitting a patch. That is the case report mode has to withhold. An alert whose manifest
   IS loaded routes to the in place path instead and withholds nothing, which is why the
   fixture matters. */
fs.writeFileSync(path.join(WORK, 'remote_alert.json'), JSON.stringify({ alerts: [{
  id: 'r1', state: 'ACTIVE', platformComponent: false,
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
  deployment: { name: 'not-in-my-repo', deploymentType: 'Deployment' },
  commonEntityInfo: { namespace: 'prod', clusterName: 'ocp' },
  violations: [{ message: 'Container "api" is privileged' }] }] }));

const vr = run(['--mode', 'report', '--path', MAN, '--alerts', path.join(WORK, 'remote_alert.json'),
                '--violation-fixes', '--out', path.join(WORK, 'vrep')]);
t('report mode writes the account but no patches', vr.status === 0 &&
  fs.existsSync(path.join(WORK, 'vrep', 'FIXING_VIOLATIONS.md')) &&
  !fs.existsSync(path.join(WORK, 'vrep', 'violation-patches')));
t('and it says how many it withheld', /NOT written/.test(vr.stdout));
t('the report still lists what it would have written, so scope stays visible',
  /would be emitted/.test(fs.readFileSync(path.join(WORK, 'vrep', 'FIXING_VIOLATIONS.md'), 'utf8')));
const vm = run(['--mode', 'manual', '--path', MAN, '--alerts', path.join(WORK, 'remote_alert.json'),
                '--violation-fixes', '--out', path.join(WORK, 'vman')]);
t('manual mode writes them', vm.status === 0 &&
  fs.existsSync(path.join(WORK, 'vman', 'violation-patches')) &&
  fs.readdirSync(path.join(WORK, 'vman', 'violation-patches')).length > 0);
t('the same run in report mode produced none, which is the whole point',
  !fs.existsSync(path.join(WORK, 'vrep', 'violation-patches')));

/* ---- fixing -------------------------------------------------------------- */

console.log('\nFixing writes to --out and leaves the source alone');
const OUT = path.join(WORK, 'out');
const fx = run(['--path', MAN, '--mode', 'auto', '--patches', '--report', '--json', '--sarif',
                '--vulns', path.join(WORK, 'vulns.ndjson'), '--alerts', path.join(WORK, 'alerts.json'),
                '--worklist', '--out', OUT]);
t('the fix run exits 0', fx.status === 0);
t('the source manifest is STILL untouched without --in-place',
  /privileged: true/.test(fs.readFileSync(path.join(MAN, 'app', 'deployment.yaml'), 'utf8')));
t('patched YAML was written', fs.existsSync(path.join(OUT, 'fixed', 'app', 'deployment.yaml')));
t('the folder structure is preserved', fs.existsSync(path.join(OUT, 'fixed', 'legacy', 'ds.yaml')));

const fixed = fs.readFileSync(path.join(OUT, 'fixed', 'app', 'deployment.yaml'), 'utf8');
const fdoc = yaml.load(fixed);
t('the patched YAML parses', !!fdoc && fdoc.kind === 'Deployment');
const c0 = fdoc.spec.template.spec.containers[0];
t('privileged was turned off', c0.securityContext.privileged === false);
t('hostNetwork was turned off', fdoc.spec.template.spec.hostNetwork === false);
t('the hardcoded credential now reads from a Secret', !!(c0.env[0].valueFrom || {}).secretKeyRef);
t('the latest tag was NOT auto changed, it needs a human', /payments:latest/.test(c0.image));
t('posture improvement is reported', /Posture \d+ -> \d+/.test(fx.stdout));

console.log('\nOutputs');
t('the HTML report exists', fs.existsSync(path.join(OUT, 'acs_audit_report.html')));
const rep = fs.readFileSync(path.join(OUT, 'acs_audit_report.html'), 'utf8');
t('the report contains the findings table', /Red Hat ACS Audit Report/.test(rep) && /ACS\.001/.test(rep));
t('the report carries the vulnerability section when CVEs were supplied',
  /Image vulnerabilities/.test(rep) && /CVE-2026-1000/.test(rep));
t('the report says CVEs are reported separately from posture',
  /Reported separately from the posture score/.test(rep));
t('no javascript: or data: URL survives into the report',
  !/href="javascript:/i.test(rep) && !/href="data:/i.test(rep));

const j = JSON.parse(fs.readFileSync(path.join(OUT, 'acs_findings.json'), 'utf8'));
t('the JSON has both posture numbers', j.posture.current && j.posture.projected);
t('the JSON carries the CVE block', j.vulnerabilities && j.vulnerabilities.cves.length === 2);
t('the priority scale is documented in the JSON, not left as a bare number',
  j.vulnerabilities.priorityScale.max === 15);

const sarif = JSON.parse(fs.readFileSync(path.join(OUT, 'acs_findings.sarif'), 'utf8'));
t('SARIF is version 2.1.0', sarif.version === '2.1.0');
t('SARIF has rules and results', sarif.runs[0].tool.driver.rules.length > 0 && sarif.runs[0].results.length > 0);
t('every SARIF result has a ruleId, level, message and location',
  sarif.runs[0].results.every((r) => r.ruleId && r.level && r.message.text &&
    r.locations[0].physicalLocation.artifactLocation.uri));
t('SARIF rules carry security-severity so the security tab can rank them',
  sarif.runs[0].tool.driver.rules.every((r) => r.properties['security-severity']));

t('the change log exists', fs.existsSync(path.join(OUT, 'CHANGES.md')));
const cl = fs.readFileSync(path.join(OUT, 'CHANGES.md'), 'utf8');
t('the change log records what still needs a human', /Still needs a human decision/.test(cl));
t('the change log states nothing was run against a cluster', /No command was run against a cluster/.test(cl));
t('the worklist exists and groups by image',
  fs.existsSync(path.join(OUT, 'image_worklist.md')) &&
  /## quay\.io\/acme\/payments:latest/.test(fs.readFileSync(path.join(OUT, 'image_worklist.md'), 'utf8')));

/* ---- merge patches ------------------------------------------------------- */

console.log('\nMerge patches, which were silently emitting the finding object');
const patchDir = path.join(OUT, 'patches');
const patches = fs.readdirSync(patchDir);
t('one patch per object, not one per finding', patches.length === 2);
const pc = fs.readFileSync(path.join(patchDir, 'Deployment_payments_api.yaml'), 'utf8');
const pdoc = yaml.load(pc);
t('the patch parses as YAML', !!pdoc);
t('it carries the changed security fields',
  pdoc.spec.template.spec.containers[0].securityContext.privileged === false);
t('it keys the container array on name, so it merges correctly',
  pdoc.spec.template.spec.containers[0].name === 'api');
/* The regression: the image field riding along would silently revert an image that was
   updated after the scan. And a patch containing policy text means the wrong object was
   diffed entirely. */
t('it does NOT carry the image field', !('image' in pdoc.spec.template.spec.containers[0]));
t('it does NOT contain finding internals', !/acsPolicy|rationale|fixKind/.test(pc));
t('it names the policies it covers', /# Covers: ACS\./.test(pc));

/* ---- guard rails --------------------------------------------------------- */

console.log('\nGuard rails');
const noGit = run(['--path', MAN, '--mode', 'auto', '--in-place']);
t('--in-place refuses outside a git repository', noGit.status === 2);
t('and explains why rather than just failing', /no undo/.test(noGit.stderr));

const only = run(['--path', MAN, '--mode', 'auto', '--only', 'ACS.001', '--out', path.join(WORK, 'o2'), '--quiet']);
t('--only restricts the fixes applied', only.status === 0);
const onlyFixed = yaml.load(fs.readFileSync(path.join(WORK, 'o2', 'fixed', 'app', 'deployment.yaml'), 'utf8'));
t('--only ACS.001 turned privileged off', onlyFixed.spec.template.spec.containers[0].securityContext.privileged === false);
t('--only ACS.001 left hostNetwork alone', onlyFixed.spec.template.spec.hostNetwork === true);

t('--dry-run with --fix writes no patched YAML',
  run(['--path', MAN, '--mode', 'auto', '--dry-run', '--out', path.join(WORK, 'o3'), '--quiet']).status === 0 &&
  !fs.existsSync(path.join(WORK, 'o3', 'fixed')));

t('a bad --vulns file exits 2 with an explanation',
  (function () {
    fs.writeFileSync(path.join(WORK, 'junk.ndjson'), 'not json at all\n');
    const r = run(['--path', MAN, '--vulns', path.join(WORK, 'junk.ndjson')]);
    return r.status === 2 && /No usable records/.test(r.stderr);
  })());
t('an unknown flag exits 2 rather than being ignored',
  run(['--path', MAN, '--nonsense']).status === 2);
t('a missing --path prints usage and exits 2', run([]).status === 2);

console.log('\nThe CLI and the GUI share one engine');
const cliSrc = fs.readFileSync(CLI, 'utf8');
t('the CLI reimplements no checks, it requires the engine',
  /require\(path\.join\(HERE, 'acs_policies\.js'\)\)/.test(cliSrc));
t('the CLI never spawns a shell to remediate anything',
  !/exec\(|execSync\(|spawn\(/.test(cliSrc.replace(/execFileSync/g, '')));
/* execFileSync with an argument ARRAY, not exec with a string. No shell is involved, so
   a repository path containing shell metacharacters cannot turn into command injection.
   This is the only subprocess the CLI ever starts. */
const callSites = cliSrc.match(/execFileSync\(/g) || [];
t('exactly one subprocess call site', callSites.length === 1);
t('it is git status, for the --in-place safety check only',
  /execFileSync\('git', \['status', '--porcelain'\]/.test(cliSrc));
t('it passes arguments as an array, so no shell can interpret the path',
  !/execFileSync\([^)]*\$\{/.test(cliSrc) && !/exec\(|execSync\(/.test(cliSrc));

fs.rmSync(WORK, { recursive: true, force: true });
console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
