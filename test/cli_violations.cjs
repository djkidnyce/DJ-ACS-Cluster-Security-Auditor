/* The CLI drafting violation fixes to YAML, run as a real process.
 *
 * test/cli.cjs exercises the argument surface. This runs the actual binary end to end
 * against the files acs_pull_all.sh writes, because the promise being tested is not "the
 * function returns a bundle", it is "you run this and get YAML on disk that you can read,
 * test in a namespace you do not care about, and apply yourself".
 *
 * The strongest assertion in this file is the negative one: report mode leaves nothing on
 * disk that anyone could apply, deliberately or by muscle memory.
 */
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs'), path = require('path'), os = require('os');
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const ROOT = path.join(__dirname, '..');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'acscli-'));
const ALERTS = path.join(work, 'alerts.json');
fs.writeFileSync(ALERTS, JSON.stringify({ alerts: [
  { id: 'a1', state: 'ACTIVE', platformComponent: false, namespace: 'batch', clusterName: 'ocp-prod',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
    deployment: { name: 'batch-runner', type: 'Deployment', namespace: 'batch' },
    violations: [{ message: 'Container "runner" is privileged' }] },
  { id: 'a2', state: 'ACTIVE', platformComponent: true, namespace: 'openshift-ovn-kubernetes',
    clusterName: 'ocp-prod',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
    deployment: { name: 'ovnkube-node', type: 'DaemonSet', namespace: 'openshift-ovn-kubernetes' },
    violations: [{ message: 'Container "ovn-controller" is privileged' }] }] }));

function run(args) {
  try {
    return { code: 0, out: execFileSync(process.execPath,
      [path.join(ROOT, 'acs_cli.js')].concat(args), { encoding: 'utf8', stdio: 'pipe' }) };
  } catch (e) {
    return { code: e.status, out: (e.stdout || '') + (e.stderr || '') };
  }
}
const walk = (d) => !fs.existsSync(d) ? [] : fs.readdirSync(d, { withFileTypes: true })
  .flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);

/* ---------------------------------------------------------------- report */

console.log('\nReport mode writes an account and nothing applicable');
const outR = path.join(work, 'r');
const r = run(['--alerts', ALERTS, '--violation-fixes', '--out', outR]);
t('the run succeeds', r.code === 0);
const filesR = walk(outR).map((f) => path.relative(outR, f));
t('the account is written', filesR.indexOf('FIXING_VIOLATIONS.md') !== -1);
t('no YAML is written at all', filesR.every((f) => !/\.ya?ml$/.test(f)));
t('and nothing else applicable either',
  filesR.every((f) => !/\.(sh|json|patch)$/.test(f)));
t('the output says how many patches it withheld', /1 patch\(es\) NOT written/.test(r.out));
t('and how to get them', /--mode manual/.test(r.out));
const accountR = fs.readFileSync(path.join(outR, 'FIXING_VIOLATIONS.md'), 'utf8');
t('the account names the object it would have patched, not just a filename',
  /\*\*Deployment\/batch-runner\*\* in `batch`/.test(accountR));
t('and which policy it covers, so the scope is readable without opening anything',
  /ACS\.001/.test(accountR));
t('the account records the mode it ran in', /Mode: report/.test(accountR));

/* ---------------------------------------------------------------- manual */

console.log('\nManual mode drafts YAML you can review');
const outM = path.join(work, 'm');
const m = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'manual', '--out', outM]);
t('the run succeeds', m.code === 0);
const yamls = walk(outM).filter((f) => /\.ya?ml$/.test(f));
t('exactly one patch is drafted, for the one fixable violation', yamls.length === 1);
const text = fs.readFileSync(yamls[0], 'utf8');
const doc = jsyaml.load(text.replace(/^#.*$/gm, ''));
t('it is valid YAML', !!doc);
t('it is a Deployment named for the violating object',
  doc.kind === 'Deployment' && doc.metadata.name === 'batch-runner');
t('it carries the namespace, so oc apply cannot land it in the wrong one',
  doc.metadata.namespace === 'batch');
t('it sets exactly the field the violation was about',
  doc.spec.template.spec.containers[0].securityContext.privileged === false);
t('the container name came from the violation text, so the merge keys correctly',
  doc.spec.template.spec.containers[0].name === 'runner');
t('the header states it was built from a violation and needs verifying',
  /Built from an ACS violation/.test(text));
t('the header states nothing was applied', /This file is data, not a command/.test(text));
t('the file contains no command anyone could paste',
  !/^\s*(kubectl|oc|curl|bash|sh)\b/m.test(text));

console.log('\nPlatform components are listed and never patched');
t('no patch was drafted for the platform component',
  yamls.every((f) => !/ovnkube/.test(f)));
const accountM = fs.readFileSync(path.join(outM, 'FIXING_VIOLATIONS.md'), 'utf8');
t('but the violation is still in the account, not hidden', /ovnkube-node/.test(accountM));
t('with the reason it was refused',
  /operator|reconcil|revert|platform/i.test(accountM));

/* ------------------------------------------------------- mode is never inferred */

console.log('\nThe mode is chosen, never inferred from what you asked for');
t('asking for violation fixes does not by itself grant manual',
  /report/.test(r.out) && filesR.every((f) => !/\.ya?ml$/.test(f)));
const bad = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'yolo', '--out', path.join(work, 'x')]);
t('an unknown mode is an error, not a silent downgrade to something permissive',
  bad.code !== 0 && /mode/i.test(bad.out));
t('and it wrote nothing', walk(path.join(work, 'x')).length === 0);

/* ---------------------------------------------------------------- auto */

console.log('\nAuto mode still cannot apply a patch to a cluster');
const outA = path.join(work, 'a');
const a = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'auto', '--out', outA]);
t('the run succeeds', a.code === 0);
t('it writes the same YAML', walk(outA).some((f) => /\.ya?ml$/.test(f)));
t('it does not emit a script to apply them',
  walk(outA).every((f) => !/\.sh$/.test(f)));
t('nothing in the output claims anything was applied to a cluster',
  !/applied to the cluster|has been applied/i.test(a.out));

/* ------------------------------------------------- choosing what to act on */

console.log('\nYou can choose which violations to act on');
const list = run(['--alerts', ALERTS, '--list-violations']);
t('--list-violations succeeds', list.code === 0);
t('it prints a key per violation', /\ba1\b/.test(list.out) && /\ba2\b/.test(list.out));
t('with the object each one is about', /batch-runner/.test(list.out) && /ovnkube-node/.test(list.out));
t('and the fix route, so you can see what selecting it would do',
  /patch/.test(list.out) && /platform/.test(list.out));
t('it writes nothing, so it is safe against production data',
  walk(path.join(work, 'listcheck')).length === 0);

const outS = path.join(work, 's');
const one = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'manual',
                 '--select', 'a1', '--out', outS]);
t('selecting one violation succeeds', one.code === 0);
t('it says how much of the total it matched', /matched 1 of 2/.test(one.out));
const selYaml = walk(outS).filter((f) => /\.ya?ml$/.test(f));
t('exactly one patch is drafted', selYaml.length === 1);
t('and it is the one that was selected', /batch_runner/.test(selYaml[0]));

/* A report covering a subset must say so. Otherwise it reads identically to a report
   covering the whole cluster, and nobody reading it later can tell which they have. */
const accountS = fs.readFileSync(path.join(outS, 'FIXING_VIOLATIONS.md'), 'utf8');
t('the report states the scope it covers', /1 of 2 violation\(s\) were selected/.test(accountS));
t('and warns that the rest are not described anywhere in it',
  /covers the selection, not the cluster/.test(accountS));

console.log('\nSelection accepts whichever identifier you have to hand');
for (const [label, term, expect] of [
  ['an object name', 'Deployment/batch-runner', 1],
  ['a policy id', 'ACS.001', 2],
  ['a policy name', 'Privileged Container', 2],
]) {
  const o = path.join(work, 'sel_' + term.replace(/[^a-z0-9]/gi, '_'));
  const r2 = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'manual', '--select', term, '--out', o]);
  t('  ' + label + ' selects ' + expect, r2.code === 0 && new RegExp('matched ' + expect + ' of 2').test(r2.out));
}

console.log('\nSelecting the platform violation alone drafts nothing, and says why');
const outP = path.join(work, 'p');
const plat = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'manual',
                  '--select', 'DaemonSet/ovnkube-node', '--out', outP]);
t('the run succeeds rather than erroring', plat.code === 0);
t('no YAML is drafted', walk(outP).every((f) => !/\.ya?ml$/.test(f)));
t('and the reason is in the report',
  /not yours to fix/i.test(fs.readFileSync(path.join(outP, 'FIXING_VIOLATIONS.md'), 'utf8')));

console.log('\nA selection that matches nothing is refused, not ignored');
const outT = path.join(work, 't');
const typo = run(['--alerts', ALERTS, '--violation-fixes', '--mode', 'manual',
                  '--select', 'Deployment/tpyo', '--out', outT]);
t('it exits non zero', typo.code !== 0);
t('it names the term that matched nothing', /Deployment\/tpyo/.test(typo.out));
t('it points at --list-violations', /--list-violations/.test(typo.out));
t('it explains that guessing would widen the scope rather than narrow it',
  /widen the scope/.test(typo.out));
t('and it writes nothing at all', walk(outT).length === 0);

console.log('\nNo selection still means everything, so nothing broke for existing callers');
t('the unselected run drafted the same single patch as before', yamls.length === 1);
t('and its report does not claim a partial scope',
  !/were selected/.test(accountM) && /Scope: all 2/.test(accountM));

fs.rmSync(work, { recursive: true, force: true });
console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
