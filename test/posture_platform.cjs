/* Two defects a user found in the field, and the regressions that keep them fixed.
 *
 * 1. Posture over zero manifests.
 *    computePosture([], []) returns 100 out of 100, Grade A. The arithmetic is right and
 *    the meaning is wrong: nothing was scanned, so nothing was found, so the score is
 *    perfect. An operator who loaded only an ACS export saw a green A and could
 *    reasonably conclude the cluster was clean. The CLI already refused to print it. The
 *    pages did not. That is the single most misleading thing this tool could output.
 *
 * 2. Privilege escalation findings dead ended at "Platform".
 *    The policy exists (ACS.003), it is auto fixable, and it has a patch template. The
 *    refusal came entirely from the platform classification, and that classification is
 *    sometimes a guess: when ACS does not send platformComponent, the tool matches the
 *    namespace instead. A team's own workload in openshift-operators was refused forever,
 *    with no way to say "I own this one".
 */
'use strict';
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
const fs = require('fs'), path = require('path');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

/* ---------------------------------------------------- 1. scoring nothing */

console.log('\nA score over zero manifests is refused, not shown as 100');
const empty = E.computePosture([], [], false);
t('the engine still computes 100 over nothing, which is why callers must guard',
  empty.score === 100 && empty.grade === 'A');

const ROOT = path.join(__dirname, '..');
for (const page of ['dj_acs_auditor.html', 'dj_acs_remediation.html']) {
  const src = fs.readFileSync(path.join(ROOT, page), 'utf8');
  /* The guard must come BEFORE the score is computed and rendered, not after. */
  const guard = src.indexOf("if (!STATE.files.length)");
  const posture = src.indexOf('computePosture(STATE.files');
  t(page + ': guards on an empty file list', guard !== -1);
  t(page + ': the guard runs before posture is computed', guard !== -1 && guard < posture);
  t(page + ': it explains that scoring nothing is not clean',
    /not the same as|means unmeasured rather than clean/.test(src));
  t(page + ': and says how to get a real score',
    /oc get deployment|Drop in the YAML/.test(src));
}
const cli = fs.readFileSync(path.join(ROOT, 'acs_cli.js'), 'utf8');
t('the CLI refuses too, and has since before the pages did',
  /No manifests were scanned, so there is no posture score/.test(cli));

/* ------------------------------------------- 2. privilege escalation route */

const mk = (ns, flag, obj) => ({ alerts: [{
  id: 'v-' + obj, state: 'ACTIVE',
  ...(flag === undefined ? {} : { platformComponent: flag }),
  namespace: ns, clusterName: 'ocp',
  policy: { id: 'p', name: 'Container with privilege escalation allowed', severity: 'HIGH_SEVERITY' },
  deployment: { name: obj, type: 'Deployment', namespace: ns },
  violations: [{ message: 'Container "webhook" allows privilege escalation' }] }] });
const first = (j) => { const a = E.importAcsViolations(j); return a.imported.concat(a.unmatched)[0]; };

console.log('\nThe privilege escalation policy is modelled and fixable');
const plain = first(mk('prod', false, 'payments-api'));
t('the violation matches a policy', plain.matched && plain.policy.id === 'ACS.003');
t('that policy is auto fixable, not a human decision', plain.policy.fixKind !== 'manual');
t('and it has a patch template, so it works with no manifest',
  !!E.VIOLATION_PATCHES['ACS.003']);
t('an ordinary workload gets a real fix route',
  E.violationFixability(plain, false).kind === 'patch');

console.log('\nHow the platform classification was reached is recorded');
const guessed = first(mk('openshift-operators', undefined, 'cert-manager-webhook'));
const told = first(mk('openshift-etcd', true, 'etcd-operator'));
t('a namespace match is marked as a guess', guessed.isPlatform && guessed.platformSource === 'namespace');
t('an ACS flag is marked as authoritative', told.isPlatform && told.platformSource === 'acs');
t('and a false flag is authoritative too, not a fallback to the namespace',
  first(mk('openshift-operators', false, 'my-app')).isPlatform === false);

console.log('\nThe refusal says which of the two it is, because they differ in confidence');
const fg = E.violationFixability(guessed, false);
const ft = E.violationFixability(told, false);
t('the guess admits it is a guess', /guess rather than something ACS told us/.test(fg.why));
t('and names the namespace that triggered it', /openshift-operators/.test(fg.why));
t('the ACS one says it is authoritative', /authoritative/.test(ft.why));
t('both are marked overridable', fg.overridable === true && ft.overridable === true);

console.log('\nOverriding is per finding and produces the correct fix');
t('without an override there is no fix', fg.fixable === false);
const ov = E.violationFixability(guessed, false, { overridePlatform: true });
t('with one, the normal route applies', ov.fixable === true && ov.kind === 'patch');
t('and the consequence is stated, not buried', /operator will revert/.test(ov.why));

const acs = E.importAcsViolations(mk('openshift-operators', undefined, 'cert-manager-webhook'));
const key = E.violationKey(acs.imported.concat(acs.unmatched)[0]);
const none = E.buildViolationFixBundle(acs, { filesByObj: {}, mode: 'manual' });
t('the bundle refuses by default', none.files.length === 0);
const some = E.buildViolationFixBundle(acs, { filesByObj: {}, mode: 'manual', overridden: [key] });
t('and honours the override', some.files.length === 1);

const y = some.files[0].text;
const doc = jsyaml.load(y.replace(/^#.*$/gm, ''));
t('the patch sets allowPrivilegeEscalation to false, which is the actual fix',
  doc.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation === false);
t('on the container named in the violation text',
  doc.spec.template.spec.containers[0].name === 'webhook');
t('and changes nothing else on that container',
  Object.keys(doc.spec.template.spec.containers[0]).sort().join(',') === 'name,securityContext');
t('the file warns that it was overridden', /OVERRIDE:/.test(y));
t('and that an operator will revert it', /will revert/.test(y));
t('it is still data rather than a command', /This file is data, not a command/.test(y));

console.log('\nAn override is never global');
const two = E.importAcsViolations({ alerts: [
  mk('openshift-operators', undefined, 'cert-manager-webhook').alerts[0],
  mk('openshift-etcd', true, 'etcd-operator').alerts[0]] });
const recs = two.imported.concat(two.unmatched);
const oneKey = E.violationKey(recs.find((r) => /cert-manager/.test(r.obj)));
const partial = E.buildViolationFixBundle(two, { filesByObj: {}, mode: 'manual', overridden: [oneKey] });
t('overriding one platform object does not release the others',
  partial.files.length === 1 && /cert_manager/.test(partial.files[0].name));
t('the other is still refused and still explained',
  partial.skipped.some((x) => x.kind === 'platform' && /etcd/.test(x.rec.obj)));

console.log('\nReport mode still withholds an overridden patch');
const rep = E.buildViolationFixBundle(acs, { filesByObj: {}, mode: 'report', overridden: [key] });
t('an override does not bypass the mode gate', rep.files.length === 0 && rep.suppressed === 1);

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
