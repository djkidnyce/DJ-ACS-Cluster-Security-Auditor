/* Platform violations, all violation states, and fixing violations without a manifest.
 *
 * Three things drove this:
 *   The ACS console Violations page defaults to USER workloads. Since 4.6 there is a
 *   selector for user, platform, or both. A default API pull that does not set the term
 *   can therefore differ from what an operator is looking at on screen.
 *
 *   The console also shows ACTIVE violations. RESOLVED and ATTEMPTED exist and matter:
 *   resolved proves a fix landed, attempted means enforcement blocked a deploy.
 *
 *   A violation whose manifest you do not have was previously a dead end. ACS gives the
 *   kind, name and namespace, which is enough to emit a merge patch.
 */
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
const yaml = require('../vendor/js-yaml.min.js');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const A = (id, pol, sev, kind, name, ns, plat, msg, state) => ({
  id: id, state: state || 'ACTIVE', platformComponent: plat,
  policy: { name: pol, severity: sev },
  deployment: { name: name, deploymentType: kind },
  commonEntityInfo: { namespace: ns, clusterName: 'ocp-prod' },
  violations: [{ message: msg }],
});

const SET = { alerts: [
  A('1', 'Privileged Container', 'HIGH_SEVERITY', 'Deployment', 'payments-api', 'prod', false, 'Container "api" is privileged'),
  A('2', 'Deployments should not have host network configured', 'HIGH_SEVERITY', 'Deployment', 'payments-api', 'prod', false, 'uses host network'),
  A('3', 'Privileged Container', 'HIGH_SEVERITY', 'DaemonSet', 'ovnkube-node', 'openshift-ovn-kubernetes', true, 'Container "ovn-controller" is privileged'),
  A('4', 'Latest tag', 'MEDIUM_SEVERITY', 'Deployment', 'web', 'prod', false, 'latest tag', 'RESOLVED'),
  A('5', 'Some Custom Policy', 'LOW_SEVERITY', 'Deployment', 'x', 'prod', false, 'whatever'),
  A('6', 'Deployments should not run as root user', 'HIGH_SEVERITY', 'Deployment', 'api2', 'prod', false, 'runs as root', 'ATTEMPTED'),
] };

/* ---- query scope --------------------------------------------------------- */

console.log('\nQuery scope: the console hides things this tool should not');
t('the default asks for BOTH user and platform',
  E.buildAlertQuery({}) === 'Platform Component:true,false');
t('the default does NOT restrict violation state, so resolved and attempted come too',
  !/Violation State/.test(E.buildAlertQuery({})));
t('user only is available for matching the console',
  E.buildAlertQuery({ platform: 'user' }) === 'Platform Component:false');
t('platform only is available', E.buildAlertQuery({ platform: 'platform' }) === 'Platform Component:true');
t('omit exists for ACS older than 4.6, where the field does not exist',
  E.buildAlertQuery({ platform: 'omit' }) === '');
t('an explicit state is honoured',
  /Violation State:ACTIVE/.test(E.buildAlertQuery({ violationState: 'ACTIVE' })));
t('a Platform Component term already in the user query is not doubled',
  (E.buildAlertQuery({ query: 'Platform Component:true' }).match(/Platform Component/g) || []).length === 1);
t('scoping by namespace still works alongside',
  /Namespace:prod/.test(E.buildAlertQuery({ namespace: 'prod' })));

/* ---- the split ----------------------------------------------------------- */

console.log('\nSplitting platform from your workloads');
const r = E.importAcsViolations(SET);
t('everything imports', r.total === 6);
t('platform violations are counted', r.platform === 1);
t('your workloads are counted', r.user === 5);
t('the flag is recognised as authoritative when ACS sends it', r.platformFlagPresent === true);
t('the platform one is flagged', r.imported.concat(r.unmatched).find((x) => x.obj === 'DaemonSet/ovnkube-node').isPlatform === true);
t('a prod workload is not flagged', r.imported.find((x) => x.obj === 'Deployment/payments-api').isPlatform === false);
t('all three states survive the import',
  ['ACTIVE', 'RESOLVED', 'ATTEMPTED'].every((st) =>
    r.imported.concat(r.unmatched).some((x) => x.state === st)));

/* When ACS predates 4.6 the flag is absent, and guessing from the namespace is the only
   option left. It must be labelled a guess, not presented as the same thing. */
console.log('\nOlder ACS: no flag, so the split falls back to a namespace heuristic');
const noFlag = E.importAcsViolations({ alerts: SET.alerts.map((a) => {
  const c = JSON.parse(JSON.stringify(a)); delete c.platformComponent; return c; }) });
t('the tool reports that the flag was absent', noFlag.platformFlagPresent === false);
t('the heuristic still catches an openshift- namespace', noFlag.platform === 1);
t('and it does not misclassify prod', noFlag.imported.every((x) => x.namespace !== 'prod' || !x.isPlatform));
for (const ns of ['openshift-etcd', 'kube-system', 'stackrox', 'rhacs-operator', 'openshift']) {
  t('  ' + ns + ' reads as platform', E.looksPlatform({ namespace: ns }) === true);
}
for (const ns of ['prod', 'openshifty-app', 'kubed', 'my-openshift-clone']) {
  t('  ' + ns + ' reads as yours', E.looksPlatform({ namespace: ns }) === false);
}

/* ---- fixing -------------------------------------------------------------- */

console.log('\nThe mode gate applies here too: report is the default');
const bRep = E.buildViolationFixBundle(r, { filesByObj: {} });
t('calling it with no mode gives you report, not patches', bRep.mode === 'report');
t('report mode emits no patch files at all', bRep.files.length === 0);
t('but it still counts what it withheld', bRep.suppressed === 2);
t('and the report lists them, so scope stays visible', /would be emitted/.test(bRep.report));
t('the mode is recorded in the report', /Mode: report/.test(bRep.report));

console.log('\nFixing violations when the manifest is nowhere to be found');
const b = E.buildViolationFixBundle(r, { filesByObj: {}, mode: 'manual' });
t('manual mode emits the patches', b.files.length === 2);
t('and records the mode in the report', /Mode: manual/.test(b.report));
t('one file per object, with both policies merged in',
  b.files.some((f) => /payments_api/.test(f.name)) &&
  /ACS\.001, ACS\.004/.test(b.files.find((f) => /payments_api/.test(f.name)).text));

const pay = yaml.load(b.files.find((f) => /payments_api/.test(f.name)).text);
t('the patch targets the right object', pay.kind === 'Deployment' && pay.metadata.name === 'payments-api');
t('and the right namespace', pay.metadata.namespace === 'prod');
t('the container name was parsed out of the violation text',
  pay.spec.template.spec.containers[0].name === 'api');
t('the container level fix is present', pay.spec.template.spec.containers[0].securityContext.privileged === false);
t('the pod level fix is present too', pay.spec.template.spec.hostNetwork === false);
t('nothing else rides along', !('image' in pay.spec.template.spec.containers[0]));

console.log('\nWhat it refuses to fix, and why');
const kinds = {};
for (const sk of b.skipped) kinds[sk.kind] = (kinds[sk.kind] || 0) + 1;
t('the platform violation is refused', kinds.platform === 1);
t('a manual policy is refused', kinds.manual === 1);
t('an unmatched policy is refused', kinds.unmatched === 1);
t('the platform refusal explains the operator will revert it',
  /reverts manual edits/.test(b.skipped.find((x) => x.kind === 'platform').why));
t('the report names every category', /Platform components, not yours to fix/.test(b.report) &&
  /Need a human decision/.test(b.report) && /No matching policy/.test(b.report));
t('the report states nothing was applied', /No command was run/.test(b.report));

console.log('\nWhen the manifest IS loaded, it is fixed there instead of patched blind');
const b2 = E.buildViolationFixBundle(r, { filesByObj: { 'Deployment/payments-api': 'app/dep.yaml' }, mode: 'manual' });
t('that object is routed to the in place path', b2.inplace.length === 2);
t('and no competing patch is emitted for it',
  !b2.files.some((f) => /payments_api/.test(f.name)));

/* The dangerous case. A strategic merge patch keys containers on name. A blank name does
   not patch your container, it ADDS a nameless one. It has to be impossible to miss. */
console.log('\nA container name that could not be parsed is flagged loudly');
const vague = E.importAcsViolations({ alerts: [
  A('9', 'Privileged Container', 'HIGH_SEVERITY', 'Deployment', 'mystery', 'prod', false,
    'this deployment has a privileged container somewhere') ] });
const b3 = E.buildViolationFixBundle(vague, { filesByObj: {}, mode: 'manual' });
t('the patch is still emitted rather than silently dropped', b3.files.length === 1);
t('it is flagged as needing the name', b3.files[0].needsContainerName === true);
t('and the file itself warns, in the file, where it cannot be missed',
  /WARNING: the container name could not be read/.test(b3.files[0].text));
t('the warning explains it would ADD a container', /ADD a nameless container/.test(b3.files[0].text));
t('the report marks it too', /container name missing, fill it in/.test(b3.report));

console.log('\nContainer name parsing');
t('double quoted', E.containerFromViolation({ detail: 'Container "web" is privileged' }) === 'web');
t("single quoted", E.containerFromViolation({ detail: "Container 'web-1' has X" }) === 'web-1');
t('unquoted followed by a verb', E.containerFromViolation({ detail: 'Container sidecar runs as root' }) === 'sidecar');
t('absent returns empty rather than a guess', E.containerFromViolation({ detail: 'something is wrong' }) === '');

console.log('\nCronJob and Pod nest the pod spec differently');
const cj = E.buildViolationPatch(Object.assign(
  E.importAcsViolations({ alerts: [A('c', 'Deployments should not have host network configured',
    'HIGH_SEVERITY', 'CronJob', 'nightly', 'batch', false, 'host network')] }).imported[0], {}));
t('a CronJob patch nests under jobTemplate',
  !!cj.patch.spec.jobTemplate.spec.template.spec && cj.patch.spec.jobTemplate.spec.template.spec.hostNetwork === false);
t('and uses batch/v1', cj.patch.apiVersion === 'batch/v1');

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
