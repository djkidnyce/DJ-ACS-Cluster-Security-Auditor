/* Loading workloads exported from a cluster as JSON.
 *
 * This was a shipped defect. The page accepted ACS alert exports and ACS vulnerability
 * exports and nothing else, so `oc get deploy -o json`, which is the most natural way to
 * dump workloads, was rejected outright with "could not read". The offline command the
 * tool printed only ever suggested -o yaml, so the JSON path was never considered.
 *
 * Every shape below is something oc actually produces.
 */
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const DEP = (name, ns) => ({
  apiVersion: 'apps/v1', kind: 'Deployment',
  metadata: {
    name: name, namespace: ns, uid: '8f0a-' + name, resourceVersion: '48211', generation: 4,
    creationTimestamp: '2026-03-02T10:11:12Z', selfLink: '/apis/apps/v1/x',
    managedFields: [{ manager: 'kubectl', operation: 'Update' }],
    ownerReferences: [{ kind: 'ReplicaSet', name: 'rs-1' }],
    annotations: { 'deployment.kubernetes.io/revision': '4', team: 'payments',
      'kubectl.kubernetes.io/last-applied-configuration': '{"huge":"blob"}' },
  },
  spec: { replicas: 2, template: { metadata: { creationTimestamp: null },
    spec: { hostNetwork: true, containers: [{ name: 'api', image: 'quay.io/acme/' + name + ':latest',
      securityContext: { privileged: true }, env: [{ name: 'DB_PASSWORD', value: 'hunter2' }] }] } } },
  status: { replicas: 2, readyReplicas: 2, conditions: [{ type: 'Available' }] },
});

console.log('\nShapes oc actually emits');
const shapes = [
  ['oc get deploy,ds -o json (kind: List)',
    JSON.stringify({ apiVersion: 'v1', kind: 'List', items: [DEP('a', 'prod'), DEP('b', 'tools')] }), 2],
  ['oc get deploy -o json (kind: DeploymentList)',
    JSON.stringify({ apiVersion: 'apps/v1', kind: 'DeploymentList', items: [DEP('a', 'prod')] }), 1],
  ['oc get deploy NAME -o json (a single object)', JSON.stringify(DEP('a', 'prod')), 1],
  ['a bare JSON array', JSON.stringify([DEP('a', 'prod'), DEP('b', 'prod')]), 2],
  ['NDJSON, one object per line',
    JSON.stringify(DEP('a', 'prod')) + '\n' + JSON.stringify(DEP('b', 'prod')), 2],
  ['concatenated objects from a shell loop, which is not valid JSON at all',
    JSON.stringify(DEP('a', 'prod'), null, 2) + '\n' + JSON.stringify(DEP('b', 'prod'), null, 2), 2],
];
for (const [label, text, want] of shapes) {
  const r = E.importKubeJson(text);
  t(label + ' -> ' + r.count + ' object(s)', r.count === want);
}

console.log('\nServer side bookkeeping is stripped, so the result is committable');
const one = E.importKubeJson(JSON.stringify(DEP('a', 'prod')));
const y = one.files[0].text;
for (const field of ['uid:', 'resourceVersion:', 'managedFields:', 'selfLink:', 'generation:',
                     'ownerReferences:', 'status:', 'last-applied-configuration', 'readyReplicas']) {
  t('  ' + field + ' removed', y.indexOf(field) === -1);
}
t('  a meaningful annotation survives', /team: payments/.test(y));
t('  the workload itself survives', /privileged: true/.test(y) && /hostNetwork: true/.test(y));
t('  the file is named by namespace and kind', one.files[0].name === 'live/prod/deployment-a.yaml');

console.log('\nThe imported object is actually scannable');
const f = E.parseFileText(one.files[0].name, y);
t('  it parses', f.docs.length === 1 && !f.errors.length);
const findings = E.scanFiles([f]);
t('  it produces findings', findings.length > 0);
t('  the hardcoded credential is caught', findings.some((x) => x.policy.id === 'ACS.010'));
t('  privileged is caught', findings.some((x) => x.policy.id === 'ACS.001'));
t('  hostNetwork is caught', findings.some((x) => x.policy.id === 'ACS.004'));

console.log('\nIt does not steal files belonging to the other importers');
const vuln = JSON.stringify({ result: { deployment: { name: 'x', namespace: 'prod' }, images: [] } });
t('  an ACS vulnerability export is not claimed as workloads', E.importKubeJson(vuln).count === 0);
const alerts = JSON.stringify({ alerts: [{ id: 'a', policy: { name: 'Privileged Container' } }] });
t('  an ACS alert export is not claimed as workloads', E.importKubeJson(alerts).count === 0);
t('  and the alert export still imports correctly', E.importAcsViolations(JSON.parse(alerts)).total === 1);

console.log('\nNon workload kinds are reported, not silently dropped');
const mixed = E.importKubeJson(JSON.stringify({ kind: 'List', items: [
  DEP('a', 'prod'),
  { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'cm', namespace: 'prod' }, data: {} },
  { apiVersion: 'v1', kind: 'Secret', metadata: { name: 's', namespace: 'prod' }, data: {} },
] }));
t('  only the workload is imported', mixed.count === 1);
t('  the skipped count is reported', mixed.skipped === 2 && /2 object\(s\) were not workload kinds/.test(mixed.errors.join(' ')));

console.log('\nBad input fails with an explanation rather than a stack trace');
t('  empty input', E.importKubeJson('').count === 0);
t('  plain text', E.importKubeJson('this is not json').count === 0);
t('  JSON that is not Kubernetes', E.importKubeJson('{"hello":"world"}').count === 0);
t('  and it says what it expected',
  /Expected something with a kind and metadata/.test(E.importKubeJson('{"hello":"world"}').errors.join(' ')));
t('  null and undefined', E.importKubeJson(null).count === 0 && E.importKubeJson(undefined).count === 0);

console.log('\nThe offline command now offers JSON, which is what people reach for');
const cmd = E.openshiftFallbackCommand('prod');
t('  suggests -o json', /-o json/.test(cmd));
t('  still offers yaml', /-o yaml/.test(cmd));
t('  scopes to the namespace', /-n prod/.test(cmd));
t('  says the server side fields are stripped on load', /strips all/.test(cmd));
const allNs = E.openshiftFallbackCommand('');
t('  blank namespace means all namespaces', /--all-namespaces/.test(allNs));

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
