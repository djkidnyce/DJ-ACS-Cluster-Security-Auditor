/* Loading what acs_pull_all.sh actually writes.
 *
 * Every assertion here corresponds to something a user hit in practice:
 *
 *   Three of the six files the pull script writes were rejected outright with
 *   "could not read ... Expected one of: kubernetes or openshift objects". The vuln
 *   parser required a deployment or an images array, and /v1/export/images and
 *   /v1/export/nodes return a bare storage.Image and storage.Node, which have neither.
 *
 *   Dropping several files loaded only one. Each import replaced the last rather than
 *   merging, so the file that happened to land last was the only one you saw.
 *
 *   Violations were reported as counts with no way to see or act on them.
 */
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const V = (cve, sev, cvss, fixedBy, extra) => Object.assign({
  cve: cve, severity: sev, cvss: cvss, summary: cve,
  link: 'https://access.redhat.com/security/cve/' + cve,
  fixedBy: fixedBy || '', state: 'OBSERVED' }, extra || {});

/* The six shapes, exactly as the endpoints return them. */
const F01 = JSON.stringify({ alerts: [{
  id: 'a1', state: 'ACTIVE', lifecycleStage: 'DEPLOY', platformComponent: false,
  policy: { id: 'p1', name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
  deployment: { id: 'd1', name: 'payments-api', deploymentType: 'Deployment' },
  commonEntityInfo: { namespace: 'prod', clusterName: 'ocp-prod' } }] });

const F02 = JSON.stringify({ alerts: [
  { id: 'a1', state: 'ACTIVE', platformComponent: false, namespace: 'prod', clusterName: 'ocp-prod',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
    deployment: { id: 'd1', name: 'payments-api', type: 'Deployment', namespace: 'prod' },
    violations: [{ message: 'Container "api" is privileged' }] },
  { id: 'a3', state: 'ACTIVE', platformComponent: true, namespace: 'openshift-ovn-kubernetes',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'HIGH_SEVERITY' },
    deployment: { name: 'ovnkube-node', type: 'DaemonSet', namespace: 'openshift-ovn-kubernetes' },
    violations: [{ message: 'Container "ovn-controller" is privileged' }] }] });

const F03 = JSON.stringify({ result: {
  deployment: { name: 'payments-api', namespace: 'prod', type: 'Deployment', clusterName: 'ocp-prod' },
  livePods: 2, images: [{ id: 'sha256:a', name: { fullName: 'quay.io/acme/payments:1.4' },
    scan: { scanTime: 't', components: [{ name: 'openssl', version: '3.0.7',
      vulns: [V('CVE-2026-1000', 'CRITICAL_VULNERABILITY_SEVERITY', 9.8, '3.0.14', { cisaKev: true })] }] } }] } });

/* No deployment. No images array. This is what /v1/export/images returns. */
const F04 = JSON.stringify({ result: { id: 'sha256:x', name: { fullName: 'quay.io/acme/unused:1.0' },
  scan: { components: [{ name: 'glibc', version: '2.34',
    vulns: [V('CVE-2026-2000', 'IMPORTANT_VULNERABILITY_SEVERITY', 7.5, '2.35')] }] } } });

/* A node. name is a plain string, not an object. */
const F05 = JSON.stringify({ result: { id: 'n1', name: 'worker-1', clusterName: 'ocp-prod',
  scan: { components: [{ name: 'kernel', version: '5.14',
    vulns: [V('CVE-2026-3000', 'IMPORTANT_VULNERABILITY_SEVERITY', 8.1, '5.15')] }] } } });

const F06 = JSON.stringify({ result: { id: 'sha256:s', name: { fullName: 'quay.io/acme/old:1.0' },
  scan: { components: [{ name: 'zlib', version: '1.2',
    vulns: [V('CVE-2026-4000', 'LOW_VULNERABILITY_SEVERITY', 3.1, '', { state: 'DEFERRED', suppressed: true })] }] } } });

/* ---- every shape is accepted ------------------------------------------- */

console.log('\nAll six files acs_pull_all.sh writes are understood');
function classify(text) {
  const k = E.importKubeJson(text);
  if (k.count) return 'workloads';
  const v = E.parseVulnExport(text);
  if (v.records.length) return 'vuln';
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j) || j.alerts || j.results || j.alert || (j.id && j.policy)) return 'alerts';
  } catch (e) { /* not one document */ }
  return 'REJECTED';
}
t('01_alerts_list.json      reads as alerts', classify(F01) === 'alerts');
t('02_alerts_full.json      reads as alerts', classify(F02) === 'alerts');
t('03_vuln_workloads.ndjson reads as CVE data', classify(F03) === 'vuln');
t('04_all_images.ndjson     reads as CVE data', classify(F04) === 'vuln');
t('05_nodes.ndjson          reads as CVE data', classify(F05) === 'vuln');
t('06_snoozed.ndjson        reads as CVE data', classify(F06) === 'vuln');

console.log('\nAn image with no running workload is labelled honestly');
const img = E.importVulnFindings(E.parseVulnExport(F04));
t('the CVE is imported', img.rows.length === 1);
t('it is not attributed to a deployment that does not exist',
  /not deployed/.test(img.rows[0].workloads[0]));
t('livePods is zero, so it does not collect the running bonus',
  img.rows[0].livePods === 0 && !img.rows[0].reasons.some((r) => /running this image/.test(r)));

console.log('\nA node CVE is imported and marked as a node');
const nd = E.importVulnFindings(E.parseVulnExport(F05));
t('the CVE is imported', nd.rows.length === 1);
t('the image is named for the node, so it is traceable', nd.rows[0].image === 'node/worker-1');
t('it is not silently attributed to a workload', /\(node\)/.test(nd.rows[0].workloads[0]));

/* ---- merging, not overwriting ------------------------------------------ */

console.log('\nDropping several files merges them rather than replacing');
let acs = null;
acs = E.mergeAcsImports(acs, E.importAcsViolations(JSON.parse(F01)));
t('after the first file there is one alert', acs.total === 1);
t('and it has no violation text, because ListAlert has none', acs.imported[0].hydrated === false);
acs = E.mergeAcsImports(acs, E.importAcsViolations(JSON.parse(F02)));
t('after the second there are two, not three: a1 was deduplicated', acs.total === 2);
const a1 = acs.imported.concat(acs.unmatched).find((r) => r.acsAlertId === 'a1');
t('and the hydrated copy of a1 won', a1.hydrated === true && /is privileged/.test(a1.detail));
t('the platform violation came through too', acs.platform === 1 && acs.user === 1);

let v = null;
for (const f of [F03, F04, F05, F06]) v = E.mergeVulnImports(v, E.importVulnFindings(E.parseVulnExport(f)));
t('four CVE files merge to four distinct CVEs', v.rows.length === 4);
t('each keeps its own image', new Set(v.rows.map((r) => r.image)).size === 4);
const sum = E.summarizeVulns(v);
t('the deferred one is excluded from active but still counted',
  sum.active === 3 && sum.accepted === 1);

console.log('\nMerging the same file twice changes nothing');
const twice = E.mergeVulnImports(v, E.importVulnFindings(E.parseVulnExport(F03)));
t('no duplicate rows appear', twice.rows.length === 4);
const acsTwice = E.mergeAcsImports(acs, E.importAcsViolations(JSON.parse(F02)));
t('no duplicate alerts appear', acsTwice.total === 2);

console.log('\nPer image counts are recomputed, not summed');
const dup = E.mergeVulnImports(
  E.importVulnFindings(E.parseVulnExport(F03)),
  E.importVulnFindings(E.parseVulnExport(F03)));
const im = dup.images.find((x) => /payments/.test(x.ref));
t('an image seen in two exports does not double count its CVEs', im.cves === 1);

/* ---- violations are actionable ----------------------------------------- */

console.log('\nEvery violation gets a fix route, so none is just a number');
const full = E.importAcsViolations(JSON.parse(F02));
for (const r of full.imported.concat(full.unmatched)) {
  const fx = E.violationFixability(r, false);
  t('  ' + r.obj + ' has a route (' + fx.kind + ') and a reason',
    !!fx.kind && !!fx.why && fx.why.length > 20);
}
const userRec = full.imported.find((r) => !r.isPlatform);
t('a matched violation with no manifest can be patched',
  E.violationFixability(userRec, false).kind === 'patch');
t('the same violation with the manifest loaded is fixed in place instead',
  E.violationFixability(userRec, true).kind === 'inplace');
const platRec = full.imported.concat(full.unmatched).find((r) => r.isPlatform);
t('a platform violation is refused whether or not a manifest exists',
  E.violationFixability(platRec, true).fixable === false &&
  E.violationFixability(platRec, false).fixable === false);

console.log('\nDrafting the fix produces reviewable YAML');
const bundle = E.buildViolationFixBundle(full, { filesByObj: {}, mode: 'manual' });
t('a patch file is produced', bundle.files.length === 1);
const y = bundle.files[0].text;
t('it parses as YAML', !!jsyaml.load(y.replace(/^#.*$/gm, '')));
const doc = jsyaml.load(y.replace(/^#.*$/gm, ''));
t('it names the right object', doc.kind === 'Deployment' && doc.metadata.name === 'payments-api');
t('it carries the namespace so it can be applied', doc.metadata.namespace === 'prod');
t('it sets the field the violation was about',
  doc.spec.template.spec.containers[0].securityContext.privileged === false);
t('the container name came from the violation text',
  doc.spec.template.spec.containers[0].name === 'api');
t('the header says it was built from a violation, not a manifest',
  /Built from an ACS violation/.test(y));
t('and that nothing was applied', /This file is data, not a command/.test(y));
t('the platform violation is not in the patches', !/ovnkube/.test(y));
t('and the report explains why it was refused',
  /Platform components, not yours to fix/.test(bundle.report));

/* ---- files that cannot be loaded say why ------------------------------- */

console.log('\nA file that cannot be loaded is told what it is, not what it is not');
const own = JSON.stringify({ tool: "DJ's ACS Auditor v1.0", generated: '2026-08-19T00:00:00Z',
  scope: { files: 3 }, posture: { current: 71 }, findings: [{ id: 'ACS.001' }] });
t('our own findings export is not accepted as an input', classify(own) === 'REJECTED');
const whyOwn = E.describeUnloadable(own);
t('and it is identified as our own output', /written by .* itself/.test(whyOwn));
t('with the reason it cannot be rescanned', /does not contain the manifests/.test(whyOwn));
t('and what to load instead', /03_vuln_workloads\.ndjson/.test(whyOwn));

const apiErr = JSON.stringify({ kind: 'Status', status: 'Failure',
  message: 'deployments.apps is forbidden: User cannot list resource' });
t('a Kubernetes API error is reported as an error, not a parse failure',
  /Kubernetes API error/.test(E.describeUnloadable(apiErr)));
t('and the server message is shown rather than swallowed',
  /is forbidden/.test(E.describeUnloadable(apiErr)));
t('and it points at the likely cause',
  /RBAC/.test(E.describeUnloadable(apiErr)));

t('an ACS error envelope is recognised too',
  /API error/.test(E.describeUnloadable(JSON.stringify({ error: { message: 'token expired' } }))));
t('an empty result says the filter matched nothing rather than looking like a bug',
  /matched no/.test(E.describeUnloadable('{}')));
t('a SARIF report is recognised as output',
  /SARIF/.test(E.describeUnloadable(JSON.stringify({ version: '2.1.0', runs: [] }))));
t('a file we have no special explanation for gets no invented one',
  E.describeUnloadable(JSON.stringify({ some: 'thing' })) === null);
t('and neither does something that is not JSON at all',
  E.describeUnloadable('not json') === null);

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
