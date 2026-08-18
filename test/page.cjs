/* Whole page tests: load each HTML file from disk exactly as a browser would, with the real
 * <script src> tags resolving to the real files in document order, then drive it.
 *
 * These catch a class of defect the engine tests structurally cannot see: an element id that
 * does not exist, a handler never bound, a panel that never unhides, a filter wired to the
 * wrong checkbox. The engine can be perfect and the page still show nothing.
 *
 * jsdom is the one thing in this repository that needs a package manager, so it is OPTIONAL.
 * Without it these tests skip and report zero rather than failing, because the tool itself
 * must keep working on a disconnected machine with no npm. Run them where you can:
 *
 *   npm install jsdom && node test/run_tests.js
 */
'use strict';
let JSDOM;
try { JSDOM = require('jsdom').JSDOM; }
catch (e) {
  console.log('\n  jsdom not installed, skipping the whole page tests.');
  console.log('  These are optional. Install with: npm install jsdom');
  console.log('\n0 passed, 0 failed');
  process.exit(0);
}

const fs = require('fs'), path = require('path'), os = require('os');
const ROOT = path.join(__dirname, '..');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

function stage(page, extras) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'acspage-'));
  fs.mkdirSync(path.join(work, 'vendor'), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'acs_policies.js'), path.join(work, 'acs_policies.js'));
  fs.copyFileSync(path.join(ROOT, page), path.join(work, page));
  for (const v of ['js-yaml.min.js', 'jszip.min.js']) {
    const src = path.join(ROOT, 'vendor', v);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(work, 'vendor', v));
  }
  // Top level let/const live in the global lexical environment, not on window, so expose
  // the few bindings the harness needs to inspect.
  fs.appendFileSync(path.join(work, page), '\n<script>' + extras + 'window.__ready=1;<\/script>\n');
  return { work, file: path.join(work, page) };
}

async function open(page, extras) {
  const st = stage(page, extras);
  const d = await JSDOM.fromFile(st.file, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true,
    beforeParse(win) {
      // Nothing in these tests is allowed to reach the network. A test that silently made a
      // real call would be worse than no test.
      win.fetch = () => Promise.reject(new Error('Failed to fetch'));
      win.alert = () => {};
      if (!win.structuredClone) win.structuredClone = (o) => JSON.parse(JSON.stringify(o));
    },
  });
  const w = d.window;
  for (let i = 0; i < 60 && !w.__ready; i++) await new Promise((r) => setTimeout(r, 40));
  if (!w.__ready) throw new Error(page + ': scripts did not finish executing');
  return { w, $: (id) => w.document.getElementById(id), cleanup: () => fs.rmSync(st.work, { recursive: true, force: true }) };
}

const V = (cve, sev, cvss, fixedBy, extra) => Object.assign({
  cve: cve, severity: sev, cvss: cvss, summary: cve, link: 'https://x/' + cve,
  fixedBy: fixedBy || '', state: 'OBSERVED' }, extra || {});
const REC = { result: { deployment: { name: 'webapp', namespace: 'prod', type: 'Deployment', clusterName: 'ocp-prod' },
  livePods: 3, images: [{ id: 'sha256:a', name: { fullName: 'quay.io/acme/webapp:1.4.2' },
    scan: { scanTime: '2026-08-10T00:00:00Z', operatingSystem: 'rhel:9', components: [
      { name: 'openssl', version: '3.0.7', vulns: [
        V('CVE-2026-1000', 'CRITICAL_VULNERABILITY_SEVERITY', 9.8, '3.0.14', { cisaKev: true, epss: { epssProbability: 0.62 } }),
        V('CVE-2026-1001', 'IMPORTANT_VULNERABILITY_SEVERITY', 7.5, '')] }] } }] } };
const ALERTS = { alerts: [{ id: 'a1', state: 'ACTIVE',
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY', description: 'd' },
  deployment: { name: 'webapp', deploymentType: 'Deployment' },
  commonEntityInfo: { namespace: 'prod', clusterName: 'ocp-prod' } }] };
const MANIFEST = ['apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: webapp', '  namespace: prod',
  'spec:', '  template:', '    spec:', '      containers:', '      - name: web',
  '        image: quay.io/acme/webapp:1.4.2', '        securityContext:', '          privileged: true'].join('\n');
const DRIFT_MANIFEST = MANIFEST.replace('webapp:1.4.2', 'webapp:1.3.0');

async function auditor() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);window.__renderVulns=()=>renderVulns();');
  const S = () => w.__STATE();

  console.log('\nAuditor page');
  t('the vulnerabilities tab exists', !!$('tab-vuln'));
  t('three live connect tabs', w.document.querySelectorAll('.tabs .tab').length === 3);
  t('the CVE panel starts hidden', $('vulnPanel').classList.contains('hidden'));

  w.__items = [{ name: 'app/deployment.yaml', text: DRIFT_MANIFEST }, { name: 'v.ndjson', text: JSON.stringify(REC) }];
  w.__load(w.__items);
  t('an NDJSON export is recognised as CVE data, not alerts', !!S().vulns && !S().acs);
  t('the CVE panel unhides', !$('vulnPanel').classList.contains('hidden'));
  const body = $('vtable').querySelector('tbody').innerHTML;
  t('CVE rows render', /CVE-2026-1000/.test(body) && /CVE-2026-1001/.test(body));
  t('the known exploited chip renders', />KEV</.test(body));
  t('the Red Hat severity words are used, not the policy words',
    /sev Critical/.test(body) && /sev Important/.test(body) && !/sev High/.test(body));
  t('an unfixable CVE says so', /no fix yet/.test(body));
  t('the ranking reasons are shown', /Known Exploited/.test(body));
  t('drift between the manifest and the scanned image is surfaced',
    /disagree about the image/.test($('vulnDrift').innerHTML) && /1\.3\.0/.test($('vulnDrift').innerHTML));
  t('CVE counts stay out of the configuration posture cards', !/Known exploited/.test($('cards').innerHTML));

  $('vFixOnly').checked = true; w.__renderVulns();
  t('the fixable filter drops the unfixable CVE', !/CVE-2026-1001/.test($('vtable').querySelector('tbody').innerHTML));
  $('vFixOnly').checked = false; $('vKevOnly').checked = true; w.__renderVulns();
  t('the known exploited filter keeps only the KEV row',
    /CVE-2026-1000/.test($('vtable').querySelector('tbody').innerHTML) &&
    !/CVE-2026-1001/.test($('vtable').querySelector('tbody').innerHTML));
  $('vKevOnly').checked = false; w.__renderVulns();

  /* The defect DJ hit: oc get -o json was rejected outright. */
  const OCJSON = JSON.stringify({ apiVersion: 'v1', kind: 'List', items: [{
    apiVersion: 'apps/v1', kind: 'Deployment',
    metadata: { name: 'live-api', namespace: 'prod', uid: 'u1', resourceVersion: '9',
      managedFields: [{ manager: 'kubectl' }] },
    spec: { template: { spec: { hostNetwork: true, containers: [{ name: 'api',
      image: 'quay.io/acme/live:1.0', securityContext: { privileged: true } }] } } },
    status: { replicas: 1 } }] });
  w.__ocj = [{ name: 'workloads.json', text: OCJSON }];
  const beforeFiles = S().files.length;
  w.__load(w.__ocj);
  t('oc get -o json loads instead of being rejected', S().files.length > beforeFiles);
  t('the imported object is named by namespace and kind',
    S().files.some((f) => f.name === 'live/prod/deployment-live-api.yaml'));
  t('server side fields were stripped before scanning',
    S().files.every((f) => !/managedFields|resourceVersion|status:/.test(f.text)));
  t('it produced findings', S().findings.some((f) => f.file === 'live/prod/deployment-live-api.yaml'));

  w.__items2 = [{ name: 'acs_alerts.json', text: JSON.stringify(ALERTS) }];
  w.__load(w.__items2);
  t('a JSON alert export is recognised as alerts', !!S().acs && S().acs.total === 1);
  t('namespace resolves from commonEntityInfo in the page', S().acs.imported[0].namespace === 'prod');
  t('the ACS cross check panel unhides', !$('acsPanel').classList.contains('hidden'));

  console.log('\n  Violation fixes respect the mode selector');
  t('the auditor defaults that selector to report', $('violMode').value === 'report');
  const bundleReport = w.eval("buildViolationFixBundle(STATE.acs, {filesByObj:{}, mode:'report'})");
  t('report mode emits no patch files', bundleReport.files.length === 0);
  t('but still says how many it would have written', bundleReport.suppressed > 0);
  t('and the report names them so the scope is still visible',
    /would be emitted/.test(bundleReport.report));
  const bundleManual = w.eval("buildViolationFixBundle(STATE.acs, {filesByObj:{}, mode:'manual'})");
  t('manual mode emits the patches', bundleManual.files.length > 0);
  t('the mode is recorded in the report itself', /Mode: manual/.test(bundleManual.report));

  $('vulnUrl').value = 'https://central.example.com';
  $('btnVulnCmd').click();
  t('the offline CVE command uses the export endpoint', /v1\/export\/vuln-mgmt\/workloads/.test($('liveOut').textContent));
  $('btnAcsCmd').click();
  t('the offline alert command includes the per id detail call', /v1\/alerts\/\$id/.test($('liveOut').textContent));
  cleanup();
}

async function remediation() {
  const { w, $, cleanup } = await open('dj_acs_remediation.html',
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);window.__undoAll=()=>undoAll();');
  const S = () => w.__STATE();

  console.log('\nRemediation page');
  t('the vulnerabilities tab exists', !!$('tab-vuln'));
  t('the violation detail checkbox exists and defaults on', !!$('acsHydrate') && $('acsHydrate').checked);

  w.__items = [{ name: 'app/deployment.yaml', text: MANIFEST }, { name: 'v.ndjson', text: JSON.stringify(REC) }];
  w.__load(w.__items);
  t('the CVE panel unhides', !$('vulnPanel').classList.contains('hidden'));
  t('the policy scan still ran alongside the CVE import', S().findings.length > 0);
  const img = $('vimgtable').querySelector('tbody').innerHTML;
  t('the declaring manifest and container are named', /app\/deployment\.yaml/.test(img) && /container web/.test(img));
  t('the panel states plainly that CVEs are not auto fixable',
    /Nothing on this panel is auto fixable/.test($('vulnPanel').textContent));

  /* ---- the mode gate. The whole point is that report mode cannot write. ---- */
  console.log('\n  Mode gate');
  t('the page opens in report mode', $('fixMode').value === 'report');
  t('report mode disables step through', $('btnStep').disabled === true);
  t('report mode disables apply all', $('btnApplyAll').disabled === true);
  t('report mode disables the patch export', $('btnPatches').disabled === true);
  t('report mode disables the fixed YAML download', $('btnDownloadAll').disabled === true);
  t('the skip confirmation box is disabled outside auto', $('skipConfirm').disabled === true);

  /* Disabled buttons are the visible half. Prove the handler itself refuses, because a
     disabled attribute is a UI hint and not a control. */
  const beforeHist = S().history.length;
  const beforeImg = S().files[0].docs[0].spec.template.spec.containers[0].image;
  w.eval('startStepping()');
  t('calling startStepping directly in report mode still refuses', S().history.length === beforeHist);
  w.eval('reviewApplyAll()');
  t('calling reviewApplyAll directly in report mode still refuses', S().history.length === beforeHist);
  $('vimgtable').querySelector('button[data-pin]').click();
  t('the image replace dialog does not even open in report mode',
    !/Replace this image reference/.test($('modalHost').textContent));
  t('and nothing was modified', S().files[0].docs[0].spec.template.spec.containers[0].image === beforeImg);

  console.log('\n  Manual mode: one at a time, apply all stays shut');
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  t('manual enables step through', $('btnStep').disabled === false);
  t('manual still refuses apply all, which is the auto path', $('btnApplyAll').disabled === true);
  w.eval('reviewApplyAll()');
  t('and calling it directly is still refused', S().history.length === beforeHist);
  t('the skip confirmation box stays disabled in manual', $('skipConfirm').disabled === true);
  t('manual enables the patch export', $('btnPatches').disabled === false);

  console.log('\n  Auto mode: everything available');
  $('fixMode').value = 'auto';
  $('fixMode').dispatchEvent(new w.Event('change'));
  t('auto enables apply all', $('btnApplyAll').disabled === false);
  t('auto enables the fixed YAML download', $('btnDownloadAll').disabled === false);
  t('auto is the only mode that offers skipping the confirmation', $('skipConfirm').disabled === false);

  /* Back to report and confirm the skip box is forced off, so a mode change cannot leave
     a permissive setting behind it. */
  $('skipConfirm').checked = true;
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));
  t('returning to report clears the skip confirmation setting', $('skipConfirm').checked === false);

  $('fixMode').value = 'auto';
  $('fixMode').dispatchEvent(new w.Event('change'));
  $('vimgtable').querySelector('button[data-pin]').click();
  t('the replace dialog refuses to invent a tag', /will not invent a replacement tag/.test($('modalHost').textContent));
  $('pinVal').value = ''; $('mYes').click();
  t('an empty replacement is rejected rather than applied', !!$('pinVal'));
  $('pinVal').value = 'quay.io/acme/webapp:1.5.0'; $('mYes').click();
  t('a real diff is previewed before anything changes',
    /Exactly what will change/.test($('modalHost').textContent) &&
    /1\.4\.2/.test($('modalHost').textContent) && /1\.5\.0/.test($('modalHost').textContent));
  t('it warns that the replacement tag is not verified',
    /does not verify that the tag exists/.test($('modalHost').textContent));
  t('preview mutated nothing',
    S().files[0].docs[0].spec.template.spec.containers[0].image === 'quay.io/acme/webapp:1.4.2');
  $('mYes').click();
  t('confirming applies it',
    S().files[0].docs[0].spec.template.spec.containers[0].image === 'quay.io/acme/webapp:1.5.0');
  t('the history records the operator supplied the value',
    S().history.length === 1 && /supplied by the operator/.test(S().history[0].changes.join(' ')));
  w.__undoAll();
  t('undo restores the original image reference',
    S().files[0].docs[0].spec.template.spec.containers[0].image === 'quay.io/acme/webapp:1.4.2');
  cleanup();
}

(async () => {
  try { await auditor(); await remediation(); }
  catch (e) { console.log('  FAIL  ' + e.message); F++; }
  console.log('\n' + P + ' passed, ' + F + ' failed');
  process.exit(F ? 1 : 0);
})();
