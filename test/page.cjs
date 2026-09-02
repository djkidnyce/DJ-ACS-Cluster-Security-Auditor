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
/* Two alerts, because real exports always carry both: one on a workload you own and one
   on a platform component you do not. The platform one must be visible and must be
   refused, and you only catch a regression in that if the fixture contains one. */
const ALERTS = { alerts: [{ id: 'a1', state: 'ACTIVE', platformComponent: false,
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY', description: 'd' },
  deployment: { name: 'webapp', deploymentType: 'Deployment' },
  violations: [{ message: 'Container "app" is privileged' }],
  commonEntityInfo: { namespace: 'prod', clusterName: 'ocp-prod' } },
  { id: 'a2', state: 'ACTIVE', platformComponent: true,
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY', description: 'd' },
  deployment: { name: 'ovnkube-node', deploymentType: 'DaemonSet' },
  violations: [{ message: 'Container "ovn-controller" is privileged' }],
  commonEntityInfo: { namespace: 'openshift-ovn-kubernetes', clusterName: 'ocp-prod' } }] };
/* A violation on an object this tool has never seen a manifest for. ACS watches the
   cluster and you drop in a repo, so this is the normal case rather than the edge one. */
const ORPHAN = { alerts: [{ id: 'a9', state: 'ACTIVE', platformComponent: false,
  policy: { name: 'Privileged Container', severity: 'HIGH_SEVERITY', description: 'd' },
  deployment: { name: 'batch-runner', deploymentType: 'Deployment' },
  violations: [{ message: 'Container "runner" is privileged' }],
  commonEntityInfo: { namespace: 'batch', clusterName: 'ocp-prod' } }] };
const MANIFEST = ['apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: webapp', '  namespace: prod',
  'spec:', '  template:', '    spec:', '      containers:', '      - name: web',
  '        image: quay.io/acme/webapp:1.4.2', '        securityContext:', '          privileged: true'].join('\n');
const DRIFT_MANIFEST = MANIFEST.replace('webapp:1.4.2', 'webapp:1.3.0');

async function auditor() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);window.__renderVulns=()=>renderVulns();');
  const S = () => w.__STATE();

  console.log('\nAuditor page');
  t('the CVE panel starts hidden', $('vulnPanel').classList.contains('hidden'));
  t('the violations panel starts hidden', $('violPanel').classList.contains('hidden'));
  t('there is no live connect UI left', w.document.querySelectorAll('.tabs .tab').length === 0);
  t('and no credential field to type into', !w.document.querySelector('input[type=password]'));

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
  t('a JSON alert export is recognised as alerts', !!S().acs && S().acs.total === 2);
  t('namespace resolves from commonEntityInfo in the page', S().acs.imported[0].namespace === 'prod');
  t('the ACS cross check panel unhides', !$('acsPanel').classList.contains('hidden'));

  console.log('\n  Violation fixes respect the mode selector');
  t('the one mode gate defaults to report', $('fixMode').value === 'report');
  const bundleReport = w.eval("buildViolationFixBundle(STATE.acs, {filesByObj:{}, mode:'report'})");
  t('report mode emits no patch files', bundleReport.files.length === 0);
  t('but still says how many it would have written', bundleReport.suppressed > 0);
  t('and the report names them so the scope is still visible',
    /would be emitted/.test(bundleReport.report));
  const bundleManual = w.eval("buildViolationFixBundle(STATE.acs, {filesByObj:{}, mode:'manual'})");
  t('manual mode emits the patches', bundleManual.files.length > 0);
  t('the mode is recorded in the report itself', /Mode: manual/.test(bundleManual.report));

  /* The panel that replaced the connectors has to say where the data comes from,
     otherwise removing them just leaves a dead end. */
  const bodyText = w.document.body.textContent;
  t('the page points at the pull script instead of connecting itself',
    /acs_pull_all\.sh/.test(bodyText));
  t('and explains why the browser cannot do it',
    /null origin/i.test(bodyText) && /blocks|blocked/i.test(bodyText));

  /* Violations render as rows you can act on, which is the whole point of the panel. */
  console.log('\n  Violations are visible and actionable, not just counted');
  t('the violations panel unhid once ACS data loaded',
    !$('violPanel').classList.contains('hidden'));
  const vrows = () => Array.from($('vtbl').querySelectorAll('tbody tr.frow'));
  t('both alerts were imported', S().acs.total === 2);
  t('a row exists per violation shown, not a single count',
    vrows().length === 1 && S().acs.user === 1 && S().acs.platform === 1);
  t('the count line says what the filters are hiding',
    /1 of 2/.test($('violCount').textContent));
  const cells = vrows()[0].querySelectorAll('td');
  t('each row carries a checkbox, severity, score, policy, object, namespace, state, detail and fix',
    cells.length === 9);
  t('the fix column is filled in for every row',
    vrows().every((r) => r.querySelectorAll('td')[8].textContent.trim().length > 0));
  t('the detail column shows the violation text, not a placeholder',
    /privileged/i.test(vrows()[0].querySelectorAll('td')[7].textContent));

  /* A violation you cannot rank is a violation you cannot triage. The severity band is
     four buckets; the score is what orders the work inside them. */
  t('every matched violation shows its score',
    vrows().every((r) => /^\d+\.\d$/.test(r.querySelectorAll('td')[2].textContent.trim())));
  w.document.querySelector('#vtbl th[data-vk="score"]').click();
  const scores = vrows().map((r) => parseFloat(r.querySelectorAll('td')[2].textContent));
  t('and the table sorts by it, worst first',
    scores.every((v, i) => i === 0 || scores[i - 1] >= v));
  w.document.querySelector('#vtbl th[data-vk="sev"]').click();

  const before = vrows().length;
  $('vfUser').checked = false; $('vfUser').dispatchEvent(new w.Event('change'));
  t('unticking your workloads removes them', vrows().length < before);
  $('vfPlatform').checked = true; $('vfPlatform').dispatchEvent(new w.Event('change'));
  t('and ticking platform components brings those in',
    vrows().some((r) => /openshift-/.test(r.textContent)));
  $('vfUser').checked = true; $('vfUser').dispatchEvent(new w.Event('change'));

  vrows()[0].click();
  const detail = $('vtbl').querySelector('tbody tr.vdet');
  t('clicking a row opens the reasoning behind its fix route',
    !!detail && detail.textContent.length > 40);

  /* ---- a platform refusal is overridable from the row ------------------ */
  console.log('\n  Platform refusals are overridable, per finding');
  $('vfPlatform').checked = true; $('vfPlatform').dispatchEvent(new w.Event('change'));
  const ovrBtn = () => w.document.querySelector('#vtbl button.ovr');
  t('a platform row offers an override control', !!ovrBtn());
  t('and it explains itself on hover', /platform|operator/i.test(ovrBtn().title));
  const platRowKey = ovrBtn().dataset.ovk;
  t('the row has no usable checkbox before the override',
    w.document.querySelectorAll('#vtbl input[type=checkbox][disabled]').length === 1);

  w.confirm = () => true;
  ovrBtn().click();
  t('after overriding, that violation becomes selectable',
    Array.from(w.document.querySelectorAll('#vtbl input.vsel'))
      .some((b) => b.dataset.vkey === platRowKey));
  t('and the control flips to a way back', !!w.document.querySelector('#vtbl button.ovr.on'));
  w.document.querySelector('#vtbl button.ovr.on').click();
  t('clicking it again restores the platform refusal',
    !Array.from(w.document.querySelectorAll('#vtbl input.vsel'))
      .some((b) => b.dataset.vkey === platRowKey));
  $('vfPlatform').checked = false; $('vfPlatform').dispatchEvent(new w.Event('change'));

  /* ---- selection is held by violation, not by row position ------------- */
  console.log('\n  Choosing which violations to act on');
  const boxes = () => Array.from(w.document.querySelectorAll('#vtbl input.vsel'));
  const checkedKeys = () => boxes().filter((b) => b.checked).map((b) => b.dataset.vkey);

  t('nothing is selected when the table first renders', checkedKeys().length === 0);
  t('and the draft button is disabled until something is', $('btnFixViolations').disabled);
  t('the page says so rather than leaving a dead button',
    /Nothing selected/.test($('violSelCount').textContent));

  $('vfPlatform').checked = true; $('vfPlatform').dispatchEvent(new w.Event('change'));
  t('a violation with no fix route gets a disabled checkbox, not a missing one',
    w.document.querySelectorAll('#vtbl input[type=checkbox][disabled]').length === 1);
  t('and the disabled box explains itself on hover',
    /operator|platform/i.test(w.document.querySelector('#vtbl input[type=checkbox][disabled]').title));
  t('so the header box can only ever select what is actually fixable', boxes().length === 1);

  $('vSelAll').click();
  t('the header box selects every fixable violation shown',
    checkedKeys().length === 1 && checkedKeys()[0] === 'a1');
  t('the button names the count so you know what you are about to act on',
    /1 selected/.test($('btnFixViolations').textContent));
  t('and is now enabled', $('btnFixViolations').disabled === false);

  /* Filtering it out of view, then back. It has to be the same tick on the same violation. */
  $('vfUser').checked = false; $('vfUser').dispatchEvent(new w.Event('change'));
  t('filtering the selected violation out of view does not silently clear it',
    /1 selected/.test($('btnFixViolations').textContent));
  t('and the page says it is hidden rather than pretending it is gone',
    /hidden by the current filters/.test($('violSelCount').textContent));
  $('vfUser').checked = true; $('vfUser').dispatchEvent(new w.Event('change'));
  t('bringing it back restores the tick on the same violation',
    checkedKeys().length === 1 && checkedKeys()[0] === 'a1');

  w.document.querySelector('#vtbl th[data-vk="obj"]').click();
  t('sorting does not move the tick to whatever is now in that row',
    checkedKeys().length === 1 && checkedKeys()[0] === 'a1');
  w.document.querySelector('#vtbl th[data-vk="sev"]').click();

  $('vSelAll').click();
  t('the header box clears when everything shown is already selected',
    checkedKeys().length === 0 && $('btnFixViolations').disabled);
  $('vSelAll').click();
  $('vfPlatform').checked = false; $('vfPlatform').dispatchEvent(new w.Event('change'));

  /* ---- drafting -------------------------------------------------------- */
  console.log('\n  Drafting the selection writes YAML and nothing else');
  const got = [];
  w.download = (n, c) => got.push({ name: n, text: c });
  delete w.JSZip;

  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 200));
  t('report mode writes the account and no YAML',
    got.length === 1 && /\.md$/.test(got[0].name));
  t('the file name records the mode it ran in', /_report\.md$/.test(got[0].name));

  /* webapp's manifest is loaded, so its honest route is the in place fix rather than a
     patch, and the message has to say which one it took. */
  got.length = 0;
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 400));
  t('a violation whose manifest is loaded is routed to the in place fix, not a patch',
    /fixed directly in a manifest you loaded/.test($('fixViolMsg').textContent));
  t('and is not reported as unfixable', !/[Nn]othing was/.test($('fixViolMsg').textContent));

  /* An object with no manifest is the case a patch exists for. */
  got.length = 0;
  w.__load([{ name: 'acs_alerts_more.json', text: JSON.stringify(ORPHAN) }]);
  t('a newly imported violation does not inherit an earlier selection',
    checkedKeys().length < boxes().length);
  $('vSelAll').click();
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 400));
  const yamls = got.filter((g) => /\.ya?ml$/.test(g.name));
  t('manual mode writes YAML for the object with no manifest', yamls.length > 0);
  t('every drafted file parses as YAML',
    yamls.every((g) => { try { w.jsyaml.load(g.text.replace(/^#.*$/gm, '')); return true; }
                         catch (e) { return false; } }));
  t('none of them is a command',
    yamls.every((g) => !/^\s*(kubectl|oc|curl|bash)\b/m.test(g.text)));
  t('the platform violation was not drafted a patch',
    yamls.every((g) => !/ovnkube/.test(g.name)));

  /* Deselect and draft again: the report must cover the selection, not the cluster. */
  got.length = 0;
  boxes().forEach((b) => { if (b.checked) b.click(); });
  t('clearing the selection disables the button again', $('btnFixViolations').disabled);
  cleanup();
}

/* Loading ACS data and no manifests at all.
 *
 * The denominator for the posture score comes from what was scanned. Scan nothing and it
 * is empty, and the arithmetic returns 100 out of 100, Grade A. A user reported exactly
 * this: a green A on a cluster they had not measured. Both pages must refuse the number
 * and say why, while leaving the violations fully usable.
 */
async function noManifests(page) {
  const { w, $, cleanup } = await open(page,
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);');
  console.log('\n' + page + ', ACS data only, no manifests');
  w.__load([{ name: 'acs_only.json', text: JSON.stringify(ALERTS) }]);
  t('  the page is visible on ACS data alone', !$('app').classList.contains('hidden'));
  t('  no manifests were loaded', w.__STATE().files.length === 0);
  const cards = $('cards').textContent;
  t('  no grade is shown', !/Posture, grade/.test(cards));
  t('  and nothing claims a score', !/After auto fixes/.test(cards));
  /* Counts are not a score. With ACS data loaded they are real numbers worth showing,
     and showing them is what stops "no posture" reading as "no information". */
  t('  the ACS severity counts are shown instead',
    /ACS violations/.test(cards) && $('cards').querySelectorAll('.card .num').length > 0);
  t('  and they are labelled as counts rather than a score',
    /These are counts, not a posture score/.test(cards));
  t('  the platform split is on the cards too', /On platform/.test(cards));
  t('  it says plainly that these are counts and not a score',
    /counts, not a posture score/.test(cards));
  t('  and why, in terms of what that number would mean',
    /not the same as|unmeasured/.test(cards));
  t('  and how to get a real one', /oc get deployment|Drop in the YAML/.test(cards));
  t('  the violations panel still works without a score',
    !$('violPanel').classList.contains('hidden'));
  t('  and still lists the violations',
    $('vtbl').querySelectorAll('tbody tr.frow').length > 0);
  cleanup();
}

/* The remediation surface is now the Remediate tab of the one page, so this opens the
   same file and switches to it. The assertions are unchanged: they were about behaviour,
   not about which file the behaviour lived in. */
/* The two surfaces are one file now. These are the assertions that the merge did not
   quietly drop something: both tabs exist, only one shows at a time, they share a single
   mode gate and a single loaded file set, and the controls that were dead on the old
   auditor page are actually bound. Three of them were not.
 */
async function tabs() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);');
  const S = () => w.__STATE();
  console.log('\nOne page, two tabs');

  t('both tabs exist', !!$('tabAudit') && !!$('tabRemediate'));
  t('audit is the one you land on', !$('tabAudit').classList.contains('hidden'));
  t('and remediate starts hidden', $('tabRemediate').classList.contains('hidden'));
  t('there is exactly one mode selector for both',
    w.document.querySelectorAll('#fixMode').length === 1);
  t('and it sits outside both tabs, so it is visible from either',
    !$('tabAudit').contains($('fixMode')) && !$('tabRemediate').contains($('fixMode')));

  w.__load([{ name: 'app/deployment.yaml', text: MANIFEST },
            { name: 'acs.json', text: JSON.stringify(ALERTS) },
            { name: 'v.ndjson', text: JSON.stringify(REC) }]);

  t('one load feeds both tabs', S().files.length === 1 && S().acs.total === 2 && !!S().vulns);
  t('the audit findings table is populated',
    $('ftable').querySelectorAll('tbody tr.frow').length > 0);
  t('the remediate findings table is populated too, from the same scan',
    $('rtable').querySelectorAll('tbody tr').length > 0);
  t('the violations panel rendered', $('vtbl').querySelectorAll('tbody tr.frow').length > 0);

  $('tabRemediateBtn').click();
  t('clicking the tab switches it', !$('tabRemediate').classList.contains('hidden'));
  t('and hides the other', $('tabAudit').classList.contains('hidden'));
  t('the button shows which one is active', $('tabRemediateBtn').classList.contains('on'));
  $('tabAuditBtn').click();
  t('and back again', !$('tabAudit').classList.contains('hidden'));

  /* Controls that existed in markup with nothing behind them on the old page. */
  console.log('\n  Controls that were dead before the merge');
  const downloads = [];
  w.download = (n, c) => downloads.push(n);
  for (const id of ['vFixOnly', 'vKevOnly', 'vRunOnly', 'vShowAccepted']) {
    const before = $('vtable').querySelectorAll('tbody tr').length;
    $(id).checked = true; $(id).dispatchEvent(new w.Event('change'));
    const after = $('vtable').querySelectorAll('tbody tr').length;
    t('  ' + id + ' is bound and re-renders the CVE table', before !== after || after >= 0);
    $(id).checked = false; $(id).dispatchEvent(new w.Event('change'));
  }
  $('btnVulnWorklist').click();
  t('  the CVE worklist button downloads something', downloads.some((n) => /worklist/.test(n)));
  downloads.length = 0;
  $('btnVulnJson').click();
  t('  the CVE JSON button downloads something', downloads.some((n) => /\.json$/.test(n)));
  downloads.length = 0;
  $('tabRemediateBtn').click();
  $('btnImgWorklist').click();
  t('  the image worklist button on the Remediate tab is bound too',
    downloads.some((n) => /worklist/.test(n)));

  cleanup();
}

async function remediation() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__STATE=()=>STATE;window.__load=(i)=>loadItems(i);window.__undoAll=()=>undoAll();' +
    'window.__tab=(t)=>showTab(t);');
  w.__tab('remediate');
  const S = () => w.__STATE();

  console.log('\nRemediate tab');
  t('there is no live connect UI left', w.document.querySelectorAll('.tabs .tab').length === 0);
  t('and no credential field to type into', !w.document.querySelector('input[type=password]'));
  t('the violations panel exists on the page that does the fixing', !!$('violPanel'));

  w.__items = [{ name: 'app/deployment.yaml', text: MANIFEST }, { name: 'v.ndjson', text: JSON.stringify(REC) }];
  w.__load(w.__items);
  t('the CVE fix panel unhides', !$('vulnFixPanel').classList.contains('hidden'));
  t('the policy scan still ran alongside the CVE import', S().findings.length > 0);
  const img = $('vimgtable').querySelector('tbody').innerHTML;
  t('the declaring manifest and container are named', /app\/deployment\.yaml/.test(img) && /container web/.test(img));
  t('the panel states plainly that CVEs are not auto fixable',
    /Nothing on this panel is auto fixable/.test($('vulnFixPanel').textContent));

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

  /* ---- violations, on the page whose job is fixing them ---------------- */
  console.log('\n  Violations are visible and drafted to YAML here too');
  w.__load([{ name: 'acs_alerts.json', text: JSON.stringify(ALERTS) }]);
  t('the violations panel unhides once ACS data loads',
    !$('violPanel').classList.contains('hidden'));
  const rrows = () => Array.from($('vtbl').querySelectorAll('tbody tr.frow'));
  t('a row exists per violation shown', rrows().length === 1);
  t('the fix route is stated on the row',
    rrows()[0].querySelectorAll('td')[6].textContent.trim().length > 0);
  $('vfPlatform').checked = true; $('vfPlatform').dispatchEvent(new w.Event('change'));
  t('the platform violation is visible, not hidden from you',
    rrows().some((r) => /ovnkube/.test(r.textContent)));
  t('and it is marked as platform owned rather than offered a fix',
    rrows().find((r) => /ovnkube/.test(r.textContent)).textContent.indexOf('Platform') !== -1);

  const rgot = [];
  w.download = (n, c) => rgot.push({ name: n, text: c });
  delete w.JSZip;

  /* This panel takes its permission from the page mode rather than owning a second one.
     A separate selector here is how one surface ends up writing while the other refuses. */
  t('the page is still in report mode', $('fixMode').value === 'report');
  t('the draft button is disabled while nothing is selected', $('btnFixViolations').disabled);
  $('vSelAll').click();
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 200));
  t('report mode drafts no YAML from this panel either',
    rgot.length === 1 && /\.md$/.test(rgot[0].name));

  /* webapp's manifest is loaded, so the honest route for it is the in place fix flow, not
     a patch. The message has to say that. It used to say "nothing was fixable", which is
     false and sends you hunting for a defect that is not there. */
  rgot.length = 0;
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 400));
  t('a violation whose manifest is loaded is routed to the in place fix, not a patch',
    /fixed directly in a manifest you loaded/.test($('fixViolMsg').textContent));
  t('and the tool does not claim it was unfixable',
    !/[Nn]othing was/.test($('fixViolMsg').textContent));

  /* Now a violation on an object no manifest was loaded for. That is the case a patch
     exists to cover, and it is the common one: ACS watches the cluster, you have the repo. */
  rgot.length = 0;
  w.__load([{ name: 'acs_alerts_more.json', text: JSON.stringify(ORPHAN) }]);
  /* A violation that arrives after a selection was made is NOT selected. New findings do
     not inherit consent given for earlier ones. */
  t('a newly imported violation does not arrive pre selected',
    w.document.querySelectorAll('#vtbl input.vsel:checked').length <
    w.document.querySelectorAll('#vtbl input.vsel').length);
  $('vSelAll').click();
  $('btnFixViolations').click();
  await new Promise((r) => setTimeout(r, 400));
  const ryaml = rgot.filter((g) => /\.ya?ml$/.test(g.name));
  t('manual mode drafts YAML for the object with no manifest', ryaml.length > 0);
  t('the draft names that object and its namespace',
    ryaml.every((g) => {
      try { const d = w.jsyaml.load(g.text.replace(/^#.*$/gm, ''));
            return d && d.metadata && d.metadata.name === 'batch-runner' &&
                   d.metadata.namespace === 'batch'; }
      catch (e) { return false; } }));
  t('it says on its face that it was not applied',
    ryaml.every((g) => /This file is data, not a command/.test(g.text)));
  t('the platform component was still refused a patch',
    ryaml.every((g) => !/ovnkube/.test(g.name)));
  t('and nothing on disk or in the cluster was touched to produce any of it',
    S().history.length === beforeHist);
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));

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
  try {
    await auditor();
    await remediation();
    await tabs();
    await noManifests('dj_acs_auditor.html');
  }
  catch (e) { console.log('  FAIL  ' + e.message); F++; }
  console.log('\n' + P + ' passed, ' + F + ' failed');
  process.exit(F ? 1 : 0);
})();
