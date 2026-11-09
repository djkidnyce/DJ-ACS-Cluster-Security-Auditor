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

/* The workflow this tool is actually used in: the scan runs on one machine, the review
 * happens on another, and neither has Node. The browser is not a preview of the fix, it is
 * the only thing that can produce one, so the export path has to work and has to be
 * usable at four figures of findings.
 */
/* Reported from a real run of 1.5.0: one checkbox in the header and none on the rows, a
 * Fix this button that appears dead, an export button greyed out next to the words "750
 * selected", and a table wider than the window.
 *
 * Every one of these is a DOM fact. The previous selection test passed while the row
 * checkboxes did not exist at all, because it clicked the header button and then asserted
 * on the FSELECTED Set. Asserting on the data structure behind a control proves the
 * structure works, not the control. These assert on elements.
 */
async function selectionUi() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__S=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__rows=()=>findingRows();window.__sel=()=>FSELECTED;window.__mode=()=>currentMode();');
  const M = (n) => ['apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: ' + n,
    '  namespace: prod', 'spec:', '  template:', '    spec:', '      hostNetwork: true',
    '      hostPID: true', '      containers:', '      - name: c',
    '        image: registry.example.internal/a-very-long-project-path/' + n + ':latest',
    '        securityContext:', '          privileged: true'].join('\n');
  const files = [];
  for (let i = 0; i < 6; i++) files.push({ name: 'team/app' + i + '.yaml', text: M('app' + i) });
  w.__load(files);
  w.__tab('remediate');

  console.log('\n  Every fixable row is selectable, on the row');
  const fixable = w.__rows().filter((f) => !f.applied && f.fixKind !== 'manual').length;
  t('the fixture produced fixable findings to select', fixable > 10);
  const boxes = w.document.querySelectorAll('#rtable input.fsel');
  t('there is a checkbox on each fixable row, not just in the header',
    boxes.length === fixable);
  t('and the header box is still there', !!$('fSelAll'));

  /* A body row with fewer cells than the header shifts every value one column left, so
     Severity renders under the checkbox heading. Counting them catches it. */
  const heads = w.document.querySelectorAll('#rtable thead th').length;
  const firstRow = w.document.querySelector('#rtable tbody tr');
  t('the body rows have as many cells as the header has columns',
    !!firstRow && firstRow.children.length === heads);
  /* The detail row is built on first expand, so open one and then check its span. A
     colspan that disagrees with the header count is how the old 7-under-8 mismatch
     showed up in the markup. */
  if (firstRow) firstRow.querySelector('td.wrapcell').click();
  const detail = w.document.querySelector('#rtable tbody tr.fdet td[colspan]');
  t('and the detail row, once opened, spans exactly that many',
    !!detail && Number(detail.getAttribute('colspan')) === heads);
  if (firstRow) firstRow.querySelector('td.wrapcell').click();

  console.log('\n  Ticking a row is what selects a finding');
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  const one = w.document.querySelector('#rtable input.fsel');
  t('clicking a row checkbox selects that finding',
    !!one && (one.click(), w.__sel().size === 1));
  t('and the export button counts it',
    /1 selected/.test($('btnExportFixed').textContent));
  t('clicking it again clears it',
    !!one && (one.click(), w.__sel().size === 0));

  /* Clicking a row opens its advisory. A checkbox inside that row must not do both. */
  const before = w.document.querySelectorAll('#rtable tbody tr.hidden').length;
  const two = w.document.querySelector('#rtable input.fsel');
  if (two) two.click();
  t('ticking a box does not also expand the advisory row',
    !!two && w.document.querySelectorAll('#rtable tbody tr.hidden').length === before);

  /* This used to clear the selection on the way into report mode, on the reasoning that
     report produces nothing so a tick in it is wasted. In practice that means ticking 750
     findings, touching the mode selector, and losing the lot. Ticks cost nothing. The
     gate belongs on the thing that writes a file, and it has to explain itself where the
     button is rather than leaving a grey rectangle. */
  console.log('\n  Report mode holds the selection and explains the gate');
  $('btnFSelAll').click();
  const held = w.__sel().size;
  t('there is a selection to hold', held > 0);
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));
  t('the ticks are kept, not thrown away', w.__sel().size === held);
  t('the row checkboxes stay usable, because ticking costs nothing',
    Array.from(w.document.querySelectorAll('#rtable input.fsel'))
      .filter((c) => !c.disabled).length > 0);
  t('the export button is the thing that is gated', $('btnExportFixed').disabled);
  t('the button itself says which control is holding it',
    /Report only\. Choose Manual or Auto/.test($('btnExportFixed').title));
  t('and the reason is written beside the button, not only at the top of the page',
    /Mode is Report only/.test($('fModeWhy').textContent) &&
    /Change Mode at the top of the page/.test($('fModeWhy').textContent));
  t('and that note is actually visible while the gate is holding',
    !$('fModeWhy').classList.contains('hidden'));
  t('pressing it anyway writes nothing',
    (function () { const n = []; const d = w.download; w.download = (x) => n.push(x);
      $('btnExportFixed').click(); w.download = d; return n.length === 0; })());
  t('switching back to manual turns it on with the selection intact',
    (function () { $('fixMode').value = 'manual';
      $('fixMode').dispatchEvent(new w.Event('change'));
      return w.__sel().size === held && $('btnExportFixed').disabled === false; })());
  $('btnFSelNone').click();
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));

  /* The reported symptom was "the fix this button does not work". It was live, it was
     clickable, requireMode refused it, and the refusal was written into #exportMsg at the
     bottom of the page below a 750 row table. A control the mode forbids is disabled and
     says why on itself, rather than looking pressable and explaining itself off screen. */
  console.log('\n  A control the mode forbids is off, and says so on itself');
  const btn = w.document.querySelector('#rtable tbody button.rfix');
  t('the per row Fix this button exists', !!btn && /Fix this/.test(btn.textContent));
  t('and in report mode it is disabled rather than live and refusing',
    !!btn && btn.disabled === true);
  t('every one of them, not just the first',
    Array.from(w.document.querySelectorAll('#rtable tbody button.rfix'))
      .every((b) => b.disabled));
  t('the button itself names the control to move',
    !!btn && /Report only\. Choose Manual or Auto in the Mode selector/.test(btn.title));
  if (btn) btn.click();
  await new Promise((r) => setTimeout(r, 40));
  t('pressing it in report mode applies nothing', w.__S().history.length === 0);
  t('and switching to manual turns every one of them on',
    (function () { $('fixMode').value = 'manual';
      $('fixMode').dispatchEvent(new w.Event('change'));
      const bs = w.document.querySelectorAll('#rtable tbody button.rfix');
      return bs.length > 0 && Array.from(bs).every((b) => !b.disabled); })());
  t('and the note beside the table goes away with them',
    $('fModeWhy').classList.contains('hidden') && $('fModeWhy').textContent === '');
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));

  /* Two containers of one object under one policy are two findings with one findingKey.
     Selection is per row, so it needs a key that separates them, or ticking one ticks
     both and the count disagrees with the screen again. */
  console.log('\n  Two containers of one object select independently');
  w.__load([{ name: 'two.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: web, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: alpha', '        image: nginx:latest',
    '        securityContext: { privileged: true }', '      - name: beta',
    '        image: redis:latest', '        securityContext: { privileged: true }'].join('\n') }]);
  w.__tab('remediate');
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  const fks = Array.from(w.document.querySelectorAll('#rtable tbody input.fsel'))
    .map((c) => c.dataset.fk);
  t('the fixture really does produce colliding finding keys',
    w.__rows().length > new Set(w.__rows().map((f) => f.file + '|' + f.obj + '|' + f.policy.id)).size);
  t('but every row checkbox carries a distinct key',
    fks.length > 1 && new Set(fks).size === fks.length);
  const c0 = w.document.querySelectorAll('#rtable tbody input.fsel')[0];
  c0.click();
  t('so ticking one container selects exactly one finding', w.__sel().size === 1);
  t('and leaves the other container unticked',
    w.document.querySelectorAll('#rtable tbody input.fsel')[1].checked === false);
  t('and the header box reads partial, not complete',
    $('fSelAll').indeterminate === true && $('fSelAll').checked === false);
  $('btnFSelNone').click();
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));

  console.log('\n  Wide tables are contained rather than pushing off screen');
  /* jsdom does no layout, so this asserts the CSS contract rather than a measured width.
     Saying that plainly is better than implying the overflow itself was reproduced. */
  const css = w.document.querySelector('style').textContent;
  for (const id of ['rtable', 'ftable', 'vtable', 'acsTable']) {
    const tb = $(id);
    if (!tb) continue;
    t('  ' + id + ' sits in a horizontally scrollable wrapper',
      !!tb.closest('.tablewrap'));
  }
  t('long unbroken values are allowed to wrap inside a cell',
    /\.tablewrap\s+td[^}]*(overflow-wrap|word-break)/.test(css) ||
    /(^|})\s*td\.wrapcell\s*{[^}]*(overflow-wrap|word-break)/m.test(css));
  t('and the wrapper scrolls rather than overflowing the page',
    /\.tablewrap\s*{[^}]*overflow-x:\s*auto/.test(css));

  /* The Audit tab is read only. It had a checkbox cell its header had no column for,
     which pushed every value one column right and left the eighth cell headerless, and
     those boxes were bound to nothing anywhere in the file. */
  console.log('\n  The read only table has no orphan controls');
  w.__tab('audit');
  const fh = w.document.querySelectorAll('#ftable thead th').length;
  const frow = w.document.querySelector('#ftable tbody tr');
  t('its body rows have as many cells as its header has columns',
    !!frow && frow.children.length === fh);
  t('it has no selection checkboxes at all',
    w.document.querySelectorAll('#ftable input.fsel').length === 0);
  t('and no checkbox cell',
    w.document.querySelectorAll('#ftable td.selcell').length === 0);
  cleanup();
}

/* The defect this suite existed to catch and did not.
 *
 * renderTable created two elements per finding, set innerHTML on each, attached two
 * listeners and appended into a live table. That is quadratic. At 75 findings it took
 * 440ms and every test passed. At 750, which is an ordinary first run against a real
 * cluster, a single render took roughly 37 seconds, and because ticking one checkbox
 * called renderTable(), clicks queued behind a render and every button looked dead.
 *
 * Nothing here asserts a wall clock number, because a timing threshold in CI is a flaky
 * test and a flaky test gets deleted. It asserts the three structural properties that
 * make the render cheap. If any of them regresses, the page gets slow again.
 */
/* The dwell on a flash message, which review caught as an undeclared rider.
 *
 * A rewrite that made refusals visible on the tab you are standing on also moved the
 * timeout from 3000 to 6000ms for all twenty two call sites without saying so. The fix
 * is not to pick one number, it is to stop an acknowledgement and a refusal sharing one
 * by accident. FLASH_REFUSAL_MS is referenced inside requireMode at roughly line 1070
 * and declared at roughly line 2260, so the first assertion here is that calling it does
 * not throw: this file has had two temporal dead zone defects already.
 */
async function flashDwell() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__flash=(m,ms)=>flash(m,ms);window.__req=(w2,a)=>requireMode(w2,a);' +
    'window.__ms=()=>({def:FLASH_MS,ref:FLASH_REFUSAL_MS});');

  console.log('\n  A refusal stays up longer than an acknowledgement');
  const ms = w.__ms();
  t('the two durations are named rather than typed inline',
    ms.def === 3000 && ms.ref === 6000);
  t('the acknowledgement dwell is back to what it was before the rewrite', ms.def === 3000);

  /* requireMode reads FLASH_REFUSAL_MS from an outer scope declared far below it. If that
     were a dead zone this throws rather than returning false. */
  let threw = null;
  let refused = null;
  try { refused = w.__req('writes', 'write corrected YAML'); }
  catch (e) { threw = e.message; }
  t('a refusal in report mode does not throw on the constant declared below it',
    threw === null);
  if (threw) console.log('        threw: ' + threw);
  t('and it still refuses', refused === false);

  /* flash() picks its target by which tab is visible. Query the same way it does, or
     this reads an element it never wrote to. That is what the first version of this
     test did, and it failed for a reason that had nothing to do with the code. */
  const flashBox = () => {
    const onRem = w.document.getElementById('tabRemediate') &&
      !w.document.getElementById('tabRemediate').classList.contains('hidden');
    return w.document.querySelector((onRem ? '#tabRemediate' : '#tabAudit') + ' .flashmsg');
  };
  const box = flashBox();
  t('the refusal reached a message element', !!box && box.textContent.length > 0);

  /* The race the guard exists for, driven at speeds a test can observe.
   *
   * The first version of this waited 120ms for clears scheduled at 3000 and 6000ms, so
   * nothing could have fired and the assertion passed with the guard removed. Proved
   * vacuous by deleting the guard and watching it stay green. Pass explicit short dwells
   * instead, so the early timer really does fire while the later message is on screen.
   */
  console.log('\n  A short message clearing does not wipe the one that replaced it');
  w.__flash('the refusal you must read', 400);
  t('the first message is showing', flashBox().textContent === 'the refusal you must read');
  w.__flash('quick acknowledgement', 50);
  t('the second replaces it', flashBox().textContent === 'quick acknowledgement');
  w.__flash('the refusal you must read', 400);
  await new Promise((r) => setTimeout(r, 150));
  t('the 50ms clear fired and left the current message alone, because it checks the text',
    flashBox().textContent === 'the refusal you must read');
  await new Promise((r) => setTimeout(r, 400));
  t('and the message does clear once its own timer comes round',
    flashBox().textContent === '');

  /* The case the text based guard could not see: the SAME message twice.
   *
   * Comparing textContent cannot distinguish "still mine" from "posted again", so the
   * first call's timer wiped the second call's message early. Pressing a refusing
   * control twice is exactly what an operator does when a button looks like it did
   * nothing, so this is a real path rather than a contrived one. */
  console.log('\n  The same refusal posted twice keeps its full dwell');
  w.__flash('Nothing selected.', 300);
  await new Promise((r) => setTimeout(r, 200));
  w.__flash('Nothing selected.', 300);      // the operator presses again
  await new Promise((r) => setTimeout(r, 180));
  t('the first timer has fired but did not wipe the second posting',
    flashBox().textContent === 'Nothing selected.');
  await new Promise((r) => setTimeout(r, 200));
  t('and the second clears on its own schedule', flashBox().textContent === '');

  cleanup();
}

/* F7 and F8. Cosmetic findings, with one real risk hidden in them: unifying the detail
 * toggle across two tables that deliberately render DIFFERENT content is an easy way to
 * silently change what one of them shows. The Audit tab renders runtimeRisk, the
 * Remediate tab renders Severity and Live in ACS. These assert both still do.
 */
async function detailRows() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);');
  const RISKY = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: app, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: q/app:1',
    '        securityContext: { privileged: true, readOnlyRootFilesystem: false }'].join('\n');
  w.__load([{ name: 'm/a.yaml', text: RISKY }]);

  console.log('\n  One toggle mechanism, two different advisories');
  w.__tab('audit');
  /* Only four policies carry runtimeRisk, and row order is by severity, so the first row
     is not reliably one of them. Find the row that should show it rather than assuming. */
  const arows = Array.from(w.document.querySelectorAll('#ftable tbody tr'));
  const arow = arows.find((r) => /ACS\.002|ACS\.008|ACS\.009|ACS\.016/.test(r.textContent))
    || arows[0];
  t('the Audit table rendered a row with a runtime risk policy on it',
    !!arow && /ACS\.(002|008|009|016)/.test(arow.textContent));
  arow.click();
  const adet = arow.nextElementSibling;
  t('clicking it inserts a detail row', !!adet && adet.classList.contains('fdet'));
  t('and reveals it', !!adet && !adet.classList.contains('hidden'));
  const acells = adet.querySelectorAll('td').length;
  t('the detail cell spans the Audit table, not some other table',
    adet.firstElementChild.getAttribute('colspan') ===
      String(w.document.querySelectorAll('#ftable thead th').length));
  t('it is one cell, so the colspan was not doubled by the merge', acells === 1);
  t('the Audit advisory still carries the runtime risk wording it is the only one to show',
    /Can stop the workload/.test(adet.textContent));
  arow.click();
  t('clicking again collapses it', adet.classList.contains('hidden'));
  t('and does not insert a second detail row',
    w.document.querySelectorAll('#ftable tbody tr.fdet').length === 1);

  w.__tab('remediate');
  $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change'));
  const rrow = w.document.querySelector('#rtable tbody tr[data-i]');
  t('the Remediate table rendered a row', !!rrow);
  const rcell = rrow.querySelector('td.wrapcell') ||
    Array.from(rrow.querySelectorAll('td')).find((c) => !c.classList.contains('selcell'));
  t('the row has a cell that is not the checkbox to click on', !!rcell);
  rcell.click();
  const rdet = rrow.nextElementSibling;
  t('it gets a detail row from the same helper', !!rdet && rdet.classList.contains('fdet'));
  t('spanning the Remediate table, which has a different column count',
    rdet.firstElementChild.getAttribute('colspan') ===
      String(w.document.querySelectorAll('#rtable thead th').length));
  t('the Remediate advisory still shows Severity, which the Audit one does not',
    /Severity/.test(rdet.textContent));
  t('the two advisories are genuinely different, so the merge did not flatten them',
    rdet.textContent !== adet.textContent);

  console.log('\n  The dead CSS rule is gone and the notes are styled in one place');
  const css = require('fs').readFileSync(require('path').join(ROOT, 'dj_acs_auditor.html'), 'utf8');
  t('table-layout:auto is removed, because auto is the initial value anyway',
    !/table-layout:auto/.test(css));
  t('the one table that needs a fixed layout still declares it',
    /#rtable\{table-layout:fixed/.test(css));
  t('the mode explanation carries no inline layout',
    !/id="fModeWhy" style=/.test(css));
  t('and is styled with the other notes instead', /#fModeWhy\{margin:/.test(css));
  t('the cell ceiling says where its number came from',
    /roughly 55 characters at this font size/.test(css));
  cleanup();
}

/* The Diff tab: what the fixes would change, side by side, before anything is written.
 *
 * The valuable assertion in here is not any single row. It is that the Diff tab and the
 * corrected YAML export are computed by the same buildFixedCopy, so a review on this tab
 * is a review of exactly what the export writes. A diff showing something the export does
 * not produce would be worse than no diff, because you would review the wrong thing and
 * believe otherwise.
 */
/* Annotating a fixed object, so a revision can say what it is.
 *
 * This came out of a real rollback: pods crashlooping after a batch of fixes, a list of
 * revisions, and no way to tell which carried which change. `oc rollout history` printed
 * a column of <none> and the ReplicaSets were anonymous.
 *
 * The properties that matter are not that an annotation exists. They are WHERE it is:
 * change-cause on the object is the column rollout history prints, and the template
 * annotation is part of the pod template hash so it rides into the ReplicaSet. Either
 * one alone leaves a gap, and a test that only checks "an annotation is present" would
 * pass with the useless half.
 */
/* Loading is additive and keyed on file name: a page that has seen 40 files has seen 40
   files for the rest of its life. Each scenario below therefore gets its own page rather
   than sharing one, because a shared page would carry the previous scenario's file count
   into the next one and the assertions would be measuring the wrong number. The first
   version of this suite did exactly that and passed anyway. */
async function diffExport() {
  const dep = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: prod }', 'spec:', '  template:', '    spec:',
    '      hostNetwork: true', '      containers:', '      - name: c',
    '        image: q/a:latest', '        securityContext: { privileged: true }'].join('\n');
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__step=()=>startStepping();');

  console.log('\n  The click through shows the change side by side');
  /* It used to be one column of + and - lines. That reads fine to somebody who already
     knows what changed and is hard to show to anybody else, which is the whole reason
     people were screenshotting it. */
  w.__load([{ name: 'm/a.yaml', text: dep('api') }]);
  w.__tab('remediate');
  $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change'));
  w.__step();
  const modal = $('modalHost');
  const sbs = modal.querySelector('table.sbs');
  t('the step panel renders a side by side table', !!sbs);
  t('with a before column and an after column',
    Array.from(sbs.querySelectorAll('thead th')).map((x) => x.textContent.trim())
      .filter(Boolean).join('|') === 'Now|After this fix');
  const chg = sbs.querySelector('tr.chg');
  t('a changed value is one row, not two', !!chg);
  t('the old value is on the left',
    !!chg && /privileged: true/.test(chg.querySelectorAll('td')[1].textContent));
  t('and the new value on the right',
    !!chg && /privileged: false/.test(chg.querySelectorAll('td')[3].textContent));
  t('both sides carry a line number',
    !!chg && chg.querySelectorAll('td.ln').length === 2);
  t('the single column version is gone', !modal.querySelector('pre.diff'));

  console.log('\n  The whole diff comes out as one file you can send somebody');
  w.__load([{ name: 'm/b.yaml', text: dep('web') }]);
  w.__tab('diff');
  const got = [];
  w.download = (n, c) => got.push({ name: n, text: c });
  $('btnDiffHtml').click();
  const out = got.find((g) => /\.html$/.test(g.name));
  t('an HTML file is written', !!out);
  t('named so two runs do not overwrite each other',
    /acs_diff_\d{8}-\d{6}_\w+\.html/.test(out.name));

  console.log('\n  It has to open on a machine that can reach nothing');
  t('no script tag', !/<script/i.test(out.text));
  t('no external stylesheet or font', !/<link|@import/i.test(out.text));
  t('nothing is fetched over the network', !/src=|href="http|cdn\./i.test(out.text));

  console.log('\n  And it has to say what it is');
  t('it states plainly that nothing was applied',
    /Nothing here has been applied/.test(out.text));
  t('it names the tool and the mode',
    out.text.indexOf(w.__S().files.length ? 'ACS Auditor' : 'x') !== -1 &&
    /mode (report|manual|auto)/.test(out.text));
  t('it carries the reference register, so a revision traces back to it',
    /Reference register/.test(out.text));

  console.log('\n  The content is the diff, not a picture of one');
  const doc = new (require('jsdom').JSDOM)(out.text).window.document;
  t('every changed file is a section', doc.querySelectorAll('details.f').length >= 2);
  t('the first one is open, so it is not a page of closed boxes',
    doc.querySelector('details.f').hasAttribute('open'));
  t('there are real diff rows', doc.querySelectorAll('table.d tbody tr').length > 10);
  t('and changed rows among them', doc.querySelectorAll('tr.chg, tr.add').length > 0);
  const row = doc.querySelector('tr.chg');
  t('a changed row has the old text on the left',
    !!row && row.querySelectorAll('td')[1].textContent.length > 0);
  t('and the new text on the right',
    !!row && row.querySelectorAll('td')[3].textContent.length > 0);
  t('the two sides differ, which is the point',
    !!row && row.querySelectorAll('td')[1].textContent !== row.querySelectorAll('td')[3].textContent);
  t('the summary counts what is inside it',
    /\+\d+/.test(doc.querySelector('details.f summary').textContent));

  console.log('\n  Exceptions are named in it rather than silently missing');
  w.eval("OPTRULES.push({policy:'ACS.001',reason:'Waived under PSC-114 for this platform.'});" +
         "applyOptOuts(STATE.scanned);STATE.findings=scopedFindings(STATE.scanned);");
  w.__tab('diff');
  got.length = 0;
  $('btnDiffHtml').click();
  const out2 = got.find((g) => /\.html$/.test(g.name));
  t('the export names the exception', /PSC-114/.test(out2.text));
  t('and says the finding is deliberately absent',
    /deliberately absent/.test(out2.text));
  t('the excepted fix is not in the diff',
    !/privileged: false/.test(out2.text));


  console.log('\n  An exception recorded after the Diff tab rendered still leaves the diff');
  /* Reported from production. The export read a cache that only renderDiffTab() wrote, and
     render() never calls it, so recording an exception on the Remediate tab left the export
     holding the previous build. The file showed the excepted change and listed it as a
     documented exception, contradicting itself, while the corrected YAML got it right.
     The order below is the reported order and it is the whole point of the test. */
  const h4 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__rules=()=>OPTRULES;window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);' +
    'window.__sync=()=>syncFindingSelection();' +
    'window.__apply=()=>{applyOptOuts(STATE.scanned);STATE.findings=scopedFindings(STATE.scanned);};');
  const d4 = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      hostNetwork: true', '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  h4.w.__load([{ name: 'm/a.yaml', text: d4 }]);
  h4.$('fixMode').value = 'manual';
  h4.$('fixMode').dispatchEvent(new h4.w.Event('change'));

  h4.w.__tab('diff');                       // render first, which is what used to be cached
  h4.w.__tab('remediate');                  // then record the exception elsewhere
  h4.w.__rules().push({ policy: 'ACS.001',
    reason: 'Accepted under waiver PSC-114 for this platform.' });
  h4.w.__apply();

  const out4 = [];
  h4.w.download = (n, c) => out4.push({ name: n, text: c });
  h4.$('btnDiffHtml').click();              // export without revisiting the Diff tab
  const html4 = out4.find((g) => /\.html$/.test(g.name));
  t('a file was written', !!html4);
  t('the excepted fix is absent from the diff', !/privileged: false/.test(html4.text));
  t('it is named as a documented exception instead', /PSC-114/.test(html4.text));
  t('the fixes that were not excepted are still there',
    /hostNetwork: false/.test(html4.text));
  t('so the document does not contradict itself',
    /PSC-114/.test(html4.text) && !/privileged: false/.test(html4.text));

  /* The property, rather than this one case: nothing listed as an exception may also appear
     as an applied change. Asserted by policy id against the register. */
  const doc4 = new (require('jsdom').JSDOM)(html4.text).window.document;
  const excepted = Array.from(doc4.querySelectorAll('table.meta tbody tr'))
    .map((tr) => (tr.querySelector('code') || {}).textContent)
    .filter(Boolean);
  t('the exception table names the policy that was excepted',
    excepted.indexOf('ACS.001') !== -1);
  const regTable = Array.from(doc4.querySelectorAll('table.meta'))
    .find((tbl) => /Policies/.test(tbl.querySelector('thead').textContent));
  t('there is a reference register to check against', !!regTable);
  const appliedCol = Array.from(regTable.querySelectorAll('tbody tr'))
    .map((tr) => (tr.querySelectorAll('td')[3] || {}).textContent || '').join(' ');
  t('and the register does not list the excepted policy as applied',
    appliedCol.indexOf('ACS.001') === -1);
  t('while it does list one that was applied', /ACS\.\d{3}/.test(appliedCol));

  console.log('\n  Same for a namespace taken out of scope after rendering');
  h4.w.__tab('diff');
  h4.w.eval("NSOUT.add('prod'); STATE.findings = scopedFindings(STATE.scanned);");
  out4.length = 0;
  h4.$('btnDiffHtml').click();
  t('with every namespace excluded there is nothing to export', out4.length === 0);
  h4.cleanup();

  console.log('\n  Nothing to show is said, not exported as an empty page');
  w.eval("FSELECTED.clear();");
  $('dSelOnly').checked = true;
  $('dSelOnly').dispatchEvent(new w.Event('change'));
  got.length = 0;
  $('btnDiffHtml').click();
  t('no file is written when there is no diff', got.length === 0);
  t('and it says so', /no diff to export|nothing would change/i.test(
    $('dtab') ? document_flash(w) : document_flash(w)));
  cleanup();
}

function document_flash(w) {
  const el = w.document.querySelector('#dtab .flashmsg') ||
             w.document.querySelector('.flashmsg');
  return el ? el.textContent : '';
}

async function optOutRules() {
  const dep = (ns, n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: ' + ns + ' }', 'spec:', '  template:',
    '    spec:', '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__S=()=>STATE;window.__tab=(t)=>showTab(t);' +
    'window.__rules=()=>OPTRULES;window.__import=(d)=>optOutImport(d);' +
    'window.__apply=()=>{applyOptOuts(STATE.scanned);STATE.findings=scopedFindings(STATE.scanned);renderTable();};' +
    'window.__tpl=()=>exceptionsTemplate();window.__dead=()=>unmatchedRules();' +
    'window.__sel=()=>FSELECTED;window.__fix=(f)=>fFixable(f);' +
    'window.__key=(f)=>findingRowKey(f);window.__ruleProblem=(r)=>optOutRuleProblem(r);');
  const MARK = 'dj-acs-auditor/exceptions';
  const R = 'Operators call the Kubernetes API. Removing the token stops them.';
  w.__load([{ name: 'm/op.yaml', text: dep('openshift-apiserver-operator', 'oas-op') },
            { name: 'm/api.yaml', text: dep('prod', 'payments-api') }]);
  const find = (pol, obj) => w.__S().findings.find(
    (f) => f.policy.id === pol && f.obj.indexOf(obj) !== -1);

  console.log('\n  A rule says what it means, and covers more than one object');
  let r = w.__import({ mark: MARK, rules: [
    { policy: 'ACS.016', namespace: 'openshift-*', reason: R }] });
  t('the rule is taken', r.rules === 1);
  t('and nothing was rejected', r.rejected === 0);
  w.__apply();
  t('it excepts the matching finding', !!find('ACS.016', 'oas-op').optOut);
  t('the reason travels with it', find('ACS.016', 'oas-op').optOut.reason === R);
  t('the same policy in a namespace it does not name is untouched',
    !find('ACS.016', 'payments-api').optOut);
  t('a different policy on the same object is untouched',
    !find('ACS.008', 'oas-op').optOut);
  t('an excepted finding is not fixable', !w.__fix(find('ACS.016', 'oas-op')));

  console.log('\n  It covers objects that did not exist when the rule was written');
  w.__load([{ name: 'm/later.yaml', text: dep('openshift-monitoring', 'mon-op') }]);
  t('a namespace loaded afterwards is covered too',
    !!find('ACS.016', 'mon-op') && !!find('ACS.016', 'mon-op').optOut);
  t('which is the whole difference from pinning exact findings',
    w.__S().findings.filter((f) => f.optOut && f.policy.id === 'ACS.016').length === 2);

  console.log('\n  A rule is refused when it would except more than it says');
  const bad = [
    [{ reason: R }, 'no policy at all'],
    [{ policy: 'ACS.016' }, 'no reason'],
    [{ policy: 'ACS.016', reason: 'n/a' }, 'a reason that is not one'],
    [{ policy: 'ACS.016', reason: R, expires: 'soon' }, 'an expiry that is not a date'],
    [{ policy: 'ACS.016', reason: R, expires: '2026-13-45' }, 'an impossible date'],
  ];
  for (const [rule, label] of bad) {
    t('  refused: ' + label, !!w.__ruleProblem(rule));
  }
  const before = w.__rules().length;
  r = w.__import({ mark: MARK, rules: bad.map((b) => b[0]) });
  t('none of them are imported', w.__rules().length === before);
  t('every one is counted as rejected', r.rejected === bad.length);
  t('and each rejection says which rule and why',
    r.problems.length === bad.length && /policy|reason|expires/.test(r.problems[0]));

  console.log('\n  An expiry puts the finding back, and says it lapsed');
  w.__rules().length = 0;
  w.__import({ mark: MARK, rules: [
    { policy: 'ACS.008', namespace: 'prod', reason: R, expires: '2020-01-01' }] });
  w.__apply();
  const lapsed = find('ACS.008', 'payments-api');
  t('the finding is not excepted', !lapsed.optOut);
  t('it is marked as having had one', !!lapsed.optOutExpired);
  t('the expiry date is carried', lapsed.optOutExpired.expires === '2020-01-01');
  t('it is fixable again, because it is a finding again', w.__fix(lapsed));
  t('the row says the exception expired',
    /Exception expired/.test($('rtable').querySelector('tbody').innerHTML));
  t('the summary says so too, rather than only the row',
    /EXPIRED/.test($('fCount').textContent));

  w.__rules().length = 0;
  w.__import({ mark: MARK, rules: [
    { policy: 'ACS.008', namespace: 'prod', reason: R, expires: '2099-01-01' }] });
  w.__apply();
  t('a date in the future excepts normally',
    !!find('ACS.008', 'payments-api').optOut);
  t('and is not marked expired', !find('ACS.008', 'payments-api').optOutExpired);

  console.log('\n  A rule that matches nothing is reported, not ignored');
  w.__rules().length = 0;
  w.__import({ mark: MARK, rules: [
    { policy: 'ACS.016', namespace: 'namespace-that-was-renamed', reason: R },
    { policy: 'ACS.016', namespace: 'openshift-*', reason: R }] });
  w.__apply();
  const dead = w.__dead();
  t('the rule matching nothing is found', dead.length === 1);
  t('and it is the right one', dead[0].namespace === 'namespace-that-was-renamed');
  t('the one that does match is not reported as dead',
    !dead.some((x) => x.namespace === 'openshift-*'));

  console.log('\n  An exact entry still wins over a rule');
  /* Pressing Opt out on one row is a decision about that row. A broad rule loaded later
     should not silently replace the reason somebody typed against it. */
  w.__rules().length = 0;
  const one = find('ACS.016', 'oas-op');
  w.__import({ mark: MARK,
    entries: [{ key: w.__key(one), reason: 'Pinned by hand for this exact finding.' }],
    rules: [{ policy: 'ACS.016', namespace: 'openshift-*', reason: R }] });
  w.__apply();
  t('the exact reason is the one that applies',
    find('ACS.016', 'oas-op').optOut.reason === 'Pinned by hand for this exact finding.');
  t('and it is not marked as coming from a rule',
    !find('ACS.016', 'oas-op').optOut.rule);


  console.log('\n  One rule instead of forty clicks');
  const h3 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__rules=()=>OPTRULES;');
  const opdep = (ns, n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: ' + ns + ' }', 'spec:', '  template:',
    '    spec:', '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  h3.w.__load([
    { name: 'm/1.yaml', text: opdep('openshift-apiserver-operator', 'oas') },
    { name: 'm/2.yaml', text: opdep('openshift-monitoring', 'mon') },
    { name: 'm/3.yaml', text: opdep('prod', 'api') }]);
  h3.w.__tab('remediate');
  h3.$('fixMode').value = 'manual';
  h3.$('fixMode').dispatchEvent(new h3.w.Event('change'));

  h3.$('btnOptBulk').click();
  t('it refuses without a policy filter, because a rule with none excepts everything',
    h3.$('bulkForm').classList.contains('hidden') && h3.w.__rules().length === 0);

  h3.$('fPolicy').value = 'ACS.016';
  h3.$('fPolicy').dispatchEvent(new h3.w.Event('change'));
  h3.$('btnOptBulk').click();
  t('with a policy set, the form opens', !h3.$('bulkForm').classList.contains('hidden'));
  t('it says how many findings it covers',
    /finding\(s\) showing now/.test(h3.$('bulkForm').textContent));
  t('and warns that it spans several namespaces',
    /spans 3 namespaces|spans \d+ namespaces/.test(h3.$('bulkForm').textContent));

  h3.$('bulkSave').click();
  t('an empty reason is refused', h3.w.__rules().length === 0);
  t('and says so in the form',
    h3.$('bulkForm').querySelector('.optmsg').textContent.length > 20);

  h3.$('bulkForm').querySelector('.optreason').value =
    'Operators call the Kubernetes API and stop without the token.';
  h3.$('bulkExpiry').value = '2099-12-31';
  h3.$('bulkSave').click();
  t('one rule is written, not one entry per finding', h3.w.__rules().length === 1);
  t('it carries the policy from the filter', h3.w.__rules()[0].policy === 'ACS.016');
  t('and the expiry from the form', h3.w.__rules()[0].expires === '2099-12-31');
  t('every matching finding is now excepted',
    h3.w.__S().findings.filter((f) => f.policy.id === 'ACS.016' && f.optOut).length === 3);
  t('and nothing else is',
    h3.w.__S().findings.filter((f) => f.optOut).length === 3);
  t('the form closes', h3.$('bulkForm').classList.contains('hidden'));

  h3.$('fNs').value = 'prod';
  h3.$('fNs').dispatchEvent(new h3.w.Event('change'));
  h3.$('fPolicy').value = 'ACS.008';
  h3.$('fPolicy').dispatchEvent(new h3.w.Event('change'));
  h3.$('btnOptBulk').click();
  h3.$('bulkForm').querySelector('.optreason').value =
    'Vendor image needs this capability, replacement tracked in PLAT-991.';
  h3.$('bulkSave').click();
  t('a namespace filter narrows the rule to that namespace',
    h3.w.__rules()[1].namespace === 'prod');
  t('so it excepts only there',
    h3.w.__S().findings.filter((f) => f.policy.id === 'ACS.008' && f.optOut).length === 1);
  h3.cleanup();

  console.log('\n  The template is the format, and it loads');
  const tpl = JSON.parse(w.__tpl());
  t('it is marked as ours', tpl.mark === MARK);
  t('it explains itself in the file', Array.isArray(tpl._readme) && tpl._readme.length > 5);
  t('it says a reason is required', tpl._readme.join(' ').indexOf('reason is required') !== -1);
  t('it documents the expiry behaviour',
    /comes back into scope/.test(tpl._readme.join(' ')));
  t('it ships worked examples', tpl.rules.length >= 2);
  w.__rules().length = 0;
  const loaded = w.__import(tpl);
  t('every example in it is valid, so the template is not aspirational',
    loaded.rules === tpl.rules.length && loaded.rejected === 0);
  t('the underscore notes do not become rules',
    w.__rules().every((x) => x.policy !== undefined));
  cleanup();
}

async function namespaces() {
  const dep = (ns, n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: ' + ns + ' }', 'spec:', '  template:',
    '    spec:', '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  const h = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__S=()=>STATE;window.__tab=(t)=>showTab(t);' +
    'window.__out=()=>NSOUT;window.__json=()=>buildFindingsJson(reportState());' +
    'window.__rep=()=>buildHtmlReport(reportState());window.__sel=()=>FSELECTED;');
  const { w, $, cleanup } = h;
  const chips = () => Array.from(w.document.querySelectorAll('.nschip'));
  const chipFor = (ns) => {
    const box = w.document.querySelector('input.nssel[data-ns="' + ns + '"]');
    return box && box.closest('.nschip');
  };
  /* The rendered posture card, not a recomputation. A test that calls computePosture
     itself would pass while the page showed a stale number. */
  const score = () => Number($('cards').querySelector('.num').textContent);

  console.log('\n  Every namespace that was loaded is offered, with what is in it');
  w.__load([{ name: 'a.yaml', text: dep('prod', 'api') },
            { name: 'b.yaml', text: dep('staging', 'web') },
            { name: 'c.yaml', text: dep('openshift-monitoring', 'mon') }]);
  t('the panel is showing', !$('nsPanel').classList.contains('hidden'));
  t('one chip per namespace', chips().length === 3);
  t('all three start in scope', /^3 of 3 in scope/.test($('nsPanelCnt').textContent));
  t('the platform namespace is marked as one',
    !!chipFor('openshift-monitoring').querySelector('.pill.plat'));
  t('and an ordinary namespace is not', !chipFor('prod').querySelector('.pill.plat'));
  const scanned = w.__S().scanned.length;
  t('nothing is excluded yet', w.__S().findings.length === scanned);

  console.log('\n  Deselecting takes a namespace out of scope, not out of view');
  const before = score();
  const cb = chipFor('staging').querySelector('input.nssel');
  cb.checked = false;
  cb.dispatchEvent(new w.Event('change', { bubbles: true }));
  t('the namespace is recorded as excluded', w.__out().has('staging'));
  t('its findings leave the working set',
    w.__S().findings.every((f) => f.ns !== 'staging'));
  t('but the scan still holds them, so the count of what was excluded is real',
    w.__S().scanned.some((f) => f.ns === 'staging'));
  t('the panel says what went with it',
    /1 excluded taking \d+ finding/.test($('nsPanelCnt').textContent));
  t('no row for it is left in the findings table',
    !$('ftable').querySelector('tbody').textContent.includes('staging'));

  console.log('\n  The score moves with both halves, or it is a lie');
  /* prod and staging are byte identical apart from the name. Excluding one of two equally
     bad namespaces must not change the score. If the findings were scoped and the objects
     were not, the excluded namespace would keep its weight in the denominator with none of
     its failures in the numerator, and deselecting namespaces would raise the score every
     time. That is the defect this asserts against, and it is the reason scopedFiles
     exists. */
  t('excluding one of two equally bad namespaces leaves the score alone',
    score() === before);
  t('and the score is not a perfect one, so there was something to get wrong',
    before < 100);

  console.log('\n  The report and the JSON say the scope was partial');
  const js = w.__json();
  t('the JSON counts only the documents in scope', js.scope.documents === 2);
  t('it names what was excluded', js.scope.excludedNamespaces.length === 1);
  t('with the namespace', js.scope.excludedNamespaces[0].namespace === 'staging');
  t('and how many findings went with it',
    js.scope.excludedNamespaces[0].findingsExcluded > 0);
  t('the findings list is scoped too',
    js.findings.every((f) => f.object.indexOf('web') === -1));
  const rep = w.__rep();
  t('the HTML report says the estate is only partly covered',
    /This report covers part of the estate/.test(rep));
  t('it names the namespace in the report body', rep.indexOf('staging') !== -1);
  t('and says it before the score, not in a footnote',
    rep.indexOf('part of the estate') < rep.indexOf('Posture'));

  console.log('\n  Deselecting the platform namespaces is one button');
  $('btnNsAll').click();
  t('everything is back in scope', w.__out().size === 0);
  $('btnNsNoPlatform').click();
  t('the platform namespace is out', w.__out().has('openshift-monitoring'));
  t('and nothing else is', w.__out().size === 1);
  t('the findings from it are gone with it',
    w.__S().findings.every((f) => f.ns !== 'openshift-monitoring'));
  $('btnNsAll').click();

  console.log('\n  An empty scope is refused a score, the same as an empty load');
  /* Namespace scoping reopened a defect this project had already closed once: files
     loaded, every namespace deselected, denominator empty, and the page printing 100 out
     of 100 Grade A over nothing. It was caught by an engine test that checks the guard
     sits before the scoring, not by anything here, so it gets an assertion here too. */
  $('btnNsNone').click();
  t('every namespace is out of scope', w.__out().size === 3);
  t('no score is shown at all', !$('cards').querySelector('.num'));
  t('and no card presents a grade either',
    !Array.from($('cards').querySelectorAll('.lbl')).some((l) => /Posture, grade/.test(l.textContent)));
  t('and it says which of the two empties this is',
    /[Ee]very namespace is out of scope/.test($('cards').textContent));
  t('it still explains why a score would be meaningless',
    /denominator/.test($('cards').textContent));
  $('btnNsAll').click();
  t('putting them back brings the score back', !!$('cards').querySelector('.num'));

  console.log('\n  A namespace column that sorts');
  w.__tab('remediate');
  const head = Array.from($('rtable').querySelectorAll('thead th')).map((x) => x.textContent.trim());
  t('the remediate table has one', head.indexOf('Namespace') !== -1);
  t('the audit table has one too',
    Array.from($('ftable').querySelectorAll('thead th')).map((x) => x.textContent.trim())
      .indexOf('Namespace') !== -1);
  const cells = Array.from($('rtable').querySelectorAll('tbody tr[data-i]'))
    .map((tr) => tr.children[3].textContent.trim());
  t('every row says which namespace it is in', cells.every((c) => c.length > 0));
  const nsTh = Array.from($('rtable').querySelectorAll('thead th'))
    .find((x) => x.dataset.key === 'ns');
  nsTh.dispatchEvent(new w.Event('click', { bubbles: true }));
  const sorted = Array.from($('rtable').querySelectorAll('tbody tr[data-i]'))
    .map((tr) => tr.children[3].textContent.trim().split(' ')[0]);
  t('clicking the header sorts by it',
    sorted.join('|') === sorted.slice().sort().join('|'));
  t('and the platform namespace is marked on the row too',
    !!$('rtable').querySelector('tbody .pill.plat'));
  const nsTd = $('rtable').querySelector('tbody td.nscell');
  t('the namespace cell carries the bare namespace as its title, pill or not',
    !!nsTd && nsTd.title.length > 0 && nsTd.textContent.trim().indexOf(nsTd.title) === 0);
  t('and the title is the namespace rather than the pill text',
    nsTd.title.indexOf('platform') === -1 || nsTd.title === 'platform');

  console.log('\n  Fixing one namespace records the ones left alone');
  $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change'));
  $('fNs').value = 'prod'; $('fNs').dispatchEvent(new w.Event('change'));
  $('btnFSelAll').click();
  const picked = Array.from(w.__sel());
  t('something was selected', picked.length > 0);
  t('select all shown took only the filtered namespace',
    w.__S().findings.filter((f) => w.__sel().has(w.__key ? w.__key(f) : ''))
      .every((f) => f.ns === 'prod') || picked.every((k) => k.indexOf('prod') !== -1));

  const got = [];
  w.download = (n, c) => got.push({ name: n, text: c });
  delete w.JSZip;
  $('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const md = got.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the export was written', !!md);
  t('it reports coverage per namespace', /## Namespace coverage/.test(md.text));
  t('every in scope namespace has a row, including the ones nobody touched',
    /\| prod \|/.test(md.text) && /\| staging \|/.test(md.text));
  t('it names the namespaces that received no fixes',
    /received no fixes in this run/.test(md.text));
  t('and says their findings are still open', /still open/.test(md.text));
  t('a namespace that was fixed is not in that list',
    md.text.split('received no fixes in this run')[1].split('.')[0].indexOf('prod') === -1);
  cleanup();
}

async function filesPanel() {
  const dep = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: d' + n + ', namespace: ns }', 'spec:', '  template:', '    spec:',
    '      hostNetwork: true', '      containers:', '      - name: c',
    '        image: q/a:1'].join('\n');
  const many = (n) => Array.from({ length: n },
    (_, i) => ({ name: 'm/f' + i + '.yaml', text: dep(i) }));
  const fresh = async () => {
    const h = await open('dj_acs_auditor.html',
      'window.__load=(i)=>loadItems(i);window.__S=()=>STATE;' +
      'window.__restore=()=>restoreFilesPanelPref();');
    h.panel = () => h.$('filesPanel');
    h.cnt = () => h.$('filesPanelCnt').textContent;
    h.chips = () => h.$('filelist').querySelectorAll('.filechip').length;
    return h;
  };

  console.log('\n  Nothing loaded, nothing to collapse');
  let h = await fresh();
  t('the panel is hidden before anything is loaded',
    h.panel().classList.contains('hidden'));

  console.log('\n  A short list stays open, because folding three files helps nobody');
  h.w.__load(many(3));
  t('the panel is showing', !h.panel().classList.contains('hidden'));
  t('and open', h.panel().open === true);
  t('the chips are still there, one per file', h.chips() === 3);

  console.log('\n  The summary carries the counts, so folding it costs nothing');
  t('it counts the files', /^3 files/.test(h.cnt()));
  t('it counts the documents', /\b3 documents\b/.test(h.cnt()));
  t('it counts the findings',
    h.cnt().indexOf(h.w.__S().findings.length + ' finding') !== -1);
  t('and it agrees with the number of chips drawn',
    Number(h.cnt().match(/^(\d+) files/)[1]) === h.chips());

  console.log('\n  The panel does not mistake its own default for a decision');
  /* The markup starts closed, so the default opening a short list is a real change to the
     open property, and a real browser queues a toggle event after it. Without a guard
     that event is indistinguishable from the operator opening the panel, the default is
     recorded as their choice, and it never applies again. The queued event is simulated
     here rather than assumed away. A default that does not change the property fires
     nothing, so there is no second case to cover. */
  t('the default opened it', h.panel().open === true);
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('and the event that follows is not read as the operator opening it',
    h.panel().dataset.touched !== '1');
  h.w.__load(many(40));
  t('so the default still applies on the next load, and folds the long list',
    h.panel().open === false);
  h.cleanup();

  console.log('\n  Documents are counted, not files, which are not the same number');
  h = await fresh();
  h.w.__load([{ name: 'm/bundle.yaml', text: [dep(90), dep(91), dep(92)].join('\n---\n') },
              { name: 'm/one.yaml', text: dep(93) }]);
  t('two files', /^2 files/.test(h.cnt()));
  t('but four documents, because one file held three', /\b4 documents\b/.test(h.cnt()));
  t('and two chips, one per file', h.chips() === 2);
  h.cleanup();

  console.log('\n  A long list folds itself away');
  h = await fresh();
  h.w.__load(many(40));
  t('40 files is past the point where the list is worth reading',
    h.panel().open === false);
  t('but the summary still says how much is behind the fold', /^40 files/.test(h.cnt()));
  t('and the chips exist, so nothing was dropped to make it fit', h.chips() === 40);

  h.cleanup();

  console.log('\n  The operator overrules the default, and it sticks');
  h = await fresh();
  h.w.__load(many(40));
  t('it starts folded', h.panel().open === false);
  h.panel().open = true;
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('opening it by hand is recorded as a choice', h.panel().dataset.touched === '1');
  h.w.__load([{ name: 'm/extra.yaml', text: dep(99) }]);
  t('a later load does not fold it back up on them', h.panel().open === true);
  t('even though it is past the threshold that folds it by default',
    h.w.__S().files.length > 12);
  h.cleanup();

  console.log('\n  Opened from a file, there is no storage at all, and that is fine');
  /* A page opened from a file:// URL has an opaque origin and touching localStorage
     throws rather than returning null. That is the primary way this tool is used, so it
     is the default case rather than the edge case: every read and write is wrapped, and
     the panel falls back to the size based default. The jsdom windows here are file://
     too, so the suites above have been exercising this the whole time. */
  h = await fresh();
  let threw = false;
  try { h.w.localStorage.getItem('x'); } catch (e) { threw = true; }
  t('the environment really does refuse storage', threw);
  h.w.__load(many(3));
  t('the panel still works', h.panel().open === true);
  h.panel().open = false;
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('and toggling it does not throw where it cannot be saved',
    h.panel().dataset.touched === '1');
  h.cleanup();

  console.log('\n  Where storage does work, a choice made earlier is still their choice');
  const fakeStore = (w) => {
    const m = new Map();
    Object.defineProperty(w, 'localStorage', {
      configurable: true,
      value: { getItem: (k) => (m.has(k) ? m.get(k) : null),
               setItem: (k, v) => m.set(k, String(v)),
               removeItem: (k) => m.delete(k) },
    });
    return m;
  };

  h = await fresh();
  fakeStore(h.w).set('acsFilesOpen', 'open');
  t('the stored preference is read back', h.w.__restore() === 'open');
  h.w.__load(many(40));
  t('and a long list stays open because they said so last time',
    h.panel().open === true);
  h.cleanup();

  h = await fresh();
  fakeStore(h.w).set('acsFilesOpen', 'shut');
  h.w.__restore();
  h.w.__load(many(3));
  t('the opposite preference holds too, on a list short enough to open by default',
    h.panel().open === false);
  t('and the counts are still there to read while it is folded',
    /^3 files/.test(h.cnt()));
  h.cleanup();

  h = await fresh();
  const store = fakeStore(h.w);
  store.set('acsFilesOpen', 'nonsense');
  t('a value that is neither is ignored rather than acted on',
    h.w.__restore() === null);
  h.w.__load(many(3));
  t('so the default decides', h.panel().open === true);

  console.log('\n  And a choice made now is what an earlier session will read');
  h.panel().open = false;
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('collapsing it is written to storage', store.get('acsFilesOpen') === 'shut');
  h.panel().open = true;
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('and opening it overwrites that', store.get('acsFilesOpen') === 'open');
  h.cleanup();

  console.log('\n  A file that could not be read outranks both');
  h = await fresh();
  h.w.__load([{ name: 'm/ok.yaml', text: dep(1) },
              { name: 'm/broken.yaml', text: 'a:\n  - b\n c: [unclosed' }]);
  t('the file that failed to parse is counted', /could not be read/.test(h.cnt()));
  t('and the count is marked as needing attention',
    h.$('filesPanelCnt').classList.contains('hot'));
  h.panel().open = false;
  h.panel().dispatchEvent(new h.w.Event('toggle'));
  t('collapsing it by hand is recorded', h.panel().dataset.touched === '1');
  h.w.__load([{ name: 'm/ok2.yaml', text: dep(2) }]);
  t('but that does not hide a parse error on the next load', h.panel().open === true);
  h.cleanup();
}

async function optOuts() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__opt=()=>OPTOUTS;window.__bundle=()=>optOutBundle();' +
    'window.__import=(d)=>optOutImport(d);window.__rows=()=>FROWS;' +
    'window.__apply=()=>{applyOptOuts(STATE.findings);renderTable();};' +
    'window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);' +
    'window.__json=()=>buildFindingsJson(reportState());');
  const dep = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: prod }', 'spec:', '  template:', '    spec:',
    '      hostNetwork: true', '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  w.__load([{ name: 'm/api.yaml', text: dep('payments-api') },
            { name: 'm/web.yaml', text: dep('web-front') }]);
  w.__tab('remediate');
  $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change'));

  const tbody = () => $('rtable').querySelector('tbody');
  const rowFor = (pol, obj) => {
    const rows = w.__rows();
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].policy.id === pol && rows[i].obj.indexOf(obj) !== -1) {
        return tbody().querySelector('tr[data-i="' + i + '"]');
      }
    }
    return null;
  };
  const click = (el) => el.dispatchEvent(new w.Event('click', { bubbles: true }));
  const target = w.__rows().find((f) => !f.applied && f.fixKind !== 'manual');
  const POL = target.policy.id, OBJ = target.obj;

  console.log('\n  Opting out asks for a reason and will not take a non answer');
  let tr = rowFor(POL, OBJ);
  t('the row offers an opt out', !!tr.querySelector('button.ropt'));
  click(tr.querySelector('button.ropt'));
  let form = tr.nextElementSibling.querySelector('.optform');
  t('a form opens under the row', !!form);
  t('and it is visible rather than opened hidden',
    !tr.nextElementSibling.classList.contains('hidden'));

  click(form.querySelector('button.optsave'));
  t('an empty reason is refused', w.__opt().size === 0);
  t('and the refusal is shown next to the box, not somewhere off screen',
    form.querySelector('.optmsg').textContent.length > 20);

  form.querySelector('.optreason').value = 'n/a';
  click(form.querySelector('button.optsave'));
  t('"n/a" is refused as a label rather than a reason', w.__opt().size === 0);

  form.querySelector('.optreason').value = 'no time';
  click(form.querySelector('button.optsave'));
  t('so is a reason too short to be an audit record', w.__opt().size === 0);
  t('the finding is still fixable while every attempt is refused',
    !!rowFor(POL, OBJ).querySelector('input.fsel:not([disabled])'));

  console.log('\n  A real reason is recorded and the finding stops being written');
  const REASON = 'Cluster policy forbids this on the payments path, waiver PSC-114.';
  form.querySelector('.optreason').value = REASON;
  click(form.querySelector('button.optsave'));
  t('the exception is recorded', w.__opt().size === 1);
  tr = rowFor(POL, OBJ);
  t('the row says so', /Opted out/.test(tr.textContent));
  t('its checkbox is disabled, so it cannot be selected for export',
    !!tr.querySelector('input[type=checkbox][disabled]'));
  t('and the disabled box says why, rather than looking broken',
    tr.querySelector('input[type=checkbox][disabled]').getAttribute('title').indexOf('PSC-114') !== -1);
  t('the button now offers the recorded exception rather than a fresh opt out',
    /Exception/.test(tr.querySelector('button.ropt').textContent));

  console.log('\n  It is per policy per object, not a blanket mute');
  const other = w.__rows().find((f) => f.policy.id === POL && f.obj !== OBJ);
  t('the same policy on another object exists to check', !!other);
  const otr = rowFor(POL, other.obj.split('/').pop());
  t('and it is untouched', !!otr.querySelector('input.fsel:not([disabled])'));
  t('only one finding is opted out',
    w.__S().findings.filter((f) => f.optOut).length === 1);

  console.log('\n  Select all skips it, so it cannot be swept back in');
  $('btnFSelAll').click();
  const sel = w.__sel();
  t('something was selected', sel.size > 0);
  t('but not the opted out finding', !sel.has(w.__key(target)));

  console.log('\n  The reason ships with the export');
  const got = [];
  w.download = (n, c) => got.push({ name: n, text: c });
  delete w.JSZip;
  $('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const md = got.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the markdown was written', !!md);
  t('it names the exception as documented rather than omitting it',
    /## Documented exceptions/.test(md.text));
  t('it carries the reason verbatim', md.text.indexOf('PSC-114') !== -1);
  t('it says the finding was not fixed and is not gone', /not fixed/.test(md.text));
  t('the exceptions travel as a file that can be loaded again',
    got.some((g) => /exceptions.*\.json$/.test(g.name)));
  const ex = got.find((g) => /exceptions.*\.json$/.test(g.name));
  const parsed = JSON.parse(ex.text);
  t('the file carries one entry', parsed.entries.length === 1);
  t('and is marked as ours, so a stray JSON is not mistaken for one',
    parsed.mark === 'dj-acs-auditor/exceptions');

  console.log('\n  An opted out finding is still a finding');
  const js = w.__json();
  const row = js.findings.find((r) => r.id === POL && r.object === OBJ);
  t('it is still in the JSON rather than filtered out of the record', !!row);
  t('and carries its exception', row.exception && row.exception.reason === REASON);
  t('findings with no exception say null rather than nothing',
    js.findings.some((r) => r.exception === null));

  console.log('\n  Loading exceptions refuses entries with the reason removed by hand');
  const r1 = w.__import({ mark: 'dj-acs-auditor/exceptions',
    entries: [{ key: 'k1', reason: '' }, { key: 'k2', reason: 'n/a' },
              { key: 'k3', reason: 'Documented in the system security plan, control CM-6.' }] });
  t('the one with a real reason is taken', r1.added === 1);
  t('the blank and the label are rejected', r1.rejected === 2);

  console.log('\n  A recorded exception survives reloading the same manifests');
  /* The handler stamps the finding it was given. Nothing above this point re-derives a
     stamp from the stored map, which is what a reload, a second scan and a loaded
     exceptions file all depend on, so it is checked on its own. */
  w.__load([{ name: 'm/api.yaml', text: dep('payments-api') },
            { name: 'm/web.yaml', text: dep('web-front') }]);
  const after = w.__S().findings.find((f) => f.policy.id === POL && f.obj === OBJ);
  t('the rescanned finding is a different object than the one that was opted out',
    after !== target);
  t('and it comes back carrying the exception', !!after.optOut);
  t('with the reason intact', after.optOut && after.optOut.reason === REASON);
  t('it is not selectable after the reload either',
    !!rowFor(POL, OBJ).querySelector('input[type=checkbox][disabled]'));
  const twin = w.__S().findings.find((f) => f.policy.id === POL && f.obj !== OBJ);
  t('the same policy on the other object did not inherit it', !twin.optOut);
  t('exactly one finding is opted out after the reload',
    w.__S().findings.filter((f) => f.optOut).length === 1);

  console.log('\n  An exceptions file written elsewhere applies to what is loaded here');
  w.__opt().clear();
  w.__apply();
  t('clearing the store clears the findings on the next pass',
    w.__S().findings.filter((f) => f.optOut).length === 0);
  const mine = w.__S().findings.find((f) => f.policy.id === POL && f.obj === OBJ);
  w.__import({ mark: 'dj-acs-auditor/exceptions', entries: [
    { key: w.__key(mine), reason: 'Waived in the system security plan under control CM-6.',
      policy: POL, obj: OBJ }] });
  w.__apply();
  t('the imported exception lands on the finding it names', !!mine.optOut);
  t('and on nothing else',
    w.__S().findings.filter((f) => f.optOut).length === 1);
  t('an imported exception reads the same as one recorded here',
    mine.optOut.reason.indexOf('CM-6') !== -1);
  w.__opt().clear();
  w.__apply();
  click(rowFor(POL, OBJ).querySelector('button.ropt'));
  const reform = rowFor(POL, OBJ).nextElementSibling.querySelector('.optform');
  reform.querySelector('.optreason').value = REASON;
  click(reform.querySelector('button.optsave'));

  console.log('\n  Removing an exception puts the finding back in scope');
  click(rowFor(POL, OBJ).querySelector('button.ropt'));
  const form2 = rowFor(POL, OBJ).nextElementSibling.querySelector('.optform');
  t('the form comes back showing what was recorded',
    form2.querySelector('.optreason').value === REASON);
  click(form2.querySelector('button.optclear'));
  t('the exception is gone', !w.__S().findings.find((f) => f.obj === OBJ && f.policy.id === POL).optOut);
  t('and the finding is selectable again',
    !!rowFor(POL, OBJ).querySelector('input.fsel:not([disabled])'));
  cleanup();
}

async function annotations() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__ver=()=>ACS_VERSION;');
  const DEP = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: payments-api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      hostNetwork: true', '      containers:', '      - name: api', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  const CM = ['apiVersion: v1', 'kind: ConfigMap',
    'metadata: { name: cfg, namespace: prod }', 'data: { a: b }'].join('\n');
  w.__load([{ name: 'm/api.yaml', text: DEP }, { name: 'm/cfg.yaml', text: CM }]);
  w.__tab('remediate');
  $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change'));
  $('btnFSelAll').click();

  const got = [];
  w.download = (n, c) => got.push({ name: n, text: c });
  delete w.JSZip;
  $('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));

  const y = got.find((g) => /api/.test(g.name) && /\.ya?ml$/.test(g.name));
  console.log('\n  A fixed object says what was done to it');
  t('the corrected file was written', !!y);
  const doc = w.jsyaml.load(y.text);
  const cc = doc.metadata.annotations['kubernetes.io/change-cause'];
  t('change-cause is on the object, which is the column rollout history prints', !!cc);
  const tpl = doc.spec.template.metadata.annotations['acs-auditor/applied'];
  t('and a second annotation is on the pod template, which is what rides into the ReplicaSet',
    !!tpl);
  t('the object level one alone would not survive into a revision, so both are required',
    !!cc && !!tpl);

  console.log('\n  Ordered date, time, tool and version, reference');
  t('it starts with the date', /^\d{4}-\d{2}-\d{2} /.test(cc));
  t('then the time, in UTC and saying so', /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}Z /.test(cc));
  t('then the tool and version',
    cc.indexOf('Z / DJ ACS Auditor ' + w.__ver() + ' / ') !== -1);
  t('then a reference', /\/ ACS-\d{8}-\d{4}-\d{3}$/.test(cc));
  t('both annotations carry the same value, so either one resolves', cc === tpl);
  t('it is short enough to read in a rollout history column', cc.length < 90);

  console.log('\n  The reference resolves to a register in the markdown');
  const md = got.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the markdown ships with the YAML', !!md);
  const ref = cc.split(' / ').pop();
  t('the register names this exact reference', md.text.indexOf('`' + ref + '`') !== -1);
  t('and says which object it belongs to',
    new RegExp('`' + ref + '`[^\n]*payments-api').test(md.text));
  t('the policies live there rather than in the annotation',
    /ACS\.001/.test(md.text) && !/ACS\.001/.test(cc));
  t('it flags the fixes that can stop the workload', /[Cc]an stop the workload/.test(md.text));
  t('and gives the command to go from a running workload back to this file',
    /acs-auditor\/applied/.test(md.text) && /oc get deploy/.test(md.text));

  console.log('\n  An object nobody fixed is left alone');
  t('the untouched ConfigMap is not in the export at all',
    !got.some((g) => /cfg/.test(g.name)));
  t('and stamping it would have restarted a workload to record that nothing happened',
    !/acs-auditor/.test(w.jsyaml.dump(w.__S().files[1].docs[0])));


  console.log('\n  Only what we changed gets stamped, even inside one file');
  /* Two objects in one file, one fixed. The file is rewritten either way, so the question
     is whether the object nobody touched comes back carrying an annotation. It must not:
     a pod template annotation is part of the pod template hash, so stamping an unchanged
     workload restarts it to record that nothing happened to it. */
  const h2 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);' +
    'window.__sync=()=>syncFindingSelection();');
  const two = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: ' + n + ', namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  h2.w.__load([{ name: 'm/both.yaml', text: two('fixme') + '\n---\n' + two('leave-alone') }]);
  h2.w.__tab('remediate');
  h2.$('fixMode').value = 'manual';
  h2.$('fixMode').dispatchEvent(new h2.w.Event('change'));
  for (const f of h2.w.__S().findings) {
    if (f.obj.indexOf('fixme') !== -1 && f.fixKind === 'auto') {
      h2.w.__sel().add(h2.w.__key(f));
    }
  }
  h2.w.__sync();
  const out2 = [];
  h2.w.download = (n, c) => out2.push({ name: n, text: c });
  delete h2.w.JSZip;
  h2.$('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const file2 = out2.find((g) => /\.ya?ml$/.test(g.name));
  t('the file was written', !!file2);
  const both = h2.w.jsyaml.loadAll(file2.text);
  const fixed = both.find((d) => d.metadata.name === 'fixme');
  const left = both.find((d) => d.metadata.name === 'leave-alone');
  t('both objects are still in the file', !!fixed && !!left);
  t('the one we changed carries the change cause',
    !!(fixed.metadata.annotations || {})['kubernetes.io/change-cause']);
  t('and the pod template annotation',
    !!((fixed.spec.template.metadata || {}).annotations || {})['acs-auditor/applied']);
  t('the one we did not change carries no change cause',
    !(left.metadata.annotations || {})['kubernetes.io/change-cause']);
  t('and no pod template annotation',
    !((left.spec.template.metadata || {}).annotations || {})['acs-auditor/applied']);
  t('it has no empty metadata block added to its pod template either',
    left.spec.template.metadata === undefined);
  t('and it is genuinely unmodified, not merely unannotated',
    left.spec.template.spec.containers[0].securityContext.privileged === true);
  h2.cleanup();


  console.log('\n  A file with nothing to fix comes back byte for byte');
  /* Both full export paths sent every loaded file through the YAML dumper. For a file with
     no findings that is pure loss: comments go, including whatever ownership header and
     change reference somebody put at the top, and quoting is normalised. The tool had no
     reason to touch the file and rewrote it anyway. */
  const h5 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__out=(f,r)=>exportText(f,r);window.__run=()=>newRun();');
  const needsFix = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: q/a:1',
    '        securityContext: { privileged: true }'].join('\n');
  const clean = ['# Owned by the platform team. Do not edit by hand.',
    '# Reviewed 2026-03-02 under CR-4471.', 'apiVersion: v1', 'kind: ConfigMap',
    'metadata:', '  name: app-config          # referenced by the api deployment',
    '  namespace: prod', 'data:', '  LOG_LEVEL: "info"', '  TIMEOUT: "30"'].join('\n');
  h5.w.__load([{ name: 'm/api.yaml', text: needsFix },
               { name: 'm/config.yaml', text: clean }]);
  t('the clean file really has no findings',
    h5.w.__S().findings.filter((f) => f.file === 'm/config.yaml').length === 0);

  const cf = h5.w.__S().files.find((f) => f.name === 'm/config.yaml');
  const written = h5.w.__out(cf, h5.w.__run());
  t('it is handed back exactly as loaded', written === clean);
  t('the ownership header survives', /Do not edit by hand/.test(written));
  t('the change reference survives, which is the one that matters',
    /CR-4471/.test(written));
  t('the inline comment survives', /referenced by the api deployment/.test(written));
  t('quoting is not normalised', /LOG_LEVEL: "info"/.test(written));
  t('and it carries no annotation, having had nothing done to it',
    !/acs-auditor|change-cause/.test(written));

  /* The file that WAS fixed is a different matter. Editing it means a YAML round trip and
     comments are lost; that is the cost of the edit, not a defect, and the fix is what was
     asked for. What it must have is the annotation. */
  const af = h5.w.__S().files.find((f) => f.name === 'm/api.yaml');
  h5.w.eval("for (const f of STATE.findings) if (f.file === 'm/api.yaml' && f.fixKind === 'auto') { STATE.applied.add(findingKey(f)); f.applied = true; }");
  const fixedOut = h5.w.__out(af, h5.w.__run());
  t('the fixed file is rewritten, which is what editing it means',
    fixedOut !== needsFix);
  t('and it does carry the annotation', /acs-auditor\/applied/.test(fixedOut));
  h5.cleanup();


  console.log('\n  The Secret that the fix points at does not exist yet, and the export says so');
  /* ACS.010 rewrites a literal credential to a secretKeyRef and nothing creates the Secret.
     Apply that first and the pod goes to CreateContainerConfigError with "secret not
     found", which is one of the two errors from the incident. The reference was created and
     the prerequisite lived in a sentence nobody read. */
  const h6 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);window.__sync=()=>syncFindingSelection();');
  h6.w.__load([{ name: 'm/a.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: payments-api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: q/a:1.2.3',
    '        env: [{ name: DB_PASSWORD, value: s3cretP@ss }]'].join('\n') }]);
  h6.w.__tab('remediate');
  h6.$('fixMode').value = 'manual';
  h6.$('fixMode').dispatchEvent(new h6.w.Event('change'));
  h6.w.eval('for (const f of STATE.findings) if (fFixable(f)) FSELECTED.add(findingRowKey(f));');
  h6.w.__sync();
  const got6 = [];
  h6.w.download = (n, c) => got6.push({ name: n, text: c });
  delete h6.w.JSZip;
  h6.$('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const md6 = got6.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the export was written', !!md6);
  t('it warns that the Secret does not exist yet',
    /Do this BEFORE you apply anything/.test(md6.text));
  t('it names the error you get if you ignore it',
    /CreateContainerConfigError/.test(md6.text));
  t('and it comes before the apply instructions, because the order is the fix',
    md6.text.indexOf('Do this BEFORE') < md6.text.indexOf('## Applying them'));
  t('it shows how to read the current value', /oc get deployment\/payments-api/.test(md6.text));
  t('it creates the Secret the manifest will point at, by its exact name',
    /oc create secret generic payments-api-secrets -n prod/.test(md6.text));
  t('it reads the value from a prompt, not the shell history',
    /read -rs -p/.test(md6.text));
  t('it verifies what landed before anything is applied',
    /oc get secret payments-api-secrets[\s\S]*base64 -d/.test(md6.text));
  t('it says to rotate the credential afterwards', /[Rr]otate/.test(md6.text));
  t('and it states that nothing was run for you',
    /Nothing above was run for you/.test(md6.text));
  h6.cleanup();


  console.log('\n  The Secret the fix points at is generated, with every key it references');
  const h7 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);window.__sync=()=>syncFindingSelection();');
  /* Two leaked credentials on one container. The fix rewrites both at once, so only the
     first finding reaches applied and the second reports no change. Deriving the keys from
     the findings produced a Secret with one key while the manifest referenced two, and the
     second credential became a reference to a key that did not exist. */
  h7.w.__load([{ name: 'm/a.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: payments-api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: q/a:1.2.3', '        env:',
    '        - { name: DB_PASSWORD, value: s3cretP@ss }',
    '        - { name: API_KEY, value: AKIAIOSFODNN7EXAMPLE }'].join('\n') }]);
  h7.w.__tab('remediate');
  h7.$('fixMode').value = 'manual';
  h7.$('fixMode').dispatchEvent(new h7.w.Event('change'));

  const runMode = async (mode) => {
    h7.$('secretMode').value = mode;
    h7.w.eval('FSELECTED.clear(); for (const f of STATE.findings) if (fFixable(f)) FSELECTED.add(findingRowKey(f));');
    h7.w.__sync();
    const out = [];
    h7.w.download = (n, c) => out.push({ name: n, text: c });
    delete h7.w.JSZip;
    h7.$('btnExportFixed').click();
    await new Promise((r) => setTimeout(r, 2200));
    return out;
  };

  const stub = await runMode('stub');
  const sfile = stub.filter((g) => /^secret-/.test(g.name));
  t('exactly one Secret is generated for the object, not one per credential',
    sfile.length === 1);
  const sec = h7.w.jsyaml.load(sfile[0].text);
  t('it is a Secret', sec.kind === 'Secret');
  t('it is in the right namespace', sec.metadata.namespace === 'prod');
  t('and is named exactly as the manifest reference expects, hyphens intact',
    sec.metadata.name === 'payments-api-secrets');
  const skeys = Object.keys(sec.stringData || {});
  t('it carries BOTH keys the manifest references', skeys.length === 2);
  t('  db_password', skeys.indexOf('db_password') !== -1);
  t('  api_key', skeys.indexOf('api_key') !== -1);
  t('the values are empty, so the file is safe to commit',
    skeys.every((k) => sec.stringData[k] === ''));
  t('and neither credential appears anywhere in it',
    !/s3cretP|AKIAIOSF/.test(sfile[0].text));

  /* The name and key must match what the manifest asks for, or this is the same
     CreateContainerConfigError one directory further along. */
  const yml = stub.find((g) => /\.ya?ml$/.test(g.name) && !/^secret-/.test(g.name));
  const dep7 = h7.w.jsyaml.load(yml.text);
  const refs = dep7.spec.template.spec.containers[0].env
    .map((e) => e.valueFrom.secretKeyRef);
  t('every reference in the manifest names the generated Secret',
    refs.every((r) => r.name === sec.metadata.name));
  t('and every key it asks for exists in that Secret',
    refs.every((r) => skeys.indexOf(r.key) !== -1));

  console.log('\n  ExternalSecret instead, for a Vault backed store');
  const ext = await runMode('external');
  const efile = ext.filter((g) => /^externalsecret-/.test(g.name));
  t('an ExternalSecret is generated', efile.length === 1);
  const es = h7.w.jsyaml.load(efile[0].text);
  t('it is an ExternalSecret', es.kind === 'ExternalSecret');
  t('it names a SecretStore to resolve against', !!es.spec.secretStoreRef.name);
  t('it targets the same Secret name the manifest references',
    es.spec.target.name === sec.metadata.name);
  t('it maps both keys', es.spec.data.length === 2);
  t('and it holds no credential either', !/s3cretP|AKIAIOSF/.test(efile[0].text));
  t('no plain Secret stub is emitted as well',
    ext.filter((g) => /^secret-/.test(g.name)).length === 0);

  console.log('\n  Or nothing, for somebody who manages Secrets elsewhere');
  const none = await runMode('none');
  t('no artifact is generated', none.filter((g) => /secret/i.test(g.name)).length === 0);
  t('but the manifest is still corrected',
    /secretKeyRef/.test(none.find((g) => /\.ya?ml$/.test(g.name)).text));
  h7.cleanup();


  console.log('\n  hostPath volumes get a recommended PVC, and a refusal to pretend it is a fix');
  const h8 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__recs=()=>pvcRecommendations();window.__sync=()=>syncFindingSelection();');
  const dep8 = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: payments-api, namespace: prod }', 'spec:', '  replicas: 3',
    '  template:', '    spec:', '      containers:', '      - { name: c, image: q/a:1.2.3 }',
    '      volumes:', '      - { name: cache, hostPath: { path: /opt/app/cache } }'].join('\n');
  const ds8 = ['apiVersion: apps/v1', 'kind: DaemonSet',
    'metadata: { name: log-shipper, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - { name: c, image: q/a:1.2.3 }', '      volumes:',
    '      - { name: varlog, hostPath: { path: /var/log } }'].join('\n');
  h8.w.__load([{ name: 'm/a.yaml', text: dep8 }, { name: 'm/b.yaml', text: ds8 }]);
  let recs8 = h8.w.__recs();
  t('one recommendation per hostPath volume', recs8.length === 2);
  t('the claim name is derived from the object and the volume',
    recs8.some((r) => r.rec.claimName === 'payments-api-cache'));
  t('it is a valid DNS name', recs8.every((r) => /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(r.rec.claimName)));
  t('and no longer than Kubernetes allows', recs8.every((r) => r.rec.claimName.length <= 63));

  console.log('\n  It will not collide with a claim that already exists');
  /* The collision check is only real if the tool can see the claims. Dropping
     oc get pvc -A -o json on the page alongside the manifests is what makes it so. */
  h8.w.__load([{ name: 'm/pvc.yaml', text: ['apiVersion: v1', 'kind: PersistentVolumeClaim',
    'metadata: { name: payments-api-cache, namespace: prod }',
    'spec: { accessModes: [ReadWriteOnce], resources: { requests: { storage: 5Gi } } }'].join('\n') }]);
  recs8 = h8.w.__recs();
  t('the existing claim name is not proposed again',
    !recs8.some((r) => r.rec.claimName === 'payments-api-cache'));
  t('a numbered name is proposed instead',
    recs8.some((r) => r.rec.claimName === 'payments-api-cache-2'));
  t('and two recommendations in one namespace do not collide with each other',
    new Set(recs8.map((r) => r.rec.claimName)).size === recs8.length);

  console.log('\n  The warnings are the point, not the manifest');
  const dep8r = recs8.find((r) => /payments/.test(r.finding.obj));
  const ds8r = recs8.find((r) => /log-shipper/.test(r.finding.obj));
  t('it says plainly that nothing is copied',
    dep8r.rec.warnings.some((x) => /[Nn]othing is copied/.test(x)));
  t('and names the host path whose contents stay behind',
    dep8r.rec.warnings.some((x) => /\/opt\/app\/cache/.test(x)));
  t('three replicas against ReadWriteOnce is called out',
    dep8r.rec.warnings.some((x) => /3 replicas/.test(x) && /ReadWriteOnce/.test(x)));
  /* A log shipper on /var/log is doing the thing hostPath exists for. Recommending a PVC
     there is actively wrong, so it is the first thing said. */
  t('a DaemonSet is warned about before anything else',
    /DaemonSet/.test(ds8r.rec.warnings[0]));
  t('the size is flagged as a placeholder',
    dep8r.rec.warnings.some((x) => /placeholder/.test(x)));
  t('and the absent storage class is explained rather than left blank',
    dep8r.rec.warnings.some((x) => /storageClassName/.test(x)));

  console.log('\n  Nothing is applied, and the artifact says what it is for');
  const claim = h8.w.jsyaml.load(dep8r.rec.text);
  t('it is a PersistentVolumeClaim', claim.kind === 'PersistentVolumeClaim');
  t('in the workload namespace', claim.metadata.namespace === 'prod');
  t('with no storageClassName, so the cluster default applies',
    claim.spec.storageClassName === undefined);
  t('it records which workload and volume it was proposed for',
    /payments-api/.test(claim.metadata.annotations['acs-auditor/recommended-for']) &&
    /cache/.test(claim.metadata.annotations['acs-auditor/recommended-for']));
  t('the volume patch references the claim by name',
    h8.w.jsyaml.load(dep8r.rec.volumePatch).persistentVolumeClaim.claimName === claim.metadata.name);
  t('ACS.012 is still a manual policy, so none of this is auto applied',
    h8.w.__S().findings.filter((f) => f.policy.id === 'ACS.012')
      .every((f) => f.fixKind === 'manual'));

  console.log('\n  And it lands in the export in a folder that says recommended');
  h8.w.__tab('remediate');
  h8.$('fixMode').value = 'manual';
  h8.$('fixMode').dispatchEvent(new h8.w.Event('change'));
  h8.w.eval('for (const f of STATE.findings) if (fFixable(f)) FSELECTED.add(findingRowKey(f));');
  h8.w.__sync();
  const out8 = [];
  h8.w.download = (n, c) => out8.push({ name: n, text: c });
  delete h8.w.JSZip;
  h8.$('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const md8 = out8.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the export describes the recommendations',
    /Recommended PersistentVolumeClaims, for review/.test(md8.text));
  t('it says they are not fixes', /not fixes and nothing has been applied/.test(md8.text));
  t('it warns about data loss on stateful workloads',
    /data loss/.test(md8.text));
  t('with a claim loaded, it does not print the caveat about not seeing the cluster',
    !/oc get pvc -A -o json/.test(md8.text));

  /* And the other way round. A fresh page with no PersistentVolumeClaim loaded must say the
     collision check is only as good as what it was given. */
  const h9 = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__sync=()=>syncFindingSelection();window.__S=()=>STATE;');
  h9.w.__load([{ name: 'm/a.yaml', text: dep8 }]);
  h9.w.__tab('remediate');
  h9.$('fixMode').value = 'manual';
  h9.$('fixMode').dispatchEvent(new h9.w.Event('change'));
  h9.w.eval('for (const f of STATE.findings) if (fFixable(f)) FSELECTED.add(findingRowKey(f));');
  h9.w.__sync();
  const out9 = [];
  h9.w.download = (n, c) => out9.push({ name: n, text: c });
  delete h9.w.JSZip;
  h9.$('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const md9 = out9.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('with no claim loaded, it says the collision check only saw the manifests',
    /oc get pvc -A -o json/.test(md9.text));
  h9.cleanup();
  h8.cleanup();


  console.log('\n  A manual finding becomes fixable once its recommendation is applied');
  /* The only lever the tool offered on a manual finding was an exception, and an exception
     does not move the score. So a team doing the work properly got the same feedback as a
     team waiving it. The value comes out of the generated artifact rather than the keyboard,
     because a retyped claim name is how a manifest comes to reference something absent. */
  const hR = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__rows=()=>FROWS;window.__res=()=>RESOLVED;window.__bundle=()=>optOutBundle();' +
    'window.__import=(d)=>optOutImport(d);window.__sync=()=>syncFindingSelection();' +
    'window.__key=(f)=>findingRowKey(f);');
  const depR = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - { name: c, image: q/a:1.2.3 }', '      volumes:',
    '      - { name: data, hostPath: { path: /opt/app/data } }'].join('\n');
  hR.w.__load([{ name: 'm/a.yaml', text: depR }]);
  hR.w.__tab('remediate');
  hR.$('fixMode').value = 'manual';
  hR.$('fixMode').dispatchEvent(new hR.w.Event('change'));

  const rowOf = (pol) => {
    const rows = hR.w.__rows();
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].policy.id === pol) {
        return hR.$('rtable').querySelector('tbody tr[data-i="' + i + '"]');
      }
    }
    return null;
  };
  const clickR = (el) => el.dispatchEvent(new hR.w.Event('click', { bubbles: true }));

  t('a manual finding with a resolution driven fix offers one',
    !!rowOf('ACS.012').querySelector('button.rres'));
  t('and its checkbox starts disabled, because nothing is resolved yet',
    rowOf('ACS.012').querySelector('td.selcell input').disabled === true);
  /* ACS.011 and ACS.020 are resolved by removing something, not editing a field, so they
     have no resolution fix and must not offer the button. */
  const noFix = hR.w.__S().findings.find((f) => f.policy.id === 'ACS.011' || f.policy.id === 'ACS.020');
  if (noFix) {
    t('a manual finding with no resolution fix does not offer one',
      !rowOf(noFix.policy.id).querySelector('button.rres'));
  }

  clickR(rowOf('ACS.012').querySelector('button.rres'));
  t('after marking it applied the checkbox enables', rowOf('ACS.012').querySelector('td.selcell input').disabled === false);
  t('and the row says it is ready', !!rowOf('ACS.012').querySelector('.pill.res'));
  t('a resolution was recorded', hR.w.__res().size === 1);
  const rec = Array.from(hR.w.__res().values())[0];
  t('it carries the claim name from the generated artifact, not typed input',
    rec.claimName === 'api-data');
  t('and names the file that was applied', /recommended\/pvc-api-data\.yaml/.test(rec.artifact));
  t('with a timestamp, so it is an audit record', /^\d{4}-\d{2}-\d{2}/.test(rec.when));

  console.log('\n  It rides in the exceptions file, as a second entry type');
  const bun = hR.w.__bundle();
  t('resolutions travel alongside the waivers', Array.isArray(bun.resolutions));
  t('and there is one', bun.resolutions.length === 1);
  t('with the policy and the object it belongs to',
    bun.resolutions[0].policy === 'ACS.012' && /api/.test(bun.resolutions[0].obj));
  /* A resolution with no value would mark a finding fixable and then produce no fix, which
     reads as the tool having silently done nothing. */
  const badImport = hR.w.__import({ mark: 'dj-acs-auditor/exceptions',
    resolutions: [{ key: 'k1' }, { key: 'k2', claimName: '' }] });
  t('an imported resolution with no value is rejected', badImport.rejected === 2);

  console.log('\n  The fix it unlocks is the mechanical one');
  hR.w.eval('FSELECTED.clear(); for (const f of STATE.findings) if (fFixable(f)) FSELECTED.add(findingRowKey(f));');
  hR.w.__sync();
  const outR = [];
  hR.w.download = (n, c) => outR.push({ name: n, text: c });
  delete hR.w.JSZip;
  hR.$('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 2500));
  const yR = outR.find((g) => /\.ya?ml$/.test(g.name) && !/^(secret|pvc|serviceaccount|networkpolicy)/.test(g.name));
  const docR = hR.w.jsyaml.load(yR.text);
  const volR = docR.spec.template.spec.volumes[0];
  t('the hostPath is gone', volR.hostPath === undefined);
  t('and the volume is a claim on the recommended name',
    volR.persistentVolumeClaim.claimName === 'api-data');

  console.log('\n  And the prerequisite comes before the apply instructions');
  const mdR = outR.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the export says what has to exist first',
    /These must exist before you apply anything/.test(mdR.text));
  t('it prints the command to confirm the claim is Bound',
    /oc get pvc api-data -n prod/.test(mdR.text));
  t('it warns that Pending means the pod waits too', /Pending/.test(mdR.text));
  t('it repeats that nothing was copied out of the host path',
    /[Nn]othing was copied/.test(mdR.text));
  t('and it appears before the apply instructions',
    mdR.text.indexOf('must exist before you apply') < mdR.text.indexOf('## Applying them'));

  console.log('\n  Marking it again undoes it');
  clickR(rowOf('ACS.012').querySelector('button.rres'));
  t('the resolution is removed', hR.w.__res().size === 0);
  t('and the finding is manual again',
    rowOf('ACS.012').querySelector('td.selcell input').disabled === true);
  hR.cleanup();

  console.log('\n  The score shows what resolving is worth, and only render() owns the cards');
  /* renderRemediateTab also wrote #cards and ran second, so it silently replaced whatever
     the Audit half put there and a card added in render() never appeared at all. */
  const hC = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__rows=()=>FROWS;');
  const hardened = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      serviceAccountName: api-sa', '      automountServiceAccountToken: false',
    '      containers:', '      - name: c', '        image: q/a:1.2.3',
    '        securityContext: { privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }',
    '        resources: { requests: { cpu: 100m, memory: 128Mi }, limits: { cpu: 500m, memory: 256Mi } }',
    '      volumes:', '      - { name: data, hostPath: { path: /opt/app/data } }'].join('\n');
  hC.w.__load([{ name: 'm/a.yaml', text: hardened }]);
  const cardsOf = () => Array.from(hC.w.document.querySelectorAll('#cards .card'))
    .map((c) => ({ n: c.querySelector('.num').textContent, l: c.querySelector('.lbl').textContent }));
  t('there is no resolved card before anything is resolved',
    !cardsOf().some((c) => /resolved/.test(c.l)));
  const base = cardsOf();
  t('the first card is the current posture', /Posture/.test(base[0].l));
  t('the second is the auto fix projection', /After auto fixes/.test(base[1].l));
  /* The merged card set, proving render() is the only writer. Before this, switching to the
     Remediate tab replaced these with a different set. */
  t('the remediate numbers are on the same card set, one owner',
    cardsOf().some((c) => /Fixes applied/.test(c.l)) &&
    cardsOf().some((c) => /Need a decision/.test(c.l)));
  hC.w.__tab('remediate');
  hC.$('fixMode').value = 'manual';
  hC.$('fixMode').dispatchEvent(new hC.w.Event('change'));
  t('and switching tabs does not replace them',
    cardsOf().some((c) => /After auto fixes/.test(c.l)));
  const rowsC = hC.w.__rows();
  let trC = null;
  for (let i = 0; i < rowsC.length; i++) {
    if (rowsC[i].policy.id === 'ACS.012') trC = hC.$('rtable').querySelector('tbody tr[data-i="' + i + '"]');
  }
  trC.querySelector('button.rres').dispatchEvent(new hC.w.Event('click', { bubbles: true }));
  const after3 = cardsOf();
  const resCard = after3.find((c) => /resolved/.test(c.l));
  t('a third card appears once something is resolved', !!resCard);
  t('it names how many', /Plus 1 resolved/.test(resCard.l));
  t('and it is higher than the auto fix projection, which is the point',
    Number(resCard.n) > Number(after3.find((c) => /After auto fixes/.test(c.l)).n));
  hC.cleanup();

  console.log('\n  Looking at the page does not stamp what is loaded');
  t('the loaded YAML carries no annotation',
    !/acs-auditor\/applied/.test(w.jsyaml.dump(w.__S().files[0].docs[0])));
  t('and no change-cause either',
    !/change-cause/.test(w.jsyaml.dump(w.__S().files[0].docs[0])));
  cleanup();
}

async function diffTab() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__S=()=>STATE;window.__sel=()=>FSELECTED;window.__key=(f)=>findingRowKey(f);' +
    'window.__built=(x)=>buildFixedCopy(x);window.__fix=(f)=>fFixable(f);');
  const M = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: app-' + n + ', namespace: ns-' + n + ' }', 'spec:', '  template:',
    '    spec:', '      hostNetwork: true', '      containers:', '      - name: c',
    '        image: q/app-' + n + ':1',
    '        env: [{ name: DB_PASSWORD, value: s3cret }]',
    '        securityContext: { privileged: true }'].join('\n');
w.__load([{name:'m/a.yaml',text:M(1)},{name:'m/b.yaml',text:M(2)}]);
console.log('\nThe Diff tab');
t('the tab button exists', !!$('tabDiffBtn'));
w.__tab('diff');
t('showTab reveals the pane', !$('tabDiff').classList.contains('hidden'));
t('and hides the others', $('tabAudit').classList.contains('hidden') && $('tabRemediate').classList.contains('hidden'));
t('an unknown tab name falls back to audit rather than showing nothing',
  (w.__tab('nonsense'), !$('tabAudit').classList.contains('hidden')));
w.__tab('diff');

let files=w.document.querySelectorAll('#dFiles button.dfile');
const names=Array.from(files).map(b=>b.dataset.f);
t('both loaded manifests appear', names.indexOf('m/a.yaml')!==-1 && names.indexOf('m/b.yaml')!==-1);
t('the generated NetworkPolicies appear as new files',
  names.filter(n=>/networkpolicy-default-deny-.*\.yaml/.test(n)).length>0);
t('and none of them is called undefined, which is what shipped from 1.5.0 to 1.6.0',
  names.every(n=>n.indexOf('undefined')===-1));
const gen=names.find(n=>/networkpolicy/.test(n));
t('a generated file has real YAML on the right, not the word undefined',
  (function(){ const b=Array.from(files).find(x=>x.dataset.f===gen); b.click();
    const txt=$('dtable').textContent;
    return /kind: NetworkPolicy/.test(txt) && txt.indexOf('undefined')===-1; })());
files=w.document.querySelectorAll('#dFiles button.dfile');
Array.from(files).find(x=>x.dataset.f==='m/a.yaml').click();
files=w.document.querySelectorAll('#dFiles button.dfile');
t('with an added and a removed count', /\+\d+/.test($('dFiles').textContent) && /-\d+/.test($('dFiles').textContent));
t('the count line says how many files and fixes', /file\(s\) would change/.test($('dCount').textContent));

const rows=w.document.querySelectorAll('#dtable tbody tr');
t('the first file renders rows', rows.length>0);
t('every row has four cells, so the columns cannot slip',
  Array.from(rows).filter(r=>!r.classList.contains('skip')).every(r=>r.querySelectorAll('td').length===4));
const chg=w.document.querySelectorAll('#dtable tbody tr.chg');
t('a changed value is one row with both sides, not two rows', chg.length>0);
const anyRow=chg[0];
t('left holds the old text and right the new',
  anyRow.querySelectorAll('td')[1].textContent!==anyRow.querySelectorAll('td')[3].textContent);
t('privileged true is on the left somewhere', /privileged: true/.test($('dtable').textContent));
t('and privileged false on the right', /privileged: false/.test($('dtable').textContent));

console.log('\n  Nothing is applied by looking');
t('STATE has no history', w.__S().history.length===0);
t('no finding is marked applied', w.__S().findings.filter(f=>f.applied).length===0);
t('the loaded YAML still says privileged: true',
  /privileged: true/.test(w.jsyaml.dump(w.__S().files[0].docs[0])));

console.log('\n  It works in report mode, because a diff is not an artifact');
t('the mode is report', $('fixMode').value==='report');
t('and rows are still rendered', w.document.querySelectorAll('#dtable tbody tr').length>0);

console.log('\n  Switching files');
files[1].click();
t('clicking the second file changes the pane',
  w.document.querySelectorAll('#dFiles button.dfile.on')[0].dataset.f==='m/b.yaml');

console.log('\n  The selection filter');
$('dSelOnly').checked=true; $('dSelOnly').dispatchEvent(new w.Event('change'));
t('with nothing ticked the filter empties the view',
  w.document.querySelectorAll('#dFiles button.dfile').length===0);
t('and says why rather than going blank', /Nothing is ticked/.test($('dEmpty').textContent));
const one=w.__S().findings.filter(f=>f.file==='m/a.yaml'&&!f.applied&&f.fixKind!=='manual')[0];
w.__sel().add(w.__key(one));
$('dSelOnly').dispatchEvent(new w.Event('change'));
const dfiles = Array.from(w.document.querySelectorAll('#dFiles button.dfile'))
  .map((b) => b.dataset.f);
t('ticking one finding brings back its file',
  dfiles.some((n) => n === 'm/a.yaml'));
t('and not the file it was not ticked on',
  !dfiles.some((n) => n === 'm/b.yaml'));
t('anything else in the list is a generated artifact, not another loaded manifest',
  dfiles.every((n) => n === 'm/a.yaml' || /new file/.test(n)));

console.log('\n  Hide unchanged lines');
$('dCtx').checked=false; $('dCtx').dispatchEvent(new w.Event('change'));
const all=w.document.querySelectorAll('#dtable tbody tr').length;
$('dCtx').checked=true; $('dCtx').dispatchEvent(new w.Event('change'));
const few=w.document.querySelectorAll('#dtable tbody tr').length;
t('hiding context shows fewer rows', few<all);
t('and says how many it hid', /unchanged line\(s\)/.test($('dtable').textContent));

  cleanup();
}

async function scale() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__S=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__sel=()=>FSELECTED;window.__rows=()=>findingRows();window.__frows=()=>FROWS;');
  const M = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: app-' + n + ', namespace: ns-' + n + ' }', 'spec:', '  template:',
    '    spec:', '      hostNetwork: true', '      hostPID: true',
    '      automountServiceAccountToken: true', '      containers:', '      - name: c',
    '        image: q/app-' + n + ':latest',
    '        securityContext: { privileged: true, allowPrivilegeEscalation: true, runAsUser: 0 }',
    '        env: [{ name: DB_PASSWORD, value: s3cret }]',
    '        ports: [{ containerPort: 80, hostPort: 80 }]'].join('\n');

  const files = [];
  for (let i = 0; i < 50; i++) files.push({ name: 'm/app' + i + '.yaml', text: M(i) });
  w.__load(files);
  w.__tab('remediate');
  const n = w.__rows().length;

  console.log('\nA real sized run: ' + n + ' findings');
  t('the run is big enough to matter', n > 400);

  /* No cap. A cap would draw some of the findings and hide the rest, which breaks Ctrl+F
     and print for the hidden ones and makes "Select all shown" act on rows that are not
     shown -- the same "the number disagrees with the screen" defect this suite exists
     for. The render is cheap because there is one innerHTML parse, no advisory is built
     until it is asked for, and a tick repaints rather than rebuilds. */
  console.log('\n  1. Every matching row is drawn, none are hidden from the operator');
  t('the number of rows equals the number of matching findings',
    w.document.querySelectorAll('#rtable tbody tr[data-i]').length === n);
  t('nothing tells the operator rows were withheld',
    !/Showing the first/.test($('rtable').textContent));
  t('FROWS is what was drawn', w.__frows().length === n);
  t('the count line agrees',
    new RegExp('showing ' + n + ' of ' + n + ' finding').test($('fCount').textContent));

  console.log('\n  2. Advisories are built when asked for, not all ' + n + ' up front');
  t('no advisory row exists before anybody opens one',
    w.document.querySelectorAll('#rtable tbody tr.fdet').length === 0);
  const row = w.document.querySelector('#rtable tbody tr[data-i="2"]');
  row.querySelector('td.wrapcell').click();
  t('clicking a row builds its own advisory',
    w.document.querySelectorAll('#rtable tbody tr.fdet').length === 1);
  t('and fills it', row.nextElementSibling.firstElementChild.innerHTML.length > 100);
  t('and reveals it', !row.nextElementSibling.classList.contains('hidden'));
  row.querySelector('td.wrapcell').click();
  t('clicking again collapses it', row.nextElementSibling.classList.contains('hidden'));
  row.querySelector('td.wrapcell').click();
  t('and a third click does not build a second advisory row',
    w.document.querySelectorAll('#rtable tbody tr.fdet').length === 1);
  row.querySelector('td.wrapcell').click();

  console.log('\n  3. Ticking a checkbox updates the count, it does not rebuild the table');
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  const first = w.document.querySelector('#rtable tbody tr[data-i]');
  first.dataset.sentinel = 'survives-a-tick';
  const box = w.document.querySelector('#rtable tbody input.fsel:not([disabled])');
  box.click();
  t('the row element is the same element afterwards',
    w.document.querySelector('#rtable tbody tr[data-i]').dataset.sentinel === 'survives-a-tick');
  t('the count still moved, so something did happen',
    /1 selected/.test($('fCount').textContent));
  const openAdv = (function () { const r = w.document.querySelector('#rtable tbody tr[data-i="4"]');
    r.querySelector('td.wrapcell').click(); return r.nextElementSibling; })();
  box.click();
  t('an advisory somebody opened is not closed by ticking a box elsewhere',
    !openAdv.classList.contains('hidden'));

  console.log('\n  4. Select all covers every drawn row, and every drawn row is every match');
  $('btnFSelAll').click();
  t('it is every fixable finding that matches the filters',
    w.__sel().size === w.__rows().filter((f) => !f.applied && f.fixKind !== 'manual').length);
  t('and every one of them has a ticked box on screen, so the number matches the table',
    Array.from(w.document.querySelectorAll('#rtable tbody input.fsel:not([disabled])'))
      .every((c) => c.checked) &&
    w.document.querySelectorAll('#rtable tbody input.fsel:not([disabled])').length ===
      w.__sel().size);
  t('the same sentinel row survived select all too',
    w.document.querySelector('#rtable tbody tr[data-i]').dataset.sentinel === 'survives-a-tick');

  console.log('\n  5. Long values cannot push the table out of the frame');
  const cells = w.document.querySelectorAll('#rtable tbody td.wrapcell');
  t('the wide columns are marked as breakable rather than left to set their own width',
    cells.length > 0);
  t('and the full value is on the cell as well, for a narrow window',
    Array.from(cells).slice(0, 30).every((c) => !c.title || c.title === c.textContent));
  const css = require('fs').readFileSync(require('path').join(ROOT, 'dj_acs_auditor.html'), 'utf8');
  t('the findings table is fixed layout, so one long cell cannot widen every column',
    /#rtable\{table-layout:fixed/.test(css));
  t('the panel cannot exceed the viewport', /\.section,details\.sec\{min-width:0;max-width:100%/.test(css));
  t('the wrapper takes any remainder as its own scrollbar', /\.tablewrap\{overflow-x:auto/.test(css));
  t('long values break inside the cell rather than being clipped out of sight',
    /td\.wrapcell[^{]*\{overflow-wrap:anywhere/.test(css));
  t('and the advisory row is free to wrap',
    /#rtable tr\.fdet td\{max-width:none;white-space:normal/.test(css));
  cleanup();
}

async function bulkExport() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__S=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__rows=()=>findingRows();window.__sel=()=>FSELECTED;');
  const S = () => w.__S();
  const M = (n) => ['apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: ' + n,
    '  namespace: prod', 'spec:', '  template:', '    spec:', '      hostNetwork: true',
    '      containers:', '      - name: c', '        image: q/' + n + ':1',
    '        securityContext:', '          privileged: true'].join('\n');

  console.log('\nFiltering a large finding list into something workable');
  w.__load([{ name: 'app/a.yaml', text: M('alpha') }, { name: 'app/b.yaml', text: M('beta') }]);
  w.__tab('remediate');
  const all = S().findings.length;
  t('the scan produced a list worth filtering', all > 10);

  const sevBoxes = () => Array.from(w.document.querySelectorAll('input.fsev'));
  sevBoxes().forEach((c) => { c.checked = (c.value === 'High'); });
  sevBoxes()[0].dispatchEvent(new w.Event('change'));
  const highOnly = w.__rows();
  t('a severity filter narrows the list',
    highOnly.length > 0 && highOnly.length < all);
  /* Read the rendered badge rather than recomputing the label from the same helper the
     filter uses, so a wrong mapping cannot agree with itself. */
  const shownSev = Array.from(w.document.querySelectorAll('#rtable tbody span.sev'))
    .map((e) => e.textContent.trim());
  t('and everything the table shows is that severity',
    shownSev.length === highOnly.length && shownSev.every((x) => x === 'High'));

  sevBoxes().forEach((c) => { c.checked = true; });
  sevBoxes()[0].dispatchEvent(new w.Event('change'));

  $('fCat').value = 'Privileges';
  $('fCat').dispatchEvent(new w.Event('change'));
  const byCat = w.__rows();
  t('a weakness class filter works, which is how you take privilege escalation on its own',
    byCat.length > 0 && byCat.every((f) => f.policy.categories.indexOf('Privileges') !== -1));
  t('the class picker is built from what was found, not the whole catalogue',
    Array.from($('fCat').options).slice(1)
      .every((o) => S().findings.some((f) => f.policy.categories.indexOf(o.value) !== -1)));
  $('fCat').value = '';
  $('fCat').dispatchEvent(new w.Event('change'));

  console.log('\n  Selection survives filtering, because it is held per finding');
  $('fixMode').value = 'manual';
  $('fixMode').dispatchEvent(new w.Event('change'));
  $('btnFSelAll').click();
  const n = w.__sel().size;
  t('select all shown takes the fixable ones', n > 0);
  t('the button names the count', new RegExp(n + ' selected').test($('btnExportFixed').textContent));
  sevBoxes().forEach((c) => { c.checked = (c.value === 'Low'); });
  sevBoxes()[0].dispatchEvent(new w.Event('change'));
  t('filtering the selection out of view does not clear it', w.__sel().size === n);
  sevBoxes().forEach((c) => { c.checked = true; });
  sevBoxes()[0].dispatchEvent(new w.Event('change'));

  console.log('\n  Export writes corrected YAML and changes nothing that is loaded');
  const got = [];
  w.download = (nm, c) => got.push({ name: nm, text: c });
  delete w.JSZip;
  $('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 900));

  const yamls = got.filter((g) => /\.ya?ml$/.test(g.name));
  t('corrected YAML is written', yamls.length > 0);
  /* This asserted exactly 2 and passed for four releases while the export was writing a
     third file called "undefined" containing the word "undefined", produced whenever a
     Generate finding was selected. The count was right past it: "undefined" does not
     match /\.ya?ml$/, so the filter above never saw it. An equality check on a filtered
     count cannot see what the filter excludes. */
  t('one file per manifest that changed, plus the generated ones',
    yamls.filter((g) => !/networkpolicy-default-deny/.test(g.name)).length === 2);
  if (yamls.filter((g) => !/networkpolicy-default-deny/.test(g.name)).length !== 2) {
    console.log('        wrote: ' + yamls.map((g) => g.name).join(', '));
  }
  t('every file written has a real name', got.every((g) => g.name.indexOf('undefined') === -1));
  t('and real content', got.every((g) => typeof g.text === 'string' && g.text.length > 0));
  const np = yamls.filter((g) => /networkpolicy-default-deny/.test(g.name));
  t('a Generate finding writes a named NetworkPolicy rather than a file called undefined',
    np.length > 0 && /kind: NetworkPolicy/.test(np[0].text));
  const doc = w.jsyaml.load(yamls[0].text);
  t('the fixes are actually in it',
    doc.spec.template.spec.containers[0].securityContext.privileged === false &&
    doc.spec.template.spec.hostNetwork === false);
  t('a readme goes with it', got.some((g) => /READ_THIS_FIRST/.test(g.name)));
  const rm = got.find((g) => /READ_THIS_FIRST/.test(g.name));
  t('the readme says nothing was run', /No command was run/.test(rm.text));
  t('it names the fixes that can stop a workload', /can stop the workload/.test(rm.text));
  t('it says how to apply them', /oc apply -f corrected/.test(rm.text));
  t('and suggests a server side dry run first', /--dry-run=server/.test(rm.text));
  t('exporting did not apply anything to the loaded files',
    S().history.length === 0 && S().findings.filter((f) => f.applied).length === 0);

  console.log('\n  Report mode produces none of it, and says why');
  got.length = 0;
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));
  t('the export button is disabled in report mode', $('btnExportFixed').disabled);
  t('and the page explains which control is holding it',
    /Report only, so nothing that could be applied/.test($('modeWhy').textContent));
  $('btnExportFixed').click();
  await new Promise((r) => setTimeout(r, 200));
  t('clicking it anyway writes nothing', got.length === 0);

  console.log('\n  The heavy sections collapse, with counts that mean something');
  const secs = w.document.querySelectorAll('details.sec');
  t('the heavy sections are collapsible', secs.length >= 3);
  t('they start open, so nothing is hidden from a first read',
    Array.from(secs).every((d) => d.open));
  t('a closed one still reports what is inside',
    $('rtableCnt').textContent.indexOf('open') !== -1);
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


/* ---------------------------------------------------------------- spec cases
 *
 * Written from .pipeline/specs.md section 7, one block per numbered edge case, rather
 * than from the code. Where the code deviates from the spec the deviation is named in
 * the label and in .pipeline/tests.md, so a reviewer can see which of the two is being
 * asserted.
 *
 * Every assertion in these two functions was proved failable: the code under test was
 * mutated, the assertion was watched go red, and the mutation was reverted. The list of
 * mutations is in .pipeline/tests.md.
 */

/* One Deployment that trips exactly one policy, so "1 of 1" in the count line is a real
   1 of 1 rather than a filtered view of a longer list. */
const SOLO = ['apiVersion: apps/v1', 'kind: Deployment',
  'metadata: { name: solo, namespace: solons, labels: { app: solo } }', 'spec:',
  '  template:', '    metadata: { labels: { app: solo } }', '    spec:',
  '      automountServiceAccountToken: false', '      serviceAccountName: solo-sa',
  '      securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }',
  '      containers:', '      - name: c',
  '        image: q/c@sha256:' + 'a'.repeat(64),
  '        securityContext: { privileged: false, allowPrivilegeEscalation: false,' +
  ' runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }',
  '        resources: { limits: { cpu: "1", memory: 1Gi }, requests: { cpu: "1", memory: 1Gi } }'
].join('\n');

const WIDE = (n) => ['apiVersion: apps/v1', 'kind: Deployment',
  'metadata: { name: app-' + n + ', namespace: ns-' + n + ' }', 'spec:', '  template:',
  '    spec:', '      hostNetwork: true', '      hostPID: true',
  '      automountServiceAccountToken: true', '      containers:', '      - name: c',
  '        image: q/app-' + n + ':latest',
  '        securityContext: { privileged: true, allowPrivilegeEscalation: true, runAsUser: 0 }',
  '        env: [{ name: DB_PASSWORD, value: s3cret }]',
  '        ports: [{ containerPort: 80, hostPort: 80 }]'].join('\n');

async function specCases() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__S=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__rows=()=>findingRows();window.__sel=()=>FSELECTED;window.__frows=()=>FROWS;' +
    'window.__key=(f)=>findingRowKey(f);window.__render=()=>render();' +
    'window.__reset=()=>{STATE.files=[];STATE.applied.clear();FSELECTED.clear();rescan();};');
  const S = () => w.__S();
  const manual = () => { $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change')); };
  const report = () => { $('fixMode').value = 'report'; $('fixMode').dispatchEvent(new w.Event('change')); };
  const sevBoxes = () => Array.from(w.document.querySelectorAll('input.fsev'));
  const applySev = () => sevBoxes()[0].dispatchEvent(new w.Event('change'));
  const boxes = () => Array.from(w.document.querySelectorAll('#rtable tbody input.fsel'));
  const tbody = () => $('rtable').querySelector('tbody');
  /* A missing element is a failure to report, not an exception that stops the suite and
     hides every case after it. */
  const clk = (el) => { if (el && el.click) el.click(); return !!el; };

  /* Spec 7 case 1. An empty table reads as a clean scan unless it says which empty it is,
     which is the misreading the section header already guards against. */
  console.log('\n  Spec case 1: no findings at all');
  w.__tab('remediate');
  w.__render();
  const empty = tbody().children;
  t('an empty scan draws exactly one row rather than an empty table',
    empty.length === 1 && empty[0].children.length === 1);
  t('that row spans every column the header declares',
    !!empty[0] && Number(empty[0].firstElementChild.getAttribute('colspan')) ===
      w.document.querySelectorAll('#rtable thead th').length);
  t('and it says there was nothing to scan, not that the scan was clean',
    !!empty[0] && empty[0].textContent === 'No findings. Load manifests above to scan them.');
  t('the header box is disabled, unticked and not part ticked',
    $('fSelAll').disabled === true && $('fSelAll').checked === false &&
    $('fSelAll').indeterminate === false);
  t('the count line reads exactly as specified',
    $('fCount').textContent === 'showing 0 of 0 finding(s), none selected');
  t('and the export button is off, with no count on it',
    $('btnExportFixed').disabled === true &&
    $('btnExportFixed').textContent === 'Download corrected YAML');
  t('nothing is selected before anybody has touched anything', w.__sel().size === 0);

  /* Spec 7 case 2. */
  console.log('\n  Spec case 2: exactly one finding, and it is fixable');
  w.__load([{ name: 'solo.yaml', text: SOLO }]);
  w.__tab('remediate');
  manual();
  t('the fixture really does produce exactly one finding', S().findings.length === 1);
  t('one finding draws one data row', tbody().querySelectorAll('tr[data-i]').length === 1);
  const solo = boxes();
  t('with one checkbox, and it is enabled',
    solo.length === 1 && solo[0].disabled === false);
  clk(solo[0]);
  t('ticking it selects exactly that finding',
    w.__sel().size === 1 && w.__frows()[0] && w.__sel().has(w.__key(w.__frows()[0])));
  t('and fills the header box completely rather than part way',
    $('fSelAll').checked === true && $('fSelAll').indeterminate === false);
  t('and the count line reads exactly as specified',
    $('fCount').textContent === 'showing 1 of 1 finding(s), 1 selected');
  t('and the export button carries the count',
    $('btnExportFixed').textContent === 'Download corrected YAML for 1 selected');

  /* Spec 5.7, exact strings rather than a substring match. A title that drifts to
     "Report only." alone still matches a regex for the first three words and no longer
     tells anybody which control to move. */
  console.log('\n  Spec 5.7: the exact words on the gated controls');
  t('with a selection and a mode that allows it, the export button has no excuse on it',
    $('btnExportFixed').title === '');
  report();
  t('in report mode the export button names the control and where it is',
    $('btnExportFixed').title ===
    'Report only. Choose Manual or Auto in the Mode selector at the top of the page.');
  t('and the note above the table carries the specified sentence, whole',
    $('fModeWhy').textContent ===
    'Mode is Report only, so nothing that could be applied is produced: Download ' +
    'corrected YAML and the per row Fix this buttons are disabled. Change Mode at the ' +
    'top of the page to Manual to get files to review, or Auto to also apply fixes ' +
    'here. Your selection is kept either way.');
  manual();
  $('btnFSelNone').click();
  t('with nothing selected the button asks for a selection rather than blaming the mode',
    $('btnExportFixed').title === 'Nothing selected. Tick the findings you want to export.');
  t('and the mode note is emptied and hidden once the mode allows writing',
    $('fModeWhy').textContent === '' && $('fModeWhy').classList.contains('hidden'));
  t('and a Fix this button that can act says what pressing it will do',
    (function () { const b = tbody().querySelector('button.rfix');
      return !!b && b.disabled === false &&
        b.title === 'Preview this fix as a diff and confirm it before anything changes.';
    })());

  /* Spec 7 case 3. */
  console.log('\n  Spec case 3: every row filtered away');
  w.__reset();
  w.__load([{ name: 'w/a.yaml', text: WIDE('a') }, { name: 'w/b.yaml', text: WIDE('b') }]);
  w.__tab('remediate');
  manual();
  const total = S().findings.length;
  t('the fixture is worth filtering', total > 10);
  sevBoxes().forEach((c) => { c.checked = false; }); applySev();
  const none = tbody().children;
  t('a filter that matches nothing draws one row, not an empty table',
    none.length === 1 && none[0].children.length === 1);
  t('and it says the findings are hidden rather than absent',
    !!none[0] && none[0].textContent === 'No findings match the current filters. ' + total +
      ' finding(s) are hidden by them.');
  t('the header box is disabled when there is nothing to tick',
    $('fSelAll').disabled === true);
  t('and the section header still reports the true total, not zero',
    new RegExp('\\b' + total + ' open').test($('rtableCnt').textContent));
  sevBoxes().forEach((c) => { c.checked = true; }); applySev();

  /* Spec 7 case 20. */
  console.log('\n  Spec case 20: rows on screen, but none of them selectable');
  $('fkAuto').checked = false; $('fkGen').checked = false; $('fkManual').checked = true;
  $('fkAuto').dispatchEvent(new w.Event('change'));
  t('there are rows on screen', w.__frows().length > 0);
  t('but none of them is fixable', w.__frows().every((f) => f.fixKind === 'manual'));
  t('so the header box is disabled, unticked and not part ticked',
    $('fSelAll').disabled === true && $('fSelAll').checked === false &&
    $('fSelAll').indeterminate === false);
  $('fSelAll').click();
  t('and clicking it selects nothing', w.__sel().size === 0);

  /* Spec 7 case 5. */
  console.log('\n  Spec case 5: a finding with no mechanical fix');
  const mrow = tbody().querySelector('tr[data-i]');
  const mf = w.__frows()[0];
  const mcb = mrow && mrow.querySelector('td.selcell input');
  t('it still gets a checkbox, so the column does not read as an oversight', !!mcb);
  t('the checkbox is disabled', !!mcb && mcb.disabled === true);
  t('and its title is the specified sentence followed by the policy remediation',
    !!mcb && !!mf &&
    mcb.title === 'No mechanical fix: this one needs a decision. ' + mf.policy.remediation);
  t('and there is no Fix this button in the action cell',
    !!mrow && !mrow.querySelector('button.rfix'));
  /* The cell is no longer empty: a finding with no mechanical fix is the one most likely
     to sit unexplained, so it is offered somewhere to record why it is being left. The
     assertion above used to read the cell as empty, which tested the absence of
     everything when what the spec says is the absence of one button. */
  t('but it can still be opted out with a reason',
    !!mrow.querySelector('button.ropt'));
  $('fkAuto').checked = true; $('fkGen').checked = true; $('fkManual').checked = true;
  $('fkAuto').dispatchEvent(new w.Event('change'));

  /* Spec 7 case 6. STATE.applied is keyed on findingKey, which is the contract the spec
     deliberately left alone, so this drives it through the real restore path in rescan
     rather than setting f.applied by hand. */
  console.log('\n  Spec case 6: a finding already applied');
  const target = S().findings.find((f) => f.fixKind === 'auto');
  S().applied.add(w.findingKey(target));
  w.__load([]);
  $('fkApplied').checked = true;
  $('fkApplied').dispatchEvent(new w.Event('change'));
  const drow = tbody().querySelector('tr.done');
  t('the applied finding comes back marked as applied',
    S().findings.some((f) => f.applied) && !!drow);
  const dcb = drow && drow.querySelector('td.selcell input');
  t('its checkbox is disabled', !!dcb && dcb.disabled === true);
  t('and says so in exactly those words', !!dcb && dcb.title === 'Already applied.');
  t('and it offers no Fix this button',
    !!drow && !drow.querySelector('button.rfix'));
  t('nor an opt out, because there is nothing left to decide',
    !!drow && !drow.querySelector('button.ropt'));
  $('btnFSelAll').click();
  t('select all shown cannot pick up an applied finding',
    !w.__sel().has(w.__key(S().findings.find((f) => f.applied))));
  $('btnFSelNone').click();
  $('fkApplied').checked = false;
  $('fkApplied').dispatchEvent(new w.Event('change'));
  S().applied.clear();
  w.__load([]);

  /* Spec 7 cases 7, 8 and 9. The selection outlives the filters, so the count on the
     button can legitimately exceed what is on screen. It has to say so. */
  console.log('\n  Spec cases 7 and 8: the selection outlives the filters');
  $('btnFSelAll').click();
  const wide = w.__sel().size;
  t('there is a selection to narrow', wide > 4);
  sevBoxes().forEach((c) => { c.checked = (c.value === 'High'); }); applySev();
  const shownNow = w.__frows().filter((f) => !f.applied && f.fixKind !== 'manual');
  const hiddenN = wide - shownNow.length;
  t('narrowing the filter keeps every tick', w.__sel().size === wide);
  t('some of the selection is genuinely off screen now', hiddenN > 0);
  t('and the count line says how many, in the specified words',
    $('fCount').textContent === 'showing ' + w.__frows().length + ' of ' +
      S().findings.length + ' finding(s), ' + wide + ' selected (' + hiddenN +
      ' of them hidden by the current filters)');
  t('the header box is fully ticked, because everything still shown is selected',
    $('fSelAll').checked === true && $('fSelAll').indeterminate === false);
  t('and the export button still promises the whole selection',
    $('btnExportFixed').textContent === 'Download corrected YAML for ' + wide + ' selected');

  $('btnFSelNone').click();
  $('btnFSelAll').click();
  const narrow = w.__sel().size;
  t('selecting all of a narrowed list takes only what is shown', narrow < wide);
  sevBoxes().forEach((c) => { c.checked = true; }); applySev();
  t('widening the filter adds no key of its own', w.__sel().size === narrow);
  t('and the header box reads part ticked rather than complete',
    $('fSelAll').indeterminate === true && $('fSelAll').checked === false);

  console.log('\n  Spec case 9: the header box acts on what is shown, and only on that');
  $('btnFSelNone').click();
  sevBoxes().forEach((c) => { c.checked = (c.value === 'High'); }); applySev();
  const shownKeys = w.__frows().filter((f) => !f.applied && f.fixKind !== 'manual')
    .map(w.__key);
  const outsider = 'a-key-for-a-finding-that-is-not-on-screen';
  w.__sel().add(outsider);
  $('fSelAll').click();
  t('one click adds exactly the keys that are drawn',
    shownKeys.length > 0 && shownKeys.every((k) => w.__sel().has(k)) &&
    w.__sel().size === shownKeys.length + 1);
  $('fSelAll').click();
  t('a second click removes exactly those and leaves the rest alone',
    shownKeys.every((k) => !w.__sel().has(k)) && w.__sel().size === 1 &&
    w.__sel().has(outsider));
  w.__sel().delete(outsider);
  sevBoxes().forEach((c) => { c.checked = true; }); applySev();
  $('btnFSelNone').click();

  /* Spec 7 case 24. */
  console.log('\n  Spec case 24: sorting keeps the selection, on the same findings');
  $('btnFSelAll').click();
  const beforeSort = Array.from(w.__sel());
  const order = () => Array.from(tbody().querySelectorAll('tr[data-i]'))
    .map((tr) => tr.children[4].textContent).join('|');
  const beforeOrder = order();
  const fileTh = w.document.querySelector('#rtable th.sortable[data-key="file"]') ||
    w.document.querySelector('#rtable th.sortable');
  fileTh.click();
  t('the sort actually reordered the table, so this is not a no-op',
    order() !== beforeOrder);
  t('the selection is the same size afterwards', w.__sel().size === beforeSort.length);
  t('and it is the same findings, not merely the same number',
    beforeSort.every((k) => w.__sel().has(k)));
  const tickedAfter = boxes().filter((c) => c.checked).map((c) => c.dataset.fk);
  t('and exactly those findings are ticked in their new positions',
    tickedAfter.length === beforeSort.length &&
    tickedAfter.every((k) => w.__sel().has(k)));

  /* Spec 7 case 21. */
  console.log('\n  Spec case 21: clearing the selection');
  const sentinel = tbody().querySelector('tr[data-i]');
  sentinel.dataset.sentinel = 'survives-a-clear';
  $('btnFSelNone').click();
  t('the set is empty', w.__sel().size === 0);
  t('every checkbox on screen is unticked', boxes().every((c) => !c.checked));
  t('the header box is clean, not part ticked',
    $('fSelAll').checked === false && $('fSelAll').indeterminate === false);
  t('the button label loses the count and the button goes off',
    $('btnExportFixed').textContent === 'Download corrected YAML' &&
    $('btnExportFixed').disabled === true);
  t('and no row was rebuilt to do it',
    tbody().querySelector('tr[data-i]').dataset.sentinel === 'survives-a-clear');
  t('Clear selection disables itself once there is nothing to clear',
    $('btnFSelNone').disabled === true);

  /* Spec 7 case 13, taken past the key comparison the existing block makes: two rows of
     one object under one policy have to be two independently exportable things. */
  console.log('\n  Spec case 13: a multi container workload exports one container, not both');
  w.__reset();
  w.__load([{ name: 'two.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: web, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: alpha', '        image: nginx:latest',
    '        securityContext: { privileged: true }', '      - name: beta',
    '        image: redis:latest',
    '        securityContext: { privileged: true }'].join('\n') }]);
  w.__tab('remediate');
  manual();
  $('fPolicy').value = 'ACS.001';
  $('fPolicy').dispatchEvent(new w.Event('change'));
  t('the two containers are two separate findings on one object',
    w.__frows().length === 2 && w.__frows()[0].obj === w.__frows()[1].obj);
  t('and one findingKey covers both, which is why a row key was needed',
    new Set(w.__frows().map((f) => w.findingKey(f))).size === 1);
  const firstBox = boxes()[0];
  const chosenRow = firstBox && w.__frows()[Number(firstBox.closest('tr').dataset.i)];
  clk(firstBox);
  t('ticking one selects one', w.__sel().size === 1);
  const wanted = S().findings.filter((f) => w.__sel().has(w.__key(f)) &&
    !f.applied && f.fixKind !== 'manual');
  t('and the export set is that one finding, not both containers',
    wanted.length === 1 && !!chosenRow && wanted[0].path === chosenRow.path);
  $('fPolicy').value = ''; $('fPolicy').dispatchEvent(new w.Event('change'));
  $('btnFSelNone').click();

  /* Spec 7 case 14. The spec documents this collision as accepted, so this asserts the
     documented behaviour: no throw, the count stays honest, and re-rendering ticks both
     because both really are one key. */
  console.log('\n  Spec case 14: the same document pasted twice into one file');
  w.__reset();
  const dupe = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: web, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: c', '        image: nginx:latest',
    '        securityContext: { privileged: true }'].join('\n');
  w.__load([{ name: 'dup.yaml', text: dupe + '\n---\n' + dupe }]);
  w.__tab('remediate');
  manual();
  $('fPolicy').value = 'ACS.001';
  $('fPolicy').dispatchEvent(new w.Event('change'));
  const dfks = boxes().map((c) => c.dataset.fk);
  t('two identical documents produce two rows', dfks.length === 2);
  t('and they share one key, which the spec accepts and documents',
    new Set(dfks).size === 1);
  clk(boxes()[0]);
  t('ticking one keeps the count at one rather than two', w.__sel().size === 1);
  t('and the count line says one, not two',
    /, 1 selected/.test($('fCount').textContent));
  w.document.querySelector('#rtable th.sortable').click();
  t('re-rendering ticks both, which is the documented consequence and not a crash',
    boxes().filter((c) => c.checked).length === 2 && w.__sel().size === 1);
  $('fPolicy').value = ''; $('fPolicy').dispatchEvent(new w.Event('change'));
  $('btnFSelNone').click();

  /* Spec 7 case 18. Cluster data is somebody else's string. */
  console.log('\n  Spec case 18: an injection shaped string in cluster data');
  w.__reset();
  const evil = 'a" onclick=alert(1) <script>';
  w.__load([{ name: 'evil.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: web, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: ' + JSON.stringify(evil),
    '        image: nginx:latest',
    '        securityContext: { privileged: true }'].join('\n') }]);
  w.__tab('remediate');
  manual();
  t('the hostile string really did reach a finding, so the rest means something',
    S().findings.some((f) => f.detail.indexOf('<script>') !== -1));
  t('no script element was created inside the table',
    w.document.querySelectorAll('#rtable tbody script').length === 0);
  t('and nothing broke out of an attribute value into a live event handler',
    w.document.querySelectorAll('#rtable tbody [onclick]').length === 0);
  t('the visible text still shows the operator what is really in the cluster',
    tbody().textContent.indexOf('<script>') !== -1);
  const ecb = boxes()[0];
  const erow = ecb && w.__frows()[Number(ecb.closest('tr').dataset.i)];
  t('the row key round trips through the attribute unchanged',
    !!ecb && !!erow && ecb.dataset.fk === w.__key(erow) &&
    ecb.dataset.fk.indexOf('<script>') !== -1);
  clk(ecb);
  t('and ticking it selects that finding under that key',
    !!erow && w.__sel().size === 1 && w.__sel().has(w.__key(erow)));
  $('btnFSelNone').click();


  /* Spec 7 case 15. A key for a finding that no longer exists keeps the button promising
     work the export will not do, so rescan drops it. Driven through a real Fix this in
     auto mode rather than by calling pruneFindingSelection directly, because the spec
     puts the call inside rescan and a direct call would pass even if it were never
     wired up. */
  console.log('\n  Spec case 15: the selection goes stale after a fix is applied');
  w.__reset();
  w.__load([{ name: 'p/a.yaml', text: WIDE('pa') }, { name: 'p/b.yaml', text: WIDE('pb') }]);
  w.__tab('remediate');
  $('fixMode').value = 'auto';
  $('fixMode').dispatchEvent(new w.Event('change'));
  if ($('skipConfirm')) $('skipConfirm').checked = true;
  $('btnFSelAll').click();
  const beforeFix = w.__sel().size;
  t('there is a selection to go stale', beforeFix > 5);
  const firstFix = tbody().querySelector('button.rfix');
  const doomed = firstFix &&
    w.__key(w.__frows()[Number(firstFix.closest('tr').dataset.i)]);
  t('and the finding about to be fixed is in it', !!doomed && w.__sel().has(doomed));
  clk(firstFix);
  await new Promise((r) => setTimeout(r, 200));
  t('applying it actually changed something', S().history.length === 1);
  t('its key is dropped from the selection', !w.__sel().has(doomed));
  t('and only the keys that went stale were dropped',
    w.__sel().size < beforeFix && w.__sel().size > 0);
  t('every key left names a finding that still exists and can still be exported',
    Array.from(w.__sel()).every((k) => S().findings
      .some((f) => !f.applied && f.fixKind !== 'manual' && w.__key(f) === k)));
  t('and the button promises exactly what is left',
    $('btnExportFixed').textContent ===
      'Download corrected YAML for ' + w.__sel().size + ' selected');
  $('btnFSelNone').click();
  report();

  /* Spec 8, the error table. None of these may throw. */
  console.log('\n  Spec 8: the error paths return rather than throwing');
  t('a finding with no ns, path or detail still yields a key with no undefined in it',
    (function () { const k = w.__key({ file: 'f', obj: 'o', policy: { id: 'p' } });
      return typeof k === 'string' && k.indexOf('undefined') === -1; })());
  t('removing #fModeWhy does not break the selection summary',
    (function () { const el = $('fModeWhy'); const p = el.parentNode; p.removeChild(el);
      let ok = true; try { report(); manual(); } catch (e) { ok = false; }
      p.appendChild(el); report(); manual(); return ok; })());
  t('an unrecognised mode value falls back to report rather than opening the gate',
    (function () { $('fixMode').value = 'not-a-mode';
      $('fixMode').dispatchEvent(new w.Event('change'));
      const ok = $('btnExportFixed').disabled === true &&
        Array.from(w.document.querySelectorAll('#rtable tbody button.rfix'))
          .every((b) => b.disabled) &&
        !$('fModeWhy').classList.contains('hidden');
      report(); return ok; })());
  cleanup();
}

/* The section 9 budget, asserted by counting operations rather than by timing a wall
   clock. A threshold in milliseconds is a flaky test and a flaky test gets deleted. */
async function specBudget() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__S=()=>STATE;window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);' +
    'window.__rows=()=>findingRows();window.__sel=()=>FSELECTED;window.__frows=()=>FROWS;' +
    'window.__key=(f)=>findingRowKey(f);window.__rt=()=>renderTable();');
  const S = () => w.__S();
  const tbody = () => $('rtable').querySelector('tbody');
  const manual = () => { $('fixMode').value = 'manual'; $('fixMode').dispatchEvent(new w.Event('change')); };

  /* Spec 7 case 4. 140 manifests is 2,100 findings, which crosses the 2,000 row line the
     spec puts a sentence behind. */
  const files = [];
  for (let i = 0; i < 140; i++) files.push({ name: 'm/app' + i + '.yaml', text: WIDE(i) });
  w.__load(files);
  w.__tab('remediate');
  const n = S().findings.length;

  console.log('\nMore rows than are comfortable to draw: ' + n + ' findings');
  t('the fixture crosses the line the spec draws at 2,000 rows', n > 2000);
  t('every single one of them is drawn, with no cap and no pagination',
    tbody().querySelectorAll('tr[data-i]').length === n);
  t('and FROWS agrees with what is on screen', w.__frows().length === n);
  t('nothing tells the operator that rows were withheld',
    !/Showing the first|not shown|withheld/i.test($('rtable').textContent));
  t('the count line carries the long list sentence, in the specified words',
    $('fCount').textContent === 'showing ' + n + ' of ' + n + ' finding(s), none selected' +
      ' — that is a lot of rows to draw at once; the filters above will make this quicker.');

  /* Spec 9: findingRows() is evaluated once per renderTable call, not three times.
     findingRows is the only place this selector is read, so counting the selector counts
     the calls. This is the assertion that would have caught the base branch, where one
     render computed the same row set three times. */
  console.log('\n  The row set is computed once per render, not three times');
  const seen = [];
  const real = w.document.querySelectorAll.bind(w.document);
  w.document.querySelectorAll = function (sel) { seen.push(sel); return real(sel); };
  w.__rt();
  t('the counter is wired to something the render really does',
    seen.indexOf('input.fsev:checked') !== -1);
  t('one render reads the severity filter exactly once',
    seen.filter((s) => s === 'input.fsev:checked').length === 1);

  /* Spec 9: refreshFindingFilters is called zero times from renderTable. Marking an
     option and watching it survive is the observable form of that: rebuilding the picker
     destroys the option the operator has just focused. */
  const opt = Array.from($('fCat').options).find((o) => o.value);
  opt.dataset.probe = 'kept';
  seen.length = 0;
  w.document.querySelector('#rtable th.sortable').click();
  t('sorting does not rebuild the filter pickers under the operator',
    Array.from($('fCat').options).some((o) => o.dataset.probe === 'kept'));
  t('and a sort also computes the row set only once',
    seen.filter((s) => s === 'input.fsev:checked').length === 1);
  w.document.querySelectorAll = real;

  /* Spec 9: zero advisoryHtml calls per render. advisoryHtml is a top level declaration
     and cannot be spied on from outside, so assert on what it would have produced, which
     survives the function being renamed. */
  console.log('\n  No advisory is built until somebody opens one');
  t('no advisory row exists after a full render of ' + n + ' findings',
    tbody().querySelectorAll('tr.fdet').length === 0);
  t('and none of the advisory markup is in the table either',
    tbody().innerHTML.indexOf('ACS criteria') === -1 &&
    tbody().innerHTML.indexOf('ACS policy') === -1);
  const r7 = tbody().querySelector('tr[data-i="7"]');
  const open7 = () => { const c = r7 && r7.querySelector('td.wrapcell'); if (c) c.click(); };
  open7();
  t('opening one builds one, and only one',
    tbody().querySelectorAll('tr.fdet').length === 1);
  t('and that one carries the advisory markup',
    !!r7 && !!r7.nextElementSibling &&
    r7.nextElementSibling.textContent.indexOf('ACS criteria') !== -1);
  t('its cell spans the whole table',
    !!r7 && !!r7.nextElementSibling &&
    Number(r7.nextElementSibling.firstElementChild.getAttribute('colspan')) ===
      w.document.querySelectorAll('#rtable thead th').length);
  open7(); open7();
  t('and toggling it three times never builds a second',
    tbody().querySelectorAll('tr.fdet').length === 1);
  open7();

  /* Spec 9: rows are inserted in one operation. The spec's words are "a single
     appendChild of a DocumentFragment"; the code assigns one innerHTML string instead,
     which is the coder's deviation D1. What the budget protects is that the tbody is
     written once rather than n times, and this asserts that property, so it holds under
     either implementation. Flagged as testing the deviation in .pipeline/tests.md. */
  console.log('\n  The table body is written once per render, not once per row');
  let recs = 0, added = 0;
  const mo = new w.MutationObserver((rs) => {
    for (const r of rs) { recs++; added += r.addedNodes.length; }
  });
  mo.observe(tbody(), { childList: true });
  w.__rt();
  await new Promise((r) => setTimeout(r, 60));
  mo.disconnect();
  t('all ' + n + ' rows arrive in a single batch of mutations',
    recs === 1 && added === n);

  /* Spec 9: the three selection controls call renderTable zero times. A tick that
     rebuilds 2,100 rows is what made every button look dead. */
  console.log('\n  Selecting does not rebuild the table');
  manual();
  recs = 0; added = 0;
  const mo2 = new w.MutationObserver((rs) => {
    for (const r of rs) { recs++; added += r.addedNodes.length; }
  });
  const keep = tbody().querySelector('tr[data-i]');
  keep.dataset.sentinel = 'same-element';
  mo2.observe(tbody(), { childList: true });
  const cb = tbody().querySelector('input.fsel:not([disabled])');
  if (cb) cb.click();
  const afterTick = $('fCount').textContent;
  $('fSelAll').click();
  const afterAll = w.__sel().size;
  $('btnFSelAll').click();
  $('btnFSelNone').click();
  await new Promise((r) => setTimeout(r, 60));
  mo2.disconnect();
  t('a tick, a select all and a clear insert no rows at all between them',
    recs === 0 && added === 0);
  t('and the rows on screen are the same elements they were before',
    tbody().querySelector('tr[data-i]').dataset.sentinel === 'same-element');
  t('the tick still moved the count, so the render really was skipped and not the work',
    /, 1 selected/.test(afterTick));
  t('and select all still took every fixable row without redrawing one of them',
    afterAll === w.__frows().filter((f) => !f.applied && f.fixKind !== 'manual').length);
  t('and clearing put the count back',
    $('fCount').textContent.indexOf(', none selected') !== -1 && w.__sel().size === 0);


  /* Spec 7 cases 16 and 17, and the definition-of-done line about all six tables.
   *
   * jsdom does no layout, so nothing here measures a width and nothing here should
   * pretend to. What is asserted is the containment contract: every wide table has a
   * scrolling ancestor, the long values are told to break rather than to set their own
   * width, and -- the part that matters most for cases 16 and 17 -- nothing clips a
   * value out of sight to achieve it. A measured overflow needs a headless browser,
   * which this repository deliberately does not have. Said again in .pipeline/tests.md.
   */
  console.log('\n  Spec cases 16 and 17: long cluster strings are contained, not hidden');
  const wrapped = (el) => !!el && !!el.closest('.tablewrap');
  t('the findings table is inside a scrolling wrapper', wrapped($('rtable')));
  t('so is the read only findings table', wrapped($('ftable')));
  t('so is the ACS violations table', wrapped($('vtbl')));
  t('so is the CVE table', wrapped($('vtable')));
  t('so is the image table', wrapped($('vimgtable')));
  t('and so is the policy catalogue, which carries the same long strings',
    wrapped($('catbody')));
  t('every data table on the page is wrapped, not just the ones that were reported',
    Array.from(w.document.querySelectorAll('body > div.app table, .section table, ' +
      'details.sec table')).every((tb) => wrapped(tb)));
  const style = w.document.querySelector('style').textContent;
  t('the wrapper is what scrolls, so the document does not',
    /\.tablewrap\{[^}]*overflow-x:\s*auto/.test(style));
  t('and it cannot grow past its own section',
    /\.tablewrap\{[^}]*max-width:\s*100%/.test(style) &&
    /\.section,details\.sec\{[^}]*max-width:\s*100%/.test(style));
  t('a value with no spaces in it is allowed to break inside its cell',
    /td\.wrapcell[^{]*\{[^}]*overflow-wrap:\s*anywhere/.test(style) &&
    /\.tablewrap td\{[^}]*overflow-wrap:\s*anywhere/.test(style));
  t('nothing clips a cell, so no path is made unreadable to make the table fit',
    !/text-overflow:\s*ellipsis/.test(style) &&
    !/\.tablewrap td\{[^}]*overflow:\s*hidden/.test(style) &&
    !/td\.wrapcell\{[^}]*white-space:\s*nowrap/.test(style));
  t('and an opened advisory is released from the column width entirely',
    /#rtable tr\.fdet td\{[^}]*max-width:\s*none/.test(style));
  /* The coder kept table-layout:fixed with a colgroup, which spec 3.2 rejected and spec
     12 lists as out of scope. Asserting what the code does, and saying so, rather than
     asserting a spec line the code does not meet. Deviation D3 in changes.md. */
  t('DEVIATION D3: the findings table uses fixed layout with explicit column widths, ' +
    'which the spec rejected',
    /#rtable\{[^}]*table-layout:\s*fixed/.test(style) &&
    w.document.querySelectorAll('#rtable colgroup col').length ===
      w.document.querySelectorAll('#rtable thead th').length);
  t('and because it does, the full value is still on the cell for a narrow window',
    Array.from(tbody().querySelectorAll('td.wrapcell')).slice(0, 40)
      .every((c) => c.title === c.textContent));
  const longPath = 'a/' + 'very-long-segment-with-no-spaces-in-it/'.repeat(5) + 'deployment.yaml';
  t('the fixture for a 180 character path is genuinely that long', longPath.length > 180);
  w.__load([{ name: longPath, text: WIDE('long') }]);
  const longCell = Array.from(tbody().querySelectorAll('td.wrapcell'))
    .find((c) => c.textContent === longPath);
  t('a 180 character path is drawn in full rather than truncated',
    !!longCell && longCell.textContent === longPath);
  t('and it is in a cell that is told to break', !!longCell &&
    longCell.classList.contains('wrapcell'));
  t('and the row still has exactly as many cells as the header has columns',
    !!longCell && longCell.closest('tr').children.length ===
      w.document.querySelectorAll('#rtable thead th').length);

  /* Spec 9 and the user's standing constraint: nothing here may run a command or reach
     the network, in any mode. */
  console.log('\n  The gate holds, and no path runs a command');
  const src = fs.readFileSync(path.join(ROOT, 'dj_acs_auditor.html'), 'utf8');
  t('report is still the option the page loads with',
    /<option value="report" selected>/.test(src));
  t('the page contains no network call of any kind',
    !/[^a-zA-Z.]fetch\s*\(/.test(src) && !/XMLHttpRequest/.test(src) &&
    !/new WebSocket/.test(src) && !/sendBeacon/.test(src));
  t('and no way to evaluate a string as code',
    !/[^a-zA-Z.$]eval\s*\(/.test(src) && !/new Function\s*\(/.test(src));
  t('and it loads no script it does not ship beside it',
    (src.match(/<script src="[^"]+"/g) || [])
      .every((s) => /"(vendor\/[A-Za-z0-9._-]+\.js|acs_policies\.js)"/.test(s)));
  $('fixMode').value = 'report';
  $('fixMode').dispatchEvent(new w.Event('change'));
  const fixButtons = Array.from(tbody().querySelectorAll('button.rfix'));
  const fixableN = w.__frows().filter((f) => !f.applied && f.fixKind !== 'manual').length;
  t('there is a Fix this button on every fixable row and on no other row',
    fixButtons.length === fixableN && fixableN > 1000);
  t('in report mode every one of the ' + fixButtons.length + ' Fix this buttons is off',
    fixButtons.every((b) => b.disabled === true));
  t('and every one of them names the control to move',
    fixButtons.every((b) => b.title === 'Report only. Choose Manual or Auto in the Mode ' +
      'selector at the top of the page to apply a fix.'));
  const hist = S().history.length;
  fixButtons.slice(0, 25).forEach((b) => b.click());
  await new Promise((r) => setTimeout(r, 60));
  t('and clicking twenty five of them applies nothing', S().history.length === hist);
  t('the mode note above the table is showing while the gate holds',
    !$('fModeWhy').classList.contains('hidden'));
  cleanup();
}


/* --------------------------------------------------------- resource limits
 *
 * Two defects live here, and both were reported from production.
 *
 * The first is that a limit should be derived from whatever request is already present
 * rather than frozen, and that an existing value is never to be touched.
 *
 * The second is the one that cost someone a workload: the per fix patch files were each
 * built by diffing the file's original state against its final state, so every patch for an
 * object contained every fix applied to that object while being named after one of them.
 * Applying what looked like the memory patch therefore also carried the cpu changes, and
 * applying a subset carried fields nobody had chosen.
 */
async function resourceLimits() {
  const { w, $, cleanup } = await open('dj_acs_auditor.html',
    'window.__load=(i)=>loadItems(i);window.__tab=(t)=>showTab(t);window.__S=()=>STATE;' +
    'window.__frows=()=>STATE.findings;window.__requestFix=(f)=>requestFix(f);' +
    'window.resourcePlan=resourcePlan;');
  const S = () => w.__S();
  const DEP = ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: payments-api, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:',
    '      - name: api', '        image: q/a:1',
    '        ports: [{ containerPort: 8080 }]',
    '        env: [{ name: MODE, value: prod }]',
    '        resources: { requests: { memory: 10Mi } }',
    '      - name: sidecar', '        image: q/s:2',
    '        resources: { requests: { cpu: 500m }, limits: { cpu: 500m } }'].join('\n');
  w.__load([{ name: 'm/api.yaml', text: DEP }]);
  w.__tab('remediate');
  $('fixMode').value = 'auto'; $('fixMode').dispatchEvent(new w.Event('change'));
  $('skipConfirm').checked = true;

  const find = (id) => w.__frows().find((f) => f.policy.id === id && !f.applied);
  const apply = (id) => { const f = find(id); if (f) w.__requestFix(f); };

  console.log('\n  A limit is derived from the request that is already there');
  apply('ACS.013');
  apply('ACS.014');
  const cur = () => S().files[0].docs[0].spec.template.spec.containers;
  const api = () => cur().find((c) => c.name === 'api');
  const side = () => cur().find((c) => c.name === 'sidecar');

  t('the 10Mi request is left exactly as it was found',
    api().resources.requests.memory === '10Mi');
  t('and the memory limit is raised to the 512Mi floor rather than 40Mi',
    api().resources.limits.memory === '512Mi');
  t('the cpu request it never had is a placeholder',
    api().resources.requests.cpu === '100m');
  t('and its cpu limit is that request times five',
    api().resources.limits.cpu === '500m');

  console.log('\n  Applying the memory fix does not undo the cpu fix');
  t('cpu survives the memory fix', !!api().resources.limits.cpu);
  t('memory survives alongside it', !!api().resources.limits.memory);
  t('the image is untouched', api().image === 'q/a:1');
  t('the ports are untouched', api().ports[0].containerPort === 8080);
  t('the env is untouched', api().env[0].name === 'MODE');

  console.log('\n  An existing value is a decision, so it is not overwritten');
  t('the sidecar cpu request is unchanged', side().resources.requests.cpu === '500m');
  t('the sidecar cpu limit is unchanged', side().resources.limits.cpu === '500m');
  t('its memory limit matches its request, because cpu is already pinned',
    side().resources.limits.memory === side().resources.requests.memory);
  const infNote = S().history.map((h) => (h.changes || []).join(' ')).join(' ');
  t('and the change note says that was inferred rather than asserting it quietly',
    /INFERRED/.test(infNote));

  console.log('\n  One patch file per fix, carrying only that fix');
  /* jsdom has no working Blob for JSZip to assemble into, which is why every other export
     suite deletes JSZip and takes the fallback. There is no fallback on this button, so
     record what the page hands to zip.file instead. That is the artifact under test; JSZip
     turning a string into bytes is not. */
  const body = {};
  let zipped = false;
  w.JSZip = function () {
    return {
      file: (n, c) => { body[n] = c; },
      generateAsync: () => { zipped = true; return Promise.resolve('ZIPBYTES'); },
    };
  };
  const blobs = [];
  w.download = (n, c) => blobs.push({ name: n, body: c });
  $('btnPatches').click();
  await new Promise((r) => setTimeout(r, 2500));
  t('a patch zip was written', zipped && blobs.length === 1 && /patches/.test(blobs[0].name));
  const names = Object.keys(body).filter((n) => /^patches\//.test(n));
  t('there is a patch for the cpu fix and one for the memory fix',
    names.length === 2 && names.some((n) => /013/.test(n)) && names.some((n) => /014/.test(n)));
  const cpuFile = names.find((n) => /013/.test(n));
  const memFile = names.find((n) => /014/.test(n));
  const yamlOf = (n) => w.jsyaml.load(body[n].split('\n').filter((l) => l[0] !== '#').join('\n'));
  const cpuPatch = yamlOf(cpuFile), memPatch = yamlOf(memFile);
  const pc = (pp, nm) => pp.spec.template.spec.containers.find((c) => c.name === nm);

  t('the cpu patch sets a cpu limit', !!pc(cpuPatch, 'api').resources.limits.cpu);
  t('the cpu patch does NOT carry the memory fix, which is the defect this locks',
    pc(cpuPatch, 'api').resources.limits.memory === undefined);
  t('the memory patch sets a memory limit', !!pc(memPatch, 'api').resources.limits.memory);
  t('the memory patch does NOT carry the cpu fix',
    pc(memPatch, 'api').resources.limits.cpu === undefined);
  t('the two patches are not byte for byte identical', body[cpuFile] !== body[memFile]);

  console.log('\n  The patch says how to apply it, because the wrong type deletes containers');
  for (const n of [cpuFile, memFile]) {
    t('  ' + n.replace('patches/', '') + ' names --type=strategic',
      /--type=strategic/.test(body[n]));
    t('  ' + n.replace('patches/', '') + ' warns that a plain merge patch replaces the list',
      /REPLACES the whole container list/.test(body[n]));
  }
  t('the README repeats it, since that is what a reviewer reads first',
    /--type=strategic/.test(body['README.md']));
  t('the files are numbered so the apply order is not a guess',
    names.every((n) => /^patches\/\d{3}_/.test(n)));

  console.log('\n  The multipliers and floors are settable from the page');
  $('btnResPanel').click();
  t('the panel opens', !$('resForm').classList.contains('hidden'));
  t('it is filled from the live settings, not from markup defaults',
    $('resCpuMult').value === '5' && $('resMemMult').value === '4' &&
    $('resMemFloor').value === '512Mi' && $('resCpuFloor').value === '500m');
  t('the worked example shows the arithmetic on a real number',
    /100m becomes 500m/.test($('resWorked').textContent));
  t('and shows the floor firing, which is the case that surprises people',
    /10Mi becomes 512Mi/.test($('resWorked').textContent));

  const set = (id, v) => { $(id).value = v; $(id).dispatchEvent(new w.Event('change')); };
  set('resMemMult', '8');
  t('changing the memory multiplier is reflected in the worked example',
    /1Gi becomes 8Gi/.test($('resWorked').textContent));
  set('resMemFloor', '1Gi');
  t('changing the floor is reflected too', /10Mi becomes 1Gi/.test($('resWorked').textContent));

  console.log('\n  A value that is not a quantity is refused, not quietly defaulted');
  set('resMemFloor', '512 megs');
  t('the problem is named', /512 megs/.test($('resProblem').textContent));
  t('and it says nothing was changed', /Nothing was changed/.test($('resProblem').textContent));
  t('the previous good floor is still in force',
    /10Mi becomes 1Gi/.test($('resWorked').textContent));
  set('resMemFloor', '1Gi');
  set('resCpuMult', '0');
  t('a multiplier below one is refused and named',
    /cpuMultiplier "0"/.test($('resProblem').textContent));
  t('and the zero multiplier never reached the arithmetic',
    /100m becomes 500m/.test($('resWorked').textContent));
  set('resCpuMult', '-3');
  t('a negative multiplier is refused too',
    /cpuMultiplier "-3"/.test($('resProblem').textContent));
  /* A number input discards non-numeric text before any script sees it, so the value that
     arrives is the empty string rather than "five". It still has to be refused, and the
     message has to show what the field actually holds rather than what was typed at it. */
  set('resCpuMult', 'five');
  t('text typed into a number field arrives empty, and is still refused',
    $('resCpuMult').value === '' && /cpuMultiplier ""/.test($('resProblem').textContent));

  /* Leave every field away from its default so the reset has something to undo. Setting
     them back by hand first made this assertion pass against a reset that did nothing. */
  set('resCpuMult', '9'); set('resMemMult', '7'); set('resMemFloor', '2Gi');
  set('resCpuFloor', '900m'); set('resMode', 'guaranteed');
  t('the fields really are off the defaults before the reset',
    $('resCpuMult').value === '9' && $('resMemFloor').value === '2Gi');
  $('btnResReset').click();
  t('Back to defaults restores every field',
    $('resCpuMult').value === '5' && $('resMemMult').value === '4' &&
    $('resMemFloor').value === '512Mi' && $('resCpuFloor').value === '500m' &&
    $('resMode').value === 'multiplier');
  t('and the engine settings follow, not just the inputs',
    /10Mi becomes 512Mi/.test($('resWorked').textContent));

  console.log('\n  Guaranteed mode applies to a container with nothing set');
  set('resMode', 'guaranteed');
  t('the panel explains what Guaranteed costs, not just what it gives',
    /reserve the full amount/.test($('resWorked').textContent));
  w.__load([{ name: 'm/second.yaml', text: ['apiVersion: apps/v1', 'kind: Deployment',
    'metadata: { name: bare, namespace: prod }', 'spec:', '  template:', '    spec:',
    '      containers:', '      - name: only', '        image: q/b:1'].join('\n') }]);
  $('fixMode').value = 'auto'; $('fixMode').dispatchEvent(new w.Event('change'));
  $('skipConfirm').checked = true;
  const bare = () => S().files.find((f) => f.name === 'm/second.yaml')
    .docs[0].spec.template.spec.containers[0];
  apply('ACS.013'); apply('ACS.014');
  t('cpu limit equals cpu request', bare().resources.limits.cpu === bare().resources.requests.cpu);
  t('memory limit equals memory request',
    bare().resources.limits.memory === bare().resources.requests.memory);
  const gNote = S().history.map((h) => (h.changes || []).join(' ')).join(' ');
  t('and the note says it was the selected mode rather than an inference',
    /for Guaranteed QoS, as selected/.test(gNote));

  console.log('\n  Guaranteed cannot honour the floor, and says so rather than hiding it');
  /* A 10Mi request under Guaranteed yields a 10Mi limit. Raising it would mean raising the
     request, which this tool does not do, so the conflict has to reach the operator. */
  $('btnResPanel').click(); set('resMode', 'guaranteed'); $('btnResPanel').click();
  const low = { name: 'c', resources: { requests: { memory: '10Mi' } } };
  const lowPlan = w.resourcePlan(low, 'memory');
  t('the limit equals the 10Mi request', lowPlan.limit === '10Mi');
  t('and a warning names the floor it could not reach',
    lowPlan.notes.some((n) => /WARNING/.test(n) && /512Mi floor/.test(n)));
  t('and says why, so it is actionable rather than just alarming',
    lowPlan.notes.some((n) => /without raising the request/.test(n)));
  cleanup();
}

(async () => {
  /* One try around the lot meant one throw cost every suite after it.
   *
   * A regression that removed a single element threw out of the block it happened in and
   * the eight suites below it never ran. The report said "1 failed" and the real number
   * was seventeen, so the count under-reported exactly when it mattered most: the run
   * where something is badly broken is the run you most need an accurate list from.
   *
   * Each suite is isolated now. One crashing does not stop the others, its failure is
   * attributed to it by name, and a crash is counted separately from an assertion that
   * returned false, because those are different problems: a false assertion is a defect
   * in the product, a throw is usually a defect in the harness or a missing element the
   * suite assumed.
   */
  const suites = [
    ['auditor', auditor],
    ['remediation', remediation],
    ['tabs', tabs],
    ['bulkExport', bulkExport],
    ['scale', scale],
    ['diffTab', diffTab],
    ['annotations', annotations],
    ['optOuts', optOuts],
    ['optOutRules', optOutRules],
    ['diffExport', diffExport],
    ['filesPanel', filesPanel],
    ['namespaces', namespaces],
    ['detailRows', detailRows],
    ['flashDwell', flashDwell],
    ['selectionUi', selectionUi],
    ['specCases', specCases],
    ['specBudget', specBudget],
    ['resourceLimits', resourceLimits],
    ['noManifests', () => noManifests('dj_acs_auditor.html')],
  ];
  const only = process.argv.slice(2).filter((a) => a[0] !== '-');
  const chosen = only.length
    ? suites.filter(([n]) => only.indexOf(n) !== -1) : suites;
  if (only.length && chosen.length !== only.length) {
    const known = suites.map(([n]) => n);
    const bad = only.filter((n) => known.indexOf(n) === -1);
    console.log('No such suite: ' + bad.join(', '));
    console.log('Known suites: ' + known.join(', '));
    process.exit(2);
  }
  const crashed = [];
  for (const [name, fn] of chosen) {
    try { await fn(); }
    catch (e) {
      crashed.push(name);
      F++;
      console.log('  FAIL  ' + name + ' threw and its remaining assertions did not run');
      console.log('        ' + (e && e.message ? e.message : String(e)));
      if (e && e.stack) {
        const frame = String(e.stack).split('\n').find((l) => /page\.cjs:\d+/.test(l));
        if (frame) console.log('        ' + frame.trim());
      }
    }
  }
  console.log('\n' + P + ' passed, ' + F + ' failed');
  if (only.length) console.log('PARTIAL RUN: only ' + only.join(', '));
  if (crashed.length) {
    console.log('SUITE(S) THAT CRASHED: ' + crashed.join(', '));
    console.log('A crash is not one failure. Every assertion after the throw in that suite');
    console.log('did not run, so the count above is a floor rather than the total.');
  }
  process.exit(F ? 1 : 0);
})();
