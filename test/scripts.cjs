/* The shell scripts, checked for the kind of inconsistency that costs an afternoon.
 *
 * These are static assertions over the script text rather than executions. They exist
 * because of a real failure: acs_preflight.sh honoured ROX_CA from the environment and
 * acs_pull_all.sh did not, so in one shell the preflight verified against an internal CA
 * and passed, and the pull that followed it fell back to the system trust store and died
 * with curl 60. Two scripts meant to be run back to back disagreed about where trust
 * comes from, and nothing in the suite could see it.
 *
 * A user cannot be expected to notice that. A test can.
 */
'use strict';
const fs = require('fs'), path = require('path');
const DIR = path.join(__dirname, '..', 'scripts');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };

const sh = fs.readdirSync(DIR).filter((f) => f.endsWith('.sh'));
const read = (f) => fs.readFileSync(path.join(DIR, f), 'utf8');

console.log('\nEvery script that talks to ACS agrees on where trust comes from');
/* Scripts that actually authenticate to ACS, which is what the trust rules are about.
   Matching on the word "curl" caught acs_summary.sh, which only mentions it in a comment
   explaining that curl and jq are all some machines have. */
const talkers = sh.filter((f) => /Authorization: Bearer/.test(read(f)) && !/pull_via_oc/.test(f));
t('there is more than one such script, so agreement is a real property',
  talkers.length >= 2);
for (const f of talkers) {
  const s = read(f);
  t('  ' + f + ' honours ROX_CA from the environment', /ROX_CA/.test(s));
}

console.log('\nA CA that cannot be read is refused, never silently ignored');
for (const f of talkers) {
  const s = read(f);
  const guards = /-r "?\$\{?(CACERT|ROX_CA)/.test(s) || /! -r/.test(s);
  t('  ' + f + ' checks the CA file is readable', guards);
}

console.log('\nNo script verifies less than it says it does');
for (const f of sh) {
  const s = read(f);
  /* -k is allowed only where no credential is on the request. The oc script probes
     reachability with -k and -o /dev/null before it has extracted the CA, which sends
     nothing and reveals nothing. Anything carrying a token must verify. */
  const lines = s.split('\n');
  const bad = [];
  lines.forEach((l, i) => {
    if (!/curl /.test(l)) return;
    if (!/\s-k\b|--insecure\b/.test(l)) return;
    if (/^\s*#/.test(l)) return;
    const carriesToken = /-H\s*"?@|Authorization|\$HDR|\$CURL\b/.test(l);
    if (carriesToken) bad.push((i + 1) + ': ' + l.trim().slice(0, 70));
  });
  t('  ' + f + ' never sends a token over an unverified connection',
    bad.length === 0);
  if (bad.length) bad.forEach((b) => console.log('        ' + b));
}

console.log('\nDefaults verify. Insecure is opt in and says what it costs');
for (const f of talkers) {
  const s = read(f);
  t('  ' + f + ' does not default to -k',
    !/^CURL_TLS="-k"/m.test(s) && !/CURL_TLS="-k"\s*$/m.test(s.split('--insecure')[0] || ''));
  t('  ' + f + ' warns that insecure exposes the token',
    /exposes? (your |the )?token|hands it to anyone|steal/i.test(s));
}

console.log('\nThe token never reaches the process table');
for (const f of talkers) {
  const s = read(f);
  t('  ' + f + ' passes the token by header file, not as an argument',
    /-H\s*"?@/.test(s) && !/Authorization: Bearer \$\{?ROX_API_TOKEN/.test(s.replace(/printf[^\n]*/g, '')));
}

console.log('\nA TLS failure explains how to get the CA, not just that one is needed');
for (const f of talkers) {
  const s = read(f);
  t('  ' + f + ' names a concrete command to obtain the CA',
    /default-ingress-cert|central-tls|router-ca/.test(s));
  t('  ' + f + ' points at openssl to identify the issuer first',
    /s_client/.test(s));
}

console.log('\nScripts do not assume a runtime the operator may not have');
for (const f of sh) {
  const s = read(f);
  const nodeLines = s.split('\n').filter((l) =>
    /\bnode\s+acs_cli/.test(l) && !/^\s*#/.test(l));
  if (!nodeLines.length) { t('  ' + f + ' suggests no Node command', true); continue; }
  t('  ' + f + ' offers the browser before suggesting Node',
    /dj_acs_auditor\.html/.test(s));
}

/* ------------------------------------------------ running without Node */

const { execFileSync } = require('child_process');
const os = require('os');

console.log('\nThe tool degrades honestly when Node cannot be installed');

/* The page is the whole point of this: it needs a browser and nothing else. */
const page = fs.readFileSync(path.join(DIR, '..', 'dj_acs_auditor.html'), 'utf8');
t('the page loads its dependencies from disk, not a package manager',
  /<script src="vendor\/js-yaml\.min\.js"><\/script>/.test(page));
t('and needs no server, being a plain file with no module imports',
  !/type="module"/.test(page) && !/import\s+.*\s+from/.test(page));

console.log('\nThe wrappers explain the alternatives rather than just failing');
for (const w of ['acs.sh', 'acs.ps1', 'acs.cmd']) {
  const src = fs.readFileSync(path.join(DIR, '..', w), 'utf8');
  t('  ' + w + ' detects a missing Node', /node/i.test(src) && /PATH|Get-Command|where node/.test(src));
  t('  ' + w + ' points at the page, which needs no runtime',
    /dj_acs_auditor\.html/.test(src));
  t('  ' + w + ' offers a container as a way to run the CLI without installing Node',
    /podman|docker/.test(src));
  t('  ' + w + ' no longer talks about "pages", plural', !/browser pages/.test(src));
}

console.log('\nacs_summary.sh gives a Node-less machine something to hand over');
const sum = path.join(DIR, 'acs_summary.sh');
t('the script exists and is executable', fs.existsSync(sum) &&
  !!(fs.statSync(sum).mode & 0o111));
const ss = fs.readFileSync(sum, 'utf8');
t('it needs only jq, no runtime', /command -v jq/.test(ss) && !/\bnode\b/.test(ss.replace(/#.*/g, '')));
t('it refuses to imply a posture score it cannot compute',
  /not a posture score/.test(ss));
t('and says where scoring and fixes actually come from',
  /dj_acs_auditor\.html/.test(ss));

/* Drive it. A summary script that cannot parse the export it was written for is worse
   than not having one, because it will be trusted. */
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sum-'));
fs.writeFileSync(path.join(work, '02_alerts_full.json'), JSON.stringify({ alerts: [
  { id: 'a1', state: 'ACTIVE', platformComponent: false, namespace: 'prod',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'CRITICAL_SEVERITY' },
    deployment: { name: 'payments-api', type: 'Deployment', namespace: 'prod' } },
  { id: 'a2', state: 'RESOLVED', platformComponent: true, namespace: 'openshift-etcd',
    policy: { id: 'p1', name: 'Privileged Container', severity: 'CRITICAL_SEVERITY' },
    deployment: { name: 'etcd', type: 'DaemonSet', namespace: 'openshift-etcd' } },
  { id: 'a3', state: 'ACTIVE', namespace: 'data',
    policy: { id: 'p3', name: 'Root User', severity: 'MEDIUM_SEVERITY' },
    deployment: { name: 'cache', type: 'StatefulSet', namespace: 'data' } }] }));
fs.writeFileSync(path.join(work, '03_vuln_workloads.ndjson'),
  JSON.stringify({ result: { deployment: { name: 'payments-api', namespace: 'prod' }, livePods: 2,
    images: [{ id: 'sha256:a', name: { fullName: 'quay.io/acme/payments:1.4' },
      scan: { components: [{ name: 'openssl', version: '3.0.7', vulns: [
        { cve: 'CVE-1', severity: 'CRITICAL_VULNERABILITY_SEVERITY', cvss: 9.8, fixedBy: '3.0.14' },
        { cve: 'CVE-2', severity: 'IMPORTANT_VULNERABILITY_SEVERITY', cvss: 7.5, fixedBy: '' },
      ] }] } }] } }));

let out = '';
let ran = true;
try { out = execFileSync('sh', [sum, work], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
catch (e) { ran = false; out = String((e.stdout || '') + (e.stderr || '')); }

t('it runs against a real pull directory', ran);
t('it counts the violations', /## Violations: 3/.test(out));
t('it breaks them down by severity', /\| CRITICAL \| 2 \|/.test(out));
t('it separates your workloads from platform components',
  /\| Your workloads \| 1 \|/.test(out) && /\| Platform components \| 1 \|/.test(out));
t('it counts the ones ACS did not label, rather than guessing',
  /No platformComponent field sent \| 1/.test(out));
t('and warns that the page will be inferring those',
  /did not\s*\n?\s*tell us who owns them|guessing/.test(out));
t('it ranks policies by how often they fire', /\| 2 \| Privileged Container/.test(out));
t('it ranks namespaces the same way', /\| 1 \| prod \|/.test(out) || /\| prod \|/.test(out));
t('it reports violation state, so a resolved one is not counted as active',
  /ACTIVE: 2/.test(out) && /RESOLVED: 1/.test(out));
t('it summarises CVEs by Red Hat severity',
  /\| CRITICAL \| 1 \|/.test(out) && /\| IMPORTANT \| 1 \|/.test(out));
t('it says how many CVEs are actually fixable', /1 of 2 distinct CVEs have a published fix/.test(out));
t('it groups the rebuild work by image', /quay\.io\/acme\/payments:1\.4/.test(out));
t('it states plainly what it cannot tell you', /What this summary cannot tell you/.test(out));
t('and never prints a score', !/Grade [A-F]\b/.test(out) && !/\b100 \/ 100\b/.test(out));

/* Missing inputs must be reported, not silently produce an empty but confident document. */
const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'sum2-'));
let out2 = '';
try { out2 = execFileSync('sh', [sum, bare], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
catch (e) { out2 = String(e.stdout || ''); }
t('an empty directory says what is missing rather than reporting zero findings',
  /No alert export found/.test(out2) && /No vulnerability export found/.test(out2));
t('and repeats that CVEs never appear in the alert endpoint',
  /empty alert list proves\s*\n?\s*nothing/.test(out2));

let code = 0;
try { execFileSync('sh', [sum], { stdio: 'ignore' }); } catch (e) { code = e.status; }
t('no argument is a usage error, not a silent success', code === 2);

fs.rmSync(work, { recursive: true, force: true });
fs.rmSync(bare, { recursive: true, force: true });

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
