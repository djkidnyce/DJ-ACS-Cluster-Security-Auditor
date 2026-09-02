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

/* ------------------------------------------ self signed Central, end to end */

/* Central's certificate is self signed by default. That is what the operator installs,
 * so "the chain will never verify" is the normal case rather than a misconfiguration,
 * and the pull has to have a route through it that is not --insecure.
 *
 * These run a real TLS server with a real self signed certificate. Asserting on the
 * script text alone would have missed both defects found here: --pinnedpubkey does not
 * bypass chain verification, so pinning without -k can never work, and the curl command
 * was assembled before the TLS decision was made, so whatever was decided was discarded.
 */
const walk = (d) => !fs.existsSync(d) ? [] : fs.readdirSync(d, { withFileTypes: true })
  .flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);

console.log('\nA self signed Central is reachable without disabling verification');

const tlsdir = fs.mkdtempSync(path.join(os.tmpdir(), 'tlss-'));
let served = false;
let srv = null;
let skipReason = '';
const hasCmd = (c) => {
  try { execFileSync('sh', ['-c', 'command -v ' + c], { stdio: 'ignore' }); return true; }
  catch (e) { return false; }
};
const addextOk = () => {
  try {
    execFileSync('sh', ['-c',
      'openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/null -days 1 -nodes'
      + ' -subj /CN=t -addext subjectAltName=DNS:localhost'], { stdio: 'ignore' });
    return true;
  } catch (e) { return false; }
};
try {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048',
    '-keyout', path.join(tlsdir, 'k.pem'), '-out', path.join(tlsdir, 'c.pem'),
    '-days', '2', '-nodes', '-subj', '/CN=localhost/O=Self Signed Central',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
  fs.writeFileSync(path.join(tlsdir, 'srv.py'), [
    'import http.server, ssl, json, sys',
    'V = {"result": {"deployment": {"name": "payments-api", "namespace": "prod", "type": "Deployment"},',
    '     "livePods": 3, "images": [{"id": "sha256:a", "name": {"fullName": "quay.io/acme/payments:1.4"},',
    '     "scan": {"components": [{"name": "openssl", "version": "3.0.7", "vulns": [',
    '       {"cve": "CVE-2026-1000", "severity": "CRITICAL_VULNERABILITY_SEVERITY", "cvss": 9.8,',
    '        "fixedBy": "3.0.14", "cisaKev": True},',
    '       {"cve": "CVE-2026-1001", "severity": "IMPORTANT_VULNERABILITY_SEVERITY", "cvss": 7.5,',
    '        "fixedBy": ""}]}]}}]}}',
    'A = {"alerts": [{"id": "a1", "state": "ACTIVE", "platformComponent": False, "namespace": "prod",',
    '     "policy": {"id": "p", "name": "Privileged Container", "severity": "CRITICAL_SEVERITY"},',
    '     "deployment": {"name": "payments-api", "type": "Deployment", "namespace": "prod"},',
    '     "violations": [{"message": "Container x is privileged"}]}]}',
    'class H(http.server.BaseHTTPRequestHandler):',
    '    def do_GET(self):',
    '        if "export" in self.path: b = json.dumps(V).encode()',
    '        elif "alert" in self.path: b = json.dumps(A).encode()',
    '        else: b = json.dumps({"ok": True}).encode()',
    '        self.send_response(200); self.send_header("Content-Type","application/json")',
    '        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)',
    '    def log_message(self, *a): pass',
    'ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)',
    'ctx.load_cert_chain(sys.argv[1], sys.argv[2])',
    's = http.server.HTTPServer(("127.0.0.1", int(sys.argv[3])), H)',
    's.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()',
  ].join('\n'));
  /* Keep the server's stderr. Discarding it meant "could not start a local TLS server"
     with no way to find out why, which is the same defect as a silent skip one level
     down: it names the symptom and withholds the cause. */
  const { spawn } = require('child_process');
  const errLog = path.join(tlsdir, 'server.err');
  const errFd = fs.openSync(errLog, 'a');
  srv = spawn('python3', [path.join(tlsdir, 'srv.py'), path.join(tlsdir, 'c.pem'),
                          path.join(tlsdir, 'k.pem'), '18443'],
              { stdio: ['ignore', 'ignore', errFd], detached: true });

  /* Probe with node's own TLS client rather than shelling out to openssl. One less
     external tool to be missing or to disagree, and what it reports is the connection
     failing rather than openssl's opinion of it. */
  execFileSync(process.execPath, ['-e',
    "const tls=require('tls');let n=0;(function go(){" +
    "const s=tls.connect({host:'127.0.0.1',port:18443,rejectUnauthorized:false}," +
    "()=>{s.destroy();process.exit(0);});" +
    "s.on('error',()=>{s.destroy();if(++n>=40)process.exit(1);setTimeout(go,250);});})();"],
    { timeout: 20000, stdio: 'ignore' });
  served = true;
} catch (e) { skipReason = (e && e.message ? String(e.message).split('\n')[0] : String(e)); }

if (!served) {
  /* Say what is missing. Thirty one assertions disappearing with no explanation is its own
     small version of a check that cannot fail: the total drops, everything still says
     passed, and nobody knows a block was not run. */
  console.log('  skip  could not start a local TLS server, so 31 assertions did not run here.');
  console.log('        Reason: ' + (skipReason || 'unknown'));
  try {
    const el = fs.readFileSync(path.join(tlsdir, 'server.err'), 'utf8').trim();
    if (el) {
      console.log('        The server itself said:');
      for (const line of el.split('\n').slice(-8)) console.log('          ' + line);
    } else {
      console.log('        The server wrote nothing to stderr, so the process did not');
      console.log('        crash. Something is refusing the connection instead.');
    }
  } catch (e) { /* no log to read */ }
  for (const [what, ok] of [
    ['python3 on PATH', hasCmd('python3')],
    ['openssl on PATH', hasCmd('openssl')],
    ['openssl accepts -addext (LibreSSL before 3.1 does not)', addextOk()],
  ]) {
    console.log('        ' + (ok ? 'ok    ' : 'MISSING ') + what);
  }
  console.log('        These run in CI on ubuntu-latest, so the coverage is not lost,');
  console.log('        but it is not being exercised on this machine.');
} else {
  const EP = 'https://127.0.0.1:18443';
  const pullSrcOf = (f) => fs.readFileSync(f, 'utf8');
  const pull = path.join(DIR, 'acs_pull_all.sh');
  /* Hermetic, in two ways that both matter.
   *
   * The script asks the cluster for a CA through oc when it cannot verify otherwise.
   * On a workstation oc usually exists and points at a real cluster, so the test would
   * block on somebody's actual API server. A stub oc on PATH that fails immediately
   * exercises the same branch deterministically and in milliseconds. This is how the
   * suite passed for me and hung for the user: my sandbox had no oc, so the branch was
   * never reached, and the test was silently only testing half the code.
   *
   * The timeout turns any future hang into a failed assertion rather than a wedged run.
   * A test suite that stops is worse than one that fails, because nobody knows where. */
  const stub = path.join(tlsdir, 'bin');
  fs.mkdirSync(stub, { recursive: true });
  fs.writeFileSync(path.join(stub, 'oc'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });

  const runPull = (args, opts) => {
    const o = opts || {};
    const out = path.join(tlsdir, 'out-' + Math.random().toString(36).slice(2));
    const env = Object.assign({}, process.env,
      { ROX_API_TOKEN: 'x', ROX_ENDPOINT: EP, KUBECONFIG: '/dev/null' });
    if (o.ocPath) env.PATH = o.ocPath + ':' + process.env.PATH;
    else if (!o.realPath) env.PATH = stub + ':' + process.env.PATH;
    let r;
    try {
      r = { code: 0, out: execFileSync('sh', [pull, '-o', out].concat(args),
        { encoding: 'utf8', env: env, timeout: 60000, stdio: ['ignore','pipe','pipe'] }) };
    } catch (e) {
      if (e.killed || e.signal) {
        r = { code: -1, out: 'TIMED OUT after 60s: ' + ((e.stdout || '') + (e.stderr || '')) };
      } else {
        r = { code: e.status, out: (e.stdout || '') + (e.stderr || '') };
      }
    }
    r.dir = out;
    r.files = walk(out).map((f) => path.basename(f));
    return r;
  };

  /* Plain run: the chain cannot verify, so it must stop and explain. */
  const plain = runPull([]);
  t('a self signed endpoint stops the run rather than pulling nothing quietly',
    plain.code !== 0);
  t('it shows the certificate issuer', /Self Signed Central/.test(plain.out));
  t('and a real SHA-256 fingerprint, not the hash of an empty handshake',
    /SHA-256 fingerprint/.test(plain.out) &&
    !/47DEQpj8HBSa\+\/TImW\+5JCeuQeRkm5NMpJWZG3hSuFU=/.test(plain.out));
  t('it never offers --insecure as the way forward',
    !/try --insecure|use --insecure|--insecure to/i.test(plain.out));
  t('it explains that the token is why', /reads your whole security posture/.test(plain.out));

  /* The symptom that started this: a directory that looks like a pull and is not one. */
  t('a failed run leaves no findings directory to be mistaken for an empty result',
    plain.files.filter((f) => /^0\d_/.test(f)).length === 0);
  t('and says so', /no findings directory was created/.test(plain.out));

  /* Pinning: the offered command must actually work. */
  const spki = execFileSync('sh', ['-c',
    'echo | openssl s_client -connect 127.0.0.1:18443 2>/dev/null | openssl x509 -pubkey -noout'
    + ' | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64'],
    { encoding: 'utf8' }).trim();
  t('the failure output offers that exact pin', plain.out.indexOf(spki) !== -1);

  const pinned = runPull(['--pin', 'sha256//' + spki]);
  t('pinning completes a full pull against the self signed endpoint', pinned.code === 0);
  t('and writes every file the pull is supposed to write',
    ['00_auth_status.json', '01_alerts_list.json', '02_alerts_full.json',
     '03_vuln_workloads.ndjson', '04_all_images.ndjson', '05_nodes.ndjson',
     '06_snoozed.ndjson'].every((f) => pinned.files.indexOf(f) !== -1));
  t('it says the chain check is off and the key is pinned',
    /chain verification off, pinned/.test(pinned.out));

  /* The pin has to be enforced, or it is decoration on top of --insecure. */
  const bad = runPull(['--pin', 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=']);
  t('a wrong pin fails closed rather than connecting anyway', bad.code !== 0);
  t('and curl names the pin as the reason', /pinned public key/i.test(bad.out));
  t('no findings data is written', bad.files.filter((f) => /\.(json|ndjson)$/.test(f)).length === 0);
  /* A wrong pin fails at the token check rather than at TLS resolution, because --pin is
     taken at face value. That leaves an error file, which is worth keeping, so the
     directory has to be marked or it reads like a pull that came back empty. */
  t('and the directory is marked as a failed run, not an empty result',
    bad.files.indexOf('RUN_FAILED.txt') !== -1);
  const marker = walk(bad.dir).find((f) => /RUN_FAILED/.test(f));
  t('the marker says plainly not to read it as a clean cluster',
    !!marker && /do not load it and conclude/i.test(fs.readFileSync(marker, 'utf8')));

  /* The certificate is its own issuer, so it works as a CA bundle when the name matches. */
  execFileSync('sh', ['-c',
    'echo | openssl s_client -connect 127.0.0.1:18443 2>/dev/null | openssl x509 > '
    + JSON.stringify(path.join(tlsdir, 'leaf.pem'))]);
  const viaCa = runPull(['--cacert', path.join(tlsdir, 'leaf.pem')]);
  t('verifying against the certificate itself also completes the pull', viaCa.code === 0);
  t('with full verification, so this is the better of the two routes',
    viaCa.out.indexOf('chain verification off') === -1);

  /* The run has to end with something a person can read. Seven JSON files in a folder
     is not a result, and a summary written but never shown is a summary nobody reads. */
  console.log('\n  The pull ends with a summary, written and displayed');
  const pinned2 = runPull(['--pin', 'sha256//' + spki]);
  t('findings.md is written into the run directory',
    pinned2.files.indexOf('findings.md') !== -1);
  t('and its contents are printed at the end of the run',
    /## Violations/.test(pinned2.out) && /What this summary cannot tell you/.test(pinned2.out));
  t('the run says where it was written',
    /Summary written to .*findings\.md/.test(pinned2.out));

  const md = walk(pinned2.dir).find((f) => /findings\.md$/.test(f));
  const body = md ? fs.readFileSync(md, 'utf8') : '';
  t('the summary counts the violations it pulled', /## Violations: \d+/.test(body));
  t('it scores the images by worst CVSS', /Worst CVSS/.test(body));
  t('and lists the highest scoring CVEs', /Highest scoring CVEs/.test(body));
  t('it flags anything on the CISA catalog', /Known Exploited/.test(body));
  /* The text is hard wrapped, so match phrases that survive a line break. */
  t('it says CVSS is not the priority the engine ranks by, and why',
    /CVSS is the score ACS supplied/.test(body) && /drifts from the first/.test(body));
  t('and it still refuses to print a posture score',
    /not a posture score/.test(body) && !/Grade [A-F]\b/.test(body));

  const nosum = runPull(['--pin', 'sha256//' + spki, '--no-summary']);
  t('--no-summary skips it for a pipeline that only wants the files',
    nosum.files.indexOf('findings.md') === -1 &&
    nosum.files.indexOf('02_alerts_full.json') !== -1);

  /* The findings and the manifests they are about have to come from the same instant.
     ACS naming a workload is only actionable if you also have the object it named, and a
     workloads.json pulled an hour later has already drifted. This is also what makes a
     before and after comparison mean anything: two run directories, diffed. */
  console.log('\n  The run captures the live workloads beside the findings');
  const goodOc = path.join(tlsdir, 'bin-oc');
  fs.mkdirSync(goodOc, { recursive: true });
  fs.writeFileSync(path.join(goodOc, 'oc'),
    '#!/bin/sh\ncase "$*" in\n' +
    '  *deployment,daemonset*) echo \'{"apiVersion":"v1","kind":"List","items":' +
    '[{"kind":"Deployment","metadata":{"name":"a","namespace":"prod"}},' +
    '{"kind":"DaemonSet","metadata":{"name":"b","namespace":"kube-system"}}]}\' ;;\n' +
    '  *) exit 1 ;;\nesac\n', { mode: 0o755 });

  const wl = runPull(['--pin', 'sha256//' + spki], { ocPath: goodOc });
  t('workloads.json lands in the same run directory as the findings',
    wl.files.indexOf('workloads.json') !== -1 &&
    wl.files.indexOf('02_alerts_full.json') !== -1);
  const wlf = walk(wl.dir).find((f) => /workloads\.json$/.test(f));
  const wlj = wlf ? JSON.parse(fs.readFileSync(wlf, 'utf8')) : null;
  t('it holds the objects oc returned, unaltered', !!wlj && wlj.items.length === 2);
  t('the run says how many objects it captured', /2 workload object\(s\)/.test(wl.out));
  t('the capture asks for every controller kind, not just deployments',
    /deployment,daemonset,statefulset,cronjob,job/.test(pullSrcOf(pull)));
  t('and across all namespaces', /--all-namespaces/.test(pullSrcOf(pull)));
  t('the capture is time bounded too, so a slow API server cannot wedge the run',
    /oc --request-timeout=60s get deployment/.test(pullSrcOf(pull)));

  /* Most people running the pull are on a jump box with a token and no oc. Losing the
     workloads is survivable; losing the findings because of it is not. */
  const noOc = runPull(['--pin', 'sha256//' + spki]);
  t('an oc that fails does not fail the run', noOc.code === 0);
  t('an oc that cannot reach the cluster is reported, not swallowed',
    /could not read workloads/.test(noOc.out));
  t('and it says the workloads were not captured',
    /workloads were not|were not captured/.test(noOc.out));
  t('and prints the command to run elsewhere',
    /oc get deployment,daemonset,statefulset,cronjob,job -A -o json/.test(noOc.out));
  t('a half written workloads.json is removed rather than left to be loaded',
    noOc.files.indexOf('workloads.json') === -1);
  /* The no oc branch cannot be reached with a stub on PATH, so assert on the source. */
  t('a host with no oc at all gets the same instruction',
    /oc is not on PATH, so the running workloads were not captured/.test(pullSrcOf(pull)));

  console.log('\n  The pull cannot hang on an unrelated cluster');
  const pullSrc = pullSrcOf(pull);
  t('the oc call that bootstraps trust is time bounded',
    /oc --request-timeout=\d+s/.test(pullSrc));
  t('and the script says it is trying that route, so a wait is explained',
    /trying the central-tls secret through your oc session/.test(pullSrc));
  t('none of the test runs timed out',
    ![plain, pinned, bad, viaCa].some((r) => /TIMED OUT/.test(r.out)));

  try { process.kill(-srv.pid); } catch (e) { /* already gone */ }
}
fs.rmSync(tlsdir, { recursive: true, force: true });

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
