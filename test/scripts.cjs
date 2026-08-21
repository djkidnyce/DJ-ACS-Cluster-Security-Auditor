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
const talkers = sh.filter((f) => /curl /.test(read(f)) && !/pull_via_oc/.test(f));
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

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
