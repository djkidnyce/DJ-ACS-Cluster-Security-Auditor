#!/usr/bin/env node
/*
 * DJ's ACS Auditor, command line.
 *
 * Produces exactly what the browser pages produce, from a terminal or a pipeline:
 * the audit report, the findings JSON, the patched YAML, strategic merge patches, the
 * change log and the CVE worklist.
 *
 * It loads acs_policies.js, the same engine the pages load. It does not reimplement a
 * single check. If the CLI and the GUI ever disagree about a manifest, that is a bug in
 * one file, not a discrepancy between two.
 *
 * WHAT IT WILL NOT DO
 *   It never contacts a cluster. It never runs a command to remediate anything. Fixes
 *   are text edits to YAML, and it is read only until you explicitly pass --fix.
 *   Use scripts/acs_pull_all.sh to fetch from ACS, then feed the output in here.
 *
 * REQUIREMENTS
 *   Node 18 or newer. Nothing else. js-yaml is vendored.
 */
'use strict';

const fs = require('fs');
const path = require('path');

/* ---------------------------------------------------------------- bootstrap */

const HERE = __dirname;

function loadYamlLib() {
  const p = path.join(HERE, 'vendor', 'js-yaml.min.js');
  if (!fs.existsSync(p)) {
    console.error('Missing ' + p);
    console.error('');
    console.error('This tool refuses to fetch it for you. Downloading a parser at runtime');
    console.error('would mean a security tool silently pulling code off the internet, and');
    console.error('on an air gapped network that attempt is itself a reportable event.');
    console.error('');
    console.error('Get it from a connected machine and copy it across:');
    console.error('  https://unpkg.com/js-yaml@4.1.0/dist/js-yaml.min.js');
    console.error('Then verify before you trust it:');
    console.error('  shasum -a 256 vendor/js-yaml.min.js');
    console.error('  expected 45dc3dd03dc07a06705a2c2989b8c7f709013f04bd5386e3279d4e447f07ebd7');
    process.exit(2);
  }
  return require(p);
}
globalThis.jsyaml = loadYamlLib();
const E = require(path.join(HERE, 'acs_policies.js'));

/* ------------------------------------------------------------------- args */

const USAGE = `
DJ's ACS Auditor, command line.

  node acs_cli.js --path <dir> [options]

INPUT
  --path <dir>          Directory of Kubernetes or OpenShift YAML. Required.
  --workloads <file>    Workloads exported from a cluster as JSON or YAML, from
                        oc get deploy,ds,sts,cronjob -o json. Server side fields
                        are stripped on load.
  --alerts <file>       ACS violation export. Use the HYDRATED one from
                        /v1/alerts/{id}; the /v1/alerts list has no violation text.
  --vulns <file>        ACS vulnerability export (.ndjson) from
                        /v1/export/vuln-mgmt/workloads.
  --exclude <glob,...>  Comma separated path fragments to skip.

MODE  (required before anything can be written as a fix)
  --mode <mode>         report | manual | auto.  Default: report.

    report   Analyse and report. No patch, no corrected manifest, nothing that
             could be applied. This is the default because the safe state should
             be what you get by doing nothing.
    manual   Produce patches and guidance for a human to review and apply.
             Nothing is modified.
    auto     Apply the safe fixes to YAML and write the corrected files.

  The mode is never inferred. Asking for --patches does not put you in manual
  mode; you choose manual and then ask for patches. An unknown value is an error
  rather than a silent downgrade. The mode is recorded in every artifact.

OUTPUT
  --out <dir>           Where to write. Default acs_audit_<timestamp>.
  --report              Write the HTML audit report.
  --json                Write the findings JSON.
  --worklist            Write the CVE rebuild worklist (needs --vulns).
  --sarif               Write SARIF 2.1.0 for GitHub and GitLab security tabs.
  --quiet               Only print the summary line.

FIXING  (all of these require --mode manual or --mode auto)
  --patches             Emit one strategic merge patch per changed object.
  --list-violations     Print every imported violation with its key and fix route, then
                        stop. Use it to decide what to pass to --select.
  --select <k,...>      Only act on these violations. Takes alert ids, or an object name
                        such as Deployment/payments-api, or a policy id such as ACS.001.
                        Comma separated, repeatable. Without it every violation is in
                        scope, which matches how the tool behaved before this existed.
  --override-platform <k,...>
                        Take responsibility for objects the tool classified as platform
                        and patch them anyway. Same identifiers as --select. Per object,
                        never global. Use when ACS did not send platformComponent and the
                        namespace guess was wrong about a workload you own.
  --violation-fixes     Emit patches for ACS violations whose manifest you do not
                        have locally, plus a written account of what could not be
                        fixed and why. In report mode the account is still written,
                        the patches are not.
  --in-place            With --mode auto, overwrite the source files instead of
                        writing to --out. Refuses unless the git tree is clean.
  --only <ACS.001,...>  Only these policy ids.
  --skip <ACS.013,...>  Everything except these policy ids.
  --dry-run             Show what --mode auto would change and write nothing.
  --fix                 Deprecated alias for --mode auto. Warns.

GATING
  --fail-on <level>     Exit 1 if anything at or above this remains unfixed.
                        critical | high | medium | low | none. Default none.

EXAMPLES
  # report only, the default
  node acs_cli.js --path ./manifests --report --json

  # manual: patches for a human to apply, nothing modified
  node acs_cli.js --path ./manifests --mode manual --patches --out ./proposed

  # auto: apply the safe fixes
  node acs_cli.js --path ./manifests --mode auto --patches --out ./remediated

  node acs_cli.js --path ./manifests --sarif --fail-on high
  node acs_cli.js --workloads workloads.json --report
  node acs_cli.js --mode manual --alerts alerts_full.json --violation-fixes --out ./fixes
`;

function parseArgs(argv) {
  const o = {
    path: '', out: '', alerts: '', vulns: '', workloads: '', exclude: [],
    report: false, json: false, worklist: false, sarif: false, quiet: false,
    fix: false, inPlace: false, patches: false, only: [], skip: [], dryRun: false,
    violationFixes: false,
    mode: '', modeGiven: false, fixAlias: false,
    failOn: 'none',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = function () { return argv[++i]; };
    switch (a) {
      case '--path': o.path = next(); break;
      case '--out': o.out = next(); break;
      case '--workloads': o.workloads = next(); break;
      case '--alerts': o.alerts = next(); break;
      case '--vulns': o.vulns = next(); break;
      case '--exclude': o.exclude = String(next() || '').split(',').filter(Boolean); break;
      case '--report': o.report = true; break;
      case '--json': o.json = true; break;
      case '--worklist': o.worklist = true; break;
      case '--sarif': o.sarif = true; break;
      case '--quiet': o.quiet = true; break;
      case '--mode': o.mode = next(); o.modeGiven = true; break;
      case '--fix': o.fixAlias = true; break;
      case '--in-place': o.inPlace = true; break;
      case '--patches': o.patches = true; break;
      case '--violation-fixes': o.violationFixes = true; break;
      case '--list-violations': o.listViolations = true; break;
      case '--override-platform':
        o.overridePlatform = (o.overridePlatform || []).concat(String(next()).split(',')
          .map(function (x) { return x.trim(); }).filter(Boolean));
        break;
      case '--select':
        o.select = (o.select || []).concat(String(next()).split(',')
          .map(function (x) { return x.trim(); }).filter(Boolean));
        break;
      case '--only': o.only = String(next() || '').split(',').map(function (x) { return x.trim().toUpperCase(); }).filter(Boolean); break;
      case '--skip': o.skip = String(next() || '').split(',').map(function (x) { return x.trim().toUpperCase(); }).filter(Boolean); break;
      case '--dry-run': o.dryRun = true; break;
      case '--fail-on': o.failOn = String(next() || 'none').toLowerCase(); break;
      case '-h': case '--help': console.log(USAGE); process.exit(0); break;
      default:
        console.error('Unknown option: ' + a);
        console.error('Run with --help for usage.');
        process.exit(2);
    }
  }
  return o;
}

const opts = parseArgs(process.argv.slice(2));
/* Any one of these is a complete input on its own.
 *
 *   --path       a repository of manifests
 *   --workloads  what is actually running, from oc get -o json
 *   --alerts     ACS violations, with no repository checked out at all
 *   --vulns      an ACS CVE export
 *
 * Requiring --path meant that somebody holding a violation export and nothing else got
 * the usage screen, which is precisely the case where drafting patches from the violation
 * is the only route available to them. */
if (!opts.path && !opts.workloads && !opts.alerts && !opts.vulns) {
  console.log(USAGE);
  process.exit(2);
}

/* ------------------------------------------------------------------- mode */

if (opts.fixAlias && !opts.modeGiven) { opts.mode = 'auto'; opts.modeGiven = true; }
let MODE;
try { MODE = E.resolveFixMode(opts.mode); }
catch (e) { console.error(e.message); process.exit(2); }
opts.fix = (MODE === 'auto');

if (opts.fixAlias) {
  console.error('Note: --fix is a deprecated alias for --mode auto. Say the mode explicitly.');
}

/* The gate. Anything that produces something applyable requires the operator to have
   chosen a writing mode, and choosing it is a separate act from asking for the output.
   Refusing here rather than silently downgrading is the point: a run that quietly does
   less than you asked is as bad as one that quietly does more, because in both cases the
   operator's mental model and the tool's behaviour have diverged without anyone saying so. */
const WRITE_FLAGS = [
  ['--patches', opts.patches],
  ['--in-place', opts.inPlace],
];
const requested = WRITE_FLAGS.filter(function (f) { return f[1]; }).map(function (f) { return f[0]; });
if (requested.length && !E.modeAllows(MODE, 'writes')) {
  console.error('');
  console.error(requested.join(' and ') + ' produce material that can be applied, and this run is in');
  console.error('report mode, which by definition produces none.');
  console.error('');
  console.error('Choose the path you actually want:');
  console.error('  --mode manual   patches and guidance, nothing modified');
  console.error('  --mode auto     apply the safe fixes');
  console.error('');
  console.error('Refusing rather than picking one for you. An auto fix nobody selected is a');
  console.error('new risk, not a mitigation.');
  process.exit(2);
}
if (opts.inPlace && MODE !== 'auto') {
  console.error('--in-place edits your source files, which is only meaningful in --mode auto.');
  process.exit(2);
}

/* ------------------------------------------------------------------ helpers */

const C = process.stdout.isTTY ? {
  red: function (s) { return '[31m' + s + '[0m'; },
  yel: function (s) { return '[33m' + s + '[0m'; },
  grn: function (s) { return '[32m' + s + '[0m'; },
  dim: function (s) { return '[2m' + s + '[0m'; },
  bold: function (s) { return '[1m' + s + '[0m'; },
} : { red: String, yel: String, grn: String, dim: String, bold: String };

function log() { if (!opts.quiet) console.log.apply(console, arguments); }

function stamp() {
  const d = new Date();
  const p = function (n) { return String(n).padStart(2, '0'); };
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '_' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

const YAML_RE = /\.(ya?ml)$/i;
const SKIP_DIRS = ['.git', 'node_modules', '.idea', '.vscode', '__pycache__', 'vendor'];

function walk(dir, root, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (e) { return acc; }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (ent.isDirectory()) {
      if (SKIP_DIRS.indexOf(ent.name) !== -1) continue;
      if (opts.exclude.some(function (x) { return rel.indexOf(x) !== -1; })) continue;
      walk(full, root, acc);
    } else if (YAML_RE.test(ent.name)) {
      if (opts.exclude.some(function (x) { return rel.indexOf(x) !== -1; })) continue;
      acc.push({ name: rel, abs: full });
    }
  }
  return acc;
}

/* Preserve the file's existing line endings. A Windows checkout must not come back with
   every line marked as changed: a two line fix should read as a two line diff in review,
   not as a rewrite of the whole file. Reviewers stop reading rewrites. */
function detectEol(text) { return /\r\n/.test(text) ? '\r\n' : '\n'; }
function applyEol(text, eol) {
  const norm = text.replace(/\r\n/g, '\n');
  return eol === '\r\n' ? norm.replace(/\n/g, '\r\n') : norm;
}

function mkdirp(p) { fs.mkdirSync(p, { recursive: true }); }

function writeOut(rel, content) {
  const dest = path.join(OUT, rel);
  mkdirp(path.dirname(dest));
  fs.writeFileSync(dest, content);
  return dest;
}

/* ------------------------------------------------------------------- load */

const ROOT = opts.path ? path.resolve(opts.path) : '';
if (ROOT && !fs.existsSync(ROOT)) { console.error('No such directory: ' + ROOT); process.exit(2); }

const OUT = path.resolve(opts.out || ('acs_audit_' + stamp()));

const found = ROOT ? walk(ROOT, ROOT, []) : [];

const files = [];
const eols = {};
let parseErrors = 0;
for (const f of found) {
  const raw = fs.readFileSync(f.abs, 'utf8');
  eols[f.name] = detectEol(raw);
  const pf = E.parseFileText(f.name, raw);
  pf.abs = f.abs;
  if (pf.errors.length) parseErrors++;
  files.push(pf);
}

/* Workloads exported from a live cluster. Accepts the JSON that `oc get ... -o json`
   produces, the YAML from -o yaml, a List wrapper, a single object, or a file of
   concatenated objects from a shell loop. Server side fields are stripped, so what gets
   scanned is what you could actually commit. */
let liveCount = 0;
if (opts.workloads) {
  if (!fs.existsSync(opts.workloads)) { console.error('No such file: ' + opts.workloads); process.exit(2); }
  const raw = fs.readFileSync(opts.workloads, 'utf8');
  let imported = E.importKubeJson(raw);
  if (!imported.count) {
    // Not JSON. Try it as YAML, which is the other thing oc emits.
    const pf = E.parseFileText(path.basename(opts.workloads), raw);
    const docs = (pf.docs || []).filter(E.looksLikeKubeObject);
    if (docs.length) {
      imported = { files: [], count: 0, errors: [] };
      for (const d of docs) {
        const list = (d.kind && /List$/.test(d.kind) && Array.isArray(d.items)) ? d.items : [d];
        for (const o of list) {
          if (!E.looksLikeKubeObject(o)) continue;
          const clean = E.sanitizeLiveObject(o, o.kind);
          const ns = (clean.metadata && clean.metadata.namespace) || 'default';
          const nm = (clean.metadata && clean.metadata.name) || 'unnamed';
          imported.files.push({ name: 'live/' + ns + '/' + String(o.kind).toLowerCase() + '-' + nm + '.yaml',
            text: jsyaml.dump(clean, { noRefs: true, lineWidth: 120 }) });
          imported.count++;
        }
      }
    }
  }
  if (!imported.count) {
    console.error('Could not read ' + opts.workloads + ' as Kubernetes objects.');
    if (imported.errors && imported.errors.length) console.error('  ' + imported.errors.slice(0, 3).join('\n  '));
    console.error('  Expected: oc get deployment,daemonset,statefulset,cronjob -o json');
    process.exit(2);
  }
  for (const f of imported.files) {
    eols[f.name] = '\n';
    files.push(E.parseFileText(f.name, f.text));
  }
  liveCount = imported.count;
}

/* No manifests is only an error when there is nothing else to work with. An alerts or CVE
   export on its own is a legitimate run: it is the case where patches drafted from the
   violation are the only route available, so refusing here would block exactly the
   workflow that needs the tool most. */
if (!files.length && !opts.alerts && !opts.vulns) {
  console.error('Nothing to scan. No YAML under ' + (ROOT || '(no --path)') +
    (opts.workloads ? ' and no objects in ' + opts.workloads : ''));
  console.error('Supply one of: --path, --workloads, --alerts, --vulns.');
  process.exit(2);
}
files.sort(function (a, b) { return a.name.localeCompare(b.name); });

let acs = null, onlyInAcs = [];
if (opts.alerts) {
  const txt = fs.readFileSync(opts.alerts, 'utf8');
  try { acs = E.importAcsViolations(JSON.parse(txt)); }
  catch (e) { console.error('Could not read ' + opts.alerts + ' as an ACS alert export: ' + e.message); process.exit(2); }
}

let vulns = null, vulnCorr = null;
if (opts.vulns) {
  const parsed = E.parseVulnExport(fs.readFileSync(opts.vulns, 'utf8'));
  if (!parsed.records.length) {
    console.error('No usable records in ' + opts.vulns + '.');
    if (parsed.errors.length) console.error('  ' + parsed.errors.slice(0, 3).join('\n  '));
    console.error('  Expected NDJSON from /v1/export/vuln-mgmt/workloads.');
    process.exit(2);
  }
  vulns = E.importVulnFindings(parsed, {});
  vulnCorr = E.correlateVulns(files, vulns);
}

let findings = E.scanFiles(files);
if (acs) onlyInAcs = E.correlate(findings, acs.imported).onlyInAcs;

/* ------------------------------------------------------------------ report */

/* The engine ranks severity with Critical as 0 and Low as 3, because that is the order
   a findings table sorts in. That is the opposite of how a threshold reads in prose, and
   getting it backwards would produce a CI gate that passes builds with criticals in them
   and blocks them on lows. So map the flag onto the engine's own scale explicitly rather
   than inventing a second one, and compare with <=, meaning "at least this severe".
   test/cli.cjs asserts this both ways round. */
const FAIL_ON_RANK = {
  critical: 0,   // block on Critical only
  high: 1,       // block on Critical and High
  medium: 2,
  low: 3,        // block on anything
  none: null,    // never block
};
const before = E.computePosture(files, findings, false);

log('');
log(C.bold("DJ's ACS Auditor") + '  ' + C.dim(E.ACS_TOOL));
log(C.dim('  mode     ') + MODE + '  ' + C.dim(E.FIX_MODE_INFO[MODE].summary));
log(C.dim('  scanned  ') + files.length + ' file(s), ' +
  files.reduce(function (n, f) { return n + f.docs.length; }, 0) + ' document(s)' +
  (ROOT ? ' under ' + ROOT : ''));
if (liveCount) log(C.dim('  live     ') + liveCount + ' object(s) from ' + opts.workloads +
  ', server side fields stripped');
if (parseErrors) log(C.yel('  ' + parseErrors + ' file(s) failed to parse and were reported, not skipped silently'));
if (acs) log(C.dim('  acs      ') + acs.total + ' violation(s) imported, ' + acs.imported.length + ' mapped' +
  (acs.hydratable ? C.yel(', ' + acs.hydratable + ' carry no violation text (use the hydrated export)') : ''));
if (vulns) log(C.dim('  cves     ') + vulns.rows.length + ' distinct across ' + vulns.images.length + ' image(s)');
log('');

/* A posture score computed over zero manifests is 100/100 grade A, which is a lie of
   exactly the kind this tool is supposed to prevent: it reads as "clean" when the truth
   is "nothing was examined". Say the second thing. */
const counts = before.counts;
if (!files.length) {
  log(C.yel('  No manifests were scanned, so there is no posture score.'));
  log(C.dim('  A score over nothing would read as 100 out of 100, which is not the same'));
  log(C.dim('  as clean. Pass --path or --workloads to get one.'));
} else {
log(C.bold('  Posture ' + before.score + '/100  grade ' + before.grade));
log('  ' + C.red(counts.Critical + ' critical') + '   ' + C.yel(counts.High + ' high') + '   ' +
  counts.Medium + ' medium   ' + counts.Low + ' low');

const autoable = findings.filter(function (f) { return f.fixKind !== 'manual'; });
const manual = findings.filter(function (f) { return f.fixKind === 'manual'; });
log('  ' + autoable.length + ' automatically fixable, ' + manual.length + ' need a human decision');
}

if (vulns) {
  const vs = E.summarizeVulns(vulns);
  log('');
  log(C.bold('  Image CVEs') + C.dim('  (reported separately, never folded into the posture score)'));
  log('  ' + C.red(vs.critical + ' critical') + '   ' + C.yel(vs.important + ' important') + '   ' +
    vs.moderate + ' moderate   ' + vs.low + ' low');
  log('  ' + (vs.kev ? C.red(vs.kev + ' known exploited') : '0 known exploited') +
    '   ' + vs.fixable + ' fixable now (' + vs.fixablePct + '%)   ' + vs.accepted + ' accepted in ACS');
  if (vs.unfixableCritical) log(C.yel('  ' + vs.unfixableCritical + ' critical CVE(s) have no published fix. Rebuilding will not clear them.'));
}
log('');

if (!opts.quiet) {
  // Ascending on rank, because rank 0 is Critical. Worst first is the order to work in.
  const shown = findings.slice().sort(function (a, b) {
    return E.sevRank(a.policy.severity) - E.sevRank(b.policy.severity) || b.policy.score - a.policy.score;
  }).slice(0, 20);
  for (const f of shown) {
    const s = E.sevLabel(f.policy.severity);
    // Pad the plain label BEFORE colouring it: ANSI escapes count toward String.padEnd
    // length, so colouring first silently misaligns every coloured row.
    const padded = s.padEnd(9);
    const tag = s === 'Critical' ? C.red(padded) : s === 'High' ? C.yel(padded) : C.dim(padded);
    log('  ' + tag + '  ' + f.policy.id + '  ' + f.policy.acsPolicy);
    log('    ' + C.dim(f.file + '  ' + f.obj) + (f.confirmedByAcs ? '  ' + C.red('live in ACS') : ''));
  }
  if (findings.length > shown.length) log(C.dim('  ...and ' + (findings.length - shown.length) + ' more. Use --json or --report for all of them.'));
  log('');
}

/* ------------------------------------------------------------------- fixes */

let applied = [];
let patched = {};

/* Manual and auto both COMPUTE the fix. They differ in what they do with it.
 *
 *   manual  compute, emit the patch, leave every file exactly as it was
 *   auto    compute, emit the patch, and write the corrected YAML
 *
 * Getting this wrong was the first thing that broke here: patches were built from the
 * applied list, which only existed in auto, so manual mode silently produced nothing.
 * A mode that quietly does less than you asked is as bad as one that does more. */
if (E.modeAllows(MODE, 'writes')) {
  if (opts.dryRun && MODE === 'auto') log(C.yel('  --dry-run: showing changes, writing nothing.'));

  /* --in-place edits the operator's own files. That is only recoverable if git can undo
     it, so require a clean tree rather than trusting that they remembered to commit. */
  if (opts.inPlace && !opts.dryRun && MODE === 'auto') {
    const { execFileSync } = require('child_process');
    let dirty = null;
    try {
      dirty = execFileSync('git', ['status', '--porcelain'], { cwd: ROOT, encoding: 'utf8' }).trim();
    } catch (e) {
      console.error(C.red('  --in-place refused: ' + ROOT + ' is not a git repository.'));
      console.error('  Without version control there is no undo for this. Write to --out instead.');
      process.exit(2);
    }
    if (dirty) {
      console.error(C.red('  --in-place refused: uncommitted changes in ' + ROOT + '.'));
      console.error('  Commit or stash first, so the fixes land as a reviewable diff and');
      console.error('  can be reverted in one command if they are wrong.');
      process.exit(2);
    }
  }

  const queue = findings.filter(function (f) {
    if (f.fixKind === 'manual') return false;
    if (opts.only.length && opts.only.indexOf(f.policy.id) === -1) return false;
    if (opts.skip.length && opts.skip.indexOf(f.policy.id) !== -1) return false;
    return true;
  });

  const byFile = {};
  for (const f of files) byFile[f.name] = f;
  const originals = {};
  for (const f of files) {
    originals[f.name] = E.dumpDocs(f.docs);
    // Keep the pre fix objects too. A merge patch is a diff between the document before
    // and the document after, so the "before" has to survive the fix pass.
    f.originalDocs = structuredClone(f.docs);
  }

  for (const f of queue) {
    if (f.fixKind === 'generate') {
      const doc = E.defaultDenyPolicy(f.ns);
      const rel = path.posix.join(path.posix.dirname(f.file), 'networkpolicy-default-deny-' + f.ns + '.yaml');
      patched[rel] = jsyaml.dump(doc, { noRefs: true, lineWidth: 120 });
      applied.push({ finding: f, file: rel, generated: true, changes: ['new file: default deny NetworkPolicy for namespace "' + f.ns + '", DNS egress allowed'] });
      continue;
    }
    const file = byFile[f.file];
    if (!file) continue;
    const res = E.applyOneFix(file.docs, f);
    if (!res) continue;
    file.docs = res.docs;
    applied.push({ finding: f, file: f.file, changes: res.changes });
  }

  for (const f of files) {
    const after = E.dumpDocs(f.docs);
    if (after !== originals[f.name]) patched[f.name] = after;
  }

  if (!files.length) { /* nothing to fix in manifests we do not have */ }
  else log(C.bold('  Fixes') + C.dim('  [' + MODE + ']'));
  if (!files.length) { /* no manifest fixes to report */ }
  else if (MODE === 'manual') {
    log('  ' + applied.length + ' fix(es) computed across ' + Object.keys(patched).length + ' file(s).');
    log('  Emitted as patches. Nothing was modified and no corrected YAML was written.');
  } else {
    log('  ' + applied.length + ' fix(es) applied across ' + Object.keys(patched).length + ' file(s)');
  }
  const placeholders = applied.filter(function (a) { return /PLACEHOLDER/.test(a.changes.join(' ')); });
  if (placeholders.length) {
    log(C.yel('  ' + placeholders.length + ' insert placeholder resource values. Tune them to your'));
    log(C.yel('  workload before you deploy, or you have traded a missing limit for a wrong one.'));
  }
  if (applied.some(function (a) { return a.finding.policy.id === 'ACS.010'; })) {
    log(C.yel('  A hardcoded credential was rewritten to a secretKeyRef. That does not create'));
    log(C.yel('  the Secret and cannot un-leak a value already in git history. Rotate it.'));
  }
  log('');
}

/* ------------------------------------------------------------------ writing */

const written = [];
const needOut = opts.report || opts.json || opts.worklist || opts.sarif || opts.violationFixes ||
  (E.modeAllows(MODE, 'writes') && !opts.dryRun && !opts.inPlace) || opts.patches;
if (needOut) mkdirp(OUT);

const state = { files: files, findings: findings, acs: acs, onlyInAcs: onlyInAcs,
                vulns: vulns, vulnCorr: vulnCorr, mode: MODE,
                source: 'acs_cli.js on ' + (ROOT || opts.workloads) + '. ' + E.modeBanner(MODE) };

if (opts.report) written.push(writeOut('acs_audit_report.html', E.buildHtmlReport(state)));
if (opts.json) written.push(writeOut('acs_findings.json', JSON.stringify(E.buildFindingsJson(state), null, 2)));
if (opts.worklist) {
  if (!vulns) { console.error(C.yel('  --worklist needs --vulns. Skipped.')); }
  else written.push(writeOut('image_worklist.md', E.buildVulnWorklist(vulns, vulnCorr)));
}

function pad(x, n) { x = String(x); return x.length >= n ? x : x + " ".repeat(n - x.length); }

/* --list-violations prints the menu that --select reads from, then stops. It writes
   nothing, so it is safe to run in any mode and against production data. */
if (opts.listViolations) {
  if (!acs) {
    console.error(C.yel('  --list-violations needs --alerts.'));
    process.exit(2);
  }
  const filesByObj = {};
  for (const f of files) for (const d of f.docs) filesByObj[E.nameOf(d)] = f.name;
  const all = acs.imported.concat(acs.unmatched);
  log('');
  log(C.bold('  ' + all.length + ' violation(s). Pass any KEY, OBJECT or POLICY to --select.'));
  log('');
  log(C.dim('  KEY                    SEVERITY  POLICY     OBJECT                          FIX'));
  for (const r of all) {
    const fx = E.violationFixability(r, !!filesByObj[r.obj]);
    const sev = String(r.acsSeverity || '').replace('_SEVERITY', '');
    let route = fx.fixable ? fx.kind : C.dim(fx.kind);
    if (fx.kind === 'platform') {
      route += C.dim(r.platformSource === 'acs' ? '  (ACS said so)' : '  (guessed from namespace)');
    }
    log('  ' + pad(E.violationKey(r), 22) + ' ' + pad(sev, 9) + ' ' +
        pad((r.policy && r.policy.id) || '(none)', 10) + ' ' +
        pad(r.obj + ' [' + r.namespace + ']', 31) + ' ' + route);
  }
  log('');
  log(C.dim('  Selecting nothing selects everything. That is the one place this tool is'));
  log(C.dim('  permissive, and it is only because it matches how it behaved before --select'));
  log(C.dim('  existed. If you want a subset, say so explicitly.'));
  log('');
  process.exit(0);
}

if (opts.sarif) written.push(writeOut('acs_findings.sarif', JSON.stringify(buildSarif(), null, 2)));

if (opts.violationFixes) {
  if (!acs) {
    console.error(C.yel('  --violation-fixes needs --alerts. Skipped.'));
  } else {
    const filesByObj = {};
    for (const f of files) for (const d of f.docs) filesByObj[E.nameOf(d)] = f.name;

    /* --select is the command line equivalent of the checkboxes in the page. It takes
       whichever of the three identifiers a person actually has to hand: the alert id from
       the export, the object they are trying to fix, or the policy they are clearing.
       Anything that matches nothing is an error rather than a silent no op, because a
       typo that quietly widens the scope to everything is exactly the failure this option
       exists to prevent. */
    let selected;
    if (opts.select && opts.select.length) {
      const all = acs.imported.concat(acs.unmatched);
      selected = new Set();
      const unmatchedTerms = [];
      for (const term of opts.select) {
        const lc = term.toLowerCase();
        const hits = all.filter(function (r) {
          return String(r.acsAlertId || '').toLowerCase() === lc ||
                 String(r.obj || '').toLowerCase() === lc ||
                 (r.policy && String(r.policy.id || '').toLowerCase() === lc) ||
                 String(r.acsPolicyName || '').toLowerCase() === lc;
        });
        if (!hits.length) unmatchedTerms.push(term);
        for (const h of hits) selected.add(E.violationKey(h));
      }
      if (unmatchedTerms.length) {
        console.error(C.red('  --select matched nothing for: ' + unmatchedTerms.join(', ')));
        console.error('  Run --list-violations to see the ids, objects and policies available.');
        console.error('  Refusing rather than guessing: a typo here would widen the scope, not narrow it.');
        process.exit(2);
      }
      log(C.dim('  --select matched ' + selected.size + ' of ' + all.length + ' violation(s)'));
    }

    let overridden;
    if (opts.overridePlatform && opts.overridePlatform.length) {
      const all = acs.imported.concat(acs.unmatched);
      overridden = new Set();
      const missed = [];
      for (const term of opts.overridePlatform) {
        const lc = term.toLowerCase();
        const hits = all.filter(function (r) {
          return String(r.acsAlertId || '').toLowerCase() === lc ||
                 String(r.obj || '').toLowerCase() === lc ||
                 (r.policy && String(r.policy.id || '').toLowerCase() === lc) ||
                 String(r.acsPolicyName || '').toLowerCase() === lc;
        });
        if (!hits.length) missed.push(term);
        for (const h of hits) overridden.add(E.violationKey(h));
      }
      if (missed.length) {
        console.error(C.red('  --override-platform matched nothing for: ' + missed.join(', ')));
        console.error('  Run --list-violations to see what is there.');
        process.exit(2);
      }
      const auth = all.filter(function (r) {
        return overridden.has(E.violationKey(r)) && r.platformSource === 'acs';
      }).length;
      log(C.yel('  --override-platform: ' + overridden.size + ' object(s) will be patched despite'));
      log(C.yel('  the platform classification. You are asserting that you own them.'));
      if (auth) {
        log(C.red('  ' + auth + ' of those were reported as platform by ACS itself, which is'));
        log(C.red('  authoritative. If that is right, the operator will revert your change.'));
      }
    }

    const b = E.buildViolationFixBundle(acs,
      { filesByObj: filesByObj, mode: MODE, selected: selected, overridden: overridden });
    for (const f of b.files) written.push(writeOut(f.name, f.text));
    written.push(writeOut('FIXING_VIOLATIONS.md', b.report));
    log(C.bold('  ACS violation fixes') + C.dim('  [' + MODE + ']'));
    if (b.deselected) {
      log(C.yel('  Scope: ' + b.selected + ' of ' + b.total + ' violation(s). ' + b.deselected +
        ' were not selected'));
      log(C.yel('  and are not described in the report. It covers the selection, not the cluster.'));
    }
    if (b.suppressed) {
      log(C.yel('  ' + b.suppressed + ' patch(es) NOT written: this run is in report mode.'));
      log(C.yel('  The account of what could be fixed is in FIXING_VIOLATIONS.md.'));
      log(C.yel('  Re-run with --mode manual to get the patches themselves.'));
    } else {
      log('  ' + b.files.length + ' patch file(s) emitted from violations with no local manifest');
    }
    if (b.inplace.length) log('  ' + b.inplace.length + ' fixed in your YAML instead, because the manifest is loaded');
    const warn = b.files.filter(function (f) { return f.needsContainerName; }).length;
    if (warn) log(C.yel('  ' + warn + ' patch(es) have a blank container name. A merge patch keys the'));
    if (warn) log(C.yel('  containers array on name, so applying one as is ADDS a container. Fill it in.'));
    const plat = b.skipped.filter(function (x) { return x.kind === 'platform'; }).length;
    if (plat) log('  ' + plat + ' on platform components, deliberately not patched. See FIXING_VIOLATIONS.md');
    log('  ' + b.skipped.length + ' not fixable in total, each with a reason in the report');
    log('');
  }
}

/* Only auto writes corrected YAML. Manual computed the same change and expressed it as a
   patch, which is the whole difference between proposing and doing. */
if (MODE === 'auto' && !opts.dryRun) {
  for (const rel of Object.keys(patched)) {
    const body = applyEol(patched[rel], eols[rel] || '\n');
    if (opts.inPlace) {
      const target = (byFileAbs(rel) || path.join(ROOT, rel));
      mkdirp(path.dirname(target));
      fs.writeFileSync(target, body);
      written.push(target);
    } else {
      written.push(writeOut(path.join('fixed', rel), body));
    }
  }
}
if (E.modeAllows(MODE, 'writes') && applied.length) {
  written.push(writeOut(MODE === 'manual' ? 'PROPOSED_CHANGES.md' : 'CHANGES.md', buildChangeLog()));
}

if (opts.patches && applied.length && E.modeAllows(MODE, 'patches')) {
  const byFile = {};
  for (const f of files) byFile[f.name] = f;

  /* One patch per OBJECT, not per finding. A merge patch is a diff between the document
     before and the document after, so ten fixes on the same Deployment all produce the
     identical cumulative patch. Emitting ten copies of the same file is noise that makes
     a reviewer stop reading, so group and list the policies that contributed. */
  const byObj = {};
  for (const a of applied) {
    if (a.generated) continue;
    const key = a.file + '||' + a.finding.obj;
    if (!byObj[key]) byObj[key] = { file: a.file, obj: a.finding.obj, policies: [] };
    if (byObj[key].policies.indexOf(a.finding.policy.id) === -1) byObj[key].policies.push(a.finding.policy.id);
  }

  let n = 0;
  for (const key of Object.keys(byObj)) {
    const g = byObj[key];
    const file = byFile[g.file];
    if (!file || !file.originalDocs) continue;
    /* buildMergePatch takes (beforeDoc, afterDoc), two documents. Passing anything else
       does not throw, it walks whatever object it was handed and emits nonsense. */
    const after = file.docs.find(function (d) { return E.nameOf(d) === g.obj; });
    const before = file.originalDocs.find(function (d) { return E.nameOf(d) === g.obj; });
    if (!before || !after) continue;
    const patch = E.buildMergePatch(before, after);
    if (!patch || !Object.keys(patch).length) continue;
    n++;
    const safeObj = g.obj.replace(/[^A-Za-z0-9]/g, '_');
    written.push(writeOut(path.join('patches', safeObj + '.yaml'),
      '# Strategic merge patch generated by ' + E.ACS_TOOL + '\n' +
      '# Source: ' + g.file + '  (' + g.obj + ')\n' +
      '# Covers: ' + g.policies.sort().join(', ') + '\n' +
      '# Only the changed fields are present, and container arrays are keyed on name the\n' +
      '# way Kubernetes merges them, so this will not clobber a field that drifted since\n' +
      '# the scan. Apply through your GitOps process. This file is data, not a command.\n' +
      jsyaml.dump(patch, { noRefs: true, lineWidth: 120 })));
  }
  if (!n) log(C.dim('  --patches: nothing to emit, no document level changes.'));
}

function byFileAbs(rel) {
  for (const f of files) if (f.name === rel) return f.abs;
  return null;
}

function buildChangeLog() {
  const L = [];
  L.push('# Change log');
  L.push('');
  L.push('Generated by ' + E.ACS_TOOL + ' (acs_cli.js) on ' + new Date().toISOString() + '.');
  L.push(E.modeBanner(MODE));
  L.push('');
  L.push('No command was run against a cluster. Every change below is a text edit to YAML.');
  if (MODE === 'manual') L.push('NOTHING WAS MODIFIED. These are proposals, expressed as patches.');
  L.push('');
  L.push('## ' + (MODE === 'manual' ? 'Proposed' : 'Applied') + ' (' + applied.length + ')');
  L.push('');
  for (const a of applied) {
    L.push('### ' + a.finding.policy.id + '  ' + a.finding.policy.acsPolicy);
    L.push('');
    L.push('* File: `' + a.file + '`');
    L.push('* Object: ' + a.finding.obj);
    L.push('* Severity: ' + E.sevLabel(a.finding.policy.severity));
    L.push('* Changed: ' + a.changes.join('; '));
    L.push('* Why: ' + a.finding.policy.rationale);
    L.push('* Standards: ' + E.citationsOf(a.finding.policy).join(' | '));
    L.push('');
  }
  const left = findings.filter(function (f) { return f.fixKind === 'manual'; });
  L.push('## Still needs a human decision (' + left.length + ')');
  L.push('');
  L.push('These were left alone on purpose. The right answer depends on context this tool');
  L.push('cannot see, and a security tool that breaks production gets switched off.');
  L.push('');
  for (const f of left) {
    L.push('* **' + f.policy.id + '** ' + f.policy.acsPolicy + ' in `' + f.file + '` (' + f.obj + ')');
    L.push('  * ' + f.policy.remediation);
  }
  L.push('');
  if (vulns) {
    const vs = E.summarizeVulns(vulns);
    L.push('## Image CVEs');
    L.push('');
    L.push(vs.active + ' active, ' + vs.critical + ' critical, ' + vs.kev + ' known exploited, ' +
      vs.fixable + ' fixable. None of these are fixed by editing YAML: ACS reports fixed');
    L.push('package versions, not fixed image tags. See image_worklist.md.');
    L.push('');
  }
  return L.join('\n');
}

/* SARIF so findings land in the GitHub and GitLab security tabs rather than being buried
   in job log output. Nobody reads job logs; a security tab has a review workflow. */
function buildSarif() {
  const rules = {};
  const results = findings.map(function (f) {
    const p = f.policy;
    if (!rules[p.id]) {
      rules[p.id] = {
        id: p.id,
        name: p.acsPolicy.replace(/[^A-Za-z0-9]/g, ''),
        shortDescription: { text: p.acsPolicy },
        fullDescription: { text: p.description },
        help: { text: p.remediation, markdown: '**' + p.acsPolicy + '**\n\n' + p.rationale + '\n\n' + p.remediation },
        properties: {
          'security-severity': String(p.score),
          tags: ['security', 'kubernetes', 'ACS'].concat(p.categories || []),
          cis: p.cis, nist: p.nist, pss: p.pss, stig: p.stig,
        },
        defaultConfiguration: {
          level: E.sevLabel(p.severity) === 'Critical' || E.sevLabel(p.severity) === 'High' ? 'error' : 'warning',
        },
      };
    }
    return {
      ruleId: p.id,
      level: E.sevLabel(p.severity) === 'Critical' || E.sevLabel(p.severity) === 'High' ? 'error' : 'warning',
      message: { text: p.acsPolicy + ' in ' + f.obj + '. ' + f.detail },
      locations: [{ physicalLocation: {
        artifactLocation: { uri: f.file },
        region: { startLine: 1 },
      } }],
      properties: { object: f.obj, fixKind: f.fixKind, confirmedByAcs: !!f.confirmedByAcs },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: "DJ's ACS Auditor",
        informationUri: 'https://github.com/djkidnyce',
        version: String(E.ACS_TOOL).replace(/^.*v/, ''),
        rules: Object.keys(rules).map(function (k) { return rules[k]; }),
      } },
      results: results,
    }],
  };
}

if (written.length) {
  log(C.bold('  Written'));
  /* Print whichever form is actually usable. A relative path is easier to read when the
     output landed under the current directory, and turns into ../../../../.. noise when it
     did not, which is not something anyone can copy into the next command. */
  for (const w of written.slice(0, 40)) {
    const rel = path.relative(process.cwd(), w);
    log('  ' + (rel.indexOf('..') === 0 ? w : rel));
  }
  if (written.length > 40) log(C.dim('  ...and ' + (written.length - 40) + ' more'));
  log('');
} else if (MODE === 'report') {
  log(C.dim('  Report mode. Nothing applyable was produced.'));
  log(C.dim('  --report, --json and --sarif give you the analysis.'));
  log(C.dim('  --mode manual gives you patches. --mode auto applies the safe fixes.'));
  log('');
}

/* ------------------------------------------------------------------ gating */

const remaining = findings.filter(function (f) {
  return !applied.some(function (a) { return a.finding === f; });
});
const after = E.computePosture(files, remaining, false);
if (E.modeAllows(MODE, 'writes') && applied.length) log(C.bold('  Posture ' + before.score + ' -> ' + after.score) +
  (MODE === 'manual' ? C.dim('  (if you apply the patches)') : '') +
  C.dim('  (measured against the same denominator, so it survives a rescan)'));

if (!Object.prototype.hasOwnProperty.call(FAIL_ON_RANK, opts.failOn)) {
  console.error('Unknown --fail-on value: ' + opts.failOn + '. Use critical, high, medium, low or none.');
  process.exit(2);
}
const threshold = FAIL_ON_RANK[opts.failOn];
if (threshold !== null) {
  const blocking = remaining.filter(function (f) { return E.sevRank(f.policy.severity) <= threshold; });
  if (blocking.length) {
    console.error('');
    console.error(C.red('  FAIL: ' + blocking.length + ' finding(s) at or above ' + opts.failOn + ' remain.'));
    for (const b of blocking.slice(0, 10)) {
      console.error('    ' + E.sevLabel(b.policy.severity) + '  ' + b.policy.id + '  ' + b.file + '  ' + b.obj);
    }
    if (blocking.length > 10) console.error('    ...and ' + (blocking.length - 10) + ' more');
    console.error('');
    console.error(C.dim('  Rolling this out? Start with --fail-on none and work the backlog down.'));
    console.error(C.dim('  A gate that blocks every merge on day one gets switched off within a week,'));
    console.error(C.dim('  and a switched off gate leaves you worse off than before you installed it.'));
    process.exit(1);
  }
}
process.exit(0);
