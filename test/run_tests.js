#!/usr/bin/env node
/* DJ's ACS Auditor test suite.
 *
 * Runs against the real shipped engine, with no framework and no dependency beyond the one
 * the tool already vendors, so it runs anywhere the tool runs including a disconnected
 * machine with no package manager.
 *
 *   node test/run_tests.js
 *
 * Exit code 0 means everything passed, 1 means something failed.
 */
'use strict';
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const HERE = __dirname;
const SUITES = [
  ['smoke.cjs', 'policy catalogue, scanning and scoring'],
  ['fixes.cjs', 'applying fixes, diffs and merge patches'],
  ['import.cjs', 'ACS violation import and correlation'],
  ['flow.cjs', 'the remediation page flow, preview, commit, undo'],
  ['live.cjs', 'live cluster connectors, token handling and sanitising'],
  ['vuln.cjs', 'vulnerability management, CVE import, priority and worklist'],
  ['hardening.cjs', 'security review regressions: URL scheme, TLS, credential lifetime'],
  ['cli.cjs', 'the command line runner, gating, fixes, patches, SARIF'],
  ['kubejson.cjs', 'loading workloads exported from a cluster as JSON'],
  ['platform.cjs', 'platform violations, all states, and fixing without a manifest'],
  ['exports.cjs', 'loading all six acs_pull_all.sh outputs, merging, violation fix routes'],
  ['cli_violations.cjs', 'the CLI drafting violation fixes to YAML, run end to end'],
  ['scripts.cjs', 'the shell scripts agree with each other about trust and credentials'],
  ['posture_platform.cjs', 'no score over zero manifests, and the platform override'],
  ['page.cjs', 'whole page wiring in a real DOM (needs jsdom, skips without it)'],
];

let pass = 0, fail = 0;
const failed = [];

for (const [file, what] of SUITES) {
  const p = path.join(HERE, file);
  if (!fs.existsSync(p)) { console.log('\nskipping ' + file + ', not present'); continue; }
  console.log('\n' + '='.repeat(64));
  console.log('  ' + file + '  ' + what);
  console.log('='.repeat(64));
  const r = spawnSync(process.execPath, [p], { cwd: HERE, encoding: 'utf8' });
  process.stdout.write(r.stdout || '');
  if (r.stderr) process.stderr.write(r.stderr);
  const m = (r.stdout || '').match(/(\d+) passed, (\d+) failed/);
  if (m) { pass += parseInt(m[1], 10); fail += parseInt(m[2], 10); }
  if (r.status !== 0) failed.push(file);
}

console.log('\n' + '='.repeat(64));
console.log('  TOTAL: ' + pass + ' passed, ' + fail + ' failed');
if (failed.length) console.log('  failing suites: ' + failed.join(', '));
console.log('='.repeat(64));
process.exit(failed.length || fail ? 1 : 0);
