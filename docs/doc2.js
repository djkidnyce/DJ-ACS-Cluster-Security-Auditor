const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
        PageBreak, BorderStyle, ShadingType } = require('docx');
const fs = require('fs');
const { P, Rich, Code, Note, Fig, Tbl, Bul, BulRich, NumList, NUMBERING, pageSetup,
        ACC, DARK, MUT, LINE } = require('./common.js');
const F = (n) => __dirname + '/figures/' + n;

/* Read the version from the engine rather than typing it here. These two files shipped
   claiming v1.0 while the tool stamped v1.1.0 into every report it wrote, which is the
   drift test/version.cjs exists to catch. */
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const VERSION = require('../acs_policies.js').ACS_VERSION;

const title = [
  new Paragraph({ spacing: { before: 2600, after: 0 },
    children: [new TextRun({ text: 'Administration Guide', bold: true, size: 60, color: DARK })] }),
  new Paragraph({ spacing: { after: 60 }, children: [new TextRun({
    text: "Managing and maintaining DJ's ACS Auditor", size: 26, color: ACC })] }),
  new Paragraph({ spacing: { after: 400 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: ACC } }, children: [new TextRun({ text: '' })] }),
  P('For maintainers, platform engineers, and anyone who owns these tools', { bold: true, size: 24 }),
  P("Covers DJ's ACS Auditor v" + VERSION, { size: 22, color: MUT }),
  P('Document date: 11 August 2026', { size: 22, color: MUT }),
  P('Author: DJ', { size: 22, color: MUT }),
  new Paragraph({ spacing: { before: 900 }, children: [new TextRun({ text: '' })] }),
  ...Note('info', 'Who this is for', [
    'This is the operator and maintainer document. It assumes you are comfortable with Node, git, YAML, and Kubernetes security concepts, and it skips the definitions.',
    'For a walkthrough of using the tool, read the User Guide instead.',
    'Scope: this covers the ACS Auditor only. DJ\'s KYSA is a separate tool in a separate repository, maintained separately. The two share design principles and nothing else, and until they are actually merged this document describes only what ships in this repository. Documenting a tool that is not here means describing files a reader cannot find.']),
  new Paragraph({ children: [new PageBreak()] }),
];

const tocItems = ['1. What you are maintaining', '2. Repository layout', '3. The one architectural rule',
  '4. The fix mode gate', '5. The two ACS data planes', '6. Running the test suites',
  '7. Adding or changing a policy', '8. Keeping the standards current', '9. Vendored dependencies',
  '10. Waivers and accepted risk', '11. CI integration', '12. Release procedure',
  '13. Security posture of the tooling itself', '14. Maintainer troubleshooting',
  '15. Ownership and escalation'];
const toc = [
  P('Contents', { heading: HeadingLevel.HEADING_1 }),
  ...tocItems.map((t) => P(t, { spacing: { after: 90 }, size: 22 })),
  P('Figures', { bold: true, size: 22, spacing: { before: 240, after: 90 } }),
  ...['Figure 5. Architecture of both toolsets (section 3)',
      'Figure 7. The two ACS data planes (section 5)',
      'Figure 6. Maintenance cycle (section 8)'].map((t) => P(t, { spacing: { after: 90 }, size: 22, color: MUT })),
  new Paragraph({ children: [new PageBreak()] }),
];

const body = [];
const H1 = (t) => body.push(P(t, { heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 } }));
const H2 = (t) => body.push(P(t, { heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 100 } }));
const T = (t) => body.push(P(t));
const push = (a) => a.forEach((x) => body.push(x));

// 1
H1('1. What you are maintaining');
T('One tool, in one repository, with two surfaces over a single engine. The browser page reads, scores and applies text edits to YAML across two tabs. The command line does the same work headless, for a pipeline. Both load acs_policies.js and neither reimplements a check.');
push([Tbl(['', "DJ's ACS Auditor v" + VERSION], [
  ['Judges against', 'Red Hat ACS default Deploy stage policies, with CIS, NIST 800-53 Rev 5, Pod Security Standards and DISA STIG carried as citations'],
  ['Policy ids', 'ACS.001 through ACS.020, a fixed set mirroring the ACS defaults'],
  ['Engine file', 'acs_policies.js, and only that file'],
  ['Surfaces', 'One page with an Audit and a Remediate tab, pull scripts, command line'],
  ['Writes to disk', 'The page hands you files to download. The CLI writes only where you point it, and only in manual or auto mode'],
  ['Talks to a cluster', 'The page never does. The scripts and the CLI issue GET only'],
  ['Tests', '823 across the engine, the page, the scripts and the command line'],
], [1900, 7400])]);
body.push(P('', { spacing: { after: 140 } }));
T('It is deliberately conservative, because it exists to be pointed at production manifests by people who may not have written them. That is the reason report is the default mode, the reason platform components are never patched, and the reason nothing it produces is ever applied on your behalf.');
push(Note('info', 'On DJ\'s KYSA, and the eventual merge', [
  'KYSA is a separate tool in a separate repository. It judges against CIS, NSA and CISA, NIST and STIG directly rather than against ACS policy, it has its own engine and its own catalogue, and it is the one wired into CI.',
  'The two are intended to merge into one project. They have not merged yet, so nothing in this document describes KYSA, and nothing in this repository contains it. When the merge happens, the shared parts, the scoring model, the vendoring strategy, the waiver format and the CI templates, will be documented here in one place rather than described twice.',
  'Until then, a reader following this document should be able to find every file it mentions in this repository. That is the test this document is written against.']));

// 2
H1('2. Repository layout');
push([Tbl(['Path', 'Role'], [
  ['acs_policies.js', 'Engine. Twenty policies, alert import and matching, the vulnerability export parser and CVE model, violation fix routing and patch drafting, diff, and merge patch builder. Policy logic lives here and nowhere else, so the page, the CLI and the tests cannot disagree.'],
  ['dj_acs_auditor.html', 'The whole browser surface. An Audit tab that reads, scores and reports, and a Remediate tab that edits your YAML with preview, confirm, step through and undo. One mode gate governs both.'],
  ['vendor/', 'Identical js-yaml and JSZip builds.'],
  ['acs_cli.js', 'Headless runner. Same engine, same output, no cluster access.'],
  ['acs.sh, acs.ps1, acs.cmd', 'Wrappers so the switches are identical across Bash, PowerShell and Command Prompt.'],
  ['scripts/', 'The ACS pull scripts. Preflight, full pull, an oc port forward variant, and PowerShell and SSH equivalents.'],
  ['test/*.cjs', 'smoke, fixes, import, flow, live, vuln, hardening, cli, kubejson, platform, exports, cli_violations, scripts, posture_platform, version. page.cjs needs jsdom and skips cleanly without it.'],
  ['test/run_tests.js', 'Runner. Aggregates every suite and prints one total.'],
  ['docs/', 'Figure generators and the two Word documents.'],
], [3600, 5700])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('warn', 'Keep the published tree clean', [
  'A working folder accumulates things that should never reach a published repository: duplicate copies of a release, dated zip archives, older version bundles, and macOS .DS_Store files.',
  'The duplicate copy is the dangerous one. A maintainer editing the wrong copy does not get an error, they get a change that silently does nothing, and they lose an afternoon before they work out why.',
  'Keep .gitignore covering .DS_Store, __pycache__, *.zip and any acs_audit_* output directory, and run git status --short before you push rather than after.']))

// 3

// 3
H1('3. The one architectural rule');
T('Policy logic lives in exactly one file. Every graphical surface, every command line entry point, and every test loads acs_policies.js. Nothing reimplements a check.');
push(Fig(F('fig5_architecture.png'), 'Figure 5. One engine, with every surface reading from it.', 640));
T('This is not a style preference. The failure mode it prevents is specific and expensive: the page reports a finding, the CLI in the pipeline does not, and nobody notices for months because the two were never compared against each other. When the engine is the only place a check exists, that disagreement cannot happen.');
push(Note('warn', 'The merge of the two pages in 1.2.0, and what it was actually about', [
  'Until 1.2.0 there were two HTML files. Eighteen function names existed in both, ten of them byte identical, kept in step by hand.',
  'That is not a tidiness problem, it is a correctness one. A fix would land on one surface and not the other, and nothing in the suite could see it because each page was tested against its own copy. It happened more than once.',
  'Merging them surfaced three controls that had markup and no listener: four CVE filter checkboxes read inside a render function but never bound to a change event, and two download buttons referenced nowhere in the script at all. Engine tests cannot catch that, because they call the render function directly, which is exactly the step a missing listener skips.',
  'If you add a third surface, add it to test/page.cjs in the same commit, and drive the controls rather than calling the renderers.']));

H2('The corollary for you');
push([Bul('Never copy a check into a second file to make something work. If a surface cannot reach the engine, fix the loading, not the logic.'),
      Bul('The ACS engine is a dual mode module: it attaches to the browser global and exports through CommonJS. That is what lets the same file serve two HTML pages and five test suites. Preserve both paths when you edit it.'),
      Bul('When you change a weight, a severity, or a check, every surface changes at once. That is the point, and it means the test suite is your only real safety net. See section 4.')]);

// 4

// 4
H1('4. The fix mode gate');
T('One mode concept, defined once in acs_policies.js, enforced identically by the command line, both HTML pages, and every artifact any of them writes. If you add a surface that can produce something applyable, it goes through this or it does not ship.');
push([Tbl(['Mode', 'writes', 'patches', 'edits', 'Meaning'], [
  ['report', 'false', 'false', 'false', 'Analysis only. Nothing that could be applied leaves the process.'],
  ['manual', 'true', 'true', 'false', 'Compute the fix, express it as a patch, modify nothing.'],
  ['auto', 'true', 'true', 'true', 'Compute the fix and write the corrected YAML.'],
], [1200, 1100, 1100, 900, 5000])]);
body.push(P('', { spacing: { after: 140 } }));
H2('The API');
push(Code(['resolveFixMode(v)        // "" or undefined -> "report"; unknown -> THROWS',
  'modeAllows(mode, what)   // what: "writes" | "patches" | "edits"',
  'modeBanner(mode)         // one line to stamp on any artifact',
  'FIX_MODES, FIX_MODE_INFO']));
push(Note('crit', 'The invariants, and why each one exists', [
  'report is the default, so the safe state is what you get by doing nothing rather than what you get by remembering a flag.',
  'An unknown mode throws rather than defaulting. A typo that silently lands somebody in a writing mode is precisely the failure this control exists to prevent, so there is no permissive fall back anywhere in the resolution path.',
  'The mode is never inferred from another option. Asking for patches does not imply manual. If you find yourself writing code that upgrades the mode based on what was requested, stop: that is the control being dismantled from the inside.',
  'Every artifact carries modeBanner(). A reviewer holding a patch should never have to ask which path produced it.']));
H2('Enforcement on the page');
T('Gate the handler, not only the button. A disabled attribute is a hint about state; it is trivially bypassed from a console and it is not a control. On the Remediate tab every write path calls requireMode() as its first statement, and test/page.cjs proves it by invoking startStepping() and reviewApplyAll() directly in report mode and asserting the history is unchanged.');
push(Note('warn', 'A defect worth knowing about, because it will recur', [
  'render() and applyMode() both set the disabled property on the step and apply buttons, and render() ran last, so it silently undid the mode restriction. The handlers still refused, so nothing could actually be written, but the buttons looked live in report mode.',
  'A control that is enforced but not visible teaches people the wrong model of the tool, and the wrong model is what they act on under pressure. There is now one expression per button that combines both conditions. If you add a button, make one place own its enabled state.']));
H2('Enforcement in the command line');
T('A run that quietly does less than you asked is as bad as one that quietly does more: in both cases the operator\'s mental model and the tool\'s behaviour have diverged and nobody said so. So asking for something applyable in report mode exits 2 with an explanation rather than being downgraded, and an unknown mode exits 2 rather than being interpreted.');
push(Note('warn', 'The bug this caused the first time round', [
  'Manual mode initially emitted zero patches. Patches were built from the applied list, which was only populated when the auto path ran, so choosing manual produced nothing at all and said nothing about it.',
  'Manual and auto must COMPUTE the same fix. They differ only in what they do with the result. If you touch this, run the CLI test that asserts both modes report the same fix count.']));

// 5
H1('5. The two ACS data planes');
T('This is the part of the ACS API that costs maintainers the most time, so it gets its own section. Everything below was verified against the upstream StackRox protocol definitions, not inferred from behaviour.');
push(Fig(F('fig7_two_data_planes.png'), 'Figure 7. Two stores behind one product, two endpoints, two document shapes.', 640));
H2('Plane one: policy violations');
push([Tbl(['Endpoint', 'Returns', 'What bites you'], [
  ['GET /v1/alerts', 'storage.ListAlert', 'No violations[] at all. Namespace and cluster live under commonEntityInfo, not deployment. Server side page size applies.'],
  ['GET /v1/alerts/{id}', 'storage.Alert', 'The only place violations[] is populated. One call per alert.'],
], [2500, 1900, 4900])]);
body.push(P('', { spacing: { after: 140 } }));
T('The engine lists, then hydrates each alert from the per id endpoint. Hydration is sequential and capped at 200 by default. That cap is deliberate: firing a thousand parallel requests at Central from a browser tab is a reliable way to get rate limited or to look like an attack, and Central is a security control you do not want to destabilise for the sake of a report.');
T('The query builder defaults to Violation State:ACTIVE so the tool agrees with the ACS console. An operator who sees more rows here than in the console will assume the tool is wrong, and being right in a way nobody believes is not useful.');
push(Note('crit', 'The defect this fixed, so nobody reintroduces it', [
  'The original import read a.deployment.namespace. That field exists on the full Alert and does not exist on a ListAlert, so every row from GET /v1/alerts came back with namespace "unknown" and correlation silently failed. Combined with the missing violations array, the result was a page that looked like it had found nothing.',
  'test/vuln.cjs holds four tests that fail against the old entity resolution and pass against the current one. If you touch alertEntity, run them and confirm they still discriminate.']));
H2('Plane two: image vulnerabilities');
push([Tbl(['Endpoint', 'Returns', 'What bites you'], [
  ['GET /v1/export/vuln-mgmt/workloads', 'Streamed NDJSON, one {"result": {...}} per line', 'res.json() fails on it, it is not one document. Token needs read on Image AND Deployment, not just Alert.'],
], [3100, 2600, 3600])]);
body.push(P('', { spacing: { after: 140 } }));
T('CVEs live at images[].scan.components[].vulns[]. The parser accepts NDJSON, a JSON array from jq -s, and a single object, and it counts unparseable lines rather than discarding them. It also surfaces a server side {"error": ...} line rather than treating it as no data.');
H2('Field references, all verified upstream');
push([Tbl(['Proto file', 'What it defines'], [
  ['api/v1/alert_service.proto', 'ListAlertsRequest with query and pagination, ListAlert versus Alert.'],
  ['storage/alert.proto', 'The full Alert, the Violation message, ViolationState, commonEntityInfo.'],
  ['api/v1/vuln_mgmt_service.proto', 'The export endpoint, the query syntax, and the result envelope.'],
  ['storage/image.proto', 'ImageScan and EmbeddedImageScanComponent.'],
  ['storage/vulnerability.proto', 'EmbeddedVulnerability: cve, cvss, nvdCvss, epss, cisaKev, exploit, advisory, fixedBy, state.'],
  ['storage/cve.proto', 'VulnerabilitySeverity and VulnerabilityState enumerations, EPSS and Exploit messages.'],
], [3200, 6100])]);
body.push(P('', { spacing: { after: 140 } }));
T('Source: github.com/stackrox/stackrox. These change between releases. When you upgrade ACS, diff them before assuming the parser still reads what you think it reads.');
H2('Why CVE data is kept out of the posture score');
T('The configuration posture score has a fixed denominator derived from what was scanned, which is the property that makes the before and after numbers comparable and survives a rescan. CVE counts change every time a vulnerability feed updates, with nothing in the manifests changing at all.');
T('Folding them together would produce a score that moves for reasons the operator did not cause and cannot act on, and the first person to notice would rightly stop trusting the number. The tool reports two things separately: a configuration posture score, and a vulnerability picture whose only headline metric is the fixable share, because that means exactly one thing and cannot drift.');
H2('The vulnerability priority model');
T('Priority runs 0 to 15, not 0 to 10. Clamping to 10 lands every critical on exactly 10 and destroys ordering at the top of the queue, which is where ordering matters most. The constant is PRIORITY_MAX and the components are CVSS, plus 2.0 for CISA KEV, plus up to 1.5 for EPSS, plus 1.0 for a published fix, plus 0.5 for running pods. Every adjustment is pushed onto reasons[] and rendered in the UI.');
push(Note('warn', 'If you change a weight, change the documentation in the same commit', [
  'The value of this score is entirely that it is auditable. A weight nobody can find the justification for is a magic number, and magic numbers in security tooling get quoted in reports and then defended by people who cannot explain them.']));

// 5
H1('6. Running the test suites');
push(Code(['node test/run_tests.js', '',
  '# the whole page tests need jsdom, and skip cleanly without it',
  'npm install jsdom && node test/run_tests.js']));
T('No install, no test framework, no network for the engine suites. The runner is plain Node and prints a pass and fail count per suite plus a total.');
H2('What the suites actually assert');
push([Tbl(['Suite', 'Count', 'Covers'], [
  ['smoke.cjs', '35', 'Catalogue integrity, unique ids, valid severities, every policy has a check, scanning and posture maths.'],
  ['fixes.cjs', '30', 'Each fix produces valid YAML, changes only what it should, and is idempotent when reapplied.'],
  ['import.cjs', '16', 'All three ACS export shapes parse, renamed policies still match, unmatched violations surface rather than vanish.'],
  ['flow.cjs', '36', 'Preview mutates nothing, undo restores byte for byte, merge patches stay minimal, diffs are correct.'],
  ['live.cjs', '32', 'URL normalising, actionable error classification, command generation, live object sanitising.'],
  ['vuln.cjs', '99', 'NDJSON parsing, CVE deduplication, priority reasoning, manifest correlation and image drift.'],
  ['hardening.cjs', '36', 'URL scheme allowlisting, and the standing guarantees: no eval, no credential field, no network call in either page, no write method anywhere.'],
  ['cli.cjs', '95', 'The whole argument surface, the mode gate, exit codes, and that --fail-on blocks on the right severities.'],
  ['kubejson.cjs', '38', 'oc get -o json in every shape it comes in, and that server side fields are stripped before scanning.'],
  ['platform.cjs', '60', 'Platform detection, all alert states, and fixing a violation with no manifest in hand.'],
  ['exports.cjs', '50', 'All six files acs_pull_all.sh writes, merging rather than overwriting, and that an unloadable file is told what it is.'],
  ['scripts.cjs', '21', 'The shell scripts agree with each other: same trust source, no token over an unverified connection, insecure never the default.'],
  ['posture_platform.cjs', '35', 'No posture score over zero manifests, and the per object platform override.'],
  ['cli_violations.cjs', '29', 'The CLI run as a real process, inspecting what lands on disk. Chiefly that report mode leaves nothing applyable behind.'],
], [1900, 900, 6500])]);
body.push(P('', { spacing: { after: 140 } }));
H2('The optional whole page tests');
T('test/page.cjs loads each HTML file from disk in a real DOM, with the actual script tags resolving to the actual files in document order, then drives it: drops an export, checks the panel unhides, clicks the filters, expands a violation row, drafts the fixes and inspects the YAML that would have been downloaded, and walks the image replacement dialog through preview, confirm and undo. 88 assertions.');
T('It catches a class of defect the engine tests structurally cannot see. An element id that does not exist, a handler never bound, a panel that never unhides, a filter wired to the wrong checkbox. The engine can be perfect and the page still show nothing.');
T('This is not hypothetical. The Download button under the violation fix panel shipped once with no click handler at all. Every engine test passed, the bundle it would have produced was correct, and pressing the button did nothing. Only a page test can see that.');
push(Note('info', 'jsdom is the one thing here that needs a package manager, so it is optional', [
  'Without jsdom the suite prints a skip notice and reports zero, it does not fail. The tool itself must keep working on a disconnected machine with no npm, and a test dependency that breaks that would defeat the point of vendoring everything else.',
  'Run them where you can: npm install jsdom, then node test/run_tests.js. Do it before any release that touched a page.']));
push(Note('crit', 'A test that cannot fail is worse than no test', [
  'During development a regression test for the posture denominator passed against both the buggy engine and the fixed one, because the fixture got everything fixed and both paths reached 100. The error cancelled itself out.',
  'The fix was to build a fixture with a residual manual finding, so the denominator error becomes visible. The rebuilt test now fails at 78 of 80 on the old engine and passes at 80 of 80 on the current one.',
  'When you write a regression test, check out the broken behaviour and prove the test fails against it. A test you never saw fail is a test you have no evidence about.']));
H2('A related trap');
T('One early test set no global YAML parser, so parsing silently returned zero documents, nothing was scanned, and the score came back a clean and completely fictional 100. Any test that scans should also assert that the fixture actually parsed into the expected number of documents. Assert the setup, not just the result.');

// 5
H1('7. Adding or changing a policy');
H2('Anatomy of an entry');
push(Code([
  '{',
  '  id: "ACS.021",',
  '  acsPolicy: "Exact ACS default policy name",',
  '  acsCriteria: "The ACS policy criteria field this mirrors",',
  '  categories: ["Privileges"],',
  '  lifecycleStages: ["DEPLOY"],',
  '  severity: "HIGH_SEVERITY",',
  '  score: 7.8,',
  '  vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",',
  '  cis: "5.2.x", nist: "AC-6, CM-7", pss: "Restricted",',
  '  stig: "Control reference, verify against current DISA release",',
  '  description: "What is wrong, in one sentence",',
  '  rationale: "Why it matters, in the operator’s terms",',
  '  remediation: "What to do about it",',
  '  fixKind: "auto",',
  '  check(doc) { /* return the offending objects, or an empty list */ },',
  '  fix(doc)   { /* mutate doc in place, only the offending fields */ },',
  '}']));
H2('Choosing fixKind, which is the decision that matters');
push([Tbl(['fixKind', 'Use when', 'Test obligation'], [
  ['auto', 'There is exactly one correct change and no plausible downside.', 'Prove the fix is idempotent and touches nothing else.'],
  ['generate', 'The right answer is a new object rather than an edit.', 'Prove the generated object is valid and does not break a working cluster on apply.'],
  ['manual', 'The correct answer depends on context the scanner cannot see.', 'Prove the finding is reported with full rationale and that no file is modified.'],
], [1400, 4200, 3700])]);
body.push(P('', { spacing: { after: 140 } }));
T('When in doubt, classify as manual. An over eager auto fix that breaks a workload costs you the entire tool, because the team turns it off and a switched off scanner protects nobody. A conservative manual classification costs a person five minutes.');
H2('Checklist for a new policy');
push(NumList([
  'Add the entry to the engine file. One place only.',
  'Add a fixture that trips it and a fixture that does not.',
  'Add a test asserting the check fires correctly on both.',
  'If it has a fix, add a test asserting valid YAML out, idempotency, and no collateral change.',
  'Confirm the posture denominator grows by the right amount. A new policy adds checks to the total whether or not anything fails it.',
  'Run the full suite. A new policy that leaves the total unchanged means it never entered the denominator, which is the exact defect described in section 6.',
  'Add the citations. A finding without a standard behind it is an opinion.']));
H2('Keeping the ACS alias table current');
T('ACS renames default policies between releases. The importer holds an alias table so a violation exported from an older or newer ACS still matches. When you find a name that fails to match, add it there rather than loosening the token scoring threshold. Loosening the threshold buys one match and costs you precision on every other policy.');

// 6
H1('8. Keeping the standards current');
T('Manifests can sit untouched for six months while the ground shifts under them. A new STIG release changes a requirement, guidance gets revised, a new class of weakness gets published. Nothing in the repository changed, but what counts as secure did. Catching that is the difference between a security check and a security program.');
push(Fig(F('fig6_maintenance.png'), 'Figure 6. The maintenance cycle, the gates before release, and what rots if nobody looks.', 640));
H2('What keeps this tool current, and what does not');
T('The ACS Auditor has no standards watcher of its own, and does not need one, because its policy set mirrors the ACS defaults rather than tracking the standards directly. The thing that goes stale here is the mirror, not the standards.');
push(Note('warn', 'The maintenance task that actually matters for this tool', [
  'When you upgrade ACS, diff its default policies against acs_policies.js and reconcile. Red Hat adds policies, renames them, and changes default severities between releases.',
  'A renamed policy does not break loudly. The importer falls back through the alias table and then token scoring, and a violation it still cannot place is reported as unmatched rather than dropped. Watch the unmatched count after an ACS upgrade: a jump in it is the signal that the catalogue has drifted from your ACS version.',
  'Most teams also tune the defaults. A tuned policy that no longer matches the shipped name is indistinguishable from a renamed one, and both are fixed the same way: add the name to the alias table.']));
H2('The citations, and how far to trust them');
T('Every policy carries CIS, NIST 800-53 Rev 5, Pod Security Standards and DISA STIG references. Those are mapping aids written to help you find the control, not authoritative extracts.');
push([Bul('Verify STIG ids against the current DISA release at public.cyber.mil before citing them in an accreditation package. Ids move between releases.'),
      Bul('NIST control families are stable, but the specific enhancement cited may not be the one your assessor expects. Treat it as a starting point for the conversation, not the end of it.'),
      Bul('If you change a citation, change it in acs_policies.js. It appears in the page, the report, the JSON and the SARIF from that one place.')]);
H2('Cadence');
T('Tie the review to your ACS upgrade cycle rather than to the calendar. There is no value in reviewing the catalogue on a schedule when nothing upstream has moved, and considerable value in reviewing it the week ACS changes underneath you.');

// 7
H1('9. Vendored dependencies');
T('Both toolsets commit their dependencies. There are exactly two, both MIT licensed, both unmodified upstream builds.');
push([Tbl(['File', 'Library', 'Version', 'Bytes', 'SHA-256'], [
  ['js-yaml.min.js', 'js-yaml', '4.1.0', '39,430', '45dc3dd03dc07a06705a2c2989b8c7f709013f04bd5386e3279d4e447f07ebd7'],
  ['jszip.min.js', 'JSZip', '3.10.1', '97,630', 'acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e'],
], [1900, 1100, 900, 900, 4500])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Why vendored and not installed');
T('Installing a package manager is not an option in many of the environments these tools are aimed at. Committing the files removes the question entirely: a machine with no route to the internet, no npm, and no proxy runs the tool identically to a fully connected one. It also gives you a fixed artifact to submit for software approval, which is the actual blocker in federal environments.');
H2('Why js-yaml rather than a hand written parser');
T('YAML is deceptively hard. Anchors, aliases, block scalars, implicit typing, and the YAML 1.1 boolean tokens y, yes, on, and off all change meaning in ways a homegrown parser gets subtly wrong. A scanner that misparses one edge case silently misses a real finding, which is worse than not scanning at all. The UMD build is one self contained file, and the same copy serves the browser and the CLI, so the two provably run identical YAML semantics.');
H2('Refresh procedure');
push(NumList([
  'On a connected machine, fetch from unpkg, which serves the exact published npm package contents.',
  'Verify size and SHA-256 against the table above. Update the table in vendor/README.md if you are deliberately moving versions.',
  'Run a functional check, not just a hash check.',
  'Run both test suites before committing the new file.',
  'Record the upstream project, version, hash, and MIT license for your software approval record.']));
push(Code(['# verify the hash',
  'shasum -a 256 vendor/js-yaml.min.js',
  '',
  '# prove it actually parses, which a hash cannot tell you',
  'node -e "const y = require(\'./vendor/js-yaml.min.js\');',
  '        const n = y.loadAll(\'kind: A\\n---\\nkind: B\\n\').length;',
  '        console.log(n === 2 ? \'OK\' : \'FAILED\')"']));
T('Do this by hand for now; there is no fetch helper in this repository. If unpkg is blocked, cdnjs mirrors both libraries, but its js-yaml build may differ, in which case verify functionally rather than by hash: parse a manifest with an anchor, a block scalar and a YAML 1.1 boolean, and confirm the result matches what the committed build produced.');

// 8
H1('10. Waivers and accepted risk');
T('Sometimes a finding is real and cannot be fixed now. Contract obligations, legacy systems, and migration timelines are legitimate reasons. Pretending the finding does not exist is not.');
push(Code(['waivers:',
  '  - id: KSA.011',
  '    paths: ["manifests/legacy/**"]',
  '    justification: >',
  '      Legacy log shipper needs the node log directory. Replacement tracked',
  '      in PLAT-882, scheduled Q4. Mount is read only, node pool is isolated.',
  '    approver: "dj"',
  '    ticket: "PLAT-882"',
  '    expires: "2026-12-31"']));
H2('The expiry field is not optional, and that is deliberate');
T('On the expiry date the finding returns automatically, the build gate counts it again, and the summary flags it as expired. Security exceptions granted without a deadline become permanent, and years later nobody remembers why the exception exists or whether the reason still applies. A date forces a fresh decision by someone who is still around to make it.');
T('Waived findings still appear in the report, marked as waived with the justification, so an auditor sees exactly what was accepted and why. They do not lower the score, because a documented decision was made. Expired ones do.');
H2('Per resource waivers');
T('The ACS Auditor does not read a waiver file today. The exception mechanism that applies to it is the one in ACS itself: a policy exception with an expiry, which the tool then sees reflected in the export as a deferred violation and reports as accepted rather than active. Use that rather than inventing a local override, because an exception ACS does not know about does not stop ACS alerting on it.');
push(Note('warn', 'Review waivers on a schedule', [
  'Nobody notices a waiver expiring unless someone looks. Put a recurring calendar item against the waiver file. The most common failure of this entire model is not a bad waiver, it is a good waiver nobody revisited.']));

// 9
H1('11. CI integration');
T('There are no CI templates in this repository yet. The CLI is built to be driven from one, and this is what a job needs to do.');
push(Code(['- name: ACS manifest audit',
  '  run: |',
  '    node acs_cli.js --path ./manifests \\',
  '      --sarif --json \\',
  '      --fail-on high \\',
  '      --out ./acs_out',
  '',
  '- name: Publish to the security tab',
  '  uses: github/codeql-action/upload-sarif@v3',
  '  with:',
  '    sarif_file: ./acs_out/acs_findings.sarif']));
T('SARIF is the reason this works without a bespoke integration. GitHub and GitLab both read it natively, so findings land in the security tab with file and line annotations rather than buried in log output.');
H2('Rolling it out without the team switching it off');
T('Start with no gate. Do not set --fail-on on day one. If the first run blocks every merge, the tool gets disabled within a week and you have made things worse than before you installed it. Report only, publish to the security tab so the backlog is visible, work it down, then set --fail-on high so new problems cannot get in while you finish clearing the old ones.');
push(Note('info', 'What a pipeline should and should not be allowed to do', [
  'Run it in report mode in CI. That is the default, so a job that forgets to say so gets the safe behaviour rather than the permissive one.',
  'Do not run --mode auto --in-place in a pipeline. The mode gate exists so that writing is a decision a person makes, and a pipeline is not a person. If you want the fixes as an artifact, use --mode manual --patches and let a human open the pull request.',
  'The CLI needs no credential. It reads files. Everything that touches ACS happens in the pull scripts, which run before the pipeline or beside it, and those take a read only token.']));

// 10
H1('12. Release procedure');
push(NumList([
  'Run both test suites. A red suite is a blocked release, not a warning.',
  'Confirm the version constant in the HTML matches package.json and the CHANGELOG entry.',
  'Confirm the vendored library hashes still match vendor/README.md.',
  'Grep the shipped files for exec, eval, and the Function constructor. There should be no matches.',
  'Confirm report mode still produces nothing applyable, on both tabs and the command line. This is the control most likely to be weakened by accident while adding a feature.',
  'Install jsdom and run the whole page tests. A page change that passes the engine tests and breaks the UI is invisible otherwise.',
  'Run the sample manifest set, apply all fixes, rescan, and confirm the projected posture equals the actual result.',
  'Update CHANGELOG.md.',
  'Run the cleanup script, then tag and publish.']));
H2('The version stamp is not cosmetic');
T('The version constant in the auditor HTML stamps every generated report, every commit message, and every readme_fix.txt. It drifted once during development: the CLI and package.json said 2.0 while the HTML still said 1.4, which means every report produced in that window was misdated evidence. Check it as part of the release, not after someone notices.');
H2('bash 3.2 compatibility');
push(Note('warn', 'macOS ships bash 3.2, and that is not going to change', [
  'Apple froze bash at 3.2 over the GPLv3 licence change, so anything bash 4 and later is unavailable on a default macOS shell. mapfile is bash 4. So are associative arrays and several parameter expansions.',
  'cleanup_release.sh originally used mapfile and failed on macOS with command not found. It failed before deleting anything, so no damage, but a cleanup script that half runs is a real hazard. It was rewritten with a while IFS= read -r loop and a temp file, no arrays for dynamic lists.',
  'Test release scripts on the oldest shell any maintainer might have, or invoke a modern bash explicitly. Do not assume the shell on your machine is the shell on theirs.']));

// 11
H1('13. Two defects worth keeping in mind');
T('Both were found by a user rather than by the suite, and both are the kind of thing a maintainer can reintroduce without noticing.');
H2('A score with an empty denominator');
push(Note('crit', 'The tool reported 100 out of 100, Grade A, on a cluster it had not measured', [
  'The posture denominator comes from what was scanned. Load an ACS export and no YAML and that denominator is empty, so the arithmetic returns a perfect score.',
  'The CLI already refused to print it. Neither page did, so an operator working in the browser saw a green A. That is the most misleading output this tool is capable of, and it existed for several releases.',
  'The guard is now in all three surfaces, and test/posture_platform.cjs asserts it runs BEFORE the score is computed rather than after. When you add a fourth surface, add the guard with it.',
  'The first version of the guard returned early and hid the violations panel along with the score, which turned "refuse to show a meaningless number" into "hide what the operator came for". The page tests caught that one.']));
H2('A refusal built on a guess that did not say it was guessing');
T('Violations on platform components are refused, which is correct: the owning operator reverts manual edits. But when ACS does not send platformComponent, the classification falls back to matching the namespace, and that guess is wrong in both directions.');
T('A privilege escalation finding on a workload a team owned, in a namespace that happened to match, was refused permanently with no way to say otherwise. The policy existed, was auto fixable and had a patch template. Nothing was missing except an admission that the tool was guessing.');
push([Bul('rec.platformSource records which signal decided: acs or namespace. Preserve it if you touch the import.'),
      Bul('violationFixability takes an options object with overridePlatform. buildViolationPatch re-derives fixability, so it must be passed the same options: not doing so was a real bug in which the override silently produced nothing.'),
      Bul('An override is a Set of violation keys, never a boolean. Per object, never global.')]);

H1('14. Security posture of the tooling itself');
T('A security tool is a target and a trust anchor. These are the properties that have been verified, and the ones you must not regress.');
push([Tbl(['Property', 'How it is enforced'], [
  ['No remediation ever executes a command', 'No exec, eval, or Function constructor exists in any shipped ACS file. Verified by grep. Fixes are pure text edits to YAML.'],
  ['The one process the tool ever spawns', 'acs_cli.js --in-place --mode auto runs git status --porcelain through execFileSync with an argument array and no shell, and refuses to overwrite your files if the tree is dirty or is not a repository. It reads, and it remediates nothing. Named here so the guarantee above is exact rather than approximately true.'],
  ['No credential can enter a browser tab', 'The in browser connectors were removed rather than hardened. Neither page contains a password field, a token identifier, a URL field, or a fetch call. The test suite asserts their absence, which is a stronger property than the token handling rules it replaced. The only browser storage used anywhere is the light or dark theme preference.'],
  ['Every cluster call is a GET', 'The engine connectors, which now serve only the scripts and the CLI, issue no write method. There is no code path anywhere in the tool that writes to a cluster.'],
  ['The token stays out of ps and out of history', 'The pull scripts read it from the environment or prompt without echo, never as a command argument. TLS is verified by default and --cacert is supported for a private CA.'],
  ['Nothing applyable is produced without an explicit mode', 'report is the default everywhere, unknown modes throw rather than defaulting, and the mode gates the handlers rather than only the buttons. See section 4.'],
  ['No CVE is ever auto remediated', 'ACS reports fixed package versions, not fixed image tags. applyImagePin only ever writes a value the operator typed, and it goes through the same preview, confirm and undo path as every other fix.'],
  ['Hydration is rate limited by construction', 'Alert detail is fetched sequentially and capped at 200. Central is a security control; a report is not worth destabilising it.'],
  ['No telemetry, no phone home', 'The browser pages make no outbound request at all. There is no fetch call in either of them.'],
  ['No network at rest', 'Dependencies are vendored. The page loads nothing from a CDN.'],
  ['Live objects are sanitised', 'Server side fields, ownerReferences, status, and last applied configuration are stripped before an object is scanned or emitted.'],
], [3000, 6300])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Threat model, stated plainly');
push([Bul('Untrusted input is the YAML and the ACS export a user loads. Both are parsed by js-yaml, never evaluated. A malicious manifest can produce a wrong finding. It cannot execute anything.'),
      Bul('There is no longer a credential exposure window in the browser, because there is no longer a credential in the browser. The window moved to the shell, where a short lived least privilege token is read from the environment, kept out of ps and out of history, and used for GETs only. This is a smaller window in a place with better controls, which is the point of moving it.'),
      Bul('The supply chain risk is the two vendored libraries. Mitigate by pinning, hashing, and verifying functionally on refresh.'),
      Bul('The most realistic failure is not an attack. It is a wrong finding trusted without review, or a stale policy set that quietly stops catching something. That is what sections 6 and 8 exist to prevent.')]);

// 12
H1('15. Running where Node cannot be installed');
T('A hardened host in a controlled enclave often has curl and jq and no route to install anything else. That machine is a first class target for this tool, not an edge case, so the split is deliberate.');
push([Tbl(['Surface', 'Needs', 'Covers'], [
  ['dj_acs_auditor.html', 'A browser', 'Everything: posture, findings, violations, fix routes, drafted YAML, the HTML report and the JSON export'],
  ['scripts/*.sh', 'bash, curl, jq', 'Getting data out of ACS'],
  ['scripts/acs_summary.sh', 'jq', 'A markdown summary of what ACS reported. Counts only'],
  ['acs_cli.js', 'Node 18+, or a container', 'The same engine headless, for CI'],
], [2400, 2000, 4900])]);
body.push(P('', { spacing: { after: 140 } }));
H2('What acs_summary.sh deliberately does not do');
T('It does not compute a posture score and it does not draft fixes. Both require the policy engine, which is acs_policies.js, which needs a JavaScript runtime.');
T('The temptation when writing that script is to approximate: count violations by severity, weight them, print a number. Do not. A posture score in this tool is passed weight over total applicable weight, and the denominator is derived from what was scanned. A summary of an ACS export has no scanned manifests, so there is no denominator, and any number produced would be a different measurement wearing the same name. That is exactly the defect fixed in 1.1.0, where a score over an empty scan read as 100 out of 100, Grade A.');
push(Note('crit', 'If you extend the summary script', [
  'Keep it to counts of what ACS reported. Nothing inferred, nothing weighted, nothing called a score.',
  'test/scripts.cjs asserts that its output contains no grade and no score, and that it states what it cannot tell you. Those assertions are the guard rail; do not relax them to make a nicer looking report.']));

H1('16. Maintainer troubleshooting');
push([Tbl(['Symptom', 'Diagnosis'], [
  ['mapfile: command not found', 'bash 3.2 on macOS. See section 10.'],
  ['A test passes against known broken code', 'The fixture cancels the error out. Rebuild it so the defect is observable, then confirm the test fails against the old code.'],
  ['Score comes back a clean 100 in a test', 'Suspect the parser was never wired up and nothing was scanned. Assert the document count in the fixture.'],
  ['git add fails or stages the wrong files', 'Scan paths are relative to the scan root while git runs at the repository root. Rebase with path.relative before staging.'],
  ['A merge patch reverts an unrelated field', 'The container array was diffed positionally instead of keyed on name. Key on name.'],
  ['ACS violations stop matching after an upgrade', 'ACS renamed a default policy. Add the new name to the alias table. Do not lower the scoring threshold.'],
  ['Alerts arrive with no violation text', 'You read ListAlert and stopped. Hydrate from /v1/alerts/{id}. See section 4.'],
  ['Namespace is unknown on every imported alert', 'Something is reading deployment.namespace again. It is on commonEntityInfo for a ListAlert. Four tests in vuln.cjs guard this.'],
  ['res.json() throws on the vulnerability export', 'It streams NDJSON, it is not a single JSON document. Read text and parse per line.'],
  ['403 on the export, 200 on alerts, same token', 'The export needs read on Image and Deployment. Alert scope alone is not enough.'],
  ['CVE counts disagree with the ACS console', 'Check whether the console view includes deferred and false positive CVEs. This tool excludes them from active counts by design and reports them separately.'],
  ['Projected posture does not survive a rescan', 'The denominator is being derived from findings rather than from what was scanned. This is the defect that produced 60 against an actual 57.'],
  ['EPERM on a path that clearly exists', 'macOS privacy protection, not a missing file. EPERM means it exists and access was denied. Grant the folder or move the work.'],
  ['An edit to a file appears to do nothing', 'Check for a duplicate copy of the tree in your working folder. Editing the wrong copy produces no error, just a change with no effect. Delete duplicates rather than working around them.'],
], [3200, 6100])]);

// 13
H1('17. Ownership and escalation');
T('Both toolsets are maintained by DJ. Issues, policy suggestions, and pull requests: github.com/djkidnyce');
H2('What to include in a report');
push([Bul('For a scoring or matching problem: the manifest set, and the ACS export if you can share it. A match failure cannot be reproduced without both.'),
      Bul('For a fix that produced wrong YAML: the input file, the policy id, and the output. The fix functions are small and this is usually a five minute diagnosis with those three things.'),
      Bul('For anything involving a token or a credential: redact it before you send anything. If a token appeared anywhere it should not have, rotate it first and report second.')]);
H2('What good maintenance looks like in practice');
T('Weekly source watch, monthly waiver review, a full test run before every release, and a diff of the ACS default policies against the engine every time ACS is upgraded. None of that is difficult. All of it is the difference between a tool people trust and a tool people quietly stop running.');

const doc = new Document({
  numbering: NUMBERING,
  styles: { default: {
    document: { run: { font: 'Calibri', size: 21, color: '1C2430' }, paragraph: { spacing: { line: 276 } } },
    heading1: { run: { font: 'Calibri', size: 32, bold: true, color: '1C2430' },
      paragraph: { spacing: { before: 320, after: 140 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: ACC } } } },
    heading2: { run: { font: 'Calibri', size: 25, bold: true, color: ACC },
      paragraph: { spacing: { before: 240, after: 90 } } },
  } },
  features: { updateFields: true },
  sections: [Object.assign({}, pageSetup('Administration Guide  |  ACS Auditor'),
    { children: [...title, ...toc, ...body] })],
});
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(__dirname + '/DJ_Security_Tooling_Administration_Guide.docx', b); console.log('WROTE', b.length, 'bytes'); });
