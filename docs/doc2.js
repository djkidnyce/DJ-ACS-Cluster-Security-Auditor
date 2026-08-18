const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
        PageBreak, BorderStyle, ShadingType } = require('docx');
const fs = require('fs');
const { P, Rich, Code, Note, Fig, Tbl, Bul, BulRich, NumList, NUMBERING, pageSetup,
        ACC, DARK, MUT, LINE } = require('./common.js');
const F = (n) => __dirname + '/figures/' + n;

const title = [
  new Paragraph({ spacing: { before: 2600, after: 0 },
    children: [new TextRun({ text: 'Administration Guide', bold: true, size: 60, color: DARK })] }),
  new Paragraph({ spacing: { after: 60 }, children: [new TextRun({
    text: "Managing and maintaining DJ's KYSA and DJ's ACS Auditor", size: 26, color: ACC })] }),
  new Paragraph({ spacing: { after: 400 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: ACC } }, children: [new TextRun({ text: '' })] }),
  P('For maintainers, platform engineers, and anyone who owns these tools', { bold: true, size: 24 }),
  P("Covers DJ's KYSA v2.0 and DJ's ACS Auditor v1.0", { size: 22, color: MUT }),
  P('Document date: 11 August 2026', { size: 22, color: MUT }),
  P('Author: DJ', { size: 22, color: MUT }),
  new Paragraph({ spacing: { before: 900 }, children: [new TextRun({ text: '' })] }),
  ...Note('info', 'Who this is for', [
    'This is the operator and maintainer document. It assumes you are comfortable with Node, git, YAML, and Kubernetes security concepts, and it skips the definitions.',
    'For a walkthrough of using the ACS tool, read the User Guide instead. For a non technical introduction to KYSA, read GETTING_STARTED.md in that repository.']),
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
T('Two related but independent toolsets. They share design principles, a scoring model, and a vendoring strategy. They do not share code, and neither depends on the other.');
push([Tbl(['', "DJ's KYSA v2.0", "DJ's ACS Auditor v1.0"], [
  ['Judges against', 'CIS, NSA and CISA, NIST 800-53 Rev 5, Pod Security Standards, DISA STIG', 'Red Hat ACS default Deploy stage policies, plus the same standards as citations'],
  ['Policy ids', 'KSA.001 upward, extensible by the catalog manager', 'ACS.001 through ACS.020, fixed set mirroring ACS defaults'],
  ['Engine file', 'ksa_catalog.js', 'acs_policies.js'],
  ['Surfaces', 'Browser GUI, CLI, catalog manager, pipeline console, source watcher', 'Auditor page, remediation page, live connect'],
  ['Writes to disk', 'Yes, via the CLI when you pass the fix switches', 'No. The browser hands you files to download'],
  ['Talks to a cluster', 'No', 'Read only GET, only when you ask. Three endpoints: OpenShift workloads, ACS alerts, ACS vulnerability export'],
  ['Tests', '80', '531 across the engine, the pages and the command line'],
], [1700, 3800, 3800])]);
body.push(P('', { spacing: { after: 140 } }));
T('KYSA is the broader tool and the one wired into CI. The ACS Auditor is narrower and deliberately more conservative, because it exists to be used against production manifests by people who may not have written them.');

// 2
H1('2. Repository layout');
H2("DJ's KYSA");
push([Tbl(['Path', 'Role'], [
  ['ksa_catalog.js', 'The policy catalogue and engine. Every finding, check, fix, weight, and citation lives here.'],
  ['dj_kysa_kubernetes_openshift_yaml_auditor.html', 'The browser GUI. Also holds the version constant that stamps every report.'],
  ['kysa_cli.js', 'Headless runner. Scan, fix, annotate, commit, push, open a pull request.'],
  ['kysa.ps1, kysa.cmd, kysa.sh', 'Shell wrappers. Identical switches across PowerShell, Command Prompt, and Bash.'],
  ['kysa_build_engine.js', 'Generates the engine module from the HTML so the GUI and CLI cannot drift apart.'],
  ['dj_kysa_catalog_manager.html', 'Authoring surface for new and deprecated KSA ids. Emits the catalogue and a README.'],
  ['dj_kysa_pipeline_console.html', 'Builds the exact CLI invocation from checkboxes. Useful for people who will not read switches.'],
  ['dj_kysa_source_watcher.py', 'Pulls current STIG, CVE, and guidance state. Standard library only.'],
  ['kysa_waivers.yaml', 'Accepted risk register. Every entry carries an expiry.'],
  ['ci_templates/', 'GitHub Actions and GitLab CI starting points.'],
  ['vendor/', 'js-yaml and JSZip, committed with hashes documented in vendor/README.md.'],
  ['test/run_tests.js', '80 tests.'],
  ['cleanup_release.sh, make_v2_release.sh, make_v2_release.ps1', 'Release helpers. Written for bash 3.2, see section 12.'],
], [3600, 5700])]);
body.push(P('', { spacing: { after: 140 } }));
H2("DJ's ACS Auditor");
push([Tbl(['Path', 'Role'], [
  ['acs_policies.js', 'Engine. Twenty policies, alert import and matching, the vulnerability export parser and CVE model, the live connectors, diff, and merge patch builder.'],
  ['dj_acs_auditor.html', 'Read only audit surface.'],
  ['dj_acs_remediation.html', 'Interactive fix surface with preview, confirm, step through, and undo.'],
  ['vendor/', 'Identical js-yaml and JSZip builds.'],
  ['test/*.cjs', 'smoke, fixes, import, flow, live, vuln, hardening, cli, kubejson, platform. page.cjs needs jsdom and skips cleanly without it.'],
  ['test/run_tests.js', 'Runner. Aggregates every suite and prints one total.'],
  ['docs/', 'Figure generators and the two Word documents.'],
], [3600, 5700])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('warn', 'Housekeeping worth doing on the KYSA folder', [
  'The KYSA working folder currently contains a directory literally named # holding a complete duplicate of the release, several dated zip archives, a Version/ folder of older bundles, and macOS .DS_Store files.',
  'None of that belongs in a published repository. The duplicate is the dangerous one: a maintainer editing the wrong copy will not get an error, they will get a change that silently does nothing. Delete it before you publish, and keep .gitignore covering .DS_Store, __pycache__, and *.zip.']));

// 3
H1('3. The one architectural rule');
T('Policy logic lives in exactly one file per toolset. Every graphical surface, every command line entry point, and every test loads that file. Nothing reimplements a check.');
push(Fig(F('fig5_architecture.png'), 'Figure 5. Both toolsets. One engine each, with every surface reading from it.', 640));
T('This is not a style preference. The failure mode it prevents is specific and expensive: the GUI reports a finding, the CLI in CI does not, and nobody notices for months because the two were never compared. KYSA goes one step further and generates the CLI engine module from the HTML with kysa_build_engine.js, so drift is not merely discouraged, it is structurally impossible.');
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
H2('Enforcement in the pages');
T('Gate the handler, not only the button. A disabled attribute is a hint about state; it is trivially bypassed from a console and it is not a control. On the remediation page every write path calls requireMode() as its first statement, and test/page.cjs proves it by invoking startStepping() and reviewApplyAll() directly in report mode and asserting the history is unchanged.');
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
push(Code(['# ACS Auditor, from the repository root',
  'node test/run_tests.js', '',
  '# KYSA, from its repository root',
  'node test/run_tests.js']));
T('No install, no test framework, no network. Both runners are plain Node and print a pass and fail count per suite plus a total.');
H2('What the ACS suites actually assert');
push([Tbl(['Suite', 'Count', 'Covers'], [
  ['smoke.cjs', '35', 'Catalogue integrity, unique ids, valid severities, every policy has a check, scanning and posture maths.'],
  ['fixes.cjs', '30', 'Each fix produces valid YAML, changes only what it should, and is idempotent when reapplied.'],
  ['import.cjs', '16', 'All three ACS export shapes parse, renamed policies still match, unmatched violations surface rather than vanish.'],
  ['flow.cjs', '36', 'Preview mutates nothing, undo restores byte for byte, merge patches stay minimal, diffs are correct.'],
  ['live.cjs', '32', 'URL normalising, actionable error classification, fallback command generation, live object sanitising.'],
], [1900, 900, 6500])]);
body.push(P('', { spacing: { after: 140 } }));
H2('The optional whole page tests');
T('test/page.cjs loads each HTML file from disk in a real DOM, with the actual script tags resolving to the actual files in document order, then drives it: drops an export, checks the panel unhides, clicks the filters, walks the image replacement dialog through preview, confirm and undo.');
T('It catches a class of defect the engine tests structurally cannot see. An element id that does not exist, a handler never bound, a panel that never unhides, a filter wired to the wrong checkbox. The engine can be perfect and the page still show nothing, which is exactly the failure this whole release was about.');
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
H2('The source watcher');
push(Code(['python3 dj_kysa_source_watcher.py [output_directory]']));
T('Standard library only, so it runs on any Python 3 without a package install. It pulls four things:');
push([Bul('Kubernetes and OpenShift STIG versions and V ids, via stigviewer.com JSON exports. This is a community mirror of the DISA STIG Library. Verify ids at public.cyber.mil before citing them in an RMF package.'),
      Bul('Recent Kubernetes and OpenShift CVEs from the NVD API 2.0, over a rolling 90 day window.'),
      Bul('Drift in the NSA and CISA Kubernetes Hardening Guidance PDF, detected from HTTP headers rather than by downloading it repeatedly.'),
      Bul('A content hash of the Kubernetes Pod Security Standards page, so a silent edit upstream becomes visible.')]);
T('It writes ksa_sources.js next to the KYSA pages. The catalog manager reads that file and shows what changed since your last published catalogue. On an air gapped network, run the watcher on a connected machine and carry that single file across.');
H2('Cadence');
T('Weekly is the right interval, and the CI templates already schedule it. More often is noise, less often means a STIG release can sit unnoticed for a quarter. The ACS toolset has no equivalent watcher because its policy set mirrors ACS defaults: when you upgrade ACS, diff its default policies against acs_policies.js and reconcile.');

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
T('The scripts fetch_vendor_libs.sh and fetch_vendor_libs.ps1 in the KYSA repository do all of this, including the functional parse. If unpkg is blocked, cdnjs mirrors both libraries, but its js-yaml build may differ, in which case verify functionally rather than by hash.');

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
T('For a genuine one off, annotate the resource itself with kysa.io/waive, kysa.io/waive-reason, kysa.io/waive-approver, and kysa.io/waive-expires. Use the file when a reviewer should see everything in one place. Use the annotation when the exception belongs to one specific resource and should travel with it.');
push(Note('warn', 'Review waivers on a schedule', [
  'Nobody notices a waiver expiring unless someone looks. Put a recurring calendar item against the waiver file. The most common failure of this entire model is not a bad waiver, it is a good waiver nobody revisited.']));

// 9
H1('11. CI integration');
push([Bul('GitHub: copy ci_templates/github_actions_kysa.yml to .github/workflows/kysa.yml'),
      Bul('GitLab: copy ci_templates/gitlab_ci_kysa.yml to .gitlab-ci.yml')]);
T('You get three behaviours: a scan on every proposed change with results in the job summary, findings published to the security dashboard on the main branch, and a weekly standards refresh followed by a pull request with fixes. Findings are emitted as SARIF, which GitHub and GitLab both read natively, so they land in the security tab rather than buried in log output.');
H2('Rolling it out without the team switching it off');
T('Start in reporting mode. Do not enable the build gate on day one. If the first run blocks every merge, the tool gets disabled within a week and you have made things worse than before you installed it. Report only, work the backlog down, then set --fail-on high so new problems cannot get in while you finish clearing the old ones.');
H2('Token handling in CI');
T('The CLI reads KYSA_TOKEN from the environment. Store it as a repository or group secret, never in the workflow file and never on the command line where it lands in shell history and process listings. On GitHub use a fine grained personal access token with read and write on code and pull requests. On GitLab use a project access token with api and write_repository scope. Scope it to the one repository it needs.');
push(Note('info', 'What the automation is allowed to do', [
  'It clones, fixes what is safe, annotates the rest, creates a branch, and opens a pull request with the before and after posture in the description. With --review-comments it comments on the specific lines needing attention.',
  'It never touches your branch. The work arrives as a proposal a person approves or rejects. Automation does the tedious part, humans keep the final say. If you ever change that, you have changed the risk profile of the tool entirely.']));

// 10
H1('12. Release procedure');
push(NumList([
  'Run both test suites. A red suite is a blocked release, not a warning.',
  'Confirm the version constant in the HTML matches package.json and the CHANGELOG entry.',
  'Confirm the vendored library hashes still match vendor/README.md.',
  'Grep the shipped files for exec, eval, and the Function constructor. There should be no matches.',
  'Confirm report mode still produces nothing applyable, on both pages and the command line. This is the control most likely to be weakened by accident while adding a feature.',
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
H1('13. Security posture of the tooling itself');
T('A security tool is a target and a trust anchor. These are the properties that have been verified, and the ones you must not regress.');
push([Tbl(['Property', 'How it is enforced'], [
  ['No remediation ever executes a command', 'No exec, eval, or Function constructor exists in any shipped ACS file. Verified by grep. Fixes are pure text edits to YAML.'],
  ['Tokens are never persisted', 'Both token fields are password inputs. No token is written to localStorage, sessionStorage, IndexedDB, or a cookie. Tokens are cleared after the request and are absent from every export. The only browser storage used anywhere is the light or dark theme preference. Verified by grep and covered by tests.'],
  ['Live connect is read only', 'Only HTTP GET is issued across all three endpoints. There is no code path that writes to a cluster.'],
  ['Nothing applyable is produced without an explicit mode', 'report is the default everywhere, unknown modes throw rather than defaulting, and the mode gates the handlers rather than only the buttons. See section 4.'],
  ['No CVE is ever auto remediated', 'ACS reports fixed package versions, not fixed image tags. applyImagePin only ever writes a value the operator typed, and it goes through the same preview, confirm and undo path as every other fix.'],
  ['Hydration is rate limited by construction', 'Alert detail is fetched sequentially and capped at 200. Central is a security control; a report is not worth destabilising it.'],
  ['No telemetry, no phone home', 'The browser pages make no outbound request except the live connect calls you explicitly trigger.'],
  ['No network at rest', 'Dependencies are vendored. The pages load nothing from a CDN.'],
  ['Live objects are sanitised', 'Server side fields, ownerReferences, status, and last applied configuration are stripped before an object is scanned or emitted.'],
], [3000, 6300])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Threat model, stated plainly');
push([Bul('Untrusted input is the YAML and the ACS export a user loads. Both are parsed by js-yaml, never evaluated. A malicious manifest can produce a wrong finding. It cannot execute anything.'),
      Bul('The credential exposure window is a live token in a browser tab for the duration of a request. Mitigate with short lived least privilege tokens rather than by trusting the tab.'),
      Bul('The supply chain risk is the two vendored libraries. Mitigate by pinning, hashing, and verifying functionally on refresh.'),
      Bul('The most realistic failure is not an attack. It is a wrong finding trusted without review, or a stale policy set that quietly stops catching something. That is what sections 6 and 8 exist to prevent.')]);

// 12
H1('14. Maintainer troubleshooting');
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
  ['An edit to a file appears to do nothing', 'Check for a duplicate copy of the tree, such as the # directory in the KYSA folder. Delete duplicates rather than working around them.'],
], [3200, 6100])]);

// 13
H1('15. Ownership and escalation');
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
  sections: [Object.assign({}, pageSetup('Administration Guide  |  KYSA and ACS Auditor'),
    { children: [...title, ...toc, ...body] })],
});
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(__dirname + '/DJ_Security_Tooling_Administration_Guide.docx', b); console.log('WROTE', b.length, 'bytes'); });
