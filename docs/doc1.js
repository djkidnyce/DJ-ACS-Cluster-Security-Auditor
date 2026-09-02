const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
        PageBreak, BorderStyle, ShadingType, TableOfContents } = require('docx');
const fs = require('fs');
const { P, Rich, Code, Note, Fig, Tbl, Bul, BulRich, NumList, NUMBERING, pageSetup,
        ACC, DARK, MUT, LINE } = require('./common.js');
const F = (n) => __dirname + '/figures/' + n;

const title = [
  new Paragraph({ spacing: { before: 2600, after: 0 }, alignment: AlignmentType.LEFT,
    children: [new TextRun({ text: "DJ's ACS Auditor", bold: true, size: 60, color: DARK })] }),
  new Paragraph({ spacing: { after: 60 }, children: [new TextRun({
    text: 'Auditing and remediating Kubernetes and OpenShift manifests against Red Hat Advanced Cluster Security', size: 26, color: ACC })] }),
  new Paragraph({ spacing: { after: 400 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: ACC } }, children: [new TextRun({ text: '' })] }),
  P('User Guide', { bold: true, size: 28 }),
  P('Version 1.0', { size: 22, color: MUT }),
  P('Document date: 11 August 2026', { size: 22, color: MUT }),
  P('Author: DJ', { size: 22, color: MUT }),
  P('Distribution: internal engineering and security teams', { size: 22, color: MUT }),
  new Paragraph({ spacing: { before: 900 }, children: [new TextRun({ text: '' })] }),
  ...Note('crit', 'The one guarantee that governs this entire tool', [
    'No command is ever executed to remediate a finding. Every fix is a text edit made to YAML inside your browser and handed back to you as a file. The tool does not call oc, kubectl, roxctl, helm, or a shell. It does not write to a cluster. It does not apply anything on your behalf.',
    'The page does not connect to anything at all. It has no URL field, no token field, and no network call in it. Data comes out of ACS through the scripts in section 7, which run in a shell where the cluster is reachable and only ever issue a GET.']),
  new Paragraph({ children: [new PageBreak()] }),
];

const toc = [
  P('Contents', { heading: HeadingLevel.HEADING_1 }),
  ...['1. What this tool does','2. One page, two tabs','3. Report, manual, or auto',
      '4. Before you start','5. Quick start',
      '6. Loading manifests and reading the audit','7. Getting the data out of ACS',
      '8. Vulnerabilities: why an empty alert list proves nothing',
      '9. Working the CVE list','10. Seeing and fixing violations','11. Applying fixes',
      '12. What gets fixed automatically, and what deliberately does not','13. Taking the result out',
      '14. How the score is calculated','15. Policy reference','16. Limits, stated plainly',
      '17. Troubleshooting','18. Contact'].map((t) => P(t, { spacing: { after: 90 }, size: 22 })),
  P('Figures', { bold: true, size: 22, spacing: { before: 240, after: 90 } }),
  ...['Figure 1. The Audit tab after a scan (section 6)',
      'Figure 2. Getting the data out of ACS (section 7)',
      'Figure 7. The two ACS data planes (section 8)',
      'Figure 3. Step through remediation (section 11)',
      'Figure 8. The violations panel and the fix routes (section 10)',
      'Figure 4. Export options (section 13)'].map((t) => P(t, { spacing: { after: 90 }, size: 22, color: MUT })),
  new Paragraph({ children: [new PageBreak()] }),
];

const body = [];
const H1 = (t) => body.push(P(t, { heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 } }));
const H2 = (t) => body.push(P(t, { heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 100 } }));
const T = (t) => body.push(P(t));
const push = (arr) => arr.forEach((x) => body.push(x));

// ---------------- 1
H1('1. What this tool does');
T('DJ\'s ACS Auditor reads Kubernetes and OpenShift YAML, evaluates it against replicas of the Red Hat Advanced Cluster Security default Deploy stage policies, scores and ranks every finding, and then rewrites the YAML for you with a full preview and an explicit confirmation before anything changes.');
T('It exists to close a specific gap. ACS tells you a running workload is in violation. It does not hand you a corrected manifest, and it does not tell you what your posture would look like once the fix lands. This tool does both, and it does it against the manifest in your repository, which is where the fix actually has to be made.');
H2('The pieces');
push([Tbl(['File', 'What it is for'], [
  ['dj_acs_auditor.html', 'The whole browser surface, in two tabs. Audit scans, scores, ranks, cross checks against ACS violations and image CVEs, and exports the report. Remediate applies fixes with preview, confirmation, one at a time stepping, and undo. See section 2.'],
  ['acs_policies.js', 'The policy engine. Every surface loads this one file, so the page, the command line and the tests cannot disagree about a manifest.'],
  ['acs_cli.js', 'The same engine headless, for a pipeline or a terminal. Needs Node; the page does not.'],
  ['scripts/', 'Getting the data out of ACS. Preflight, the full pull, and PowerShell, SSH and oc port forward variants. Bash and curl, no runtime.'],
  ['vendor/', 'js-yaml and JSZip, committed to the repository so the tool needs no package manager and no network access.'],
  ['test/run_tests.js', '899 tests against the real engine, the page, the scripts and the command line.'],
], [2200, 7100])]);
body.push(P('', { spacing: { after: 120 } }));
T('Open dj_acs_auditor.html by double clicking it. There is nothing to install, no server to start, and no package manager involved. Node is needed only for the command line runner and the test suite, never for the page.');


// ---------------- 2 modes
H1('2. One page, two tabs');
T('There is one file to open, dj_acs_auditor.html, and it has two tabs.');
push([Tbl(['Tab', 'What it is for', 'What it can change'], [
  ['Audit', 'Reading. Posture, the findings table, the cross check against ACS, the violations panel, image CVEs, the policy catalogue, and the reports you take away. Drafting a patch from an ACS violation happens here too.',
   'Nothing you loaded. Drafting a patch writes a new file for you to review; it does not touch your manifests.'],
  ['Remediate', 'Changing. Step through fixes one at a time, review and apply a batch, replace an image reference, undo any of it.',
   'The YAML you loaded, in memory, and only once you move the Mode selector off Report only. Files on disk change when you download the result.'],
], [1500, 5000, 2800])]);
body.push(P('', { spacing: { after: 140 } }));
T('They share one loaded file set, one scan and one mode gate. Load your manifests and your ACS export once and both tabs see them.');
push(Note('info', 'Why the Mode selector sits above the tabs rather than inside one', [
  'It governs both. A control that decides whether the tool may write has to be visible from wherever you are standing when you ask it to write.',
  'Put it inside the Remediate tab and the Audit tab would be drafting patches under a setting you cannot currently see. That is the kind of arrangement where somebody is genuinely surprised by what came out, and being surprised by a security tool is the failure this whole design is built to avoid.']));
push(Note('warn', 'If you are coming from an earlier version', [
  'There used to be two files: dj_acs_auditor.html and dj_acs_remediation.html. They are now one, and the remediation file is deleted.',
  'This was not tidying. Eighteen functions existed in both files, ten of them byte identical, and they were kept in step by hand. That is how a fix reached one surface and not the other, which happened more than once. One file means one file list, one violations table and one mode gate, and no way for the two halves to drift apart.']));

H1('3. Report, manual, or auto');
push(Note('crit', 'You choose the path. Every time. The tool never chooses for you.', [
  'Report is the default on every surface, on the page and on the command line. The safe state is the one you get by doing nothing, not the one you get by remembering a flag.',
  'An auto fix that nobody selected is a new risk, not a mitigation.']));
push([Tbl(['Mode', 'What it produces', 'Modifies anything'], [
  ['report', 'The analysis: report, findings JSON, SARIF. Nothing that could be applied.', 'No'],
  ['manual', 'Patches and written guidance for a human to review and apply.', 'No'],
  ['auto', 'Applies the safe fixes and writes corrected YAML, with a preview and a confirmation for each change.', 'Yes'],
], [1400, 5900, 2000])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Why this is a security control rather than a convenience');
T('A remediation tool that can write before the operator has chosen to write is a new risk, not a mitigation. The failure mode is not the tool doing something malicious. It is somebody at the end of a long incident clicking the obvious button, producing a change to a production manifest they did not intend, and then defending it in review because a plausible looking diff is attached to it.');
T('Three rules follow from that, and they are enforced identically on the page, on the command line, and in every file either of them writes.');
push([Bul('The mode is never inferred from anything else. Asking for patches does not put you in manual mode. You choose the mode, then you ask for the output.'),
      Bul('An unknown mode is an error, never a quiet fall back to something permissive. A typo that lands you in a writing mode is exactly the failure this exists to prevent.'),
      Bul('The mode is recorded in every artifact. A reviewer holding a patch should not have to ask which path produced it.')]);
H2('On the page');
T('The page opens in report mode and nothing will change a file until you move off it. One mode selector sits above the tabs and governs both of them, because a control that decides whether the tool may write has to be visible from wherever you are standing when you ask it to write. The mode gates the handlers, not just the buttons: calling the apply functions directly from the browser console in report mode still refuses, because a disabled attribute is a hint about state rather than a control over it.');
push([Bul('Step through one by one becomes available in manual and auto.'),
      Bul('Review and apply all is auto only. Manual means looking at each change, so reaching a batch apply from it would defeat the point of having chosen manual.'),
      Bul('The checkbox that skips the confirmation prompt is offered only in auto, and switching back to report clears it, so a mode change can never leave a more permissive setting behind it.')]);
H2('On the command line');
push(Code(['# report is the default',
  'node acs_cli.js --path ./manifests --report --json',
  '',
  '# manual: patches for a human to apply, nothing modified',
  'node acs_cli.js --path ./manifests --mode manual --patches --out ./proposed',
  '',
  '# auto: apply the safe fixes to a copy',
  'node acs_cli.js --path ./manifests --mode auto --patches --out ./remediated']));
T('Asking for something applyable while in report mode is refused rather than silently upgraded, and the refusal states the choice instead of making it:');
push(Code(['--patches produce material that can be applied, and this run is in',
  'report mode, which by definition produces none.',
  '',
  'Choose the path you actually want:',
  '  --mode manual   patches and guidance, nothing modified',
  '  --mode auto     apply the safe fixes',
  '',
  'Refusing rather than picking one for you. An auto fix nobody selected is a',
  'new risk, not a mitigation.']));
T('Manual and auto compute exactly the same fix. They differ only in what they do with it: manual expresses it as a patch and leaves every file untouched, auto writes the corrected YAML as well. Manual writes PROPOSED_CHANGES.md, auto writes CHANGES.md, and both carry a Mode line at the top.');
push(Note('warn', 'One deprecated spelling', [
  'The old --fix flag still works and behaves as --mode auto, so existing scripts do not break silently. It prints a note telling you to say the mode explicitly. It will be removed.']));

// ---------------- 3
H1('4. Before you start');
H2('What you actually need installed');
T('The answer for most people is nothing. The page is a file you open.');
push([Tbl(['To do this', 'You need', 'Node?'], [
  ['Read, score, cross check, see violations, draft fixes, export the report', 'A browser. Open dj_acs_auditor.html', 'No'],
  ['Apply fixes with preview, confirmation and undo', 'The same file, Remediate tab', 'No'],
  ['Pull data out of ACS', 'bash, curl, jq', 'No'],
  ['Pull from Windows, or over SSH to a jump host', 'PowerShell 5.1 or newer, no modules', 'No'],
  ['Summarise a pull from the shell', 'jq', 'No'],
  ['Run the audit headless, in a pipeline', 'acs_cli.js', 'Yes, Node 18 or newer'],
  ['Run the test suite', 'test/run_tests.js', 'Yes'],
], [4100, 3400, 1800])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('ok', 'If Node cannot be installed on the machine you audit from', [
  'This is normal on a hardened host in a controlled enclave, and it is a supported path rather than a limitation you have to work around.',
  'Everything in the audit itself is available: the page computes the posture, lists the violations, routes the fixes and drafts the YAML, and it needs a browser and nothing else. The pull scripts are bash and curl.',
  'For something you can read or hand over without leaving the shell, scripts/acs_summary.sh turns a pull directory into a markdown summary using jq. It counts what ACS reported. It does not compute a posture score and does not draft fixes, because both need the policy engine, and it says so in its own output rather than printing a number it has not earned.',
  'If the host has podman or docker, the command line runner works without installing anything: podman run --rm -v "$PWD":/w:Z -w /w docker.io/library/node:20-alpine node acs_cli.js --help',
  'The wrappers acs.sh, acs.ps1 and acs.cmd detect a missing Node and print these routes rather than failing with command not found.']));


H2('Requirements');
push([Bul('A current browser. Chrome, Edge, Firefox, or Safari. The page uses the File System Access API for folder upload where available and falls back to a directory input where it is not.'),
      Bul('The YAML you want audited, either as loose files or a whole folder tree.'),
      Bul('Optional but recommended: the output of scripts/acs_pull_all.sh, which is what turns a manifest audit into a cross check against what your cluster is actually running.')]);
H2('What the tool never asks for');
T('It does not ask for cluster write access, a kubeconfig, a service account, an admission webhook, or anything installed on a node. If a workflow ever seems to want one of those, you are not in this tool.');
H2('Working disconnected');
T('Everything the page needs is committed alongside it. js-yaml and JSZip are vendored, so a machine with no route to the internet, no npm, and no proxy runs the tool identically to one that is fully connected. This matters on classified and air gapped networks, where the usual answer of "just npm install it" is not available, and it is the same reason the tool refuses to fetch a parser at runtime: a security tool quietly pulling code off the internet is itself a reportable event.');

// ---------------- 3
H1('5. Quick start');
push(NumList(['Open dj_acs_auditor.html. There is one file and it has two tabs.',
  'Drag your manifest folder onto the drop zone, or press Browse folder. Drop the output of scripts/acs_pull_all.sh on it at the same time if you have it.',
  'Stay on the Audit tab. Read the posture cards: the weighted compliance score now, and what it becomes once the safe fixes are applied.',
  'Sort the findings table by Score to see what hurts most, and read the Violations from ACS panel for what your cluster is actually reporting.',
  'Press Download the audit report to keep the evidence.',
  'Switch to the Remediate tab to change anything. Nothing there will touch a file until you move the Mode selector off Report only.']));
push(Note('ok', 'Want to see it work before trusting it with real manifests', [
  'There is a Load a deliberately bad sample button on the drop zone. It loads a small manifest set that trips a spread of policies across every severity, so you can walk the full workflow, apply fixes, and undo them without touching anything of yours.']));

// ---------------- 4
H1('6. Loading manifests and reading the audit');
T('Figure 1 shows the auditor after a folder has been loaded. Everything on the page is derived from the files you dropped in. Nothing is fetched, and nothing is remembered between sessions.');
push(Fig(F('fig1_auditor_overview.png'), 'Figure 1. The auditor after a scan. Posture cards, category breakdown, and the sortable findings table.', 640));
H2('The posture cards');
T('The left card is your weighted compliance score as the manifests stand today. The right card is the projected score once every automatic fix is applied. The difference between them is the honest value of working the Remediate tab, and section 14 explains exactly how both numbers are computed, including why you get no score at all when no manifests were scanned.');
H2('The findings table');
T('Every column sorts. Click a header once for ascending, again for descending. The columns are ID, Severity, Score, Policy, Object, File, and Fix.');
push([Bul('ID is the internal identifier, ACS.001 through ACS.020, stable across releases of this tool.'),
      Bul('Severity is the ACS severity for the matching default policy.'),
      Bul('Score is a CVSS v3.1 style base score, used for ranking within a severity band.'),
      Bul('Object is the workload kind and name, so you know which Deployment is at fault, not just which file.'),
      Bul('File is the path relative to the folder you loaded, which is what you need to open the right file in your editor.'),
      Bul('Fix says Auto, Generate, or Manual. Section 11 explains the distinction and why it is the most important judgment in the tool.')]);
H2('Posture by category');
T('The bars group findings the way ACS groups its own policies: Privileges, Network, Kubernetes, Docker CIS, Resource Management, Security Best Practices, and DevOps Best Practices. A single tall bar usually means a systemic problem, one bad base template copied across twenty services, rather than twenty unrelated mistakes.');

// ---------------- 5
H1('7. Getting the data out of ACS');
T('Earlier versions of this tool carried a connect panel in the page: type a Central URL, paste an API token, press fetch. It has been removed. This section explains why, because the reasoning matters more than the feature did, and then shows what to do instead.');
push(Note('warn', 'Why there is no connect button any more', [
  'A page opened from a file has a null origin. Neither ACS Central nor the OpenShift API sends a header that permits a null origin, so the browser blocks the response before the page ever sees it. This is the browser working correctly and no amount of rewriting the page changes it.',
  'That left a feature which asked you to paste a live ACS API token into a browser tab in exchange for a request that then failed. The token was real, the risk was real, and the benefit was zero.',
  'Mitigating that risk, masking the field, clearing the value, keeping it out of storage, was work spent making a credential slightly safer in a place it had no reason to be. Removing the feature deletes the risk class instead of managing it. The test suite now asserts the stronger property: no password field, no token identifier and no network call exists in either page.']));
push(Fig(F('fig2_pull_workflow.png'), 'Figure 2. The supported path. The scripts run where the cluster is reachable, and the page reads what they write.', 640));

H2('Central\'s certificate is self signed, and that is normal');
T('The RHACS operator installs a self signed certificate for Central. Your system trust store will never verify it, so a certificate error on the first run is the expected outcome rather than a sign something is broken.');
push(Note('crit', 'The one thing not to do', [
  'Do not reach for --insecure. This request carries a token that reads your entire security posture, and disabling verification hands it to anyone on the network path between you and Central.',
  'The script does not offer it as a shortcut, which is deliberate. A tool that suggests turning verification off is teaching a habit that outlives the tool.']));
T('Run the pull and it works out the best available route itself, most trustworthy first:');
push(NumList([
  'A CA you supplied, with --cacert or ROX_CA. You decided where it came from.',
  'The central-tls secret, read through your authenticated oc session. The cluster tells us its own CA over a connection oc has already verified. If you are logged in this usually just works, and the CA is saved beside the run for next time.',
  'Neither of those, so it stops and shows you the certificate issuer, its SHA-256 fingerprint, and two commands that will work.']));
T('Confirm that fingerprint against the cluster through some channel other than the connection you are trying to trust. That confirmation is the entire security of what comes next.');
push(Code(['# A: verify against the certificate itself. A self signed certificate is its',
           '# own issuer, so it works as a CA bundle. Keeps the hostname check.',
           './scripts/acs_pull_all.sh --cacert findings/central-cert.pem -o findings',
           '',
           '# B: pin the public key. Works even when the hostname does not match the',
           '# certificate, which is common through a port forward.',
           "./scripts/acs_pull_all.sh --pin 'sha256//<the hash it printed>' -o findings"]));
T('A is better where it works, because it keeps full verification. The script tests it against your endpoint before recommending it, so it only appears as an option when it genuinely works.');
T('B turns the chain check off and requires that exact public key instead. Pinning on its own cannot help with a self signed certificate: the pin is an additional check rather than a replacement, so curl rejects the chain before it ever looks at the key. Pinned, a wrong key fails closed rather than connecting anyway.');
push(Note('info', 'What a failed run leaves behind', [
  'Nothing that could be mistaken for a pull. If TLS never resolved there is no findings directory at all.',
  'If TLS worked and the token was rejected, the directory is marked RUN_FAILED.txt saying in plain terms that there are no findings in it and not to conclude the cluster is clean. An almost empty directory that looks like a successful run is a worse outcome than an error.']));

H2('Step one: the preflight');
T('Run scripts/acs_preflight.sh before anything else. It checks that the endpoint resolves and answers, that TLS verifies, that the token is valid, and, most usefully, that the token can actually read each of the three things the export needs.');
T('That last check is worth its own paragraph. A token scoped only to Alert will pull violations perfectly and return 403 on the vulnerability export. You see violations, you see no CVEs, and nothing tells you the second half silently failed. The preflight catches it in one line.');
H2('Step two: the pull');
T('scripts/acs_pull_all.sh writes seven files into a timestamped directory:');
push([Tbl(['File', 'Endpoint', 'What it is for'], [
  ['00_auth_status.json', '/v1/auth/status', 'Who the token is and what it can see. Evidence for the audit trail.'],
  ['01_alerts_list.json', '/v1/alerts', 'Every violation, slim. No violation text, by design of the API.'],
  ['02_alerts_full.json', '/v1/alerts/{id}', 'The same violations hydrated with their violation text. This is the one that matters.'],
  ['03_vuln_workloads.ndjson', '/v1/export/vuln-mgmt/workloads', 'CVEs in the images your workloads are actually running.'],
  ['04_all_images.ndjson', '/v1/export/images', 'Every image ACS has scanned, deployed or not.'],
  ['05_nodes.ndjson', '/v1/export/nodes', 'CVEs on the nodes themselves.'],
  ['06_snoozed.ndjson', '/v1/alerts', 'Violations somebody deferred, so a deferral does not become invisible.'],
], [2700, 2700, 3900])]);
body.push(P('', { spacing: { after: 140 } }));
T('The scripts read the token from the environment or prompt for it without echo. It is never passed as a command argument, so it does not appear in ps output where any other user on the machine could read it, and it does not land in your shell history. TLS is verified by default and --cacert is supported for a private CA.');
push(Note('info', 'If you are not on a Unix shell, or Central is not reachable from your workstation', [
  'scripts/acs_pull_all.ps1 is the PowerShell equivalent and needs no additional modules.',
  'scripts/acs_pull_over_ssh.ps1 runs the pull on a jump host over SSH and brings the files back, for the case where Central is only reachable from inside the environment.',
  'scripts/acs_pull_via_oc.sh uses an oc port forward to Central instead of a route, for clusters where Central has no external route at all. Note that an HTTP proxy will break a port forward: the tool passes --noproxy so the local forward is not sent through it.']));
H2('Where the files land');
T('Each run gets its own directory, named for the moment it ran:');
push(Code(['./scripts/acs_pull_all.sh -o findings', '',
           'findings/', '  acs_findings_20260821_143022/', '    00_auth_status.json', '    01_alerts_list.json',
           '    ...', '  acs_findings_20260822_091500/', '    ...']));
T('The -o flag names the parent, not the run. A second run never overwrites the first, which matters more than it sounds: an export you cannot compare against last week is worth much less than one you can, and proving a fix landed means holding both.');
T('Pass --no-timestamp when you want the files written straight into -o, which is usually a pipeline that expects a fixed path.');

H2('What the run gives you at the end');
T('The pull finishes by writing findings.md into the run directory and printing it. A directory of seven JSON files is not a result anybody can read, so the run ends with something you can look at, forward, or attach to a ticket without opening anything else.');
push([Bul('Violations counted by severity, by policy and by namespace, split between your workloads and platform components, with a count of any that arrived without the platformComponent field at all.'),
      Bul('CVEs by Red Hat severity, how many have a published fix, and how many are on the CISA Known Exploited Vulnerabilities catalog.'),
      Bul('Images ranked by worst CVSS, with critical, KEV and fixable counts beside each, because you rebuild an image once and every fixable CVE inside it clears together.'),
      Bul('The highest scoring CVEs, with the version each is fixed in.'),
      Bul('workloads.json, the running deployments, daemonsets, statefulsets, cronjobs and jobs, captured in the same directory at the same moment as the findings.')]);
push(Note('info', 'Why the workloads are captured by the same run', [
  'ACS names a workload in violation. Fixing it requires the object it named. Pull the findings now and the manifests an hour later and you are describing two different clusters, and every count you compare between them is off by whatever moved in between.',
  'Because both land in one timestamped directory, a run before your changes and a run after them diff cleanly, and the difference is evidence rather than an assertion.',
  'The capture is time bounded at sixty seconds and never fails the run. If oc is missing, or present but pointed somewhere it cannot reach, the pull says so, prints the command to run where your oc session does work, and carries on with the findings intact.']));
T('It is jq only, so it works on a machine where Node cannot be installed. Pass --no-summary to skip it in a pipeline that only wants the files.');
push(Note('info', 'CVSS in the summary is not the priority this tool ranks by', [
  'The summary reports CVSS, which is the score ACS supplied for each CVE.',
  'The tool\'s own priority runs to 15 rather than 10, because it adds the CISA catalog, EPSS exploitation probability, whether a fix exists and whether pods are actually running the image. Every one of those adjustments is named on screen.',
  'That model lives in the policy engine, so it comes from the page or the CLI. It is deliberately not reimplemented in the summary script: a second ranking that drifts from the first is worse than having only one.']));

H2('Step three: drop them on the page');
push(Note('info', 'If you use Browse files rather than dragging', [
  'The picker now offers .ndjson and .jsonl as well as .yaml and .json. It previously filtered to .yaml, .yml and .json only, which made three of the seven files the pull script writes invisible in the dialog while drag and drop accepted them perfectly well.',
  'If you are on an older copy and cannot see 03_vuln_workloads.ndjson in the file picker, that is why. Drag it instead, or update.']));
T('Drag all of them onto the drop zone at once, in any order, alongside your YAML. They accumulate rather than replace each other, which was not true in an earlier version and is the reason this is spelled out: dropping six files used to leave you looking at whichever one landed last.');
T('A violation that arrives twice, once slim from 01 and once hydrated from 02, is recognised as the same violation and deduplicated, with the hydrated copy kept. Nothing is uploaded anywhere. The file is read inside the tab and never leaves the machine.');
H2('Auditing what is deployed rather than what you think is deployed');
T('To audit the running cluster rather than the repository, export the live objects with oc and drop that file on the page as well:');
push(Code(['oc get deployment,daemonset,statefulset,cronjob,job --all-namespaces -o json > workloads.json']));
T('A live object from the API is not a manifest. It carries server side bookkeeping that would be wrong, noisy, or actively dangerous to write back into git, so the tool strips it on load:');
push([Bul('managedFields, resourceVersion, uid, selfLink, generation and creationTimestamp, all assigned by the API server.'),
      Bul('ownerReferences, so a Pod created by a ReplicaSet does not carry a dangling parent link into your repository.'),
      Bul('The entire status block, which is observed state rather than something you declare.'),
      Bul('The kubectl.kubernetes.io/last-applied-configuration annotation, which is a stale copy of the object embedded inside the object.')]);
T('Meaningful annotations survive. If stripping annotations would leave an empty map, the map itself is removed rather than left as an empty stub, which keeps the emitted YAML clean. The test suite asserts all of this, including that a sanitised object remains fully scannable and fixable.');

// ---------------- 6
// ---------------- 6 vulnerabilities
H1('8. Vulnerabilities: why an empty alert list proves nothing');
push(Note('crit', 'If you take one thing from this document, take this', [
  'An image CVE is not a policy violation. It only produces an alert if somebody wrote a policy that fires on it, and most teams have not.',
  'A cluster full of critical, actively exploited CVEs can return an empty /v1/alerts list. Empty is not clean. It means you asked the wrong endpoint.']));
T('ACS is one product with two entirely separate data stores behind it, reached by two different endpoints that return two different document shapes. Figure 7 lays out both.');
push(Fig(F('fig7_two_data_planes.png'), 'Figure 7. The two ACS data planes, what each endpoint returns, and the trap between them.', 640));
H2('The first surprise: the alert list has no violation text in it');
T('GET /v1/alerts returns storage.ListAlert, a deliberately slim projection. It carries the policy name, severity and categories, the lifecycle stage and the state. It does not carry the violations array, and the namespace and cluster live under commonEntityInfo rather than under deployment.');
T('The practical effect is a list of rows that name a policy and explain nothing. Only GET /v1/alerts/{id} returns the full storage.Alert with violations[] populated. The tool now does both: it lists, then fetches the detail one alert at a time. That is what the Fetch violation detail checkbox controls, it is on by default, and it is capped at 200 alerts so the page does not hammer Central, which is a security control you do not want to destabilise.');
push(Note('info', 'Three other reasons an alert query comes back thinner than you expected', [
  'The query defaults to Violation State:ACTIVE so it matches the ACS console. Resolved and attempted violations are excluded unless you ask for them.',
  'ACS applies a server side page size. The tool sets pagination.limit explicitly and tells you when the result hit that limit, because a silently truncated list understates the problem.',
  'Your token is scoped. A token that can only see two namespaces returns findings for two namespaces and gives you no indication that the other forty exist.']));
H2('The second surprise: CVEs come from a completely different endpoint');
T('Vulnerability data comes from GET /v1/export/vuln-mgmt/workloads. Two things about it catch people out.');
push([Bul('It streams NDJSON, one JSON object per line, not a single JSON document. Calling res.json() on it fails. The tool reads it as text and parses line by line, and it accepts the array form that jq -s produces as well.'),
      Bul('The token needs read access to Image and Deployment. A token scoped only to Alert returns 403 here while the violations tab keeps working perfectly, which is a genuinely confusing way to see nothing.')]);
T('Field names and response shapes were verified against the upstream StackRox service and message definitions: vuln_mgmt_service.proto for the endpoint and query syntax, image.proto for the scan structure, and vulnerability.proto and cve.proto for the CVE fields and the severity and state enumerations. Confirm them against your own ACS version before treating them as fixed.');
H2('Using it');
push(NumList([
  'Run scripts/acs_preflight.sh and confirm the token can read Image and Deployment. A token scoped only to Alert fails here and nowhere else.',
  'Run scripts/acs_pull_all.sh. Scope by namespace if the cluster is large, because a full export is slow.',
  'Drop 03_vuln_workloads.ndjson onto the page with your manifests. Add 04_all_images.ndjson if you want images that are scanned but not deployed, and 05_nodes.ndjson for the nodes themselves.']));
T('The tool reads all three shapes. An image with no running workload is labelled as not deployed rather than attributed to a Deployment that does not exist, and a node CVE is labelled as a node. A record that carried scan data the tool could not tie to either is reported as an error rather than silently dropped.');

// ---------------- 7 working the CVE list
H1('9. Working the CVE list');
H2('The severity words are different, deliberately');
T('ACS grades vulnerabilities on the Red Hat scale, which is not the vocabulary used for policy severity. The tool keeps them visually consistent and verbally distinct so nobody conflates an Important CVE with a High policy violation in a report.');
push([Tbl(['ACS value', 'Shown as', 'Not to be confused with'], [
  ['CRITICAL_VULNERABILITY_SEVERITY', 'Critical', 'Critical policy severity'],
  ['IMPORTANT_VULNERABILITY_SEVERITY', 'Important', 'High policy severity'],
  ['MODERATE_VULNERABILITY_SEVERITY', 'Moderate', 'Medium policy severity'],
  ['LOW_VULNERABILITY_SEVERITY', 'Low', 'Low policy severity'],
], [3600, 1900, 3800])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Priority, and why it runs to 15 rather than 10');
T('CVSS on its own is a poor work queue. A 9.8 in a package nothing can reach outranks a 7.5 that is on the CISA Known Exploited Vulnerabilities catalog and being used this week, which is backwards. Priority starts at the CVSS ACS prefers and adds a short list of named, bounded signals.');
push([Tbl(['Signal', 'Adds', 'Why'], [
  ['On the CISA KEV catalog', '2.0', 'Someone is exploiting it in the wild, right now. This is the strongest signal available.'],
  ['EPSS 50 percent or higher', '1.5', 'Predicted likelihood of exploitation in the next 30 days.'],
  ['EPSS 10 to 50 percent', '0.7', 'Same signal, weaker.'],
  ['A fix is published', '1.0', 'You can act on it today. An unfixable critical is not more urgent, it is differently urgent.'],
  ['Pods are running the image', '0.5', 'Reachable beats theoretical.'],
], [2800, 900, 5600])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('info', 'Why not clamp it back to a familiar 0 to 10', [
  'Because clamping lands every critical on exactly 10 and destroys the ordering at precisely the top of the queue, where ordering is the entire point. A 9.8 on the KEV catalog running in production would sort identically to a 9.8 nobody has ever exploited.',
  'A wider separate scale keeps the ranking intact and stops anyone quoting the number as if it were a CVSS score. It is not one. Every adjustment is listed in the last column of the table so you can audit the ranking rather than trust it.']));
H2('What the panel gives you that the ACS console does not');
push([Bul('The file. The console tells you an image is vulnerable. This tells you which manifest, which object, and which container line pulls it, which is where the fix actually has to be made.'),
      Bul('Drift. If the manifest says one tag and ACS scanned another, git and the cluster disagree. That is a finding on its own, and it means a deploy from your repository would change what is running.'),
      Bul('Coverage gaps. Scanned images with no manifest in the set you loaded are listed. Either the manifest is elsewhere, or the workload was created outside git. The second one is worth chasing.'),
      Bul('Accepted risk kept separate. CVEs deferred or marked false positive in ACS stay visible and are excluded from the active counts, so the headline numbers survive a review.')]);
H2('There is no auto fix for a CVE, and that is the correct answer');
push(Note('warn', 'Why the tool will not bump your image tag for you', [
  'ACS reports a component level fix: openssl is fixed in 3.0.14. It does not and cannot tell you which image tag contains that package version, because that depends entirely on how your image is built.',
  'A tool that derived one from the other would be guessing, and a wrong guess points a production Deployment at a tag that does not exist, or at one that clears the CVE and breaks the application.',
  'What the tool does instead: ranks the work, names the file, and emits a rebuild worklist grouped by image, because you rebuild an image once and every fixable CVE inside it clears together. Then, on the Remediate tab, you can apply a replacement image reference that you supply, with the same preview, confirmation and undo as every other fix.']));
H2('The image worklist');
T('Download the image worklist gives you a markdown document grouped by image rather than by CVE. For each image it lists the fixable CVEs with the package versions to move to, the ones with no published fix that rebuilding will not clear, the workloads using it, and the manifest files that declare it. Accepted risk is listed at the end for the record.');
T('A list organised by CVE looks like progress and cannot be actioned. A list organised by image is a set of rebuilds.');

// ---------------- 8
H1('10. Seeing and fixing violations');
T('An earlier version of this page reported ACS data as three numbers: violations imported, violations matched, violations not matched. That tells you something is wrong and gives you no way to look at it or act on it. Every violation now gets a row, and every row says what can be done about it.');
push(Fig(F('fig8_violations_panel.png'), 'Figure 8. The violations panel. Tick what you want to fix; the Fix column says what each route will do.', 640));
H2('The filters');
T('Five checkboxes, and the defaults are chosen to match what the ACS console shows you first:');
push([Bul('Your workloads and Platform components. On by default and off by default respectively, the same split the ACS console applies. Platform violations are real and worth seeing, but they are not yours to fix, and mixing them into your queue makes your queue look worse and less actionable than it is.'),
      Bul('Matched to a policy and Unmatched. A violation the catalogue cannot map to a policy is still shown, under its own filter, rather than dropped.'),
      Bul('Fixable only, for when you want the work queue rather than the picture.')]);
T('Click any row to open the rationale, the standards the policy maps to, the cluster and lifecycle stage it came from, and the reasoning behind the fix route it was given.');
H2('Severity and Score are two different things');
T('Severity is what your ACS reported. If your team has tuned a policy, that is the tuned value, and it is what your cluster believes.');
T('Score is this tool\'s own CVSS style ranking of the weakness class, fixed per policy in the catalogue. The two can disagree, and where they do it is usually because the policy was tuned rather than because something is wrong.');
T('Sort by Score to order the work inside a severity band. Four severity buckets tell you which pile a finding is in; the score tells you where in the pile. A violation this tool does not model shows an em dash rather than a zero, because zero would sort it below every real finding and read as harmless rather than as not assessed.');
H2('The fix routes');
T('Six routes, and which one a violation gets depends on what the tool can see:');
push([Tbl(['Route', 'What it means', 'What you do'], [
  ['In your YAML', 'The manifest for this object is loaded, so the fix can be made in the real file.', 'Use the Remediate tab. You get a diff, a confirmation, and undo.'],
  ['Patch', 'ACS reported it, you did not load the manifest, but the violation carries enough to draft a patch.', 'Draft the YAML, review it, test it, apply it.'],
  ['Need manifest', 'Fixable in principle, but the violation does not carry enough to draft a patch safely.', 'Load the manifest, then it becomes an in place fix.'],
  ['Human decision', 'The policy has no mechanical fix. A network policy or an image provenance rule is a decision, not an edit.', 'Read the remediation text and decide.'],
  ['Platform', 'A platform component.', 'Do not patch it. See below.'],
  ['Not modelled', 'No policy in the catalogue matches this one.', 'Add it to the catalogue, or handle it in ACS.'],
], [1700, 4200, 3400])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Platform components, and when the tool is guessing');
T('A violation on a platform component is listed and refused by default. That default is right: objects reconciled by an operator get reverted, usually within seconds and without telling you, so the edit does not fix the violation and does add drift that is now harder to see because somebody made a change that looks deliberate.');
T('But the classification is not always ACS\'s, and the difference matters:');
push([Tbl(['The row says', 'What that means', 'How much to trust it'], [
  ['ACS said so', 'ACS sent platformComponent on the alert.', 'Authoritative. ACS knows what the cluster operators own.'],
  ['guessed from namespace', 'ACS did not send the field, so the namespace was matched against a platform pattern instead.', 'A guess, and wrong in both directions. Your own workload in openshift-operators matches it. A platform component elsewhere does not.'],
], [2200, 3900, 3200])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('warn', 'Every platform refusal can be overridden, per object', [
  'Press override on the row. If the classification was a guess, the normal fix routes apply immediately. If ACS itself reported it as platform, you are asked to confirm first, because that claim is authoritative and you are contradicting it.',
  'It is never global. Overriding one object does not release the others, and it does not bypass the mode gate: report mode still writes no YAML.',
  'The drafted file says on its face that it was overridden and that an operator may revert it, so the next person to read that patch knows what they are holding.',
  'From the command line: --override-platform Deployment/cert-manager-webhook, taking the same identifiers as --select.']));
T('This exists because the earlier behaviour produced a dead end. A privilege escalation finding on a workload a team owned, sitting in a namespace that happened to match the pattern, was refused forever with no way to say "this one is mine". The tool had decided on their behalf, and had not mentioned that it was guessing.');
H2('Choosing which ones to fix');
T('Each row carries a checkbox. Nothing is ticked when the table first renders, and the draft button stays disabled until something is, which is the same reasoning as report mode being the default: the state you get by doing nothing is the state that does nothing.');
push([Bul('The box in the table header ticks or clears every fixable violation currently shown. Currently shown, not everything imported. Selecting rows you have filtered out of view is how somebody ends up drafting a patch for a namespace they had deliberately excluded.'),
      Bul('A violation with no fix route this tool can take, a platform component for instance, gets a disabled checkbox rather than no checkbox. Hover it for the reason. A missing control looks like an oversight; a disabled one with a tooltip is an answer.'),
      Bul('The selection follows the violation, not the row. Change a filter or sort a column and your ticks stay on the same violations. The count next to the button tells you if some of what you selected is currently hidden.'),
      Bul('A violation imported after you made a selection does not arrive pre ticked. Consent given for one finding does not extend to findings you have not seen yet.')]);
push(Note('info', 'The report records the scope, not just the fixes', [
  'If you drafted fixes for four violations out of thirty, the written account says so at the top and states that the other twenty six are not described anywhere in it.',
  'This matters six months later. A document covering a subset reads identically to a document covering the whole cluster unless it says which one it is, and the person reading it then is usually not the person who generated it.']));
H2('Drafting the fix');
T('Press Draft fixes for the ones you selected. What comes out is YAML files and a written account, and nothing else. No command is run. No cluster is contacted. Nothing is applied.');
T('Each drafted file carries a header naming the object, the namespace, the policies it covers, and the fact that it was built from a violation rather than from a manifest the tool has read, which is exactly why it needs a human to look at it before it goes anywhere. Where several policies apply to the same object they are merged into one file, because you apply a patch to an object once, and ten files for the same Deployment is not ten fixes.');
push(Note('info', 'One warning the header will sometimes carry, and why it matters', [
  'A strategic merge patch keys the containers array on name. If the container name could not be read out of the violation text, the patch would add a nameless container to your Deployment rather than patching the one you meant.',
  'The tool does not guess. It emits the patch with the name blank and puts a warning in the header telling you to fill it in. Read the header before you apply anything.']));
T('The same thing from the command line, where the mode is explicit for the same reason it is explicit in the page:');
push(Code(['# the default. An account of what could be fixed, and no YAML at all.',
           'node acs_cli.js --alerts 02_alerts_full.json --violation-fixes',
           '',
           '# the YAML itself, for everything.',
           'node acs_cli.js --alerts 02_alerts_full.json --violation-fixes --mode manual --out fixes']));
T('The checkboxes have a command line equivalent. See what is there, then name what you want:');
push(Code(['# the menu: every violation, its key, its object and its fix route. Writes nothing.',
           'node acs_cli.js --alerts 02_alerts_full.json --list-violations',
           '',
           '# then act on a subset. Takes an alert id, an object, or a policy id.',
           'node acs_cli.js --alerts 02_alerts_full.json --violation-fixes --mode manual \\',
           '  --select Deployment/payments-api,ACS.004 --out fixes']));
push(Note('warn', 'A --select term that matches nothing is an error, not a warning', [
  'The command exits non zero, names the term that matched nothing, and writes no files.',
  'This is deliberate and it is the opposite of how most tools treat a bad filter. A typo in a narrowing option does not narrow less, it fails to narrow at all, and the run you thought was scoped to one Deployment quietly covers the cluster. Failing is the safe direction.',
  'Omitting --select entirely still means everything, which is how the tool behaved before the option existed. That is the one permissive default here, and it is only for compatibility.']));
T('Then review the files, apply them to a namespace you do not care about, confirm the workload still runs, and only then take them to the change you actually care about.');

H2('Cross checking against what you have in git');
T('If you loaded manifests as well, findings that appear in both are marked live in ACS. That marking is worth more than it looks: it tells you the problem is not theoretical, it exists in a running cluster right now, and it should jump the queue.');
T('The cross check earns its keep in both directions.');
push([Bul('In the manifest but not in ACS. The namespace may be outside ACS coverage, or a policy exception may be suppressing it. Both are worth confirming rather than assuming.'),
      Bul('In ACS but not in your manifests. Either the manifest is not in the set you loaded, or the cluster has drifted away from git. Drift is a finding in its own right.')]);
H2('Policy name matching');
T('ACS renames policies between releases and most teams tune them, so exact string matching alone would silently lose violations. The importer falls back through three stages: exact match, then a table of known naming variants across ACS versions, then token scoring with stemming and a best match tie break. A violation that still cannot be matched is surfaced as unmatched rather than discarded, because a scanner that throws away what it does not understand looks exactly like a scanner that found nothing.');

// ---------------- 7
H1('11. Applying fixes');
T('Switch to the Remediate tab. It works on the same files you already loaded, with the same findings the Audit tab scored, and it offers three ways to work through the fixes. All three show a real diff computed against your actual file, not a description of what might happen.');
push(Fig(F('fig3_step_through.png'), 'Figure 3. Step through mode. One fix at a time, with the diff, the rationale, and the standards behind it.', 640));
H2('Step through one by one');
T('The most careful option, and the one to use the first few times. It presents one fix at a time with the policy that triggered it, why it matters, exactly what will change as a diff, and the citations behind the recommendation. Your choices are Apply and continue, Skip this one, or Stop here. A progress bar tracks how far through the queue you are.');
H2('Review and apply all');
T('Previews the entire batch as one combined diff, grouped by file, with a summary of every change. A single confirmation applies the lot. Use this once you have seen what the fixes look like and trust the classification.');
H2('Fix this, per row');
T('Every automatically fixable finding in the table has its own button, with the same confirmation dialog. Use it when you want three specific fixes and nothing else.');
H2('Preview never mutates');
T('Preview and commit are separate code paths. Generating a preview builds the change against a scratch copy and throws it away. Nothing in your loaded files changes until you confirm. This is asserted directly by the test suite rather than left as a claim.');
H2('Confirmation and undo');
push([Bul('Every route asks for confirmation before it writes. There is a checkbox to suppress the prompt once you trust it. It is off by default and it resets when you reload.'),
      Bul('Undo last steps back one fix. Undo everything returns the files to exactly how they were loaded. The test suite verifies the restore byte for byte, not just structurally.')]);

H2('Working a list of a thousand findings');
T('A first run against a real cluster returns findings in the hundreds or thousands. A flat list that long is not a work queue, it is a wall, so the findings table filters and every row is selectable.');
push([Bul('Severity. Critical and High with the rest unticked is the top of the list.'),
      Bul('Fix kind: auto, generate, manual, or already applied. Ticking auto alone gives you exactly what can be exported.'),
      Bul('Weakness class. Privileges on its own is every privilege escalation finding, which is usually where the first pass goes.'),
      Bul('ACS policy, when you are working one policy across the estate.')]);
T('The class and policy pickers are built from what was actually found rather than from the whole catalogue, so you never pick an option that returns nothing.');
T('The heavy sections collapse, and each header carries its count. The count is the point rather than the collapsing: a header reading showing 84 of 1104, 1104 open, 40 critical tells you both where to start and that a filter is hiding most of the list. A narrowed list looks like a shorter one, and a shorter one reads as a cleaner cluster.');
push(Note('info', 'Selection follows the finding, not the row', [
  'Ticks are held against the finding itself, so filtering and sorting cannot move a tick onto something else. Select a critical, filter it out of view, and it is still selected when you come back.',
  'Select all shown takes every fixable finding currently visible, which is deliberately not everything loaded. A finding with no mechanical fix gets a disabled checkbox naming the reason, rather than no checkbox, so the absence of an option reads as an answer instead of an oversight.']));

H2('Corrected YAML for a chosen subset, from the browser');
T('The scan runs on a Linux box, the files are copied to a Windows machine, and the review happens there. Neither end has Node and neither can be given it. So the browser is not a preview of the fix, it is what produces it.');
T('Tick what you want, choose Manual or Auto, and press Download corrected YAML. You get a ZIP holding a corrected folder with your manifests rewritten in the layout you loaded them in, plus READ_THIS_FIRST.md recording every change applied, every fix that can stop a workload, every placeholder value still needing tuning, and anything that could not be applied and why.');
T('The export runs against a copy. Nothing in the page moves, the undo history is untouched, and you can export one severity band, review it, then export another without the two interfering.');
push(Note('crit', 'Exporting is not applying', [
  'No command runs, from the browser or from anywhere else. The tool has no path to your cluster and is not given one. What you get is files.',
  'Nothing in that ZIP reaches a cluster until you put it there through your own change process. Run oc apply -f corrected/ --dry-run=server first: it asks the API server what it would do, which catches an admission controller rejecting the change before you find out during a rollout.',
  'In report mode the export controls are disabled and the page names the control holding them, so a greyed out button reads as a deliberate gate rather than a broken tool.']));

// ---------------- 8
H1('12. What gets fixed automatically, and what deliberately does not');
push(Note('crit', 'Automatic describes the edit, not your application', [
  'An automatic fix means the change to the YAML is unambiguous: there is one correct value and the tool knows it. It says nothing about whether your workload survives the change.',
  'Four of them remove something an application may be relying on. readOnlyRootFilesystem on anything that writes to disk. Dropping all capabilities from an image that needs one. runAsNonRoot against an image with no numeric non root user, which the kubelet refuses to start at all. Unmounting the service account token from a pod that calls the Kubernetes API.',
  'Each carries a note naming the specific failure and the remedy, and it appears in the confirmation dialog, the change log, the drafted patch header, the command line output and its own section in the report. Apply them in a namespace you do not care about first, and watch the pod actually start.']));


T('Fixes carry one of three classifications, and choosing that classification correctly is the most consequential judgment in the tool.');
H2('Auto');
T('One correct change with no plausible downside. Thirteen policies qualify: privileged, allowPrivilegeEscalation, readOnlyRootFilesystem, host network, host PID, host IPC, CAP_SYS_ADMIN and capability drops, runAsNonRoot, CPU and memory requests and limits, automountServiceAccountToken, privileged host ports, and rewriting a hardcoded credential in an environment variable to a secretKeyRef.');
H2('Generate');
T('Creates a new object rather than editing an existing one. Currently one policy: the default deny NetworkPolicy, emitted with DNS egress already permitted so it does not break name resolution the moment you apply it.');
H2('Manual');
T('The correct answer depends on context the scanner cannot see, so the finding is explained in full and the file is left alone.');
push([Bul('Pinning an image digest instead of the latest tag requires knowing which build is blessed.'),
      Bul('Removing a hostPath mount requires a storage decision.'),
      Bul('Replacing the default service account requires the replacement to exist first.'),
      Bul('Removing a container runtime socket mount usually means redesigning whatever needed it.')]);
T('Guessing at these breaks working systems. A security tool that breaks production gets switched off, and a switched off tool leaves you less secure than you were before it was installed.');
push(Note('warn', 'Three fixes need your attention after they are applied', [
  'The CPU and memory fixes insert placeholder values. They are flagged as PLACEHOLDER in the confirmation dialog and again in the change log. Tune them to your workload before you deploy, or you will trade a missing limit for a wrong one.',
  'The secret rewrite points the environment variable at a secretKeyRef, but it cannot un-leak a credential that is already in git history. Rotate the credential. The fix is flagged for exactly this reason.']));

// ---------------- 9
H1('13. Taking the result out');
H2('What is in the audit report');
T('The HTML report is the artifact that outlives the session and gets attached to a ticket or an accreditation package, so everything visible in the page reaches it:');
push([Bul('The posture summary and the per category breakdown, when manifests were scanned. When none were, it says so and explains why rather than printing a score. See section 14.'),
      Bul('Every finding in your manifests, with the policy, the object, the file, the severity and the fix classification.'),
      Bul('Every violation ACS reported, split into your workloads and platform components, each with its fix route. The platform section states whether that split came from the ACS platformComponent field or from a namespace match, because those are different claims.'),
      Bul('Image CVEs, when a vulnerability export was supplied, ranked and kept visually separate from the configuration posture so nobody adds the two together.'),
      Bul('The method, the limits, and the references, so a reviewer can see what the numbers mean without asking you.')]);
push(Note('warn', 'If you have a report from an earlier version that looks empty', [
  'Before 1.2.0 the report rendered only findings from scanned manifests. A run with an ACS export and no YAML produced about five kilobytes of headings and method notes while the page it came from was listing dozens of violations.',
  'Regenerate it. The data was never lost, it just was not written into the document.']));


T('Six export routes, because the right one depends on how your manifests are managed.');
push(Fig(F('fig4_outputs.png'), 'Figure 4. Export options. Patched YAML, a single file, strategic merge patches, the diff, and the change log.', 640));
push([Tbl(['Export', 'Use it when'], [
  ['Patched YAML as a ZIP', 'Your manifests are plain YAML in git. Preserves your exact folder structure and includes the change log.'],
  ['One combined YAML file', 'You want a single artifact to review or diff in one pass.'],
  ['Strategic merge patches', 'Your manifests are templated by Helm or Kustomize and cannot be edited directly. One patch per applied fix.'],
  ['The full diff to clipboard', 'You are pasting into a pull request description, a change ticket, or a chat thread.'],
  ['Change log in markdown', 'You need the audit trail: every change, why it was made, the citations, and everything still awaiting a human decision.'],
  ['Corrected YAML for selected findings', 'You are working a large list on a machine with no Node, and you want files for the subset you ticked rather than for everything. Includes READ_THIS_FIRST.md with the changes, the risky ones and the placeholders.'],
], [3000, 6300])]);
body.push(P('', { spacing: { after: 120 } }));
H2('Why the merge patches are worth understanding');
T('Each patch carries only the fields that actually changed, and container arrays are keyed on the container name, which is how Kubernetes merges those arrays. That is deliberate. A naive patch that includes the whole container array would carry the image field along with it and silently revert an image that was updated after your scan. Keying on name means the patch touches the security context and nothing else. The test suite checks patch minimality specifically because this is easy to get wrong and expensive to notice late.');

// ---------------- 10
H1('14. How the score is calculated');
push(Note('warn', 'What the score is measured against', [
  'Twenty policies. Red Hat ACS ships roughly seventy defaults and most teams add their own, so a clean score here means clean against twenty checks. It is not compliance with the ACS default policy set and should never be quoted as such.',
  'Build stage rules, runtime behaviour policies and image CVE policies cannot be judged from a manifest at all. Violations this tool does not model arrive through your ACS export and are shown as unmatched rather than dropped, with the fix route "Not modelled".',
  'Watch the unmatched count after an ACS upgrade. A jump in it means the catalogue has drifted from your ACS version.']));


push(Note('crit', 'When there is no score at all, and why that is the correct answer', [
  'The denominator comes from what was scanned, never from what was found. That is what makes the projected score comparable to a real rescan.',
  'It also means scoring zero manifests returns 100 out of 100, Grade A. That is arithmetically correct and completely misleading: nothing was scanned, so nothing was found. If you load an ACS export and no YAML, the page, the CLI and the report all refuse to show a number and say why.',
  'Unmeasured is not the same as clean. A green A on a cluster nobody has looked at is the worst output a security tool can produce, and this one used to produce it. Your violations and CVEs remain fully usable without a score.']));
T('Every applicable pairing of a policy and an object counts as one check. Checks are weighted by severity, and your score is the percentage of the total available weight that you pass.');
push([Tbl(['Severity', 'Weight', 'Grade band', 'Score'], [
  ['Critical', '18', 'A', '90 and above'],
  ['High', '10', 'B', '80 to 89'],
  ['Medium', '5', 'C', '70 to 79'],
  ['Low', '2', 'D', '60 to 69'],
  ['', '', 'F', 'below 60'],
], [2300, 1500, 2300, 3200])]);
body.push(P('', { spacing: { after: 140 } }));
push(Note('info', 'The rule that makes the before and after numbers comparable', [
  'The denominator is derived only from what was scanned, never from what was found.',
  'If a check dropped out of the total the moment it started passing, fixing things would shrink the denominator and the projected score would not survive a rescan. Keeping every applicable check in the total means the projection you see before you apply is the score you get after you apply. This was a real defect during development, caught because a projection of 60 rescanned as 57, and there is now a regression test that fails against the old logic and passes against the current one.']));

// ---------------- 11
H1('15. Policy reference');
T('Twenty policies, modelled on the ACS defaults. Check them against your own ACS version before treating them as authoritative, since defaults shift between releases and most teams tune them.');
push([Tbl(['ID', 'ACS policy', 'Severity', 'Score', 'Fix'], [
  ['ACS.001', 'Privileged Container', 'High', '8.8', 'Auto'],
  ['ACS.002', 'Container using read write root filesystem', 'Medium', '5.3', 'Auto'],
  ['ACS.003', 'Container with privilege escalation allowed', 'High', '7.8', 'Auto'],
  ['ACS.004', 'Deployments should not have host network configured', 'High', '8.1', 'Auto'],
  ['ACS.005', 'Deployments should not have host PID configured', 'High', '7.8', 'Auto'],
  ['ACS.006', 'Deployments should not have host IPC configured', 'Medium', '6.5', 'Auto'],
  ['ACS.007', 'CAP_SYS_ADMIN capability added', 'High', '8.8', 'Auto'],
  ['ACS.008', 'Container does not drop all capabilities', 'Medium', '6.3', 'Auto'],
  ['ACS.009', 'Deployments should not run as root user', 'High', '7.8', 'Auto'],
  ['ACS.010', 'Environment Variable Contains Secret', 'Critical', '9.1', 'Auto'],
  ['ACS.011', 'Mounting Container Runtime Socket', 'Critical', '9.3', 'Manual'],
  ['ACS.012', 'Deployment mounts sensitive host directory', 'High', '8.8', 'Manual'],
  ['ACS.013', 'No CPU request or limit specified', 'Medium', '5.5', 'Auto'],
  ['ACS.014', 'No memory request or limit specified', 'Medium', '5.5', 'Auto'],
  ['ACS.015', 'Latest tag', 'Medium', '5.9', 'Manual'],
  ['ACS.016', 'Pod Service Account Token Automatically Mounted', 'Medium', '6.5', 'Auto'],
  ['ACS.017', 'Deployment uses the default service account', 'Medium', '5.3', 'Manual'],
  ['ACS.018', 'Deployments should have at least one ingress Network Policy', 'Medium', '6.5', 'Generate'],
  ['ACS.019', 'Docker CIS 5.7: do not map privileged ports within containers', 'Low', '3.7', 'Auto'],
  ['ACS.020', 'Kubernetes Dashboard Deployed', 'High', '7.5', 'Manual'],
], [1100, 4500, 1200, 900, 1000])]);
body.push(P('', { spacing: { after: 140 } }));
T('Every finding also carries citations to the CIS Kubernetes Benchmark, NIST SP 800-53 Rev 5, the Kubernetes Pod Security Standards, and DISA STIG. Press View the policy catalogue on the Audit tab to read the full entry for any policy, including the rationale and the remediation text.');

// ---------------- 12
H1('16. Limits, stated plainly');
push([Bul('This is static analysis of manifest text. The page never contacts a cluster at all. The scripts do, and they only ever issue a GET.'),
      Bul('It is not a replacement for ACS, for admission control such as Pod Security Admission or Kyverno, or for runtime enforcement. It is a way to fix the manifest before any of those have to reject it.'),
      Bul('ACS policies that evaluate build metadata or runtime process behaviour cannot be judged from YAML at all. Those violations are reported as unmatched rather than pretended away.'),
      Bul('Image CVEs are pulled from ACS, not discovered by this tool. It does no scanning of its own. If ACS has not scanned an image, this tool has nothing to report about it, and it says so rather than showing a reassuring zero.'),
      Bul('CVE data is a point in time snapshot of what the ACS feeds knew when the export ran. It ages. Re-export rather than trusting yesterday\'s file.'),
      Bul('STIG references are mapping aids. Verify them against the current DISA release before citing them in an accreditation package.'),
      Bul('Policy names, severities, and remediation text are modelled on ACS defaults with the structure verified against the upstream StackRox definitions at github.com/stackrox/stackrox. Confirm against your own version.')]);

// ---------------- 13
H1('17. Troubleshooting');
push([Tbl(['Symptom', 'Cause and fix'], [
  ['Folder upload opens a second dialog', 'Your browser does not support the File System Access API and fell back to a directory input. Pick the folder once in the fallback dialog. Chrome and Edge take the single action path.'],
  ['Looking for the connect button from an older version', 'Removed, deliberately. It could never work from a file:// page and the token risk was real while the benefit was zero. Use scripts/acs_pull_all.sh. See section 7.'],
  ['Certificate error running the pull script', 'Central uses an internal CA. Pass --cacert with your CA bundle. Do not reach for the insecure flag on a request carrying a bearer token.'],
  ['Dropped six files and only one appeared', 'Fixed. Imports now accumulate and deduplicate rather than replacing each other. If you are on an older copy, that is the symptom, and updating is the fix.'],
  ['A file is rejected with "expected Kubernetes or OpenShift objects"', 'The page now says what the file actually is instead. The most common case is dropping the tool\'s own findings export back in: that is a record of a previous run, not an input, and it has no manifests in it to rescan.'],
  ['Violations import but there is nothing to click', 'You are on an older copy. Violations are rows with a fix route on each one. See section 10.'],
  ['Posture shows 100 and grade A with ACS data loaded', 'Fixed. That was a score over zero manifests: an empty denominator reads as perfect. The page and the CLI now refuse the number and say so. If you still see it, you are on an older copy.'],
  ['A privilege escalation finding shows Platform and offers no fix', 'Check whether the row says ACS said so or guessed from namespace. If it is a guess and you own the object, press override. See section 10.'],
  ['ACS violations import but nothing is marked live', 'Policy names did not match. Check the unmatched list. If a name in your ACS version is missing from the alias table, it belongs in acs_policies.js. See the administration guide.'],
  ['Alerts come back with a policy name but no explanation', 'You fetched the list without the detail. GET /v1/alerts returns ListAlert, which has no violations array. Tick Fetch violation detail. See section 7.'],
  ['Zero alerts returned and the cluster is clearly not clean', 'Three usual causes: the query defaults to active violations only, the token is scoped to fewer namespaces than you think, or you are looking for CVEs, which never appear here at all. Use the Vulnerabilities tab.'],
  ['403 on the vulnerability tab but the violations tab works', 'The token can read Alert but not Image and Deployment. The export needs both. This is the single most common cause of an empty CVE pull.'],
  ['404 on /v1/export/vuln-mgmt/workloads', 'The endpoint exists in ACS 3.74 and later. On an older Central use roxctl or the GraphQL API.'],
  ['The vulnerability pull returns no CVEs', 'Most often the images have not been scanned yet, or the namespace filter matched nothing. An image with no scan data is not an image with no vulnerabilities, and the tool says which it is.'],
  ['The CVE numbers do not match the ACS console', 'Check whether the console view includes deferred and false positive CVEs. This tool excludes them from the active counts and reports them separately.'],
  ['Projected score does not match a rescan', 'Report it. This should not happen and there is a regression test guarding it. Include the manifest set.'],
  ['Nothing happens when a file is dropped', 'Confirm the file parses as YAML. Files that fail to parse are listed rather than silently skipped, so check the file list panel.'],
], [3000, 6300])]);

// ---------------- 14
H1('18. Contact');
T('Questions, bugs, or policy suggestions: github.com/djkidnyce');
T('If you are reporting a scoring or matching problem, include the manifest set and, where you can share it, the ACS export. Both are needed to reproduce a match failure.');

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
  sections: [Object.assign({}, pageSetup("DJ's ACS Auditor  |  User Guide"),
    { children: [...title, ...toc, ...body] })],
});
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(__dirname + '/DJ_ACS_Auditor_User_Guide.docx', b); console.log('WROTE', b.length, 'bytes'); });
