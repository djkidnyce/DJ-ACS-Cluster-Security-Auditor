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
    'The two live connect features described in section 6 are read only HTTP GET calls that pull manifests and violations in. Nothing is ever pushed back out.']),
  new Paragraph({ children: [new PageBreak()] }),
];

const toc = [
  P('Contents', { heading: HeadingLevel.HEADING_1 }),
  ...['1. What this tool does','2. Report, manual, or auto','3. Before you start','4. Quick start',
      '5. Loading manifests and reading the audit','6. Pulling straight from your cluster',
      '7. Vulnerabilities: why an empty alert list proves nothing',
      '8. Working the CVE list','9. Cross checking against your ACS export','10. Applying fixes',
      '11. What gets fixed automatically, and what deliberately does not','12. Taking the result out',
      '13. How the score is calculated','14. Policy reference','15. Limits, stated plainly',
      '16. Troubleshooting','17. Contact'].map((t) => P(t, { spacing: { after: 90 }, size: 22 })),
  P('Figures', { bold: true, size: 22, spacing: { before: 240, after: 90 } }),
  ...['Figure 1. The auditor after a scan (section 5)',
      'Figure 2. The live connect panel (section 6)',
      'Figure 7. The two ACS data planes (section 7)',
      'Figure 3. Step through remediation (section 10)',
      'Figure 4. Export options (section 12)'].map((t) => P(t, { spacing: { after: 90 }, size: 22, color: MUT })),
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
  ['dj_acs_auditor.html', 'Scan, score, rank, cross check against ACS policy violations and image CVEs, export the report. Read only. It never modifies anything.'],
  ['dj_acs_remediation.html', 'Apply fixes interactively with preview, confirmation, one at a time stepping, and undo.'],
  ['acs_policies.js', 'The policy engine both pages share, so the two can never disagree about a manifest.'],
  ['vendor/', 'js-yaml and JSZip, committed to the repository so the tool needs no package manager and no network access.'],
  ['test/run_tests.js', '531 tests against the real engine, the pages and the command line.'],
], [2700, 6600])]);
body.push(P('', { spacing: { after: 120 } }));
T('Open either HTML file by double clicking it. There is nothing to install, no server to start, and no package manager involved.');


// ---------------- 2 modes
H1('2. Report, manual, or auto');
push(Note('crit', 'You choose the path. Every time. The tool never chooses for you.', [
  'Report is the default on every surface, in the pages and in the command line. The safe state is the one you get by doing nothing, not the one you get by remembering a flag.',
  'An auto fix that nobody selected is a new risk, not a mitigation.']));
push([Tbl(['Mode', 'What it produces', 'Modifies anything'], [
  ['report', 'The analysis: report, findings JSON, SARIF. Nothing that could be applied.', 'No'],
  ['manual', 'Patches and written guidance for a human to review and apply.', 'No'],
  ['auto', 'Applies the safe fixes and writes corrected YAML, with a preview and a confirmation for each change.', 'Yes'],
], [1400, 5900, 2000])]);
body.push(P('', { spacing: { after: 140 } }));
H2('Why this is a security control rather than a convenience');
T('A remediation tool that can write before the operator has chosen to write is a new risk, not a mitigation. The failure mode is not the tool doing something malicious. It is somebody at the end of a long incident clicking the obvious button, producing a change to a production manifest they did not intend, and then defending it in review because a plausible looking diff is attached to it.');
T('Three rules follow from that, and they are enforced identically in the pages, the command line, and every file either of them writes.');
push([Bul('The mode is never inferred from anything else. Asking for patches does not put you in manual mode. You choose the mode, then you ask for the output.'),
      Bul('An unknown mode is an error, never a quiet fall back to something permissive. A typo that lands you in a writing mode is exactly the failure this exists to prevent.'),
      Bul('The mode is recorded in every artifact. A reviewer holding a patch should not have to ask which path produced it.')]);
H2('On the pages');
T('The remediation page opens in report mode and nothing on it will change a file until you move off it. The mode gates the buttons and the handlers, not just the buttons: calling the apply functions directly from the browser console in report mode still refuses, because a disabled attribute is a hint about state, not a control over it.');
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
H1('3. Before you start');
H2('Requirements');
push([Bul('A current browser. Chrome, Edge, Firefox, or Safari. The pages use the File System Access API for folder upload where available and fall back to a directory input where it is not.'),
      Bul('The YAML you want audited, either as loose files or a whole folder tree.'),
      Bul('Optional: a violation export from ACS Central, or a live token if you plan to pull from the cluster directly.')]);
H2('What the tool never asks for');
T('It does not ask for cluster write access, a kubeconfig, a service account, an admission webhook, or anything installed on a node. If a workflow ever seems to want one of those, you are not in this tool.');
H2('Working disconnected');
T('Everything the pages need is committed alongside them. js-yaml and JSZip are vendored, so a machine with no route to the internet, no npm, and no proxy runs the tool identically to one that is fully connected. This matters on classified and air gapped networks, where the usual answer of "just npm install it" is not available.');

// ---------------- 3
H1('4. Quick start');
push(NumList(['Open dj_acs_auditor.html.',
  'Drag your manifest folder onto the drop zone, or press Browse folder.',
  'Read the posture cards at the top. They tell you the weighted compliance score now and what it becomes once the safe fixes are applied.',
  'Sort the findings table by Score to see what hurts most.',
  'Press Download the audit report to keep the evidence, then move to dj_acs_remediation.html to actually fix it.']));
push(Note('ok', 'Want to see it work before trusting it with real manifests', [
  'Both pages have a Load a deliberately bad sample button. It loads a small manifest set that trips a spread of policies across every severity, so you can walk the full workflow, apply fixes, and undo them without touching anything of yours.']));

// ---------------- 4
H1('5. Loading manifests and reading the audit');
T('Figure 1 shows the auditor after a folder has been loaded. Everything on the page is derived from the files you dropped in. Nothing is fetched, and nothing is remembered between sessions.');
push(Fig(F('fig1_auditor_overview.png'), 'Figure 1. The auditor after a scan. Posture cards, category breakdown, and the sortable findings table.', 640));
H2('The posture cards');
T('The left card is your weighted compliance score as the manifests stand today. The right card is the projected score once every automatic fix is applied. The difference between them is the honest value of running the remediation page, and section 13 explains exactly how both numbers are computed.');
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
H1('6. Pulling straight from your cluster');
T('Both pages carry a live connect panel. It has two tabs. The OpenShift tab pulls the live workload objects out of the cluster API so you can audit what is actually deployed rather than what you think is deployed. The ACS tab pulls violations out of ACS Central so findings can be marked as confirmed in a running cluster.');
push(Fig(F('fig2_live_connect.png'), 'Figure 2. The live connect panel, showing the ACS Central tab. The OpenShift API tab sits beside it.', 640));
H2('OpenShift API tab');
push(NumList(['API URL: your cluster API endpoint, for example https://api.example.com:6443. You can get it with oc whoami --show-server.',
  'Token: a bearer token. The quickest source is oc whoami -t once you are logged in.',
  'Namespace: optional. Leave it blank to sweep every namespace you can read, or name one to scope the pull.',
  'Press Pull live workloads.']));
T('The tool requests Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, and Pods, then sanitises each object before it goes anywhere near the scanner.');
H2('What sanitising removes, and why it matters');
T('A live object from the API is not a manifest. It carries server side bookkeeping that would be wrong, noisy, or actively dangerous to write back into git. The tool strips it:');
push([Bul('managedFields, resourceVersion, uid, selfLink, generation, and creationTimestamp, all of which are assigned by the API server.'),
      Bul('ownerReferences, so a Pod created by a ReplicaSet does not carry a dangling parent link into your repository.'),
      Bul('The entire status block, which is observed state and not something you declare.'),
      Bul('The kubectl.kubernetes.io/last-applied-configuration annotation, which is a stale copy of the object embedded inside the object.')]);
T('Meaningful annotations survive. If stripping annotations would leave an empty map, the map itself is removed rather than left as an empty stub, which keeps the emitted YAML clean. The test suite asserts all of this, including that a sanitised object remains fully scannable and fixable.');
H2('ACS Central tab');
push(NumList(['Central URL: the route to ACS Central, for example https://central-stackrox.apps.example.com.',
  'Token: an ACS API token. Generate one in the ACS console under Platform Configuration, Integrations, Authentication Tokens. A read only role is sufficient and is what you should use.',
  'Query: optional ACS search syntax, for example Severity:CRITICAL_SEVERITY, to narrow what comes back.',
  'Press Fetch violations.']));
T('The tool calls the /v1/alerts endpoint with an Authorization bearer header. Every violation returned is matched back to a policy in the catalogue, and any violation that cannot be matched to a manifest is reported separately rather than quietly dropped.');
H2('Token handling');
push(Note('warn', 'Read this before you paste a token', [
  'Both token fields are password inputs, so the value is masked on screen and excluded from browser autofill history.',
  'The token is held in a variable for the duration of the request and cleared afterward. It is never written to localStorage, sessionStorage, IndexedDB, or a cookie. It is never included in the audit report, the JSON export, the change log, or any downloaded file. This has been verified by grep across every shipped file and is covered by the test suite.',
  'It is still a live credential in a browser tab. Use a short lived, least privilege token. For OpenShift, oc whoami -t returns a token tied to your session, which expires. For ACS, create a dedicated read only token rather than reusing an admin one, and revoke it when you are finished.']));
H2('When the connection fails');
T('The most common failure is not a bad token. It is the browser blocking the request before it leaves, because a page opened from disk has a null origin and neither the OpenShift API server nor ACS Central sends a header permitting it. This is the browser working correctly.');
T('The tool classifies the failure and tells you which one you hit rather than showing a generic error. Three ways forward:');
push([Bul('Add your origin to spec.additionalCORSAllowedOrigins on the APIServer resource. This is a cluster change and needs a change request in most environments.'),
      Bul('Serve the page from an origin the API already trusts, such as a route on the cluster itself.'),
      BulRich([{ t: 'Use the offline path. Press ' }, { t: 'Show the offline command instead', b: true },
               { t: ' and the tool prints a ready to run curl or oc command with your URL already filled in. Run it in a terminal, save the output, and drop the file onto the page. Same result, no cluster change, and it is usually the fastest route in a locked down environment.' }])]);

// ---------------- 6
// ---------------- 6 vulnerabilities
H1('7. Vulnerabilities: why an empty alert list proves nothing');
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
  'Open the Vulnerabilities (CVEs) tab in the live connect panel.',
  'Enter the Central URL and an API token with read on Image and Deployment. Scope by namespace if the cluster is large, because a full export is slow.',
  'Press Pull vulnerability data.',
  'Or, if the browser blocks the call, press Show the offline command instead, run the curl it generates, and drop the resulting .ndjson file onto the drop zone with your manifests.']));

// ---------------- 7 working the CVE list
H1('8. Working the CVE list');
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
  'What the tool does instead: ranks the work, names the file, and emits a rebuild worklist grouped by image, because you rebuild an image once and every fixable CVE inside it clears together. Then, on the remediation page, you can apply a replacement image reference that you supply, with the same preview, confirmation and undo as every other fix.']));
H2('The image worklist');
T('Download the image worklist gives you a markdown document grouped by image rather than by CVE. For each image it lists the fixable CVEs with the package versions to move to, the ones with no published fix that rebuilding will not clear, the workloads using it, and the manifest files that declare it. Accepted risk is listed at the end for the record.');
T('A list organised by CVE looks like progress and cannot be actioned. A list organised by image is a set of rebuilds.');

// ---------------- 8
H1('9. Cross checking against your ACS export');
T('You do not need a live connection to use ACS data. Export violations from ACS Central or produce a roxctl JSON report, then drop that file onto the page alongside your YAML. The importer accepts all three export shapes.');
T('Findings that appear in both your manifests and your ACS data are marked live in ACS. That marking is worth more than it looks: it tells you the problem is not theoretical, it exists in a running cluster right now, and it should jump the queue.');
H2('Reading the disagreements');
T('The cross check earns its keep in both directions.');
push([Bul('In the manifest but not in ACS. The namespace may be outside ACS coverage, or a policy exception may be suppressing it. Both are worth confirming rather than assuming.'),
      Bul('In ACS but not in your manifests. Either the manifest is not in the set you loaded, or the cluster has drifted away from git. Drift is a finding in its own right.')]);
H2('Policy name matching');
T('ACS renames policies between releases and most teams tune them, so exact string matching alone would silently lose violations. The importer falls back through three stages: exact match, then a table of known naming variants across ACS versions, then token scoring with stemming and a best match tie break. A violation that still cannot be matched is surfaced as unmatched rather than discarded, because a scanner that throws away what it does not understand looks exactly like a scanner that found nothing.');

// ---------------- 7
H1('10. Applying fixes');
T('Open dj_acs_remediation.html. It loads manifests the same way the auditor does, and it offers three ways to work through the fixes. All three show a real diff computed against your actual file, not a description of what might happen.');
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

// ---------------- 8
H1('11. What gets fixed automatically, and what deliberately does not');
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
H1('12. Taking the result out');
T('Five export routes, because the right one depends on how your manifests are managed.');
push(Fig(F('fig4_outputs.png'), 'Figure 4. Export options. Patched YAML, a single file, strategic merge patches, the diff, and the change log.', 640));
push([Tbl(['Export', 'Use it when'], [
  ['Patched YAML as a ZIP', 'Your manifests are plain YAML in git. Preserves your exact folder structure and includes the change log.'],
  ['One combined YAML file', 'You want a single artifact to review or diff in one pass.'],
  ['Strategic merge patches', 'Your manifests are templated by Helm or Kustomize and cannot be edited directly. One patch per applied fix.'],
  ['The full diff to clipboard', 'You are pasting into a pull request description, a change ticket, or a chat thread.'],
  ['Change log in markdown', 'You need the audit trail: every change, why it was made, the citations, and everything still awaiting a human decision.'],
], [3000, 6300])]);
body.push(P('', { spacing: { after: 120 } }));
H2('Why the merge patches are worth understanding');
T('Each patch carries only the fields that actually changed, and container arrays are keyed on the container name, which is how Kubernetes merges those arrays. That is deliberate. A naive patch that includes the whole container array would carry the image field along with it and silently revert an image that was updated after your scan. Keying on name means the patch touches the security context and nothing else. The test suite checks patch minimality specifically because this is easy to get wrong and expensive to notice late.');

// ---------------- 10
H1('13. How the score is calculated');
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
H1('14. Policy reference');
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
T('Every finding also carries citations to the CIS Kubernetes Benchmark, NIST SP 800-53 Rev 5, the Kubernetes Pod Security Standards, and DISA STIG. Press View the policy catalogue on the auditor page to read the full entry for any policy, including the rationale and the remediation text.');

// ---------------- 12
H1('15. Limits, stated plainly');
push([Bul('This is static analysis of manifest text. It does not query a cluster unless you explicitly use the live connect panel, and even then it only reads.'),
      Bul('It is not a replacement for ACS, for admission control such as Pod Security Admission or Kyverno, or for runtime enforcement. It is a way to fix the manifest before any of those have to reject it.'),
      Bul('ACS policies that evaluate build metadata or runtime process behaviour cannot be judged from YAML at all. Those violations are reported as unmatched rather than pretended away.'),
      Bul('Image CVEs are pulled from ACS, not discovered by this tool. It does no scanning of its own. If ACS has not scanned an image, this tool has nothing to report about it, and it says so rather than showing a reassuring zero.'),
      Bul('CVE data is a point in time snapshot of what the ACS feeds knew when the export ran. It ages. Re-export rather than trusting yesterday\'s file.'),
      Bul('STIG references are mapping aids. Verify them against the current DISA release before citing them in an accreditation package.'),
      Bul('Policy names, severities, and remediation text are modelled on ACS defaults with the structure verified against the upstream StackRox definitions at github.com/stackrox/stackrox. Confirm against your own version.')]);

// ---------------- 13
H1('16. Troubleshooting');
push([Tbl(['Symptom', 'Cause and fix'], [
  ['Folder upload opens a second dialog', 'Your browser does not support the File System Access API and fell back to a directory input. Pick the folder once in the fallback dialog. Chrome and Edge take the single action path.'],
  ['Live connect fails immediately with no network activity', 'Browser blocked it at the origin check. Use Show the offline command instead, or serve the page from a trusted origin. See section 6.'],
  ['Certificate error on connect', 'Your cluster or Central uses an internal CA the browser does not trust. Trust the CA, or use the offline command path.'],
  ['ACS violations import but nothing is marked live', 'Policy names did not match. Check the unmatched list. If a name in your ACS version is missing from the alias table, it belongs in acs_policies.js. See the administration guide.'],
  ['Alerts come back with a policy name but no explanation', 'You fetched the list without the detail. GET /v1/alerts returns ListAlert, which has no violations array. Tick Fetch violation detail. See section 6.'],
  ['Zero alerts returned and the cluster is clearly not clean', 'Three usual causes: the query defaults to active violations only, the token is scoped to fewer namespaces than you think, or you are looking for CVEs, which never appear here at all. Use the Vulnerabilities tab.'],
  ['403 on the vulnerability tab but the violations tab works', 'The token can read Alert but not Image and Deployment. The export needs both. This is the single most common cause of an empty CVE pull.'],
  ['404 on /v1/export/vuln-mgmt/workloads', 'The endpoint exists in ACS 3.74 and later. On an older Central use roxctl or the GraphQL API.'],
  ['The vulnerability pull returns no CVEs', 'Most often the images have not been scanned yet, or the namespace filter matched nothing. An image with no scan data is not an image with no vulnerabilities, and the tool says which it is.'],
  ['The CVE numbers do not match the ACS console', 'Check whether the console view includes deferred and false positive CVEs. This tool excludes them from the active counts and reports them separately.'],
  ['Projected score does not match a rescan', 'Report it. This should not happen and there is a regression test guarding it. Include the manifest set.'],
  ['Nothing happens when a file is dropped', 'Confirm the file parses as YAML. Files that fail to parse are listed rather than silently skipped, so check the file list panel.'],
], [3000, 6300])]);

// ---------------- 14
H1('17. Contact');
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
