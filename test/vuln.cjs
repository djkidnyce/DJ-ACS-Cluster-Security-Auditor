globalThis.jsyaml=require('../vendor/js-yaml.min.js');
const E=require('../acs_policies.js');
let P=0,F=0;const t=(l,c)=>{console.log((c?'  pass  ':'  FAIL  ')+l);c?P++:F++};

/* ============================================================================
 * Fixtures modelled on the real wire shapes, not on what would be convenient.
 *
 * ListAlert  is what GET /v1/alerts returns: no violations array, namespace and
 *            cluster nested under commonEntityInfo.
 * Alert      is what GET /v1/alerts/{id} returns: violations[] present, scoping
 *            fields at the top level.
 * The vuln export is NDJSON: one {"result":{...}} per line.
 *
 * Field names taken from stackrox proto:
 *   api/v1/alert_service.proto, storage/alert.proto,
 *   api/v1/vuln_mgmt_service.proto, storage/image.proto,
 *   storage/vulnerability.proto, storage/cve.proto
 * ========================================================================== */

/* ---- 1. The defect the user hit: /v1/alerts returns nothing usable -------- */

const LIST_ALERTS={alerts:[
 {id:'a1',lifecycleStage:'DEPLOY',state:'ACTIVE',time:'2026-08-10T00:00:00Z',
  policy:{id:'p1',name:'Privileged Container',severity:'HIGH_SEVERITY',
          categories:['Privileges'],description:'Alert on deployments with privileged containers'},
  deployment:{id:'d1',name:'webapp',deploymentType:'Deployment'},
  commonEntityInfo:{clusterName:'ocp-prod',namespace:'prod',clusterId:'c1',namespaceId:'n1'}},
 {id:'a2',lifecycleStage:'DEPLOY',state:'ACTIVE',
  policy:{id:'p2',name:'Environment Variable Contains Secret',severity:'CRITICAL_SEVERITY',categories:['Security Best Practices']},
  deployment:{id:'d1',name:'webapp',deploymentType:'Deployment'},
  commonEntityInfo:{clusterName:'ocp-prod',namespace:'prod'}},
 {id:'a3',lifecycleStage:'DEPLOY',state:'ACTIVE',
  policy:{id:'p3',name:'Mounting Container Runtime Socket',severity:'CRITICAL_SEVERITY',categories:['Privileges']},
  deployment:{id:'d2',name:'legacy-agent',deploymentType:'DaemonSet'},
  commonEntityInfo:{clusterName:'ocp-prod',namespace:'tools'}}
]};

console.log('\nThe ListAlert shape, which is what /v1/alerts actually returns');
const L=E.importAcsViolations(LIST_ALERTS);
t('reads all three ListAlert entries',L.total===3);
t('matches them to policies despite the slim shape',L.imported.length===3);
/* This is the regression. The old code read a.deployment.namespace, which does not exist on
   a ListAlert, so every row came back namespace "unknown" and correlation silently failed. */
t('namespace comes from commonEntityInfo, not deployment',
  L.imported.every(r=>r.namespace!=='unknown'));
t('prod namespace resolved correctly',
  L.imported.filter(r=>r.namespace==='prod').length===2);
t('tools namespace resolved correctly',
  L.imported.filter(r=>r.namespace==='tools').length===1);
t('cluster name resolved from commonEntityInfo',
  L.imported.every(r=>r.cluster==='ocp-prod'));
t('DaemonSet kind preserved from deploymentType',
  L.imported.some(r=>r.obj==='DaemonSet/legacy-agent'));
/* The honest bit: a ListAlert has no violation text, so the tool must say so rather than
   invent one, and must flag that detail is available if you go and get it. */
t('records that no violation text was present',L.imported.every(r=>r.hydrated===false));
t('counts how many rows could be hydrated',L.hydratable===3);
t('falls back to the policy description rather than inventing a violation',
  L.imported[0].detail==='Alert on deployments with privileged containers');
t('carries the alert id so detail can be fetched',L.imported.every(r=>r.acsAlertId));
t('carries lifecycle stage',L.imported.every(r=>r.lifecycleStage==='DEPLOY'));
t('carries ACS categories',L.imported[0].acsCategories.indexOf('Privileges')===0);

/* ---- 2. The full Alert from /v1/alerts/{id} ------------------------------ */

const FULL_ALERT={id:'a1',lifecycleStage:'DEPLOY',state:'ACTIVE',
 clusterId:'c1',clusterName:'ocp-prod',namespace:'prod',namespaceId:'n1',
 policy:{id:'p1',name:'Privileged Container',severity:'HIGH_SEVERITY'},
 deployment:{id:'d1',name:'webapp',type:'Deployment',namespace:'prod',clusterName:'ocp-prod'},
 violations:[{message:'Container "web" is privileged'},{message:'Container "sidecar" is privileged'}]};

console.log('\nThe full Alert shape from /v1/alerts/{id}');
const FA=E.importAcsViolations(FULL_ALERT);
t('a bare single Alert object is accepted',FA.total===1);
t('violation messages are read',FA.imported[0].violations.length===2);
t('marked as hydrated',FA.imported[0].hydrated===true);
t('violations joined into the detail line',/sidecar/.test(FA.imported[0].detail));
t('top level namespace used when commonEntityInfo is absent',FA.imported[0].namespace==='prod');
t('nothing left to hydrate',FA.hydratable===0);

console.log('\nOther entity types are not dropped');
const RES=E.importAcsViolations({alerts:[
 {id:'r1',state:'ACTIVE',policy:{name:'Secret Mounted as Environment Variable',severity:'HIGH_SEVERITY'},
  resource:{name:'db-creds',resourceType:'SECRETS'},commonEntityInfo:{namespace:'prod',clusterName:'ocp-prod'}},
 {id:'n1',state:'ACTIVE',policy:{name:'Some Node Policy',severity:'LOW_SEVERITY'},
  node:{name:'worker-3'},commonEntityInfo:{clusterName:'ocp-prod'}}
]});
t('a resource alert keeps its name',(RES.imported.concat(RES.unmatched)).some(r=>/db-creds/.test(r.obj)));
t('a node alert keeps its name',(RES.imported.concat(RES.unmatched)).some(r=>r.obj==='Node/worker-3'));
t('neither is silently discarded',RES.total===2);

/* ---- 3. The query builder ------------------------------------------------ */

console.log('\nQuery building');
t('defaults to BOTH user and platform, and to every violation state',
  E.buildAlertQuery({})==='Platform Component:true,false');
/* The contract is that a state the caller already named is never doubled, not that the
   query is left otherwise untouched: the platform term is still appended. */
t('an explicit state in the user query is not doubled',
  (E.buildAlertQuery({query:'Violation State:RESOLVED'}).match(/Violation State/g)||[]).length===1);
t('and that state is preserved verbatim',
  /Violation State:RESOLVED/.test(E.buildAlertQuery({query:'Violation State:RESOLVED'})));
t('ANY plus omit is a completely unfiltered query',
  E.buildAlertQuery({violationState:'ANY',platform:'omit'})==='');
t('namespace is joined with a plus, which is ACS search syntax',
  E.buildAlertQuery({namespace:'prod',platform:'omit'})==='Namespace:prod');
t('user query comes first',
  E.buildAlertQuery({query:'Severity:CRITICAL_SEVERITY',cluster:'ocp-prod',platform:'omit'})
  ==='Severity:CRITICAL_SEVERITY+Cluster:ocp-prod');

console.log('\nThe offline alert command tells you about the two phase problem');
const AC=E.acsFallbackCommand('https://central.example.com/','Severity:CRITICAL_SEVERITY');
t('includes the list call',/\/v1\/alerts\?query=/.test(AC));
t('includes the per id detail call, which is the part people miss',
  /\/v1\/alerts\/\$id/.test(AC));
t('explains why the list alone looks empty',/looks empty/.test(AC));
t('sets an explicit pagination limit',/pagination\.limit=/.test(AC));
t('reads the token from the environment, not the command line',/ROX_API_TOKEN=<paste/.test(AC));
t('trailing slash on the URL does not double up',!/example\.com\/\/v1/.test(AC));

/* ---- 4. Vulnerability export parsing -------------------------------------- */

const V=(cve,sev,cvss,fixedBy,extra)=>Object.assign({
  cve:cve,severity:sev,cvss:cvss,summary:cve+' summary',
  link:'https://access.redhat.com/security/cve/'+cve,
  fixedBy:fixedBy||'',state:'OBSERVED'},extra||{});

const REC1={result:{deployment:{id:'d1',name:'webapp',namespace:'prod',type:'Deployment',clusterName:'ocp-prod'},
  livePods:3,
  images:[{id:'sha256:aaa',name:{registry:'quay.io',remote:'acme/webapp',tag:'1.4.2',fullName:'quay.io/acme/webapp:1.4.2'},
    scan:{scanTime:'2026-08-10T00:00:00Z',operatingSystem:'rhel:9',scannerVersion:'4.6.0',components:[
      {name:'openssl',version:'3.0.7',source:'OS',fixedBy:'3.0.14',vulns:[
        V('CVE-2026-1000','CRITICAL_VULNERABILITY_SEVERITY',9.8,'3.0.14',{cisaKev:true,epss:{epssProbability:0.62}}),
        V('CVE-2026-1001','IMPORTANT_VULNERABILITY_SEVERITY',7.5,'3.0.14')]},
      {name:'glibc',version:'2.34',source:'OS',vulns:[
        V('CVE-2026-2000','MODERATE_VULNERABILITY_SEVERITY',5.5,''),
        V('CVE-2026-2001','LOW_VULNERABILITY_SEVERITY',3.1,'2.35',{state:'DEFERRED'})]}]}}]}};

const REC2={result:{deployment:{id:'d2',name:'worker',namespace:'prod',type:'Deployment',clusterName:'ocp-prod'},
  livePods:0,
  images:[{id:'sha256:aaa',name:{fullName:'quay.io/acme/webapp:1.4.2'},
    scan:{scanTime:'2026-08-10T00:00:00Z',operatingSystem:'rhel:9',components:[
      {name:'openssl',version:'3.0.7',vulns:[V('CVE-2026-1000','CRITICAL_VULNERABILITY_SEVERITY',9.8,'3.0.14',{cisaKev:true,epss:{epssProbability:0.62}})]}]}},
   {id:'sha256:bbb',name:{fullName:'registry.access.redhat.com/ubi9/ubi:9.4'},
    scan:{scanTime:'2026-08-09T00:00:00Z',operatingSystem:'rhel:9',components:[
      {name:'systemd',version:'252',vulns:[V('CVE-2026-3000','IMPORTANT_VULNERABILITY_SEVERITY',8.1,'253')]}]}}]}};

const NDJSON=JSON.stringify(REC1)+'\n'+JSON.stringify(REC2)+'\n';

console.log('\nParsing the vulnerability export');
const p1=E.parseVulnExport(NDJSON);
t('reads NDJSON, which is what the endpoint actually streams',p1.records.length===2);
t('unwraps the result envelope',!!p1.records[0].deployment);
const p2=E.parseVulnExport(JSON.stringify([REC1,REC2]));
t('also reads a JSON array, which is what jq -s produces',p2.records.length===2);
const p3=E.parseVulnExport(JSON.stringify(REC1));
t('also reads a single object',p3.records.length===1);
t('empty input is not an error',E.parseVulnExport('').records.length===0);
const p4=E.parseVulnExport(JSON.stringify(REC1)+'\nnot json\n'+JSON.stringify(REC2));
t('a bad line is counted, not swallowed',p4.errors.length===1&&p4.records.length===2);
t('a server error line is surfaced',
  E.parseVulnExport(JSON.stringify({error:{message:'permission denied'}})).errors.length===1);

console.log('\nFlattening into CVE rows');
const imp=E.importVulnFindings(p1);
t('two workloads seen',imp.workloads===2);
t('the same image in two workloads is one image, not two',imp.images.length===2);
/* This is the number that would be wrong if dedup were missing: CVE-2026-1000 appears in
   webapp and in worker, but it is one thing to fix. */
t('a CVE shared by two workloads is one row',
  imp.rows.filter(r=>r.cve==='CVE-2026-1000').length===1);
t('but both workloads are recorded against it',
  imp.rows.find(r=>r.cve==='CVE-2026-1000').workloads.length===2);
t('five distinct CVEs across both images',imp.rows.length===5);
t('sorted worst first',imp.rows[0].sevLabel==='Critical');

console.log('\nSeverity mapping, which is the Red Hat scale not the policy scale');
t('CRITICAL maps to Critical',E.vulnSeverity('CRITICAL_VULNERABILITY_SEVERITY').label==='Critical');
t('IMPORTANT maps to Important, not High',E.vulnSeverity('IMPORTANT_VULNERABILITY_SEVERITY').label==='Important');
t('MODERATE maps to Moderate, not Medium',E.vulnSeverity('MODERATE_VULNERABILITY_SEVERITY').label==='Moderate');
t('an unrecognised value degrades to Unknown rather than throwing',
  E.vulnSeverity('SOMETHING_NEW').label==='Unknown');

console.log('\nPriority scoring is explainable, every increment named');
const crit=imp.rows.find(r=>r.cve==='CVE-2026-1000');
t('KEV is called out by name',crit.reasons.some(r=>/Known Exploited/.test(r)));
t('EPSS is expressed as a percentage a human can read',crit.reasons.some(r=>/EPSS 62\.0%/.test(r)));
t('the availability of a fix is a named factor',crit.reasons.some(r=>/fix is published/.test(r)));
t('running pods are a named factor',crit.reasons.some(r=>/running this image/.test(r)));
t('the score stays on the documented 0 to 15 scale',crit.priority<=E.PRIORITY_MAX);
t('a KEV critical outranks a plain critical of the same CVSS',
  E.scoreVuln(V('CVE-X','CRITICAL_VULNERABILITY_SEVERITY',9.8,'1',{cisaKev:true}),{}).score >
  E.scoreVuln(V('CVE-Y','CRITICAL_VULNERABILITY_SEVERITY',9.8,'1'),{}).score);
const nofix=imp.rows.find(r=>r.cve==='CVE-2026-2000');
t('an unfixable CVE says so plainly',nofix.reasons.some(r=>/no upstream fix/.test(r)));
t('and is not marked fixable',nofix.fixable===false);

console.log('\nAccepted risk is separated, never silently dropped');
const deferred=imp.rows.find(r=>r.cve==='CVE-2026-2001');
t('a DEFERRED CVE is still present in the rows',!!deferred);
t('and is flagged as accepted',deferred.accepted===true);
t('the accepted count is reported',imp.accepted===1);
const sum=E.summarizeVulns(imp);
t('accepted CVEs are excluded from the active count',sum.active===4&&sum.accepted===1);
t('but are reported as their own number',sum.accepted===1);
t('critical count excludes accepted',sum.critical===1);
t('fixable count is over active only',sum.fixable===3);
t('KEV count surfaced',sum.kev===1);
t('unfixable criticals called out separately',sum.unfixableCritical===0);
t('fixable percentage computed over active',sum.fixablePct===75);
t('top priority list is capped and sorted',
  sum.topPriority.length<=10&&sum.topPriority[0].cve==='CVE-2026-1000');
t('summary of an empty import does not divide by zero',
  E.summarizeVulns({rows:[],images:[]}).fixablePct===0);

console.log('\nCorrelating CVEs back to the manifest that pulls the image');
const FILES=[{name:'app/deployment.yaml',text:[
 'apiVersion: apps/v1','kind: Deployment','metadata:','  name: webapp','  namespace: prod',
 'spec:','  template:','    spec:','      containers:','        - name: web',
 '          image: quay.io/acme/webapp:1.4.2'].join('\n')},
 {name:'app/worker.yaml',text:[
 'apiVersion: apps/v1','kind: Deployment','metadata:','  name: worker','  namespace: prod',
 'spec:','  template:','    spec:','      containers:','        - name: worker',
 '          image: quay.io/acme/webapp:1.3.0'].join('\n')}];
const corr=E.correlateVulns(FILES,imp);
t('finds the manifest that declares the vulnerable image',
  corr.matches.some(m=>m.file==='app/deployment.yaml'&&m.exact===true));
t('reports the container name so you know which line to edit',
  corr.matches.some(m=>m.container==='web'));
/* Drift detection: worker.yaml says 1.3.0 but ACS scanned 1.4.2 running. That gap is a
   finding in its own right, because git and the cluster disagree. */
t('flags a tag mismatch between manifest and cluster as drift',
  corr.matches.some(m=>m.file==='app/worker.yaml'&&m.drift===true));
t('records what the manifest actually says when it drifts',
  corr.matches.some(m=>m.manifestImage==='quay.io/acme/webapp:1.3.0'));
t('an image with no matching manifest is reported, not hidden',
  corr.unmatchedImages.indexOf('registry.access.redhat.com/ubi9/ubi:9.4')>=0);

console.log('\nThe worklist is grouped by image, because that is the unit of work');
const wl=E.buildVulnWorklist(imp,corr);
t('groups under the image reference',/## quay\.io\/acme\/webapp:1\.4\.2/.test(wl));
t('separates fixable from unfixable',/### Fixable now/.test(wl)&&/### No fix published yet/.test(wl));
t('names the package versions to move to',/openssl to 3\.0\.14 or later/.test(wl));
t('points at the file to edit',/app\/deployment\.yaml/.test(wl));
t('lists accepted risk separately for the record',/## Already accepted in ACS/.test(wl));
t('states plainly that nothing was executed',/Nothing has been applied to a cluster/.test(wl));
t('marks known exploited vulnerabilities in the table',/\| yes \|/.test(wl));

console.log('\nThere is no auto fix for a CVE, and that is deliberate');
const doc=jsyaml.load(FILES[0].text);
let threw=false;
try{E.applyImagePin(doc,'web','');}catch(e){threw=true;}
t('refuses to pin without a replacement you supplied',threw);
E.applyImagePin(doc,'web','quay.io/acme/webapp:1.5.0');
t('applies the replacement you did supply',
  E.containersOf(E.podSpec(doc))[0].c.image==='quay.io/acme/webapp:1.5.0');
let threw2=false;
try{E.applyImagePin(doc,'nonexistent','x:1');}catch(e){threw2=true;}
t('errors rather than silently doing nothing on a bad container name',threw2);
t('no fix function in the catalogue claims to remediate a CVE',
  E.ACS_POLICIES.every(p=>!/CVE-\d/.test(String(p.remediation||''))||p.fixKind!=='auto'));

console.log('\nThe offline vulnerability command');
const VC=E.vulnFallbackCommand('https://central.example.com',{namespace:'prod'});
t('curls the export endpoint',/curl[^\n]*\n[^\n]*\/v1\/export\/vuln-mgmt\/workloads/.test(VC));
t('does not curl the alerts endpoint, which has no CVEs in it',
  !/curl[^\n]*\n[^\n]*\/v1\/alerts/.test(VC));
t('states outright that CVEs are not in /v1/alerts',
  /image CVE is not a policy/.test(VC));
t('scopes by namespace using ACS search syntax',/Namespace%3Aprod/.test(VC));
t('sets the server side timeout',/timeout=300/.test(VC));
t('warns about the Image and Deployment permission trap',/read on Image and Deployment/.test(VC));
t('gives a way to check the export is not empty',/wc -l/.test(VC));
t('offers roxctl for a single image',/roxctl .* image scan/.test(VC));

console.log('\nImage reference handling');
t('prefers fullName',E.imageRef({name:{fullName:'a/b:1',registry:'x',remote:'y'}})==='a/b:1');
t('reconstructs from parts when fullName is missing',
  E.imageRef({name:{registry:'quay.io',remote:'acme/app',tag:'2.0'}})==='quay.io/acme/app:2.0');
t('degrades to unknown rather than undefined',E.imageRef({})==='unknown');

console.log('\nNothing here mutates its input');
const before=JSON.stringify(p1.records);
E.importVulnFindings(p1);
E.summarizeVulns(imp);
E.correlateVulns(FILES,imp);
t('the parsed export is unchanged after import, summary and correlate',
  JSON.stringify(p1.records)===before);

console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
