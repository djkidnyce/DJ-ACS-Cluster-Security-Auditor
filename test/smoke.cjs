globalThis.jsyaml=require('../vendor/js-yaml.min.js');
const E=require('../acs_policies.js');
let P=0,F=0;const t=(l,c)=>{console.log((c?'  pass  ':'  FAIL  ')+l);c?P++:F++};
const SRC=`apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
  namespace: prod
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: web
        image: reg.example.com/web:latest
        ports:
        - containerPort: 8080
          hostPort: 80
        env:
        - name: DB_PASSWORD
          value: hunter2
        securityContext:
          privileged: true
          capabilities:
            add: [SYS_ADMIN, NET_BIND_SERVICE]
      volumes:
      - name: sock
        hostPath:
          path: /var/run/docker.sock
`;
console.log('\nPolicy catalogue');
t('20 policies loaded',E.ACS_POLICIES.length===20);
t('every policy has an ACS name',E.ACS_POLICIES.every(p=>p.acsPolicy&&p.acsPolicy.length>3));
t('every policy has ACS severity',E.ACS_POLICIES.every(p=>E.ACS_SEVERITY[p.severity]));
t('every policy has remediation text',E.ACS_POLICIES.every(p=>p.remediation&&p.remediation.length>20));
t('every policy has rationale',E.ACS_POLICIES.every(p=>p.rationale&&p.rationale.length>20));
t('every policy carries citations',E.ACS_POLICIES.every(p=>E.citationsOf(p).length>0));
t('every policy has a STIG reference',E.ACS_POLICIES.every(p=>p.stig&&p.stig!=='n/a'));
t('every policy has CVSS score and vector',E.ACS_POLICIES.every(p=>p.score>0&&/^CVSS:3\.1/.test(p.vector)));
t('ids unique',new Set(E.ACS_POLICIES.map(p=>p.id)).size===20);
t('auto fixes have a fix function',E.ACS_POLICIES.filter(p=>p.fixKind==='auto').every(p=>typeof p.fix==='function'));
t('manual policies have no fix function',E.ACS_POLICIES.filter(p=>p.fixKind==='manual').every(p=>!p.fix));
console.log('\nScanning');
const files=[E.parseFileText('app.yaml',SRC)];
t('file parsed',files[0].errors.length===0&&files[0].docs.length===1);
const found=E.scanFiles(files);
const ids=found.map(f=>f.policy.id);
console.log('        found: '+ids.join(', '));
for(const id of ['ACS.001','ACS.002','ACS.003','ACS.004','ACS.005','ACS.007','ACS.008','ACS.009','ACS.010','ACS.011','ACS.013','ACS.014','ACS.015','ACS.016','ACS.017','ACS.018','ACS.019'])
  t('detected '+id,ids.includes(id));
t('sorted by severity, Critical first',E.sevLabel(found[0].policy.severity)==='Critical');
t('findings carry a field path',found.filter(f=>f.policy.id!=='ACS.018').every(f=>f.path));
console.log('\nPosture');
const before=E.computePosture(files,found,false);
const after=E.computePosture(files,found,true);
console.log('        current '+before.score+'/'+before.grade+'   projected '+after.score+'/'+after.grade);
t('score bounded',before.score>=0&&after.score<=100);
t('projection improves on current',after.score>before.score);
t('severity counts populated',before.counts.Critical>0&&before.counts.High>0);
t('categories scored',Object.keys(before.catScores).length>2);

/* This catalogue printed "CIS 5.2.1" with no benchmark named for its entire life, and the
   numbers turned out to be the OpenShift benchmark's while every heading said Kubernetes.
   The two differ: Kubernetes v2.0.1 inserted a new 5.2.1 and shifted 5.2.2 onwards down one.
   Nothing in the output could have revealed that, which is what these assertions are for. */
console.log('\nEvery standard cited is declared, dated, and names its benchmark');
{
  t('there is a standards table', E.STANDARDS && Object.keys(E.STANDARDS).length >= 6);
  const used = new Set();
  for (const p of E.ACS_POLICIES) {
    for (const k of ['cisK8s', 'cisOcp', 'nist', 'pss', 'stig']) {
      if (p[k] && p[k] !== 'n/a') used.add(k === 'cisOcp' ? 'cisOcp' : k);
    }
  }
  t('policies cite at least four standards, so this is a real check', used.size >= 4);
  for (const k of used) t('  ' + k + ' is declared in the table', !!E.STANDARDS[k]);
  for (const [k, st] of Object.entries(E.STANDARDS)) {
    t('  ' + k + ' names a release', !!st.release && st.release.length > 1);
    t('  ' + k + ' states its confidence', !!st.confidence);
    t('  ' + k + ' carries a checkable URL', /^https:\/\//.test(st.url || ''));
  }

  console.log('\n  The two CIS benchmarks are not confused with each other');
  const byId = (id) => E.ACS_POLICIES.find((p) => p.id === id);
  /* The shift is the whole finding. Privileged containers is 5.2.2 in the Kubernetes
     benchmark and 5.2.1 in the OpenShift one, and five more controls move the same way. */
  const shifted = [['ACS.001','5.2.2','5.2.1'], ['ACS.005','5.2.3','5.2.2'],
                   ['ACS.006','5.2.4','5.2.3'], ['ACS.004','5.2.5','5.2.4'],
                   ['ACS.003','5.2.6','5.2.5'], ['ACS.009','5.2.7','5.2.6']];
  for (const [id, k8s, ocp] of shifted) {
    t('  ' + id + ' is ' + k8s + ' in Kubernetes and ' + ocp + ' in OpenShift',
      byId(id).cisK8s === k8s && byId(id).cisOcp === ocp);
  }
  t('the citation line says which benchmark each number came from',
    /CIS K8s 5\.2\.2/.test(E.citationsOf(byId('ACS.001')).join(' ')) &&
    /CIS OCP 5\.2\.1/.test(E.citationsOf(byId('ACS.001')).join(' ')));
  t('controls the OpenShift benchmark does not cover read n/a rather than guessing',
    byId('ACS.012').cisOcp === 'n/a' && byId('ACS.019').cisOcp === 'n/a');
  t('and those still carry their Kubernetes number',
    byId('ACS.012').cisK8s === '5.2.11' && byId('ACS.019').cisK8s === '5.2.12');
  t('policies with no CIS section at all say n/a in both',
    byId('ACS.013').cisK8s === 'n/a' && byId('ACS.013').cisOcp === 'n/a');
  t('and produce no CIS citation rather than prose that looks like one',
    !/CIS/.test(E.citationsOf(byId('ACS.013')).join(' ')));

  console.log('\n  The Docker citation names the right control');
  /* It said Docker 5.7, which is "Ensure sshd is not run within containers". */
  t('the policy no longer claims Docker 5.7',
    !/5\.7/.test(byId('ACS.019').acsPolicy));
  t('and the Docker benchmark entry records the correction',
    /5\.8/.test(E.STANDARDS.cisDocker.note));

  console.log('\n  The age is computed, and supersession is separate from staleness');
  t('a review date is recorded', /^\d{4}-\d{2}-\d{2}$/.test(E.STANDARDS_ASOF));
  t('age today is small, because the date is real', E.standardsAgeDays() < 400);
  t('and it grows', E.standardsAgeDays(new Date(Date.now() + 90 * 86400000)) >= 90);
  t('nothing is stale the day it is reviewed',
    E.standardsAreStale(new Date(E.STANDARDS_ASOF + 'T00:00:00Z')) === false);
  t('everything is stale long enough after it',
    E.standardsAreStale(new Date(Date.now() + (E.STANDARDS_STALE_DAYS + 30) * 86400000)) === true);
  t('nothing is superseded today, every entry having been read from the publication',
    E.supersededStandards().length === 0);
  /* Driven with a synthetic table so the mechanism is tested without inventing a fake
     superseded standard in the shipped data. */
  t('but the mechanism works when a release is superseded',
    E.supersededStandards({ x: { label: 'X', release: 'v1', supersededBy: 'v2' } }).length === 1);

  console.log('\n  The report and the JSON both carry it');
  const d = { apiVersion:'apps/v1', kind:'Deployment', metadata:{ name:'a', namespace:'prod' },
    spec:{ template:{ metadata:{}, spec:{ containers:[{ name:'c', image:'q/a:1',
      securityContext:{ privileged:true } }] } } } };
  const files = [{ name:'a.yaml', docs:[d], originalDocs:[d], errors:[] }];
  const found = E.scanFiles(files);
  const html = E.buildHtmlReport({ files: files, findings: found });
  t('the report has a standards section', /Standards referenced/.test(html));
  t('it comes before the method', html.indexOf('Standards referenced') < html.indexOf('<h2>Method</h2>'));
  t('it names both CIS releases', /v2\.0\.1/.test(html) && /v2\.0\.0/.test(html));
  t('it names the Kubernetes release, so the gap is visible', /1\.37\.1/.test(html));
  t('it says when it was last reviewed', html.indexOf(E.STANDARDS_ASOF) !== -1);
  const js = E.buildFindingsJson({ files: files, findings: found });
  t('the JSON records the review date', js.standards.lastReviewed === E.STANDARDS_ASOF);
  t('and the age as a number', typeof js.standards.ageDays === 'number');
  t('and each finding carries both CIS numbers',
    js.findings[0].standards.cisK8s !== undefined && js.findings[0].standards.cisOcp !== undefined);
}

console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
