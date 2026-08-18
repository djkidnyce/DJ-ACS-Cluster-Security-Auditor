globalThis.jsyaml=require('../vendor/js-yaml.min.js');
const E=require('../acs_policies.js');
let P=0,F=0;const t=(l,c)=>{console.log((c?'  pass  ':'  FAIL  ')+l);c?P++:F++};

/* Shaped like a real /v1/alerts response from ACS Central. */
const ALERTS={alerts:[
 {id:'a1',state:'ACTIVE',
  policy:{name:'Privileged Container',severity:'HIGH_SEVERITY',description:'Alert on privileged'},
  deployment:{name:'webapp',namespace:'prod',type:'Deployment',clusterName:'ocp-prod'},
  violations:[{message:'Container "web" is privileged'}]},
 {id:'a2',state:'ACTIVE',
  policy:{name:'Environment Variable Contains Secret',severity:'CRITICAL_SEVERITY'},
  deployment:{name:'webapp',namespace:'prod',type:'Deployment',clusterName:'ocp-prod'},
  violations:[{message:'Env var DB_PASSWORD looks like a secret'}]},
 {id:'a3',state:'ACTIVE',
  policy:{name:'Fixable CVSS >= 7',severity:'HIGH_SEVERITY'},
  deployment:{name:'webapp',namespace:'prod',type:'Deployment',clusterName:'ocp-prod'},
  violations:[{message:'CVE-2024-1234 fixable'}]},
 {id:'a4',state:'ACTIVE',
  policy:{name:'Deployment mounts the Docker socket',severity:'CRITICAL_SEVERITY'},
  deployment:{name:'legacy-agent',namespace:'tools',type:'DaemonSet',clusterName:'ocp-prod'},
  violations:[{message:'Mounts /var/run/docker.sock'}]}
]};

console.log('\nImport shapes');
const r=E.importAcsViolations(ALERTS);
t('reads the alerts wrapper',r.total===4);
t('matched the known policies',r.imported.length===3);
t('left the image CVE policy unmatched, correctly',r.unmatched.length===1&&/Fixable CVSS/.test(r.unmatched[0].acsPolicyName));
t('bare array form also works',E.importAcsViolations(ALERTS.alerts).total===4);
t('roxctl results wrapper works',E.importAcsViolations({results:ALERTS.alerts}).total===4);
t('empty input does not throw',E.importAcsViolations({}).total===0);

console.log('\nName matching');
t('exact match recognised',E.matchPolicy('Privileged Container').confidence==='exact');
t('renamed policy still matches',['fuzzy','weak'].includes(E.matchPolicy('ACME Privileged Container Check').confidence));
t('socket policy matched by wording',(E.matchPolicy('Deployment mounts the Docker socket')||{}).policy && E.matchPolicy('Deployment mounts the Docker socket').policy.id==='ACS.011');
t('nonsense does not match',E.matchPolicy('Totally Unrelated Thing')===null);
t('empty name does not match',E.matchPolicy('')===null);

console.log('\nCorrelation with a local scan');
const SRC=`apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
  namespace: prod
spec:
  template:
    spec:
      containers:
      - name: web
        image: reg/web:1.0
        env:
        - name: DB_PASSWORD
          value: hunter2
        securityContext:
          privileged: true
`;
const files=[E.parseFileText('app.yaml',SRC)];
const found=E.scanFiles(files);
const co=E.correlate(found,r.imported);
const priv=found.find(f=>f.policy.id==='ACS.001');
const secret=found.find(f=>f.policy.id==='ACS.010');
t('privileged finding confirmed by ACS',priv.confirmedByAcs===true);
t('confirmed finding carries cluster context',priv.acsCluster==='ocp-prod'&&priv.acsNamespace==='prod');
t('secret finding confirmed by ACS',secret.confirmedByAcs===true);
t('ACS only violation kept separately',co.onlyInAcs.length===1&&co.onlyInAcs[0].obj==='DaemonSet/legacy-agent');
const unconfirmed=found.filter(f=>!f.confirmedByAcs);
t('local only findings remain unconfirmed',unconfirmed.length>0);
console.log('        confirmed by both: '+found.filter(f=>f.confirmedByAcs).map(f=>f.policy.id).join(', '));
console.log('        only in ACS: '+co.onlyInAcs.map(v=>v.acsPolicyName).join(', '));
console.log('        only in local scan: '+unconfirmed.length+' findings');
console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
