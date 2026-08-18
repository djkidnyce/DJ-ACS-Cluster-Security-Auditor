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
console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
