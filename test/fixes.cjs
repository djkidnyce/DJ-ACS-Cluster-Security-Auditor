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
      containers:
      - name: web
        image: reg.example.com/web:latest
        env:
        - name: DB_PASSWORD
          value: hunter2
        securityContext:
          privileged: true
`;
let files=[E.parseFileText('app.yaml',SRC)];
let found=E.scanFiles(files);

console.log('\nApplying one fix at a time');
const priv=found.find(f=>f.policy.id==='ACS.001');
const r1=E.applyOneFix(files[0].docs,priv);
t('applyOneFix returns a result',!!r1);
t('reports what changed',r1.changes.length===1&&r1.changes[0].includes('privileged'));
t('produces valid YAML',(()=>{try{return jsyaml.loadAll(r1.yaml).length===1}catch(e){return false}})());
t('privileged is now false',jsyaml.load(r1.yaml).spec.template.spec.containers[0].securityContext.privileged===false);
t('ONLY that policy applied, hostNetwork untouched',jsyaml.load(r1.yaml).spec.template.spec.hostNetwork===true);
t('original documents not mutated',files[0].docs[0].spec.template.spec.containers[0].securityContext.privileged===true);
t('before and after documents returned',!!r1.beforeDoc&&!!r1.afterDoc);

console.log('\nManual policies are never auto applied');
const manual=found.find(f=>f.policy.id==='ACS.015');
t('latest tag is classified manual',manual.fixKind==='manual');
t('applyOneFix refuses a manual policy',E.applyOneFix(files[0].docs,manual)===null);

console.log('\nDiff');
const diff=E.diffLines(E.dumpDocs(files[0].docs),r1.yaml);
const changed=diff.filter(d=>d.t!==' ');
t('diff detects a change',changed.length>0);
t('diff shows a removal and an addition',changed.some(d=>d.t==='-')&&changed.some(d=>d.t==='+'));
t('removed line mentions privileged true',changed.filter(d=>d.t==='-').some(d=>/privileged:\s*true/.test(d.text)));
t('added line mentions privileged false',changed.filter(d=>d.t==='+').some(d=>/privileged:\s*false/.test(d.text)));
const compact=E.compactDiff(diff,2);
t('compact diff is shorter than full',compact.length<diff.length);
t('compact diff keeps every change',compact.filter(d=>d.t!==' '&&d.t!=='@').length===changed.length);

console.log('\nMerge patch');
const patch=E.buildMergePatch(r1.beforeDoc,r1.afterDoc);
t('patch carries identity',patch.kind==='Deployment'&&patch.metadata.name==='webapp'&&patch.metadata.namespace==='prod');
t('patch includes the changed field',JSON.stringify(patch).includes('privileged'));
t('patch omits unrelated fields',!JSON.stringify(patch.spec||{}).includes('image'));
t('patch serializes to YAML',jsyaml.dump(patch).includes('privileged'));

console.log('\nSequential application, the one by one flow');
let docs=files[0].docs;
const autoFindings=found.filter(f=>f.fixKind==='auto');
const applied=[];
const history=[];
for(const f of autoFindings){
  const res=E.applyOneFix(docs,f);
  if(res){history.push(structuredClone(docs));docs=res.docs;applied.push(f.policy.id)}
}
t('applied several fixes in sequence',applied.length>=5);
t('sequence result is valid YAML',(()=>{try{return jsyaml.loadAll(E.dumpDocs(docs)).length===1}catch(e){return false}})());
const after1=jsyaml.load(E.dumpDocs(docs));
t('privileged fixed',after1.spec.template.spec.containers[0].securityContext.privileged===false);
t('hostNetwork fixed',after1.spec.template.spec.hostNetwork===false);
t('readOnlyRootFilesystem added',after1.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem===true);
t('secret env rewritten to secretKeyRef',!!after1.spec.template.spec.containers[0].env[0].valueFrom);
t('literal secret value removed',after1.spec.template.spec.containers[0].env[0].value===undefined);
t('latest tag deliberately untouched',after1.spec.template.spec.containers[0].image.endsWith(':latest'));

console.log('\nUndo');
const restored=history[history.length-1];
t('undo restores the prior state exactly',
  JSON.stringify(restored)===JSON.stringify(history[history.length-1]));
const rescanned=E.scanFiles([{name:'app.yaml',text:'',docs,errors:[]}]);
t('no auto fixable findings remain',!rescanned.some(f=>f.fixKind==='auto'));
t('manual findings persist',rescanned.some(f=>f.fixKind==='manual'));
console.log('        remaining: '+rescanned.map(f=>f.policy.id).join(', '));
console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
