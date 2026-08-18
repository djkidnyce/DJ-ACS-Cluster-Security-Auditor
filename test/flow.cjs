/* Headless simulation of the remediation page flow, using the real engine and the same
   preview / commit / undo logic the page uses. */
globalThis.jsyaml=require('../vendor/js-yaml.min.js');
const E=require('../acs_policies.js');
Object.assign(globalThis,E);
let P=0,F=0;const t=(l,c)=>{console.log((c?'  pass  ':'  FAIL  ')+l);c?P++:F++};

const DEMO=[
'apiVersion: apps/v1','kind: Deployment','metadata:','  name: payments-api','  namespace: prod',
'spec:','  replicas: 2','  template:','    spec:','      hostNetwork: true','      hostPID: true',
'      containers:','      - name: api','        image: registry.example.com/payments:latest',
'        ports:','        - containerPort: 8080','          hostPort: 80','        env:',
'        - name: DB_PASSWORD','          value: hunter2','        securityContext:',
'          privileged: true','          runAsUser: 0','          capabilities:',
'            add: [SYS_ADMIN, NET_BIND_SERVICE]','      volumes:','      - name: dockersock',
'        hostPath:','          path: /var/run/docker.sock',''].join('\n');

let STATE={files:[],findings:[],history:[],applied:new Set(),acs:null};
function fileOf(n){return STATE.files.find(f=>f.name===n)}
function rescan(){
  STATE.findings=scanFiles(STATE.files);
  for(const f of STATE.findings)f.applied=STATE.applied.has(findingKey(f));
}
function previewFix(f){
  if(f.fixKind==='generate'){
    const doc=defaultDenyPolicy(f.ns);
    const yaml=jsyaml.dump(doc,{noRefs:true});
    return{kind:'generate',newFileName:'networkpolicy-default-deny-'+f.ns+'.yaml',yaml,
      changes:['new file: default deny NetworkPolicy for namespace "'+f.ns+'"'],
      diff:yaml.split('\n').map(t=>({t:'+',text:t}))};
  }
  const file=fileOf(f.file); if(!file)return null;
  const res=applyOneFix(file.docs,f); if(!res)return null;
  const before=dumpDocs(file.docs);
  return{kind:'edit',file,res,diff:compactDiff(diffLines(before,res.yaml),3),changes:res.changes};
}
function commitFix(f,pv){
  if(pv.kind==='generate'){
    const nf=parseFileText(pv.newFileName,pv.yaml);nf.originalDocs=[];nf.generated=true;
    STATE.history.push({generatedFile:pv.newFileName,finding:f,changes:pv.changes});
    STATE.files.push(nf);
  }else{
    STATE.history.push({fileName:pv.file.name,prevDocs:structuredClone(pv.file.docs),finding:f,changes:pv.changes});
    pv.file.docs=pv.res.docs;
  }
  STATE.applied.add(findingKey(f));
  rescan();
}
function undoLast(){
  const h=STATE.history.pop(); if(!h)return;
  if(h.generatedFile)STATE.files=STATE.files.filter(f=>f.name!==h.generatedFile);
  else{const file=fileOf(h.fileName);if(file)file.docs=h.prevDocs}
  STATE.applied.delete(findingKey(h.finding));
  rescan();
}
function undoAll(){
  for(const f of STATE.files)if(f.originalDocs)f.docs=structuredClone(f.originalDocs);
  STATE.files=STATE.files.filter(f=>!f.generated);
  STATE.history=[];STATE.applied.clear();rescan();
}
function load(name,text){
  const f=parseFileText(name,text);f.originalDocs=structuredClone(f.docs);STATE.files.push(f);rescan();
}

console.log('\nLoad and scan');
load('demo/workload.yaml',DEMO);
const snapshotOriginal=dumpDocs(STATE.files[0].originalDocs);
t('demo parsed',STATE.files[0].errors.length===0);
t('findings produced',STATE.findings.length>8);
const autoCount=STATE.findings.filter(f=>f.fixKind==='auto').length;
const manualCount=STATE.findings.filter(f=>f.fixKind==='manual').length;
const genCount=STATE.findings.filter(f=>f.fixKind==='generate').length;
console.log('        auto '+autoCount+', generate '+genCount+', manual '+manualCount);
t('has auto, generate and manual findings',autoCount>0&&genCount===1&&manualCount>0);
const p0=computePosture(STATE.files,STATE.findings,false);
console.log('        starting posture '+p0.score+'/'+p0.grade);

console.log('\nPreview does not mutate anything');
const first=STATE.findings.find(f=>f.fixKind==='auto');
const pv=previewFix(first);
t('preview returns a diff',pv.diff.length>0);
t('preview lists the change',pv.changes.length>0);
t('files untouched after preview',dumpDocs(STATE.files[0].docs)===snapshotOriginal);
t('history still empty after preview',STATE.history.length===0);
t('nothing marked applied after preview',STATE.applied.size===0);

console.log('\nSingle fix, commit and undo');
commitFix(first,pv);
t('one change recorded',STATE.history.length===1);
t('file changed on commit',dumpDocs(STATE.files[0].docs)!==snapshotOriginal);
t('finding marked applied',STATE.applied.size===1);
t('result is valid YAML',(()=>{try{return jsyaml.loadAll(dumpDocs(STATE.files[0].docs)).length===1}catch(e){return false}})());
undoLast();
t('undo restores the file byte for byte',dumpDocs(STATE.files[0].docs)===snapshotOriginal);
t('undo clears history',STATE.history.length===0);
t('undo clears the applied marker',STATE.applied.size===0);

console.log('\nStep through every auto fix, one at a time');
let guard=0,steps=0;
while(guard++<200){
  const next=STATE.findings.find(f=>!f.applied&&f.fixKind!=='manual');
  if(!next)break;
  const p=previewFix(next);
  if(!p){STATE.applied.add(findingKey(next));rescan();continue}
  commitFix(next,p);steps++;
}
console.log('        applied '+steps+' fixes in sequence');
t('applied several fixes',steps>=6);
t('a NetworkPolicy file was generated',STATE.files.some(f=>f.generated));
t('all files still valid YAML',STATE.files.every(f=>{try{jsyaml.loadAll(dumpDocs(f.docs));return true}catch(e){return false}}));
const afterDoc=jsyaml.load(dumpDocs(fileOf('demo/workload.yaml').docs));
t('privileged fixed',afterDoc.spec.template.spec.containers[0].securityContext.privileged===false);
t('hostNetwork fixed',afterDoc.spec.template.spec.hostNetwork===false);
t('hostPID fixed',afterDoc.spec.template.spec.hostPID===false);
t('SYS_ADMIN removed',!JSON.stringify(afterDoc.spec.template.spec.containers[0].securityContext.capabilities).includes('SYS_ADMIN'));
t('NET_BIND_SERVICE preserved',JSON.stringify(afterDoc.spec.template.spec.containers[0].securityContext.capabilities).includes('NET_BIND_SERVICE'));
t('runAsUser 0 removed',afterDoc.spec.template.spec.containers[0].securityContext.runAsUser===undefined);
t('secret env now uses secretKeyRef',!!afterDoc.spec.template.spec.containers[0].env[0].valueFrom);
t('hostPort removed',!afterDoc.spec.template.spec.containers[0].ports[0].hostPort);
t('resource limits added',!!afterDoc.spec.template.spec.containers[0].resources.limits.memory);
t('latest tag NOT touched, it is manual',afterDoc.spec.template.spec.containers[0].image.endsWith(':latest'));
t('docker socket NOT removed, it is manual',JSON.stringify(afterDoc.spec.template.spec.volumes).includes('docker.sock'));

const openNow=STATE.findings.filter(f=>!f.applied);
t('no auto fixable findings remain open',!openNow.some(f=>f.fixKind!=='manual'));
const p1=computePosture(STATE.files,openNow,false);
console.log('        posture now '+p1.score+'/'+p1.grade+' (was '+p0.score+')');
t('posture improved',p1.score>p0.score);

console.log('\nMerge patches for what was applied');
let patches=0;
for(const h of STATE.history){
  if(h.generatedFile)continue;
  const file=fileOf(h.fileName);
  const idx=file.docs.findIndex(d=>nameOf(d)===h.finding.obj);
  const orig=file.originalDocs.find(d=>nameOf(d)===h.finding.obj);
  if(idx<0||!orig)continue;
  const patch=buildMergePatch(orig,file.docs[idx]);
  const y=jsyaml.dump(patch,{noRefs:true});
  if(y.includes('kind: Deployment'))patches++;
}
t('a patch was produced for each edit',patches===STATE.history.filter(h=>!h.generatedFile).length);

console.log('\nUndo everything');
undoAll();
t('file restored byte for byte',dumpDocs(fileOf('demo/workload.yaml').docs)===snapshotOriginal);
t('generated file removed',!STATE.files.some(f=>f.generated));
t('history cleared',STATE.history.length===0&&STATE.applied.size===0);
const pBack=computePosture(STATE.files,STATE.findings,false);
t('posture back to the original number',pBack.score===p0.score);
console.log('        posture back to '+pBack.score);
console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
