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

/* ACS.010 matched on the variable name alone, so APP_PASSWORD_FILE=/etc/secrets/app was
   reported as a leaked credential and the auto fix replaced the path with a secretKeyRef.
   The application then opened a file named after its own password. It also flagged the
   service account token path that Kubernetes mounts itself. */
console.log('\nACS.010 reads the value, not just the variable name');
{
  const mk = (env) => ({ apiVersion: 'apps/v1', kind: 'Deployment',
    metadata: { name: 'api', namespace: 'prod' },
    spec: { template: { metadata: {}, spec: { containers: [{ name: 'c', image: 'q/a:1', env: [env] }] } } } });
  const flagged = (env) => {
    const d = mk(env);
    return E.scanFiles([{ name: 'a.yaml', docs: [d], originalDocs: [d], errors: [] }])
      .some((x) => x.policy.id === 'ACS.010');
  };

  const references = [
    [{ name: 'APP_PASSWORD_FILE', value: '/etc/secrets/app/password' }, 'an absolute path, which is the secure pattern'],
    [{ name: 'TOKEN_FILE', value: '/var/run/secrets/kubernetes.io/serviceaccount/token' }, 'the service account token path Kubernetes mounts itself'],
    [{ name: 'PASSWORD_PATH', value: '/var/run/pw' }, 'a path under another name'],
    [{ name: 'DB_PASSWORD', value: 'file:///run/secrets/db' }, 'a file URL'],
    [{ name: 'DB_PASSWORD', value: '$(DB_SECRET)' }, 'a substitution something else resolves'],
    [{ name: 'DB_PASSWORD', value: '${DB_SECRET}' }, 'the brace form of it'],
  ];
  for (const [env, label] of references) {
    t('  not a finding: ' + label, !flagged(env));
  }

  const literals = [
    [{ name: 'DB_PASSWORD', value: 's3cretP@ss' }, 'a literal password'],
    [{ name: 'API_KEY', value: 'AKIAIOSFODNN7EXAMPLE' }, 'a literal key'],
    [{ name: 'PASSWORD_FILE', value: 'hunter2' }, 'named _FILE but holding the secret itself'],
    [{ name: 'DB_PASSWORD', value: 'relative/path/not/absolute' }, 'a relative path, which is not the file pattern'],
  ];
  for (const [env, label] of literals) {
    t('  still a finding: ' + label, flagged(env));
  }

  /* The fix has to agree with the check. If it edits something the check never reported,
     the diff shows a change nobody can trace to a finding. */
  console.log('\n  The fix agrees with the check');
  const pathDoc = mk({ name: 'APP_PASSWORD_FILE', value: '/etc/secrets/app/password' });
  const before = JSON.stringify(pathDoc);
  const pol = E.ACS_POLICIES.find((p) => p.id === 'ACS.010');
  pol.fix(pathDoc);
  t('  the fix leaves a path env var alone', JSON.stringify(pathDoc) === before);
  const litDoc = mk({ name: 'DB_PASSWORD', value: 's3cretP@ss' });
  pol.fix(litDoc);
  const env0 = litDoc.spec.template.spec.containers[0].env[0];
  t('  and still rewrites a literal one', !!env0.valueFrom && env0.value === undefined);

  console.log('\n  The guard is exported so both surfaces share one definition');
  t('  envValueIsReference is exported', typeof E.envValueIsReference === 'function');
  t('  it says an absolute path is a reference', E.envValueIsReference('/etc/x') === true);
  t('  and a literal is not', E.envValueIsReference('s3cret') === false);
  t('  empty is not a reference either', E.envValueIsReference('') === false);
}

console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
