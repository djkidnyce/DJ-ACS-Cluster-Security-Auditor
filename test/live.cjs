globalThis.jsyaml=require('../vendor/js-yaml.min.js');
const E=require('../acs_policies.js');
let P=0,F=0;const t=(l,c)=>{console.log((c?'  pass  ':'  FAIL  ')+l);c?P++:F++};

console.log('\nURL handling');
t('trailing slashes stripped',E.normalizeBase('https://central.example.com///')==='https://central.example.com');
t('whitespace trimmed',E.normalizeBase('  https://api.x:6443  ')==='https://api.x:6443');
t('empty stays empty',E.normalizeBase('')==='');

console.log('\nError messages are actionable, not just "failed"');
const corsMsg=E.explainFetchError(new TypeError('Failed to fetch'),'https://central.example.com/v1/alerts');
t('names CORS as the likely cause',/CORS/.test(corsMsg));
t('mentions the certificate possibility',/certificate/i.test(corsMsg));
t('points at the offline route',/offline command/i.test(corsMsg));
t('includes the URL that failed',corsMsg.includes('https://central.example.com/v1/alerts'));
t('a real error passes through unchanged',E.explainFetchError(new Error('boom'),'u')==='boom');

console.log('\nFallback commands are copy and paste ready');
const c=E.acsFallbackCommand('https://central.example.com/','Severity:CRITICAL');
t('uses bearer auth',/Authorization: Bearer \$ROX_API_TOKEN/.test(c));
t('reads the token from the environment, not the command line',/export ROX_API_TOKEN=/.test(c));
t('URL encodes the query',c.includes('query=Severity%3ACRITICAL'));
t('offers a roxctl alternative',/roxctl/.test(c));
t('no trailing double slash',!/example\.com\/\/v1/.test(c));
const oc=E.openshiftFallbackCommand('prod');
t('scopes to the namespace when given',oc.includes('-n prod'));
t('falls back to all namespaces',E.openshiftFallbackCommand('').includes('--all-namespaces'));

console.log('\nLive object sanitising');
const live={apiVersion:'apps/v1',kind:'Deployment',
 metadata:{name:'web',namespace:'prod',uid:'abc-123',resourceVersion:'99',generation:4,
   creationTimestamp:'2026-01-01T00:00:00Z',selfLink:'/x',managedFields:[{manager:'kubectl'}],
   ownerReferences:[{kind:'ReplicaSet'}],
   annotations:{'kubectl.kubernetes.io/last-applied-configuration':'{...}','deployment.kubernetes.io/revision':'3','team':'payments'}},
 spec:{template:{metadata:{creationTimestamp:null},spec:{containers:[{name:'c',image:'x:1',securityContext:{privileged:true}}]}}},
 status:{replicas:3,conditions:[{type:'Available'}]}};
const s=E.sanitizeLiveObject(live,'Deployment');
t('status removed',s.status===undefined);
t('managedFields removed',s.metadata.managedFields===undefined);
t('uid and resourceVersion removed',s.metadata.uid===undefined&&s.metadata.resourceVersion===undefined);
t('ownerReferences removed',s.metadata.ownerReferences===undefined);
t('last-applied annotation removed',!s.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration']);
t('revision annotation removed',!s.metadata.annotations['deployment.kubernetes.io/revision']);
t('meaningful annotations kept',s.metadata.annotations.team==='payments');
t('template creationTimestamp removed',s.spec.template.metadata.creationTimestamp===undefined);
t('name and namespace kept',s.metadata.name==='web'&&s.metadata.namespace==='prod');
t('the actual spec survives',s.spec.template.spec.containers[0].securityContext.privileged===true);
t('original object not mutated',live.status!==undefined&&live.metadata.uid==='abc-123');

console.log('\nSanitised objects are scannable and fixable');
const yaml=jsyaml.dump(s,{noRefs:true});
const files=[E.parseFileText('live/prod/deployment-web.yaml',yaml)];
const found=E.scanFiles(files);
t('sanitised live object parses',files[0].errors.length===0);
t('privileged still detected on the live object',found.some(f=>f.policy.id==='ACS.001'));
const priv=found.find(f=>f.policy.id==='ACS.001');
const res=E.applyOneFix(files[0].docs,priv);
t('fix applies to a live pulled object',!!res&&res.changes.length===1);
t('fixed live object is valid YAML',(()=>{try{return jsyaml.load(res.yaml).kind==='Deployment'}catch(e){return false}})());
t('fixed output carries no server side junk',!/managedFields|resourceVersion|status:/.test(res.yaml));

console.log('\nAll annotations stripped leaves no empty map');
const bare=E.sanitizeLiveObject({metadata:{name:'x',annotations:{'deployment.kubernetes.io/revision':'1'}},spec:{}},'Deployment');
t('empty annotations object removed entirely',bare.metadata.annotations===undefined);

console.log('\n'+P+' passed, '+F+' failed');
process.exit(F?1:0);
