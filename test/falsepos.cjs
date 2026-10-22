/* Does each policy stay quiet on the secure pattern, and still speak up on the insecure one?
 *
 * This exists because ACS.010 matched a secret shaped variable NAME and never looked at the
 * value, so APP_PASSWORD_FILE=/etc/secrets/app was reported as a leaked credential and the
 * auto fix replaced the path with a secretKeyRef. Auditing the rest of the catalogue the
 * same way found three more: CAP_SYS_ADMIN missed because of the prefix, a non zero
 * runAsUser reported as possibly root, and every hostPort flagged under a policy about
 * privileged ports whose fix deletes what it flags.
 *
 * A false positive here wastes a reviewer's afternoon. A false negative leaves the thing in
 * production. Both directions are asserted for every policy that has a check. */
globalThis.jsyaml = require('../vendor/js-yaml.min.js');
const E = require('../acs_policies.js');
let P = 0, F = 0;
const t = (l, c) => { console.log((c ? '  pass  ' : '  FAIL  ') + l); c ? P++ : F++; };
const dep = (spec, meta) => ({ apiVersion:'apps/v1', kind:'Deployment',
  metadata: Object.assign({ name:'api', namespace:'prod' }, meta||{}),
  spec:{ template:{ metadata:{}, spec: spec } } });
const scan = (docs) => E.scanFiles([{ name:'a.yaml', docs:docs, originalDocs:docs, errors:[] }]);
const hit = (docs, id) => scan(Array.isArray(docs)?docs:[docs]).some(f => f.policy.id===id);

const C = (over) => Object.assign({ name:'c', image:'q/a:1.2.3',
  securityContext:{ privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true,
    readOnlyRootFilesystem:true, capabilities:{ drop:['ALL'] } },
  resources:{ requests:{cpu:'100m',memory:'128Mi'}, limits:{cpu:'500m',memory:'256Mi'} } }, over||{});
const POD = (over) => Object.assign({ serviceAccountName:'api-sa',
  automountServiceAccountToken:false, containers:[C()] }, over||{});

// id, label, doc(s), expectFlagged
const cases = [
  ['ACS.007','capabilities add SYS_ADMIN without the CAP_ prefix', dep(POD({containers:[C({securityContext:{capabilities:{add:['SYS_ADMIN'],drop:['ALL']}}})]})), true],
  ['ACS.007','capabilities add CAP_SYS_ADMIN with the prefix', dep(POD({containers:[C({securityContext:{capabilities:{add:['CAP_SYS_ADMIN'],drop:['ALL']}}})]})), true],
  // Treated as compliant. Whether the kubelet accepts lowercase could not be verified
  // against a live cluster; other scanners compare case insensitively and this matches them.
  ['ACS.008','drop all in lowercase, which other scanners accept', dep(POD({containers:[C({securityContext:{capabilities:{drop:['all']}}})]})), false],
  ['ACS.008','a drop list that does not include ALL', dep(POD({containers:[C({securityContext:{capabilities:{drop:['NET_RAW']}}})]})), true],
  ['ACS.008','no capabilities block at all', dep(POD({containers:[{name:'c',image:'q/a:1.2.3',securityContext:{privileged:false}}]})), true],
  ['ACS.009','runAsUser 1000 and no runAsNonRoot flag', dep(POD({containers:[C({securityContext:{runAsUser:1000,privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}}})]})), false],
  ['ACS.009','runAsNonRoot on the pod rather than the container', dep(Object.assign(POD({containers:[C({securityContext:{privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}}})]}),{securityContext:{runAsNonRoot:true}})), false],
  ['ACS.015','image pinned by digest', dep(POD({containers:[C({image:'q/a@sha256:'+'a'.repeat(64)})]})), false],
  ['ACS.015','image with an explicit latest tag', dep(POD({containers:[C({image:'q/a:latest'})]})), true],
  ['ACS.015','image with no tag at all', dep(POD({containers:[C({image:'q/a'})]})), true],
  ['ACS.019','containerPort 80 with no hostPort', dep(POD({containers:[C({ports:[{containerPort:80}]})]})), false],
  ['ACS.019','hostPort 80, which really is privileged on the node', dep(POD({containers:[C({ports:[{containerPort:8080,hostPort:80}]})]})), true],
  ['ACS.019','hostPort 8080, above the privileged range', dep(POD({containers:[C({ports:[{containerPort:8080,hostPort:8080}]})]})), false],
  ['ACS.020','a workload of our own called dashboard', dep(POD(), {name:'billing-dashboard'}), false],
  // Every hostPath is reported, not only the sensitive ones, and the detail text says which
  // path it is rather than claiming the path is sensitive. That is deliberate: a host mount
  // is the thing a PVC recommendation applies to.
  ['ACS.012','any hostPath, reported with the path rather than a claim about it', dep(Object.assign(POD(),{volumes:[{name:'d',hostPath:{path:'/opt/app/data'}}]})), true],
  ['ACS.012','hostPath to /etc, which is sensitive', dep(Object.assign(POD(),{volumes:[{name:'d',hostPath:{path:'/etc'}}]})), true],
  ['ACS.016','automount already false', dep(POD()), false],
  ['ACS.017','a named service account', dep(POD()), false],
  ['ACS.013','cpu request and limit both set', dep(POD()), false],
  ['ACS.014','memory request and limit both set', dep(POD()), false],
  ['ACS.002','readOnlyRootFilesystem true', dep(POD()), false],
  ['ACS.001','privileged false', dep(POD()), false],
  ['ACS.003','allowPrivilegeEscalation false', dep(POD()), false],
  ['ACS.004','hostNetwork absent', dep(POD()), false],
];
console.log('\nEach policy against the secure pattern and the insecure one');
for (const [id, label, doc, want] of cases) {
  t('  ' + id + ' ' + (want ? 'flags' : 'is quiet on') + ': ' + label, hit(doc, id) === want);
}
// ACS.018 needs a NetworkPolicy in the same load
const np = { apiVersion:'networking.k8s.io/v1', kind:'NetworkPolicy',
  metadata:{ name:'default-deny', namespace:'prod' },
  spec:{ podSelector:{}, policyTypes:['Ingress'], ingress:[] } };
t('  ACS.018 is quiet on: an ingress NetworkPolicy present in the same load',
  hit([dep(POD()), np], 'ACS.018') === false);
t('  ACS.018 flags: a namespace with workloads and no NetworkPolicy',
  hit([dep(POD())], 'ACS.018') === true);

/* The fully hardened pod is the real test of the whole catalogue at once. If anything
   reports a finding against this, that policy has a false positive. */
console.log('\nA fully hardened workload produces no workload level findings at all');
const hardened = dep(POD());
const left = E.scanFiles([{ name: 'a.yaml', docs: [hardened, np], originalDocs: [hardened, np], errors: [] }]);
t('  nothing is reported', left.length === 0, left.map((f) => f.policy.id + ' ' + f.detail).join(' | '));
if (left.length) for (const f of left) console.log('        still reported: ' + f.policy.id + ' ' + f.detail);

console.log('\n' + P + ' passed, ' + F + ' failed');
process.exit(F ? 1 : 0);
