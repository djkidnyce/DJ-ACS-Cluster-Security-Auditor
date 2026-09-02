/* DJ's ACS Auditor, policy engine.
 *
 * Shared by dj_acs_auditor.html, which is the whole browser surface, and importable under Node for
 * the test suite. One copy of the rules, so the audit page and the remediation page can
 * never disagree about what is wrong with a manifest.
 *
 * Design note on shape. Every policy here mirrors the structure of a real Red Hat Advanced
 * Cluster Security default policy: a name, a severity on the ACS scale, ACS categories, the
 * lifecycle stage, and ACS remediation text. That is deliberate. When you import a violation
 * export from ACS Central or roxctl, findings are matched back to these rules by ACS policy
 * name, so the same problem lines up whether it came from your running cluster or from a
 * local scan of the YAML.
 *
 * Structure verified against the upstream definition at
 * github.com/stackrox/stackrox/blob/master/pkg/defaults/policies/files/privileged.json
 *
 * Policy names and severities should still be checked against your own ACS version.
 * Defaults shift between releases and most teams tune them, which is why the importer falls
 * back to fuzzy name matching rather than silently dropping a violation it does not know.
 *
 * Nothing here executes anything. It reads YAML, reports, and rewrites YAML.
 */
'use strict';

/* One version string, stamped into every report, JSON export, SARIF run, patch header
   and CLI banner. It is the only place a version is written down in code, and
   test/version.cjs asserts it agrees with the newest CHANGELOG heading and with the git
   tag when one is checked out. A tool whose banner disagrees with its tag cannot be used
   as evidence, because you cannot tell which build produced a given report. */
const ACS_VERSION = '1.5.0';
const ACS_TOOL = "DJ's ACS Auditor v" + ACS_VERSION;

/* ACS severity scale and the weight each carries in the posture score. A Critical costs
   nine times a Low, because averaging them evenly is how a scanner reports a comfortable
   number over a cluster that is on fire. */
const ACS_SEVERITY = {
  CRITICAL_SEVERITY: { label: 'Critical', weight: 18, rank: 0 },
  HIGH_SEVERITY: { label: 'High', weight: 10, rank: 1 },
  MEDIUM_SEVERITY: { label: 'Medium', weight: 5, rank: 2 },
  LOW_SEVERITY: { label: 'Low', weight: 2, rank: 3 },
};
function sevLabel(s) { return (ACS_SEVERITY[s] || ACS_SEVERITY.LOW_SEVERITY).label; }
function sevWeight(s) { return (ACS_SEVERITY[s] || ACS_SEVERITY.LOW_SEVERITY).weight; }
function sevRank(s) { return (ACS_SEVERITY[s] || ACS_SEVERITY.LOW_SEVERITY).rank; }

const WORKLOADS = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob', 'DeploymentConfig'];
const DANGEROUS_CAPS = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'SYS_RAWIO', 'BPF', 'PERFMON', 'SYS_BOOT'];
const SECRET_ENV_RE = /(PASS(WORD)?|PASSWD|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|CONN(ECTION)?[_-]?STR)/i;
const SOCKET_PATHS = ['/var/run/docker.sock', '/run/docker.sock', '/var/run/crio/crio.sock',
  '/run/containerd/containerd.sock', '/var/run/containerd/containerd.sock'];

/* ------------------------------------------------------------------ helpers */

function podSpec(doc) {
  if (!doc || typeof doc !== 'object') return null;
  const k = doc.kind;
  if (k === 'Pod') return doc.spec || null;
  if (['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'DeploymentConfig'].includes(k))
    return (doc.spec && doc.spec.template && doc.spec.template.spec) || null;
  if (k === 'CronJob')
    return (doc.spec && doc.spec.jobTemplate && doc.spec.jobTemplate.spec &&
      doc.spec.jobTemplate.spec.template && doc.spec.jobTemplate.spec.template.spec) || null;
  return null;
}
function containersOf(ps) {
  const out = [];
  for (const key of ['containers', 'initContainers'])
    for (const c of (ps && Array.isArray(ps[key]) ? ps[key] : [])) out.push({ c, list: key });
  return out;
}
function nameOf(doc) {
  return ((doc && doc.kind) || 'Unknown') + '/' + ((doc && doc.metadata && doc.metadata.name) || 'unnamed');
}
function nsOf(doc) { return (doc && doc.metadata && doc.metadata.namespace) || 'default'; }
function sc(c) { if (!c.securityContext) c.securityContext = {}; return c.securityContext; }
function eachC(doc, cb) {
  const ps = podSpec(doc);
  if (!ps) return [];
  const out = [];
  for (const e of containersOf(ps)) {
    const r = cb(e.c, e.list, ps);
    if (r) Array.isArray(r) ? out.push(...r) : out.push(r);
  }
  return out;
}

/* ------------------------------------------------------------------ policies
 *
 * fixKind decides how the remediation page treats a finding:
 *   auto      one correct change, no plausible downside, applied on confirmation
 *   generate  produces a new object rather than editing an existing one
 *   manual    the right answer depends on context the scanner cannot see, so it is
 *             explained and left alone. Guessing breaks working systems, and a security
 *             tool that breaks production gets switched off.
 */
const ACS_POLICIES = [

{ id: 'ACS.001',
  acsPolicy: 'Privileged Container',
  acsCriteria: 'Privileged Container',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 8.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  cis: '5.2.1', nist: 'AC-6, CM-7', pss: 'Baseline',
  stig: 'Privileged container controls (verify against your STIG release)',
  description: 'Alert on deployments with containers running in privileged mode',
  rationale: 'Containers running as privileged represent greater post exploitation risk by allowing an attacker to access all host devices, run a daemon inside the container, and escape isolation entirely.',
  remediation: 'Verify that privileged capabilities are required and cannot be provided with a subset of other controls. Set securityContext.privileged to false and add back only the specific capabilities the workload proves it needs.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => (c.securityContext && c.securityContext.privileged === true)
      ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') runs privileged',
          path: l + '.' + c.name + '.securityContext.privileged' } : null);
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (c.securityContext && c.securityContext.privileged === true) {
        c.securityContext.privileged = false;
        return 'container "' + c.name + '": privileged true to false';
      }
    });
  } },

{ id: 'ACS.002',
  runtimeRisk: 'Can crash loop a workload that writes anywhere on its root filesystem, which is common: log files, PID files, a scratch directory, or a framework that writes to /tmp on startup. Mount an emptyDir at each path that needs to be writable, then apply this.',
  acsPolicy: 'Container using read-write root filesystem',
  acsCriteria: 'Read-Only Root Filesystem',
  categories: ['Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 5.3, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L',
  cis: 'General container hardening', nist: 'CM-7, SI-7', pss: 'Recommended practice',
  stig: 'Container immutability controls (verify)',
  description: 'Alert on deployments with containers using a read-write root filesystem',
  rationale: 'A writable root filesystem lets an attacker who gains code execution persist tooling, tamper with binaries, and drift the running container away from the image that was scanned.',
  remediation: 'Set the container securityContext.readOnlyRootFilesystem to true. Mount an emptyDir volume for any path the application genuinely writes to, such as /tmp.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => !(c.securityContext && c.securityContext.readOnlyRootFilesystem === true)
      ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') has a read write root filesystem',
          path: l + '.' + c.name + '.securityContext.readOnlyRootFilesystem' } : null);
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!(c.securityContext && c.securityContext.readOnlyRootFilesystem === true)) {
        sc(c).readOnlyRootFilesystem = true;
        return 'container "' + c.name + '": readOnlyRootFilesystem set to true';
      }
    });
  } },

{ id: 'ACS.003',
  acsPolicy: 'Container with privilege escalation allowed',
  acsCriteria: 'Allow Privilege Escalation',
  categories: ['Privileges'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 7.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
  cis: '5.2.5', nist: 'AC-6(10), CM-7', pss: 'Restricted',
  stig: 'Privilege escalation controls (verify)',
  description: 'Alert on containers that allow privilege escalation',
  rationale: 'Without allowPrivilegeEscalation set to false a process can gain more privileges than its parent through setuid binaries or file capabilities, defeating the container user restriction from below.',
  remediation: 'Set securityContext.allowPrivilegeEscalation to false on every container. This applies no_new_privs, which closes the setuid escalation path entirely.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => !(c.securityContext && c.securityContext.allowPrivilegeEscalation === false)
      ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') allows privilege escalation',
          path: l + '.' + c.name + '.securityContext.allowPrivilegeEscalation' } : null);
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!(c.securityContext && c.securityContext.allowPrivilegeEscalation === false)) {
        sc(c).allowPrivilegeEscalation = false;
        return 'container "' + c.name + '": allowPrivilegeEscalation set to false';
      }
    });
  } },

{ id: 'ACS.004',
  acsPolicy: 'Deployments should not have host network configured',
  acsCriteria: 'Host Network',
  categories: ['Network', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  cis: '5.2.4', nist: 'SC-7, AC-6', pss: 'Baseline',
  stig: 'Host namespace controls (verify)',
  description: 'Alert on deployments that use the host network namespace',
  rationale: 'hostNetwork places the pod directly on the node network stack. It can sniff node traffic, reach services bound only to localhost such as the kubelet API, and it bypasses NetworkPolicy completely.',
  remediation: 'Set hostNetwork to false and expose the workload through a Service instead.',
  fixKind: 'auto',
  check(doc) {
    const ps = podSpec(doc);
    return (ps && ps.hostNetwork === true)
      ? [{ obj: nameOf(doc), detail: 'Pod spec sets hostNetwork true', path: 'spec.hostNetwork' }] : [];
  },
  fix(doc) {
    const ps = podSpec(doc);
    if (ps && ps.hostNetwork === true) { ps.hostNetwork = false; return ['hostNetwork set to false']; }
    return [];
  } },

{ id: 'ACS.005',
  acsPolicy: 'Deployments should not have host PID configured',
  acsCriteria: 'Host PID',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 7.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
  cis: '5.2.2', nist: 'AC-6, SC-39', pss: 'Baseline',
  stig: 'Host namespace controls (verify)',
  description: 'Alert on deployments that share the host process namespace',
  rationale: 'hostPID exposes every process on the node. Even without ptrace it leaks credentials from process arguments and environment, and it makes the node process table a shared resource.',
  remediation: 'Set hostPID to false.',
  fixKind: 'auto',
  check(doc) {
    const ps = podSpec(doc);
    return (ps && ps.hostPID === true)
      ? [{ obj: nameOf(doc), detail: 'Pod spec sets hostPID true', path: 'spec.hostPID' }] : [];
  },
  fix(doc) {
    const ps = podSpec(doc);
    if (ps && ps.hostPID === true) { ps.hostPID = false; return ['hostPID set to false']; }
    return [];
  } },

{ id: 'ACS.006',
  acsPolicy: 'Deployments should not have host IPC configured',
  acsCriteria: 'Host IPC',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 6.5, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
  cis: '5.2.3', nist: 'AC-6, SC-39', pss: 'Baseline',
  stig: 'Host namespace controls (verify)',
  description: 'Alert on deployments that share the host IPC namespace',
  rationale: 'hostIPC lets the container read and manipulate host shared memory segments and message queues belonging to other processes on the node.',
  remediation: 'Set hostIPC to false.',
  fixKind: 'auto',
  check(doc) {
    const ps = podSpec(doc);
    return (ps && ps.hostIPC === true)
      ? [{ obj: nameOf(doc), detail: 'Pod spec sets hostIPC true', path: 'spec.hostIPC' }] : [];
  },
  fix(doc) {
    const ps = podSpec(doc);
    if (ps && ps.hostIPC === true) { ps.hostIPC = false; return ['hostIPC set to false']; }
    return [];
  } },

{ id: 'ACS.007',
  acsPolicy: 'CAP_SYS_ADMIN capability added',
  acsCriteria: 'Add Capabilities',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 8.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  cis: '5.2.8', nist: 'AC-6, CM-7', pss: 'Baseline',
  stig: 'Capability controls (verify)',
  description: 'Alert on deployments that add high risk Linux capabilities',
  rationale: 'Capabilities such as SYS_ADMIN, SYS_PTRACE and NET_ADMIN are documented container escape primitives. SYS_ADMIN alone is close to full root on the node.',
  remediation: 'Remove the high risk entries from securityContext.capabilities.add. If one is genuinely required, isolate the workload on a dedicated node pool with compensating controls and record the justification.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => {
      const add = (c.securityContext && c.securityContext.capabilities && c.securityContext.capabilities.add) || [];
      const bad = add.filter((a) => DANGEROUS_CAPS.includes(String(a).toUpperCase()));
      return bad.length ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') adds ' + bad.join(', '),
        path: l + '.' + c.name + '.securityContext.capabilities.add' } : null;
    });
  },
  fix(doc) {
    return eachC(doc, (c) => {
      const cap = c.securityContext && c.securityContext.capabilities;
      if (cap && Array.isArray(cap.add)) {
        const bad = cap.add.filter((a) => DANGEROUS_CAPS.includes(String(a).toUpperCase()));
        if (bad.length) {
          cap.add = cap.add.filter((a) => !DANGEROUS_CAPS.includes(String(a).toUpperCase()));
          if (!cap.add.length) delete cap.add;
          return 'container "' + c.name + '": removed capabilities ' + bad.join(', ');
        }
      }
    });
  } },

{ id: 'ACS.008',
  runtimeRisk: 'Dropping ALL removes capabilities some images genuinely need: NET_BIND_SERVICE for a port below 1024, NET_RAW for ping style health checks, CHOWN or SETUID for an entrypoint that drops privileges itself. Add back exactly what the workload needs rather than reverting the drop.',
  acsPolicy: 'Container does not drop all capabilities',
  acsCriteria: 'Drop Capabilities',
  categories: ['Privileges'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 6.3, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H',
  cis: '5.2.9', nist: 'AC-6, CM-7', pss: 'Restricted',
  stig: 'Capability controls (verify)',
  description: 'Alert on containers that do not drop all capabilities',
  rationale: 'The container runtime grants a default set of roughly fourteen capabilities including NET_RAW and SETUID that almost no application uses. Every retained capability is unnecessary attack surface.',
  remediation: 'Set securityContext.capabilities.drop to ALL. Add back only NET_BIND_SERVICE if the process must bind a port below 1024.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => {
      const cap = c.securityContext && c.securityContext.capabilities;
      const dropsAll = cap && Array.isArray(cap.drop) && cap.drop.some((d) => String(d).toUpperCase() === 'ALL');
      return !dropsAll ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') does not drop ALL capabilities',
        path: l + '.' + c.name + '.securityContext.capabilities.drop' } : null;
    });
  },
  fix(doc) {
    return eachC(doc, (c) => {
      const s = sc(c);
      const cap = s.capabilities || {};
      const dropsAll = Array.isArray(cap.drop) && cap.drop.some((d) => String(d).toUpperCase() === 'ALL');
      if (!dropsAll) {
        const keep = (cap.add || []).filter((a) => String(a).toUpperCase() === 'NET_BIND_SERVICE');
        s.capabilities = { drop: ['ALL'] };
        if (keep.length) s.capabilities.add = keep;
        return 'container "' + c.name + '": capabilities drop ALL' + (keep.length ? ', kept ' + keep.join(', ') : '');
      }
    });
  } },

{ id: 'ACS.009',
  runtimeRisk: 'If the image has no numeric non root USER, the kubelet refuses to start the container with CreateContainerConfigError, because it cannot verify the user is not root. Set runAsUser to the uid the image runs as, or rebuild the image with a USER line, then apply this.',
  acsPolicy: 'Deployments should not run as root user',
  acsCriteria: 'Run as Privileged User',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 7.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
  cis: '5.2.6', nist: 'AC-6, CM-6', pss: 'Restricted',
  stig: 'Non root execution controls (verify)',
  description: 'Alert on containers that may run as the root user',
  rationale: 'Root inside a container is root against the kernel. Combined with any breakout primitive or a writable host mount it becomes node compromise, and UID 0 defeats file ownership defences on mounted volumes.',
  remediation: 'Set the pod securityContext.runAsNonRoot to true and remove any runAsUser of 0. On OpenShift let the restricted-v2 SCC assign the UID rather than pinning one.',
  fixKind: 'auto',
  check(doc) {
    const ps = podSpec(doc);
    if (!ps) return [];
    const out = [];
    const podNonRoot = ps.securityContext && ps.securityContext.runAsNonRoot === true;
    const podUid0 = ps.securityContext && ps.securityContext.runAsUser === 0;
    for (const { c, list } of containersOf(ps)) {
      const csc = c.securityContext || {};
      if (csc.runAsUser === 0)
        out.push({ obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + list + ') sets runAsUser 0',
          path: list + '.' + c.name + '.securityContext.runAsUser' });
      else if (podUid0 && csc.runAsUser === undefined)
        out.push({ obj: nameOf(doc), detail: 'Pod securityContext sets runAsUser 0, inherited by "' + c.name + '"',
          path: 'spec.securityContext.runAsUser' });
      else if (!podNonRoot && csc.runAsNonRoot !== true)
        out.push({ obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + list + ') has no runAsNonRoot guarantee',
          path: 'spec.securityContext.runAsNonRoot' });
    }
    return out;
  },
  fix(doc) {
    const ps = podSpec(doc);
    if (!ps) return [];
    const ch = [];
    if (!ps.securityContext) ps.securityContext = {};
    if (ps.securityContext.runAsUser === 0) { delete ps.securityContext.runAsUser; ch.push('removed pod level runAsUser 0'); }
    if (ps.securityContext.runAsNonRoot !== true) { ps.securityContext.runAsNonRoot = true; ch.push('pod securityContext.runAsNonRoot set to true'); }
    for (const { c } of containersOf(ps))
      if (c.securityContext && c.securityContext.runAsUser === 0) {
        delete c.securityContext.runAsUser;
        ch.push('container "' + c.name + '": removed runAsUser 0');
      }
    return ch;
  } },

{ id: 'ACS.010',
  acsPolicy: 'Environment Variable Contains Secret',
  acsCriteria: 'Environment Variable',
  categories: ['Security Best Practices'],
  lifecycleStages: ['DEPLOY'],
  severity: 'CRITICAL_SEVERITY',
  score: 9.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  cis: 'General secrets hygiene', nist: 'IA-5(7), SC-28, SA-11', pss: 'n/a',
  stig: 'Secrets in environment variables (verify)',
  description: 'Alert on deployments with environment variables that contain secrets',
  rationale: 'A literal credential in a manifest lives in git history, CI logs, kubectl describe output and every backup, permanently. Rotation requires a code change and a redeploy.',
  remediation: 'Move the value into a Secret managed by an external store and reference it with valueFrom.secretKeyRef. Rotate the exposed credential immediately, it has to be treated as compromised.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => Array.isArray(c.env)
      ? c.env.filter((e) => e && typeof e.value === 'string' && e.value.length > 0 && SECRET_ENV_RE.test(e.name || ''))
        .map((e) => ({ obj: nameOf(doc),
          detail: 'Container "' + c.name + '" (' + l + ') env "' + e.name + '" holds a literal credential',
          path: l + '.' + c.name + '.env.' + e.name }))
      : null);
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!Array.isArray(c.env)) return null;
      const ch = [];
      const owner = ((doc.metadata && doc.metadata.name) || 'app').toLowerCase().replace(/[^a-z0-9]/g, '');
      for (const e of c.env)
        if (e && typeof e.value === 'string' && e.value.length > 0 && SECRET_ENV_RE.test(e.name || '')) {
          delete e.value;
          e.valueFrom = { secretKeyRef: { name: owner + '-secrets', key: String(e.name).toLowerCase() } };
          ch.push('container "' + c.name + '": env ' + e.name + ' now reads from Secret "' + owner + '-secrets" (create it out of band and ROTATE the exposed value)');
        }
      return ch.length ? ch : null;
    });
  } },

{ id: 'ACS.011',
  acsPolicy: 'Mounting Container Runtime Socket',
  acsCriteria: 'Volume Destination',
  categories: ['Privileges', 'Docker CIS'],
  lifecycleStages: ['DEPLOY'],
  severity: 'CRITICAL_SEVERITY',
  score: 9.3, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  cis: 'General', nist: 'AC-6, SC-4', pss: 'Baseline',
  stig: 'Host filesystem controls (verify)',
  description: 'Alert on deployments that mount the container runtime socket',
  rationale: 'The runtime socket is the control plane for every container on the node. Mounting it grants the ability to start a privileged container, mount the host filesystem and take the node. It is the most direct escape path in Kubernetes.',
  remediation: 'Requires a human decision: remove the socket mount. If the workload genuinely needs runtime introspection, use the Kubernetes API with scoped RBAC, or a sidecar exposing a read only audited interface.',
  fixKind: 'manual',
  check(doc) {
    const ps = podSpec(doc);
    if (!ps || !Array.isArray(ps.volumes)) return [];
    return ps.volumes.filter((v) => v && v.hostPath && SOCKET_PATHS.includes(String(v.hostPath.path || '')))
      .map((v) => ({ obj: nameOf(doc), detail: 'Volume "' + v.name + '" mounts the runtime socket ' + v.hostPath.path,
        path: 'spec.volumes.' + v.name }));
  } },

{ id: 'ACS.012',
  acsPolicy: 'Deployment mounts sensitive host directory',
  acsCriteria: 'Volume Source',
  categories: ['Privileges'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 8.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  cis: 'PSS volume restrictions', nist: 'AC-6, SC-4', pss: 'Baseline',
  stig: 'Host filesystem controls (verify)',
  description: 'Alert on deployments that mount a host path',
  rationale: 'A hostPath mount pierces container isolation. Mounting / or /etc is direct node compromise, and even a narrow path enables persistence and credential theft on the host.',
  remediation: 'Requires a human decision: replace the hostPath with a PersistentVolumeClaim, ConfigMap, Secret or emptyDir. If a node path is genuinely unavoidable, mount it readOnly, scope it to the narrowest directory and pair it with an admission policy.',
  fixKind: 'manual',
  check(doc) {
    const ps = podSpec(doc);
    if (!ps || !Array.isArray(ps.volumes)) return [];
    return ps.volumes.filter((v) => v && v.hostPath && !SOCKET_PATHS.includes(String(v.hostPath.path || '')))
      .map((v) => {
        const p = String(v.hostPath.path || '?');
        const severe = p === '/' || p.startsWith('/etc') || p.startsWith('/root') || p.startsWith('/var/lib/kubelet');
        return { obj: nameOf(doc), detail: 'Volume "' + v.name + '" mounts hostPath ' + p + (severe ? ' (node takeover risk)' : ''),
          path: 'spec.volumes.' + v.name };
      });
  } },

{ id: 'ACS.013',
  acsPolicy: 'No CPU request or limit specified',
  acsCriteria: 'CPU Resource Request',
  categories: ['Resource Management', 'DevOps Best Practices'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 5.5, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
  cis: 'General', nist: 'SC-5, SC-6', pss: 'n/a',
  stig: 'Resource limit controls (verify)',
  description: 'Alert on containers without CPU requests or limits',
  rationale: 'Without limits a single pod can exhaust node CPU and evict its neighbours. It is a denial of service primitive available to any compromised or simply buggy workload.',
  remediation: 'Set resources.requests.cpu and resources.limits.cpu on every container. Values inserted by the fix are placeholders and must be tuned to the real workload before deploy.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => {
      const r = c.resources || {};
      const missing = [];
      if (!(r.requests && r.requests.cpu)) missing.push('request');
      if (!(r.limits && r.limits.cpu)) missing.push('limit');
      return missing.length ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') missing CPU ' + missing.join(' and '),
        path: l + '.' + c.name + '.resources.cpu' } : null;
    });
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!c.resources) c.resources = {};
      const ch = [];
      if (!c.resources.requests) c.resources.requests = {};
      if (!c.resources.limits) c.resources.limits = {};
      if (!c.resources.requests.cpu) { c.resources.requests.cpu = '100m'; ch.push('container "' + c.name + '": cpu request 100m (PLACEHOLDER, tune it)'); }
      if (!c.resources.limits.cpu) { c.resources.limits.cpu = '500m'; ch.push('container "' + c.name + '": cpu limit 500m (PLACEHOLDER, tune it)'); }
      return ch.length ? ch : null;
    });
  } },

{ id: 'ACS.014',
  acsPolicy: 'No memory request or limit specified',
  acsCriteria: 'Memory Resource Request',
  categories: ['Resource Management', 'DevOps Best Practices'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 5.5, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
  cis: 'General', nist: 'SC-5, SC-6', pss: 'n/a',
  stig: 'Resource limit controls (verify)',
  description: 'Alert on containers without memory requests or limits',
  rationale: 'A container with no memory limit can consume the node until the kernel OOM killer intervenes, taking unrelated workloads with it. Memory is the resource that actually takes nodes down.',
  remediation: 'Set resources.requests.memory and resources.limits.memory on every container. Values inserted by the fix are placeholders and must be tuned before deploy.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => {
      const r = c.resources || {};
      const missing = [];
      if (!(r.requests && r.requests.memory)) missing.push('request');
      if (!(r.limits && r.limits.memory)) missing.push('limit');
      return missing.length ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') missing memory ' + missing.join(' and '),
        path: l + '.' + c.name + '.resources.memory' } : null;
    });
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!c.resources) c.resources = {};
      const ch = [];
      if (!c.resources.requests) c.resources.requests = {};
      if (!c.resources.limits) c.resources.limits = {};
      if (!c.resources.requests.memory) { c.resources.requests.memory = '128Mi'; ch.push('container "' + c.name + '": memory request 128Mi (PLACEHOLDER, tune it)'); }
      if (!c.resources.limits.memory) { c.resources.limits.memory = '512Mi'; ch.push('container "' + c.name + '": memory limit 512Mi (PLACEHOLDER, tune it)'); }
      return ch.length ? ch : null;
    });
  } },

{ id: 'ACS.015',
  acsPolicy: 'Latest tag',
  acsCriteria: 'Image Tag',
  categories: ['DevOps Best Practices', 'Security Best Practices'],
  lifecycleStages: ['BUILD', 'DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
  cis: 'General supply chain hygiene', nist: 'CM-2, SI-7, SR-11', pss: 'n/a',
  stig: 'Container image controls (verify)',
  description: 'Alert on deployments using an image with the latest tag or no tag',
  rationale: 'A latest or absent tag means the image content can change underneath you. What passed testing is not provably what runs in production, and a registry compromise silently redeploys attacker code on the next pull.',
  remediation: 'Requires a human decision: pin the image to an immutable version tag, ideally a sha256 digest, and enforce it with admission policy. Only you know which build is blessed.',
  fixKind: 'manual',
  check(doc) {
    return eachC(doc, (c, l) => {
      const img = String(c.image || '');
      if (!img || img.includes('@sha256:')) return null;
      const tag = img.includes(':') ? img.split(':').pop() : '';
      return (!tag || tag === 'latest')
        ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') image "' + img + '" uses ' + (tag ? 'the latest tag' : 'no tag'),
            path: l + '.' + c.name + '.image' } : null;
    });
  } },

{ id: 'ACS.016',
  runtimeRisk: 'Breaks any pod that calls the Kubernetes API from inside itself: operators, controllers, service meshes, anything using in cluster config. If the pod needs the API, leave the token mounted and scope the service account instead.',
  acsPolicy: 'Pod Service Account Token Automatically Mounted',
  acsCriteria: 'Automount Service Account Token',
  categories: ['Kubernetes'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  cis: '5.1.6', nist: 'AC-6, IA-5', pss: 'n/a',
  stig: 'Service account token controls (verify)',
  description: 'Alert on pods that automatically mount a service account token',
  rationale: 'Every pod receives a Kubernetes API credential at a well known path unless told otherwise. An attacker with code execution harvests it immediately and talks to the API server with whatever RBAC that account holds.',
  remediation: 'Set automountServiceAccountToken to false on the pod spec. Re enable it only for workloads that genuinely call the Kubernetes API, which is a small minority.',
  fixKind: 'auto',
  check(doc) {
    const ps = podSpec(doc);
    if (!ps) return [];
    return ps.automountServiceAccountToken !== false
      ? [{ obj: nameOf(doc), detail: 'Pod automounts a service account token', path: 'spec.automountServiceAccountToken' }] : [];
  },
  fix(doc) {
    const ps = podSpec(doc);
    if (ps && ps.automountServiceAccountToken !== false) {
      ps.automountServiceAccountToken = false;
      return ['automountServiceAccountToken set to false (re enable if this pod calls the Kubernetes API)'];
    }
    return [];
  } },

{ id: 'ACS.017',
  acsPolicy: 'Deployment uses the default service account',
  acsCriteria: 'Service Account',
  categories: ['Kubernetes'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 5.3, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
  cis: '5.1.5', nist: 'AC-6, IA-2', pss: 'n/a',
  stig: 'Service account controls (verify)',
  description: 'Alert on deployments that use the default service account',
  rationale: 'The default service account is shared by every pod in the namespace that does not opt out. Any RBAC granted to it, now or in future, silently flows to all of them.',
  remediation: 'Requires a human decision: create a dedicated ServiceAccount per workload and set spec.serviceAccountName. The account must exist before the workload deploys, so a scanner cannot do this safely on its own.',
  fixKind: 'manual',
  check(doc) {
    const ps = podSpec(doc);
    if (!ps) return [];
    const sa = ps.serviceAccountName || ps.serviceAccount;
    return (!sa || sa === 'default')
      ? [{ obj: nameOf(doc), detail: 'Pod uses the ' + (sa ? '"default"' : 'implicit default') + ' service account',
           path: 'spec.serviceAccountName' }] : [];
  } },

{ id: 'ACS.018',
  acsPolicy: 'Deployments should have at least one ingress Network Policy',
  acsCriteria: 'Missing Ingress Network Policy',
  categories: ['Network'],
  lifecycleStages: ['DEPLOY'],
  severity: 'MEDIUM_SEVERITY',
  score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  cis: '5.3.2', nist: 'SC-7, AC-4, CA-9', pss: 'n/a',
  stig: 'Network segmentation controls (verify)',
  description: 'Alert on deployments in a namespace with no ingress NetworkPolicy',
  rationale: 'Kubernetes networking is allow all by default. Without a NetworkPolicy every pod can reach every other pod, so one compromised workload can scan and attack the whole cluster east to west.',
  remediation: 'Apply a default deny ingress and egress NetworkPolicy per namespace, then add explicit allow rules for the flows genuinely required. The remediation page generates the default deny policy with DNS egress already permitted.',
  fixKind: 'generate',
  fileset: true },

{ id: 'ACS.019',
  acsPolicy: 'Docker CIS 5.7: do not map privileged ports within containers',
  acsCriteria: 'Exposed Port',
  categories: ['Docker CIS', 'Network'],
  lifecycleStages: ['DEPLOY'],
  severity: 'LOW_SEVERITY',
  score: 3.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
  cis: '5.7', nist: 'CM-7, SC-7', pss: 'n/a',
  stig: 'Non privileged host ports (verify)',
  description: 'Alert on containers binding a host port',
  rationale: 'hostPort binds the container directly to the node IP, bypassing Service level control and complicating scheduling. A port below 1024 sits in the privileged range.',
  remediation: 'Remove the hostPort and expose the workload through a Service. If a fixed external port is genuinely required, terminate it at an Ingress or Route rather than on the node.',
  fixKind: 'auto',
  check(doc) {
    return eachC(doc, (c, l) => Array.isArray(c.ports)
      ? c.ports.filter((p) => p && p.hostPort).map((p) => ({
        obj: nameOf(doc),
        detail: 'Container "' + c.name + '" (' + l + ') binds hostPort ' + p.hostPort + (p.hostPort < 1024 ? ' (privileged range)' : ''),
        path: l + '.' + c.name + '.ports.hostPort',
      })) : null);
  },
  fix(doc) {
    return eachC(doc, (c) => {
      if (!Array.isArray(c.ports)) return null;
      const ch = [];
      for (const p of c.ports) if (p && p.hostPort) { ch.push('container "' + c.name + '": removed hostPort ' + p.hostPort); delete p.hostPort; }
      return ch.length ? ch : null;
    });
  } },

{ id: 'ACS.020',
  acsPolicy: 'Kubernetes Dashboard Deployed',
  acsCriteria: 'Image Name',
  categories: ['Kubernetes'],
  lifecycleStages: ['DEPLOY'],
  severity: 'HIGH_SEVERITY',
  score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  cis: 'General', nist: 'AC-6, CM-7', pss: 'n/a',
  stig: 'Dashboard controls (verify)',
  description: 'Alert on the Kubernetes dashboard being deployed',
  rationale: 'The dashboard is not inherently insecure, but it is repeatedly paired with an over permissive service account, and that combination has been the entry point in several widely reported cluster compromises.',
  remediation: 'Requires a human decision: remove the dashboard, or confirm it is bound to a minimal service account, requires authentication and is not reachable from outside the cluster.',
  fixKind: 'manual',
  check(doc) {
    return eachC(doc, (c, l) => {
      const img = String(c.image || '');
      return /kubernetes-dashboard|kubernetesui\/dashboard/i.test(img)
        ? { obj: nameOf(doc), detail: 'Container "' + c.name + '" (' + l + ') runs the Kubernetes dashboard image',
            path: l + '.' + c.name + '.image' } : null;
    });
  } },

];

/* --------------------------------------------------------------- evaluation */

function parseFileText(name, text) {
  const docs = [];
  const errors = [];
  try {
    for (const d of jsyaml.loadAll(text)) if (d && typeof d === 'object') docs.push(d);
  } catch (e) { errors.push(String(e.message || e)); }
  return { name, text, docs, errors };
}

/* Which policies are evaluated against a given document, so posture has an honest
   denominator. A policy that does not apply must not be counted as passed. */
const APPLIES = {};
function policyApplies(policy, doc) {
  if (policy.fileset) return false;
  const f = APPLIES[policy.id];
  return f ? f(doc) : !!podSpec(doc);
}

function scanFiles(files) {
  const findings = [];
  for (const f of files)
    for (const doc of f.docs)
      for (const p of ACS_POLICIES) {
        if (!p.check) continue;
        try {
          for (const hit of p.check(doc))
            findings.push({
              policy: p, file: f.name, obj: hit.obj, detail: hit.detail, path: hit.path,
              ns: nsOf(doc), source: 'local scan',
              fixKind: p.fixKind, selected: p.fixKind !== 'manual',
            });
        } catch (e) { /* a malformed document must not take the whole scan down */ }
      }

  const netpol = ACS_POLICIES.find((p) => p.id === 'ACS.018');
  const nsWithWorkloads = new Set();
  const nsWithPolicy = new Set();
  for (const f of files) for (const d of f.docs) {
    if (d && WORKLOADS.includes(d.kind)) nsWithWorkloads.add(nsOf(d));
    if (d && d.kind === 'NetworkPolicy') nsWithPolicy.add(nsOf(d));
  }
  for (const ns of nsWithWorkloads)
    if (!nsWithPolicy.has(ns))
      findings.push({
        policy: netpol, file: '(scanned set)', obj: 'Namespace/' + ns,
        detail: 'Namespace "' + ns + '" has workloads but no ingress NetworkPolicy',
        path: 'namespace/' + ns, ns, source: 'local scan',
        fixKind: 'generate', selected: true,
      });

  findings.sort((a, b) =>
    sevRank(a.policy.severity) - sevRank(b.policy.severity) ||
    b.policy.score - a.policy.score ||
    a.policy.id.localeCompare(b.policy.id));
  return findings;
}

/* Posture is a weighted compliance rate: every applicable policy and object pair is one
   check, weighted by ACS severity. The denominator comes only from what was scanned, never
   from what was found. Break that and the projected score stops surviving a rescan, which
   turns the headline number into a lie. */
function computePosture(files, findings, assumeFixed) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const unresolved = new Set();
  for (const f of findings) {
    if (assumeFixed && f.fixKind !== 'manual' && f.selected !== false) continue;
    counts[sevLabel(f.policy.severity)]++;
    unresolved.add(f.file + '|' + f.obj + '|' + f.policy.id);
  }
  let totalW = 0, failW = 0;
  const catTotal = {}, catFail = {};
  const unit = (cat, w, failed) => {
    totalW += w; catTotal[cat] = (catTotal[cat] || 0) + w;
    if (failed) { failW += w; catFail[cat] = (catFail[cat] || 0) + w; }
  };
  for (const file of files) for (const doc of file.docs) {
    const obj = nameOf(doc);
    for (const p of ACS_POLICIES)
      if (policyApplies(p, doc))
        unit(p.categories[0], sevWeight(p.severity), unresolved.has(file.name + '|' + obj + '|' + p.id));
  }
  const netpol = ACS_POLICIES.find((p) => p.id === 'ACS.018');
  const nsWithWorkloads = new Set();
  for (const file of files) for (const doc of file.docs)
    if (doc && WORKLOADS.includes(doc.kind)) nsWithWorkloads.add(nsOf(doc));
  for (const ns of nsWithWorkloads) {
    const hit = findings.find((f) => f.policy.id === 'ACS.018' && f.ns === ns);
    const failed = !!hit && !(assumeFixed && hit.fixKind !== 'manual' && hit.selected !== false);
    unit(netpol.categories[0], sevWeight(netpol.severity), failed);
  }
  const score = totalW ? Math.round(100 * (1 - failW / totalW)) : 100;
  const catScores = {};
  for (const c of Object.keys(catTotal)) catScores[c] = Math.round(100 * (1 - (catFail[c] || 0) / catTotal[c]));
  return {
    score, counts, catScores,
    grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F',
  };
}

/* ------------------------------------------------- ACS violation import */

function normalizeName(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }

/* Known naming variants. ACS has renamed several defaults across releases, and teams clone
   and rename policies constantly, so an alias table beats trying to be cleverer with fuzzy
   matching. Anything not listed still falls through to token scoring below. */
const POLICY_ALIASES = {
  'ACS.001': ['Privileged Containers', 'Container Running as Privileged'],
  'ACS.002': ['Read-Only Root Filesystem', 'Container using read-write root filesystem',
              'Writable root filesystem'],
  'ACS.003': ['Privilege Escalation', 'Allow Privilege Escalation'],
  'ACS.004': ['Host Network', 'Deployment uses host network', 'hostNetwork configured'],
  'ACS.005': ['Host PID', 'Deployment uses host PID namespace'],
  'ACS.006': ['Host IPC', 'Deployment uses host IPC namespace'],
  'ACS.007': ['Added Capabilities', 'CAP_SYS_ADMIN capability added', 'Dangerous capability added'],
  'ACS.008': ['Drop All Capabilities', 'Container does not drop all capabilities'],
  'ACS.009': ['Deployments should not run as root user', 'Container running as root',
              'Run as Privileged User'],
  'ACS.010': ['Environment Variable Contains Secret', 'Secret in environment variable',
              'Plaintext secret in environment'],
  'ACS.011': ['Mounting Docker Socket', 'Deployment mounts the Docker socket',
              'Docker Socket Mounted', 'Mounting Container Runtime Socket',
              'Container runtime socket mounted'],
  'ACS.012': ['Deployment mounts sensitive host directory', 'Mounts host path',
              'Host mount', 'Sensitive host mount'],
  'ACS.013': ['No CPU Request Specified', 'No CPU Limit Specified', 'Container CPU limit not set'],
  'ACS.014': ['No Memory Request Specified', 'No Memory Limit Specified', 'Container memory limit not set'],
  'ACS.015': ['Latest tag', 'Image using latest tag', 'No image tag specified'],
  'ACS.016': ['Pod Service Account Token Automatically Mounted', 'Automount service account token'],
  'ACS.017': ['Deployment uses the default service account', 'Default service account in use'],
  'ACS.018': ['Deployments should have at least one ingress Network Policy',
              'Missing Ingress Network Policy', 'No ingress network policy'],
  'ACS.019': ['Privileged Ports Mapped', 'Docker CIS 5.7', 'Host port mapped'],
  'ACS.020': ['Kubernetes Dashboard Deployed', 'Kubernetes dashboard'],
};

/* Crude stemmer, enough to make mounts, mounting and mounted collide. A real stemmer would
   be overkill for matching a few dozen policy names. */
function stem(w) { return w.replace(/(ings|ing|ed|es|s)$/, ''); }
function tokensOf(s) { return normalizeName(s).split(' ').filter((w) => w.length > 3).map(stem); }

/* Match an ACS policy name back to a local rule. Exact, then alias, then containment, then
   best scoring token overlap. The point is that a violation from a renamed or tuned policy
   still lands on the right rule rather than being silently discarded, because a dropped
   violation is indistinguishable from a clean result. */
function matchPolicy(acsName) {
  const want = normalizeName(acsName);
  if (!want) return null;

  let hit = ACS_POLICIES.find((p) => normalizeName(p.acsPolicy) === want);
  if (hit) return { policy: hit, confidence: 'exact' };

  hit = ACS_POLICIES.find((p) => (POLICY_ALIASES[p.id] || []).some((a) => normalizeName(a) === want));
  if (hit) return { policy: hit, confidence: 'alias' };

  hit = ACS_POLICIES.find((p) => {
    const a = normalizeName(p.acsPolicy);
    return a.includes(want) || want.includes(a);
  });
  if (hit) return { policy: hit, confidence: 'fuzzy' };

  /* Token scoring. Best match wins rather than first match, and ties break on the number
     of shared tokens, so a distinctive word like "socket" outweighs a generic one like
     "deployment" that half the catalogue shares. */
  const wt = tokensOf(acsName);
  if (wt.length < 2) return null;
  let best = null, bestScore = 0, bestShared = 0;
  for (const p of ACS_POLICIES) {
    const pt = tokensOf(p.acsPolicy + ' ' + p.acsCriteria + ' ' + (POLICY_ALIASES[p.id] || []).join(' '));
    const shared = wt.filter((w) => pt.includes(w));
    if (shared.length < 2) continue;
    const score = shared.length / Math.min(wt.length, pt.length || 1);
    if (shared.length > bestShared || (shared.length === bestShared && score > bestScore)) {
      bestShared = shared.length; bestScore = score; best = p;
    }
  }
  return best && bestScore >= 0.4 ? { policy: best, confidence: 'weak' } : null;
}

/* Accepts what ACS actually hands you, which is not one shape but four.
 *
 * The distinction that matters, and the reason findings looked empty before: GET /v1/alerts
 * returns storage.ListAlert, a deliberately slim projection. It carries policy.name,
 * policy.severity, policy.categories, lifecycleStage and state, but it has NO violations
 * array, and the namespace and cluster live under commonEntityInfo rather than under
 * deployment. Reading a.deployment.namespace against a ListAlert yields undefined, and
 * reading a.violations yields nothing at all.
 *
 * The full storage.Alert, with violations[].message and the policy criteria, only comes back
 * from GET /v1/alerts/{id}. See fetchAcsAlerts, which lists then hydrates.
 * Reference: stackrox/proto/api/v1/alert_service.proto and storage/alert.proto.
 */
function alertEntity(a) {
  const cei = a.commonEntityInfo || a.common_entity_info || {};
  const dep = a.deployment || {};
  const res = a.resource || {};
  const node = a.node || {};
  const img = a.image || {};
  let kind = 'Deployment';
  let name = '';
  if (dep && dep.name) { kind = dep.type || dep.deploymentType || dep.deployment_type || 'Deployment'; name = dep.name; }
  else if (res && res.name) { kind = String(res.resourceType || res.resource_type || cei.resourceType || cei.resource_type || 'Resource'); name = res.name; }
  else if (node && node.name) { kind = 'Node'; name = node.name; }
  else if (img && (img.name || img.fullName)) { kind = 'Image'; name = (img.name && img.name.fullName) || img.fullName || img.name || ''; }
  return {
    kind: kind || 'Deployment',
    name: name || 'unknown',
    // ListAlert puts these on commonEntityInfo. The full Alert puts them at the top level
    // and duplicates them onto deployment. Take whichever is present.
    namespace: cei.namespace || a.namespace || dep.namespace || res.namespace || 'unknown',
    cluster: cei.clusterName || cei.cluster_name || a.clusterName || a.cluster_name ||
             dep.clusterName || dep.cluster_name || dep.cluster || '',
  };
}

function importAcsViolations(json) {
  let alerts = [];
  if (Array.isArray(json)) alerts = json;
  else if (json && Array.isArray(json.alerts)) alerts = json.alerts;      // ListAlertsResponse
  else if (json && Array.isArray(json.results)) alerts = json.results;    // roxctl report
  else if (json && json.alert) alerts = [json.alert];
  else if (json && json.id && json.policy) alerts = [json];               // a single full Alert

  const imported = [];
  const unmatched = [];
  for (const a of alerts) {
    const pol = a.policy || {};
    const name = pol.name || a.policyName || a.policy_name || '';
    const m = matchPolicy(name);
    const ent = alertEntity(a);
    const vios = Array.isArray(a.violations) ? a.violations.map((v) => v && v.message).filter(Boolean) : [];
    const proc = a.processViolation || a.process_violation;
    if (proc && proc.message) vios.push(proc.message);
    const rec = {
      acsAlertId: a.id || '',
      acsPolicyName: name,
      acsPolicyId: pol.id || '',
      acsSeverity: pol.severity || a.severity || null,
      acsCategories: Array.isArray(pol.categories) ? pol.categories.slice() : [],
      lifecycleStage: a.lifecycleStage || a.lifecycle_stage || '',
      /* undefined on ACS older than 4.6, which is different from false and must not be
         collapsed into it. looksPlatform falls back to a namespace heuristic only when
         this is genuinely absent. */
      platformComponent: (a.platformComponent !== undefined ? a.platformComponent
                        : (a.platform_component !== undefined ? a.platform_component : undefined)),
      entityType: a.entityType || a.entity_type || '',
      namespace: ent.namespace,
      cluster: ent.cluster,
      obj: ent.kind + '/' + ent.name,
      // A ListAlert has no violation text. Say so rather than inventing one, and record that
      // the record is not hydrated so the UI can offer to fetch the detail.
      detail: vios.length ? vios.join('; ') : (pol.description || 'Reported by ACS'),
      violations: vios,
      hydrated: vios.length > 0,
      state: a.state || '',
      enforcement: (a.enforcement && a.enforcement.action) || a.enforcementAction || a.enforcement_action || '',
      time: a.time || '',
      matched: !!m,
      confidence: m ? m.confidence : null,
      policy: m ? m.policy : null,
    };
    if (m) imported.push(rec); else unmatched.push(rec);
  }
  const all = imported.concat(unmatched);
  for (const r of all) {
    r.isPlatform = looksPlatform(r);
    /* Record which signal decided it. These are not the same claim.
     *
     * platformComponent from ACS is authoritative: ACS knows what it installed and what
     * the cluster operators own. The namespace pattern is a guess made when the field is
     * absent, and it is wrong in both directions: a team can deploy their own workload
     * into openshift-operators, and a genuine platform component can sit somewhere the
     * pattern does not match.
     *
     * Refusing to fix on the strength of a guess, without saying it was a guess, is how
     * a real finding on a workload you own gets quietly parked forever. */
    r.platformSource = rec_platform_source(r);
  }
  const hydratable = all.filter((r) => !r.hydrated && r.acsAlertId).length;
  const platform = all.filter((r) => r.isPlatform).length;
  /* If nothing in the set reports the flag, say so rather than letting the caller assume
     the split is authoritative when it came from a namespace guess. */
  const reportsFlag = all.some((r) => r.platformComponent !== undefined);
  return { imported, unmatched, total: alerts.length, hydratable,
           platform: platform, user: all.length - platform,
           platformFlagPresent: reportsFlag };
}

/* Correlate imported violations with locally scanned findings so the audit shows one row per
   real problem. A finding confirmed by both is worth more than either alone: ACS proves it is
   live in a cluster, the local scan proves which manifest line causes it. */
function correlate(findings, imported) {
  const byKey = {};
  for (const f of findings) byKey[f.policy.id + '|' + f.obj] = f;
  const onlyInAcs = [];
  for (const v of imported) {
    const f = byKey[v.policy.id + '|' + v.obj];
    if (f) {
      f.confirmedByAcs = true;
      f.acsNamespace = v.namespace;
      f.acsCluster = v.cluster;
    } else {
      onlyInAcs.push(v);
    }
  }
  return { onlyInAcs };
}

/* --------------------------------------------- live cluster connectors
 *
 * These are the only functions in this file that touch the network, and they only run when
 * the operator explicitly clicks Connect. Tokens are held in a local variable for the
 * duration of the call and are never written to localStorage, never logged, and never
 * included in any exported file.
 *
 * The honest caveat, stated up front because it will be the first thing you hit: a browser
 * enforces the same origin policy on these calls. A page opened from a file:// URL has a
 * null origin, and neither ACS Central nor the OpenShift API server sends an
 * Access-Control-Allow-Origin header that permits it, so the browser blocks the response
 * before your code ever sees it. That is the browser protecting you, not a bug here.
 *
 * It works when the page is served from an origin the API already allows:
 *   OpenShift  spec.additionalCORSAllowedOrigins on the APIServer resource
 *   ACS        serve this page from Central's own route, or through a reverse proxy
 * Otherwise use the offline route: run the command this page generates for you and drop
 * the resulting JSON onto the page. Same result, no CORS involved.
 */

/* ------------------------------------------------------------ URL safety
 *
 * Escaping is not enough for a URL that lands in an href.
 *
 * HTML escaping handles & < > and quotes, so it stops you breaking out of the
 * attribute. It does nothing about the VALUE of that attribute being a scheme that
 * executes. href="javascript:..." and href="data:text/html,..." survive escaping
 * completely intact and run script in this page's origin the moment somebody clicks.
 *
 * That matters here more than in most applications. Every link this tool renders comes
 * from data supplied by someone else: EmbeddedVulnerability.link and Advisory.link
 * arrive in an ACS export, and the tool explicitly invites an operator to drop an
 * export they were handed onto the page. The page holding that link also holds a live
 * ACS bearer token and every manifest the operator loaded. A security tool is a high
 * value target precisely because the person running it is privileged.
 *
 * So: allowlist the scheme, do not blocklist. A blocklist of javascript: and data:
 * misses vbscript:, blob:, filesystem:, and whatever gets added next. Return null for
 * anything not on the list and let the caller render inert text instead.
 */
const SAFE_URL_SCHEMES = ['https:', 'http:'];

function safeUrl(u) {
  const raw = String(u == null ? '' : u).trim();
  if (!raw) return null;
  // Strip control characters and whitespace before anything else looks at it. A tab or
  // newline embedded inside the scheme, as in "java<TAB>script:alert(1)", is ignored by
  // the HTML parser but would defeat a naive string comparison.
  const cleaned = raw.replace(/[\u0000-\u0020\u007f-\u009f]/g, '');
  if (!cleaned) return null;
  // A scheme relative URL (//evil.example) inherits the page scheme. On a file:// page
  // that resolves somewhere useless, and on a served page it is an open redirect
  // primitive. Neither is wanted, so require an explicit scheme.
  if (/^\/\//.test(cleaned)) return null;
  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch (e) {
    return null;   // relative or malformed: not something we should link to
  }
  if (SAFE_URL_SCHEMES.indexOf(parsed.protocol) === -1) return null;
  return parsed.href;
}

function normalizeBase(u) { return String(u || '').trim().replace(/\/+$/, ''); }

/* Turn a fetch failure into something a human can act on. A bare "Failed to fetch" sends
   people hunting for a network problem when the real cause is almost always CORS. */
function explainFetchError(err, url) {
  const msg = String((err && err.message) || err);
  if (/Failed to fetch|NetworkError|Load failed/i.test(msg)) {
    return 'The browser blocked the request to ' + url + ' before any response came back. ' +
      'In order of likelihood: the API does not allow this page\'s origin (CORS), the ' +
      'endpoint uses a certificate your browser does not trust, or the host is unreachable. ' +
      'Open ' + url + ' directly in a tab first to accept the certificate, then retry. ' +
      'If it still fails, use the offline command shown below instead, which avoids the ' +
      'browser entirely.';
  }
  return msg;
}

async function apiGet(url, token, tokenHeader) {
  const headers = { Accept: 'application/json' };
  headers[tokenHeader || 'Authorization'] = 'Bearer ' + token;
  let res;
  try {
    res = await fetch(url, { headers, mode: 'cors', credentials: 'omit' });
  } catch (e) {
    throw new Error(explainFetchError(e, url));
  }
  if (res.status === 401) throw new Error('401 Unauthorized. The token was rejected. For ACS create an API token under Platform Configuration, Integrations, Authentication Tokens. For OpenShift run: oc whoami -t');
  if (res.status === 403) throw new Error('403 Forbidden. The token is valid but lacks permission. ACS needs a role with read access to alerts; OpenShift needs get and list on the workload types in the namespaces you are scanning.');
  if (res.status === 404) throw new Error('404 Not Found at ' + url + '. Check the base URL. ACS Central is usually https://central-stackrox.apps.<cluster>, the OpenShift API is usually https://api.<cluster>:6443');
  if (!res.ok) {
    let body = '';
    try { body = (await res.text()).slice(0, 300); } catch (e) {}
    throw new Error(res.status + ' ' + res.statusText + (body ? ': ' + body : ''));
  }
  return res.json();
}

/* Build the ACS search query string. Two defaults matter here.
 *
 * Violation State: the ACS console shows active violations, so an operator comparing this
 * tool against the console and seeing extra rows will assume this tool is wrong. Default to
 * ACTIVE to match, and make it explicit rather than implicit so it can be widened.
 *
 * Lifecycle Stage: DEPLOY is the only stage this tool can reason about from a manifest.
 * BUILD and RUNTIME violations are still fetched when asked for, and are reported in the
 * unmatched list rather than dropped, but they are not the default. */
/* Platform violations.
 *
 * ACS 4.6 introduced a distinction between violations on YOUR workloads and violations on
 * the platform itself: OpenShift's own components, the operators, and ACS. The Violations
 * page in the console has a selector for user workloads, platform, or both, and it does
 * NOT default to both. So a violation you can see in the console under the platform view
 * can be missing from an API pull, and the reason is the filter, not the data.
 *
 * The search option is "Platform Component", a boolean, from
 * storage/alert.proto: bool platform_component = 22 // search:"Platform Component"
 *
 * Values here:
 *   'all'      both. Emitted as Platform Component:true,false, a comma being OR in ACS
 *              search syntax. This is the default because the whole point of an audit
 *              tool is not to hide half the estate behind a filter you did not set.
 *   'user'     your workloads only, matching the console default.
 *   'platform' the platform only.
 *   'omit'     leave the term out entirely. Needed for ACS older than 4.6, where the
 *              field does not exist and naming it can reject the whole query.
 */
const PLATFORM_SCOPES = ['all', 'user', 'platform', 'omit'];

function buildAlertQuery(opts) {
  const o = opts || {};
  const parts = [];
  if (o.query) parts.push(String(o.query).trim());
  const joined = parts.join('+');
  const hasState = /Violation\s*State\s*:/i.test(joined);
  /* Default to every state, not just ACTIVE.
   *
   * The ACS console shows active violations, so this returns MORE than the console does,
   * and that is deliberate for an audit tool. RESOLVED tells you something was a problem
   * and stopped being one, which is exactly what you need when you are asked to show a
   * trend or to prove a fix landed. ATTEMPTED means enforcement blocked a deploy, which
   * is a finding about your pipeline even though nothing is running.
   *
   * Pass violationState:'ACTIVE' to match the console instead. */
  if (!hasState && o.violationState !== 'ANY' && o.violationState !== 'ALL') {
    if (o.violationState) parts.push('Violation State:' + o.violationState);
    /* no term at all when unset: ACS then returns every state */
  }
  if (!/Platform\s*Component\s*:/i.test(joined)) {
    const scope = o.platform === undefined ? 'all' : o.platform;
    if (scope === 'all') parts.push('Platform Component:true,false');
    else if (scope === 'user') parts.push('Platform Component:false');
    else if (scope === 'platform') parts.push('Platform Component:true');
    /* 'omit' adds nothing */
  }
  if (o.namespace) parts.push('Namespace:' + o.namespace);
  if (o.cluster) parts.push('Cluster:' + o.cluster);
  if (o.lifecycleStage) parts.push('Lifecycle Stage:' + o.lifecycleStage);
  return parts.filter(Boolean).join('+');
}

/* Namespaces that belong to the platform rather than to you. Used only as a fallback when
   ACS is older than 4.6 and does not report platformComponent at all, so the tool can
   still separate the two rather than presenting one undifferentiated pile.
   This is a heuristic and is labelled as one wherever it is used. */
const PLATFORM_NS_RE = /^(openshift|kube|stackrox|rhacs|open-cluster-management|multicluster-engine|hive|assisted-installer)(-|$)/;

function rec_platform_source(rec) {
  if (rec.platformComponent === true) return 'acs';
  if (rec.platformComponent === false) return 'acs';
  return rec.isPlatform ? 'namespace' : 'namespace';
}

function looksPlatform(rec) {
  if (rec.platformComponent === true) return true;
  if (rec.platformComponent === false) return false;
  return PLATFORM_NS_RE.test(String(rec.namespace || ''));
}

/* Pull violations straight from ACS Central.
 *
 * Two phases, and the second one is the point. GET /v1/alerts returns ListAlert, which has
 * no violation text. GET /v1/alerts/{id} returns the full storage.Alert. Listing alone gave
 * rows with a policy name and nothing to explain them, which is what "does not show
 * findings" looks like from the operator's side. So: list, then hydrate.
 *
 * Hydration is capped and sequential on purpose. Firing a thousand parallel requests at
 * Central from a browser tab is a good way to get rate limited or to be mistaken for an
 * attack, and Central is a security control you do not want to destabilise. */
async function fetchAcsAlerts(centralUrl, token, opts) {
  const base = normalizeBase(centralUrl);
  if (!base) throw new Error('Enter the ACS Central URL, for example https://central-stackrox.apps.example.com');
  if (!token) throw new Error('Enter an ACS API token.');
  const o = opts || {};
  const limit = Math.max(1, Math.min(5000, o.limit || 1000));
  const params = [];
  let q = buildAlertQuery(o);
  if (q) params.push('query=' + encodeURIComponent(q));
  // ACS applies a server side default page size. Ask for what we want explicitly, otherwise
  // a large cluster silently returns a truncated set and the report understates the problem.
  params.push('pagination.limit=' + limit);
  if (o.offset) params.push('pagination.offset=' + o.offset);
  let url = base + '/v1/alerts' + (params.length ? '?' + params.join('&') : '');
  let json;
  let platformFallback = false;
  try {
    json = await apiGet(url, token);
  } catch (e) {
    /* ACS before 4.6 has no Platform Component field, and naming an unknown search option
       rejects the whole query rather than ignoring the term. Retry once without it, and
       say so, rather than reporting zero violations on an older Central. */
    const msg = String((e && e.message) || e);
    const namedTheField = /Platform\s*Component/i.test(q);
    if (namedTheField && /(400|invalid|unknown|unrecognized|not a valid)/i.test(msg)) {
      const q2 = buildAlertQuery(Object.assign({}, o, { platform: 'omit' }));
      const p2 = [];
      if (q2) p2.push('query=' + encodeURIComponent(q2));
      p2.push('pagination.limit=' + limit);
      if (o.offset) p2.push('pagination.offset=' + o.offset);
      url = base + '/v1/alerts?' + p2.join('&');
      json = await apiGet(url, token);
      platformFallback = true;
      q = q2;
    } else {
      throw e;
    }
  }
  const result = importAcsViolations(json);
  result.query = q;
  result.platformFallback = platformFallback;
  result.truncated = result.total >= limit;

  if (o.hydrate === false) return result;
  const cap = Math.max(0, Math.min(500, o.hydrateLimit === undefined ? 200 : o.hydrateLimit));
  const targets = result.imported.concat(result.unmatched)
    .filter((r) => !r.hydrated && r.acsAlertId).slice(0, cap);
  let hydrated = 0;
  const failures = [];
  for (const rec of targets) {
    try {
      const full = await apiGet(base + '/v1/alerts/' + encodeURIComponent(rec.acsAlertId), token);
      const vios = Array.isArray(full.violations) ? full.violations.map((v) => v && v.message).filter(Boolean) : [];
      const proc = full.processViolation || full.process_violation;
      if (proc && proc.message) vios.push(proc.message);
      if (vios.length) {
        rec.violations = vios;
        rec.detail = vios.join('; ');
        rec.hydrated = true;
        hydrated += 1;
      }
      const ent = alertEntity(full);
      if (ent.namespace && ent.namespace !== 'unknown') rec.namespace = ent.namespace;
      if (ent.cluster) rec.cluster = ent.cluster;
    } catch (e) {
      failures.push(rec.acsAlertId + ': ' + ((e && e.message) || e));
    }
  }
  result.hydrated = hydrated;
  result.hydrateFailures = failures;
  result.hydrateCapped = result.hydratable > cap;
  return result;
}

/* The command to run when the browser will not make the call for you. Generated with the
   operator's own URL already filled in, because a fallback nobody can copy and paste is
   not a fallback. */
/* TLS guidance shared by every command this tool prints.
 *
 * These commands send a bearer token that is, in practice, read access to your entire
 * security posture. -k disables certificate verification, which hands that token to
 * anyone positioned on the path. Internal CA environments are exactly where an on path
 * attacker is plausible, and -k is how an operator gets trained to stop noticing.
 *
 * So the generated command verifies by default and shows how to trust your own CA.
 * Insecure mode still exists, because sometimes you genuinely are in a lab, but it is
 * opt in and it says what it costs. A tool that prints -k is teaching a habit. */
function tlsPreamble(insecure) {
  if (insecure) {
    return [
      '# WARNING: certificate verification is DISABLED below (-k).',
      '# Your API token is exposed to anyone who can intercept this connection.',
      '# Use this only on a throwaway lab cluster. For anything real, use --cacert.',
    ];
  }
  return [
    '# Certificate verification is ON, which is what you want when the request carries',
    '# a token. If your Central uses an internal CA, point curl at it:',
    '#   export ROX_CA=/path/to/internal-ca.pem     then add:  --cacert "$ROX_CA"',
    '# Get the CA from the cluster with:',
    '#   oc get cm -n openshift-config-managed default-ingress-cert -o jsonpath=\'{.data.ca-bundle\\.crt}\' > ca.pem',
  ];
}
function curlFlags(insecure) { return insecure ? 'curl -sk' : 'curl -sS --fail-with-body ${ROX_CA:+--cacert "$ROX_CA"}'; }

function acsFallbackCommand(centralUrl, query, opts) {
  const base = normalizeBase(centralUrl) || 'https://central-stackrox.apps.example.com';
  const o = opts || {};
  const q = buildAlertQuery({ query: query, violationState: o.violationState, namespace: o.namespace, cluster: o.cluster });
  const limit = o.limit || 1000;
  const qs = '?query=' + encodeURIComponent(q) + '&pagination.limit=' + limit;
  const host = base.replace(/^https?:\/\//, '');
  const C = curlFlags(o.insecure);
  return tlsPreamble(o.insecure).concat([
    '',
    '# Run where the API is reachable, then drop the JSON onto this page.',
    '# The token comes from the environment, not the command line: arguments are',
    '# visible in ps to every user on the box and land in your shell history.',
    'export ROX_API_TOKEN=<paste your ACS API token>',
    'export ROX_ENDPOINT=' + base,
    '',
    '# The query below asks for BOTH user workload and platform violations.',
    '# The ACS console defaults to user workloads only, so a violation you can see there',
    '# under the platform view will be missing from a default API pull. On ACS older than',
    '# 4.6 the Platform Component field does not exist: drop that term if you get a 400.',
    '',
    '# 1. The list. Fast, but ListAlert carries no violation text.',
    C + ' -H "Authorization: Bearer $ROX_API_TOKEN" \\',
    '  "$ROX_ENDPOINT/v1/alerts' + qs + '" -o acs_alerts.json',
    '',
    '# 2. The detail. Only /v1/alerts/{id} returns the full Alert with violations[].',
    '#    This is why the list on its own looks empty. Drop acs_alerts_full.json instead.',
    'jq -r \'.alerts[].id\' acs_alerts.json | while read -r id; do',
    '  ' + C + ' -H "Authorization: Bearer $ROX_API_TOKEN" "$ROX_ENDPOINT/v1/alerts/$id"',
    'done | jq -s \'{alerts: .}\' > acs_alerts_full.json',
    '',
    '# Or let the bundled script do all of it, including pagination:',
    '#   ./scripts/acs_pull_all.sh -o findings',
    '',
    '# Or, with roxctl already logged in:',
    '# roxctl -e ' + host + ':443 alert list -o json > acs_alerts.json',
  ]).join('\n');
}

/* Live workloads from the OpenShift or Kubernetes API, so you can audit what is actually
   running rather than what git says should be running. Those two drift, and the gap is
   frequently where the real finding lives. */
const LIVE_KINDS = [
  { path: '/apis/apps/v1/deployments', kind: 'Deployment' },
  { path: '/apis/apps/v1/daemonsets', kind: 'DaemonSet' },
  { path: '/apis/apps/v1/statefulsets', kind: 'StatefulSet' },
  { path: '/apis/batch/v1/cronjobs', kind: 'CronJob' },
];

/* A live object is full of server side bookkeeping that must not end up in a manifest you
   commit. Strip it so the YAML this tool hands back is something you could actually apply. */
function sanitizeLiveObject(doc, kind) {
  const d = structuredClone(doc);
  d.kind = d.kind || kind;
  d.apiVersion = d.apiVersion || (kind === 'CronJob' ? 'batch/v1' : 'apps/v1');
  if (d.metadata) {
    for (const k of ['managedFields', 'resourceVersion', 'uid', 'selfLink', 'generation',
                     'creationTimestamp', 'ownerReferences'])
      delete d.metadata[k];
    if (d.metadata.annotations) {
      delete d.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration'];
      delete d.metadata.annotations['deployment.kubernetes.io/revision'];
      if (!Object.keys(d.metadata.annotations).length) delete d.metadata.annotations;
    }
  }
  delete d.status;
  if (d.spec && d.spec.template && d.spec.template.metadata)
    delete d.spec.template.metadata.creationTimestamp;
  return d;
}

/* Accept workloads exported as JSON, which is what `oc get ... -o json` produces.
 *
 * This was a real gap. The live connect path pulled objects from the API and converted
 * them internally, and the offline fallback command told you to use `-o yaml`. Anyone
 * who reached for `-o json` instead, which is the more natural choice for a machine
 * readable dump, got a flat refusal from the page: it only recognised ACS alert exports
 * and ACS vulnerability exports, so a perfectly good workload dump was rejected as
 * unreadable. The tool was pickier than it had any reason to be.
 *
 * Four shapes turn up in practice and all four are handled:
 *   {"kind":"List","items":[...]}            oc get deploy,ds,sts -o json
 *   {"kind":"DeploymentList","items":[...]}  oc get deploy -o json
 *   {"kind":"Deployment", ...}               oc get deploy NAME -o json
 *   [ {...}, {...} ]                         jq -s, or a hand assembled array
 * Plus concatenated objects from a shell loop, which is neither valid JSON nor NDJSON
 * but is exactly what `for k in ...; do oc get $k -o json; done` writes to one file.
 */
function looksLikeKubeObject(o) {
  return !!(o && typeof o === 'object' && typeof o.kind === 'string' &&
            (o.apiVersion || o.metadata) && !Array.isArray(o));
}

function importKubeJson(text) {
  const raw = String(text == null ? '' : text).trim();
  const objects = [];
  const errors = [];
  if (!raw) return { files: [], count: 0, errors: errors };

  const collect = (o) => {
    if (!o || typeof o !== 'object') return;
    if (Array.isArray(o)) { o.forEach(collect); return; }
    // A List wrapper, whatever its kind is called. Recurse rather than special casing
    // every FooList name, because there are dozens and new ones keep arriving.
    if (Array.isArray(o.items) && /List$/.test(o.kind || '')) { o.items.forEach(collect); return; }
    if (Array.isArray(o.items) && !o.kind) { o.items.forEach(collect); return; }
    if (looksLikeKubeObject(o)) objects.push(o);
  };

  let parsedWhole = false;
  try { collect(JSON.parse(raw)); parsedWhole = true; }
  catch (e) { /* not one document, try the other shapes */ }

  if (!parsedWhole) {
    // Line delimited first, then concatenated objects. The concatenated case is what a
    // shell loop produces, and refusing it would send people back to reformat a file
    // they already have.
    let any = false;
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
      const s = line.trim();
      if (!s) continue;
      try { collect(JSON.parse(s)); any = true; } catch (e) { any = false; break; }
    }
    if (!any) {
      objects.length = 0;
      let depth = 0, start = -1, inStr = false, esc = false;
      for (let i = 0; i < raw.length; i++) {
        const c = raw[i];
        if (inStr) {
          if (esc) esc = false;
          else if (c === '\\') esc = true;
          else if (c === '"') inStr = false;
          continue;
        }
        if (c === '"') { inStr = true; continue; }
        if (c === '{') { if (depth === 0) start = i; depth++; }
        else if (c === '}') {
          depth--;
          if (depth === 0 && start >= 0) {
            try { collect(JSON.parse(raw.slice(start, i + 1))); }
            catch (e) { errors.push('Could not parse an object near character ' + start); }
            start = -1;
          }
        }
      }
    }
  }

  if (!objects.length) {
    return { files: [], count: 0,
      errors: errors.concat(['No Kubernetes objects found. Expected something with a kind and metadata.']) };
  }

  /* Everything from a live cluster carries server side bookkeeping. Strip it with the
     same function the live connector uses, so a JSON dump and an API pull produce
     identical YAML rather than two subtly different results. */
  const files = [];
  const seen = {};
  let skipped = 0;
  for (const o of objects) {
    const kind = o.kind || 'Unknown';
    if (WORKLOADS.indexOf(kind) === -1 && kind !== 'NetworkPolicy' &&
        kind !== 'ServiceAccount' && kind !== 'Namespace') {
      skipped++;
      continue;
    }
    let clean;
    try { clean = sanitizeLiveObject(o, kind); }
    catch (e) { errors.push('Could not clean ' + kind + ': ' + ((e && e.message) || e)); continue; }
    const ns = (clean.metadata && clean.metadata.namespace) || 'default';
    const nm = (clean.metadata && clean.metadata.name) || 'unnamed';
    let name = 'live/' + ns + '/' + kind.toLowerCase() + '-' + nm + '.yaml';
    if (seen[name]) { name = name.replace(/\.yaml$/, '-' + (++seen[name]) + '.yaml'); }
    else seen[name] = 1;
    files.push({ name: name, text: jsyaml.dump(clean, { noRefs: true, lineWidth: 120 }) });
  }
  if (skipped) errors.push(skipped + ' object(s) were not workload kinds and were skipped.');
  return { files: files, count: files.length, errors: errors, skipped: skipped };
}

async function fetchOpenShiftWorkloads(apiUrl, token, namespace) {
  const base = normalizeBase(apiUrl);
  if (!base) throw new Error('Enter the OpenShift API URL, for example https://api.example.com:6443');
  if (!token) throw new Error('Enter a token. Get one with: oc whoami -t');
  const ns = String(namespace || '').trim();
  const files = [];
  const errors = [];
  let count = 0;
  for (const k of LIVE_KINDS) {
    const path = ns
      ? k.path.replace(/\/([a-z]+)$/, '/namespaces/' + encodeURIComponent(ns) + '/$1')
      : k.path;
    let json;
    try { json = await apiGet(base + path, token); }
    catch (e) { errors.push(k.kind + ': ' + e.message); continue; }
    const items = (json && json.items) || [];
    for (const item of items) {
      const clean = sanitizeLiveObject(item, k.kind);
      const nsName = (clean.metadata && clean.metadata.namespace) || 'default';
      const fname = 'live/' + nsName + '/' + k.kind.toLowerCase() + '-' +
        ((clean.metadata && clean.metadata.name) || 'unnamed') + '.yaml';
      files.push({ name: fname, text: jsyaml.dump(clean, { noRefs: true, lineWidth: 120 }) });
      count++;
    }
  }
  return { files, count, errors };
}

function openshiftFallbackCommand(namespace) {
  const ns = String(namespace || '').trim();
  const scope = ns ? '-n ' + ns : '--all-namespaces';
  return [
    '# Run where the cluster is reachable, then drop the output onto this page.',
    '# JSON and YAML both work. One file is fine, and so is a folder of them.',
    '',
    '# Simplest: everything in one JSON file.',
    'oc get deployment,daemonset,statefulset,cronjob,job ' + scope + ' -o json > workloads.json',
    '',
    '# Or as YAML, if you prefer reading it.',
    'oc get deployment,daemonset,statefulset,cronjob,job ' + scope + ' -o yaml > workloads.yaml',
    '',
    '# Or one file per kind.',
    'mkdir -p live && cd live',
    'for k in deployment daemonset statefulset cronjob job; do',
    '  oc get $k ' + scope + ' -o json > $k.json',
    'done',
    '',
    '# The export carries server side fields: status, managedFields, uid, resourceVersion,',
    '# ownerReferences and the last-applied-configuration annotation. This page strips all',
    '# of them on load, so what you scan is what you could actually commit.',
  ].join('\n');
}

/* ==================================================================== vulnerability management
 *
 * Why this exists as a separate surface from everything above.
 *
 * /v1/alerts only ever returns POLICY violations. An image CVE is not a policy violation
 * unless somebody wrote a policy that fires on it, so a cluster full of critical CVEs can and
 * routinely does return an empty or near empty alert list. That is not a broken tool and it
 * is not a clean cluster. The two are different data planes and have to be fetched
 * differently.
 *
 * Vulnerability data comes from the streaming export:
 *   GET /v1/export/vuln-mgmt/workloads?query=<Search Option:Value+...>&timeout=<seconds>
 * Each line of the response is one JSON object:
 *   {"result": {"deployment": {...}, "images": [...], "livePods": N}}
 * CVEs sit at images[].scan.components[].vulns[].
 *
 * Verified against the upstream service and message definitions:
 *   stackrox/proto/api/v1/vuln_mgmt_service.proto   (endpoint, query syntax, response shape)
 *   stackrox/proto/storage/image.proto              (ImageScan, EmbeddedImageScanComponent)
 *   stackrox/proto/storage/vulnerability.proto      (EmbeddedVulnerability)
 *   stackrox/proto/storage/cve.proto                (VulnerabilitySeverity, VulnerabilityState, EPSS, Exploit)
 * Check these against your own ACS version before treating the field names as fixed.
 */

/* ACS grades vulnerabilities on the Red Hat scale, which is NOT the same vocabulary as the
   policy severity scale used everywhere else in this file. Keeping them in one namespace
   would be a quiet way to produce a wrong number, so they are mapped explicitly. */
const VULN_SEVERITY = {
  CRITICAL_VULNERABILITY_SEVERITY: { label: 'Critical', rank: 4, weight: 18 },
  IMPORTANT_VULNERABILITY_SEVERITY: { label: 'Important', rank: 3, weight: 10 },
  MODERATE_VULNERABILITY_SEVERITY: { label: 'Moderate', rank: 2, weight: 5 },
  LOW_VULNERABILITY_SEVERITY: { label: 'Low', rank: 1, weight: 2 },
  UNKNOWN_VULNERABILITY_SEVERITY: { label: 'Unknown', rank: 0, weight: 1 },
};
function vulnSeverity(s) {
  return VULN_SEVERITY[s] || VULN_SEVERITY.UNKNOWN_VULNERABILITY_SEVERITY;
}

/* States that mean a human already made a decision about this CVE. They stay visible, they
   do not count against you, and they are never silently dropped, because a deferral that
   disappears from the report is indistinguishable from a CVE nobody ever looked at. */
function vulnIsAccepted(v) {
  const st = v.state || v.vulnerabilityState || '';
  return st === 'DEFERRED' || st === 'FALSE_POSITIVE' || v.suppressed === true;
}

/* Parse the export. Three shapes in the wild, because curl, roxctl and a browser fetch all
   hand you something slightly different:
     1. NDJSON, one {"result": {...}} per line. This is what the endpoint actually streams.
     2. A JSON array, which is what you get if somebody ran it through jq -s.
     3. A single object, from a one deployment export.
   A parser that only handles the shape it was written against fails silently on the other
   two, so handle all three and count what could not be parsed rather than swallowing it. */
function parseVulnExport(text) {
  const raw = String(text == null ? '' : text).trim();
  const records = [];
  const errors = [];
  if (!raw) return { records, errors };

  /* ACS has three export endpoints and they return three different record shapes. This
   * parser originally understood only the first, so two thirds of what acs_pull_all.sh
   * writes was rejected as unreadable:
   *
   *   /v1/export/vuln-mgmt/workloads   {"result": {deployment, images[], livePods}}
   *   /v1/export/images                {"result": {storage.Image}}   no deployment
   *   /v1/export/nodes                 {"result": {storage.Node}}    no deployment, no images
   *
   * The last two carry CVEs in exactly the same place, scan.components[].vulns[], so the
   * fix is to normalise them into the workload shape rather than write two more parsers.
   * An image with nothing running it is still an image you are storing, and a node CVE is
   * still a CVE. Both belong in the report.
   */
  const take = (o) => {
    if (!o || typeof o !== 'object') return;
    if (o.error) { errors.push(String(o.error.message || o.error)); return; }
    const r = o.result || o;
    if (!r || typeof r !== 'object') return;

    if (r.deployment || r.images) { records.push(r); return; }

    /* A bare image. Wrap it as a workload with no deployment so everything downstream
       treats it identically. livePods 0 is the truth and it matters: the priority model
       adds 0.5 for a running image, and an image nothing runs must not collect it. */
    const nm = r.name;
    if (r.scan && nm && typeof nm === 'object' &&
        (nm.fullName || nm.full_name || nm.remote || /^sha256:/.test(String(r.id || '')))) {
      records.push({ deployment: null, livePods: 0, sourceKind: 'image', images: [r] });
      return;
    }

    /* A node. The scan looks the same but there is no image to attribute it to.
       Synthesise one named for the node so the CVE is counted and traceable, and mark the
       record so the UI can say plainly this is a node finding. You cannot fix a node CVE
       by editing a manifest, and the tool should never imply that you can. */
    if (r.scan && typeof nm === 'string' && nm) {
      records.push({
        deployment: { name: nm, namespace: '(node)', type: 'Node',
                      clusterName: r.clusterName || r.cluster_name || '' },
        livePods: 0, sourceKind: 'node',
        images: [{ id: r.id || nm, name: { fullName: 'node/' + nm }, scan: r.scan }],
      });
      return;
    }

    /* Scan data we could not attribute. Say so rather than dropping it: a parser that
       silently discards what it does not recognise is indistinguishable from one that
       found nothing. */
    if (r.scan) errors.push('A record carried scan data but no recognisable image or node identity.');
  };

  // Try whole document first: array, or a single object.
  try {
    const j = JSON.parse(raw);
    if (Array.isArray(j)) { j.forEach(take); return { records, errors }; }
    if (j && Array.isArray(j.results)) { j.results.forEach(take); return { records, errors }; }
    take(j);
    if (records.length || errors.length) return { records, errors };
  } catch (e) { /* fall through to NDJSON */ }

  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try { take(JSON.parse(line)); }
    catch (e) { errors.push('Line ' + (i + 1) + ' is not valid JSON'); }
  }
  return { records, errors };
}

function imageRef(img) {
  const n = (img && img.name) || {};
  const full = n.fullName || n.full_name || '';
  if (full) return full;
  const reg = n.registry ? n.registry + '/' : '';
  const rem = n.remote || '';
  const tag = n.tag ? ':' + n.tag : '';
  return (reg + rem + tag) || (img && img.id) || 'unknown';
}

/* An explainable priority score, on a 0 to 15 scale.
 *
 * CVSS on its own is a poor work queue. A 9.8 in a package nobody can reach ranks above a 7.5
 * that is on the CISA KEV list and being exploited this week, which is backwards. So the
 * score starts at the CVSS ACS prefers and adds a small number of named, bounded signals.
 *
 * Why 15 and not 10. The obvious move is to clamp back to the familiar 0 to 10 range, and it
 * is wrong. Clamping makes every critical land on exactly 10, which destroys the ordering at
 * precisely the top of the queue where ordering is the whole point: a 9.8 that is on the KEV
 * list and running in production would sort identically to a 9.8 nobody has ever exploited.
 * A separate wider scale keeps the ranking intact and stops anyone mistaking this number for
 * a CVSS score, which it is not.
 *
 *   PRIORITY_MAX = 10 CVSS + 2.0 KEV + 1.5 EPSS + 1.0 fixable + 0.5 running
 *
 * Every adjustment is recorded in reasons[] and shown in the UI. A ranking nobody can audit
 * is a ranking nobody should trust, including this one. */
const PRIORITY_MAX = 15;
function scoreVuln(v, ctx) {
  const c = ctx || {};
  const base = Number(v.cvss) || Number(v.nvdCvss) || Number(v.nvd_cvss) || 0;
  const reasons = [];
  let score = base;
  if (base) reasons.push('CVSS ' + base.toFixed(1));

  if (v.cisaKev === true || v.cisa_kev === true) {
    score += 2.0;
    reasons.push('on the CISA Known Exploited Vulnerabilities catalog, +2.0');
  }
  const epss = v.epss || {};
  const p = Number(epss.epssProbability !== undefined ? epss.epssProbability : epss.epss_probability) || 0;
  if (p >= 0.5) { score += 1.5; reasons.push('EPSS ' + (p * 100).toFixed(1) + '% chance of exploitation, +1.5'); }
  else if (p >= 0.1) { score += 0.7; reasons.push('EPSS ' + (p * 100).toFixed(1) + '% chance of exploitation, +0.7'); }

  const fixedBy = v.fixedBy || v.fixed_by || '';
  if (fixedBy) { score += 1.0; reasons.push('a fix is published, so this is actionable today, +1.0'); }
  else { reasons.push('no upstream fix yet, so this cannot be patched away'); }

  if (c.livePods > 0) { score += 0.5; reasons.push(c.livePods + ' pod(s) running this image right now, +0.5'); }

  if (vulnIsAccepted(v)) {
    reasons.push('deferred or marked a false positive in ACS, so it is excluded from the active count');
  }
  return { score: Math.round(Math.min(PRIORITY_MAX, Math.max(0, score)) * 10) / 10, reasons: reasons };
}

/* Flatten the export into one row per CVE per component per image per workload, then
   deduplicate. The same CVE in the same image across ten Deployments is one thing to fix,
   not ten, and a report that says ten inflates the number an operator has to defend. */
function importVulnFindings(parsed, opts) {
  const o = opts || {};
  const records = (parsed && parsed.records) || [];
  const rows = [];
  const byCve = {};
  const images = {};
  let accepted = 0;

  for (const rec of records) {
    const dep = rec.deployment || {};
    const livePods = Number(rec.livePods !== undefined ? rec.livePods : rec.live_pods) || 0;
    /* An image export has no deployment at all. Labelling it "unknown" reads like missing
       data the operator should go and find; "(not deployed)" is the actual fact and tells
       them the image exists in a registry ACS scanned but nothing is running it. */
    const kindOf = rec.sourceKind === 'node' ? 'Node'
                 : rec.sourceKind === 'image' ? 'Image' : (dep.type || 'Deployment');
    const workload = {
      kind: kindOf,
      name: dep.name || (rec.sourceKind === 'image' ? '(not deployed)' : 'unknown'),
      namespace: dep.namespace || (rec.sourceKind === 'image' ? '(no workload)' : 'unknown'),
      cluster: dep.clusterName || dep.cluster_name || '',
      livePods: livePods,
      sourceKind: rec.sourceKind || 'workload',
    };
    for (const img of (rec.images || [])) {
      const ref = imageRef(img);
      const scan = img.scan || {};
      if (!images[ref]) {
        images[ref] = {
          ref: ref,
          id: img.id || '',
          os: scan.operatingSystem || scan.operating_system || '',
          scanTime: scan.scanTime || scan.scan_time || '',
          scanner: scan.scannerVersion || scan.scanner_version || '',
          notes: (scan.notes || []).concat(img.notes || []),
          workloads: [],
          cves: 0, fixable: 0, critical: 0, important: 0,
        };
      }
      const im = images[ref];
      const wkey = workload.namespace + '/' + workload.kind + '/' + workload.name;
      if (im.workloads.indexOf(wkey) === -1) im.workloads.push(wkey);

      // An image with no scan data is not an image with no vulnerabilities. Say which.
      if (!scan.components && !(scan.components || []).length) im.unscanned = !scan.scanTime && !scan.scan_time;

      for (const comp of (scan.components || [])) {
        for (const v of (comp.vulns || comp.vulnerabilities || [])) {
          const cve = v.cve || v.id || '';
          if (!cve) continue;
          const sev = vulnSeverity(v.severity);
          const fixedBy = v.fixedBy || v.fixed_by || '';
          const pr = scoreVuln(v, { livePods: livePods });
          const acceptedHere = vulnIsAccepted(v);
          const key = cve + '|' + ref + '|' + (comp.name || '') + '|' + (comp.version || '');
          let row = byCve[key];
          if (!row) {
            row = {
              cve: cve,
              severity: v.severity || 'UNKNOWN_VULNERABILITY_SEVERITY',
              sevLabel: sev.label,
              sevRank: sev.rank,
              cvss: Number(v.cvss) || 0,
              nvdCvss: Number(v.nvdCvss || v.nvd_cvss) || 0,
              epss: Number((v.epss || {}).epssProbability !== undefined
                ? (v.epss || {}).epssProbability : (v.epss || {}).epss_probability) || 0,
              cisaKev: v.cisaKev === true || v.cisa_kev === true,
              exploit: v.exploit || null,
              advisory: v.advisory || null,
              summary: v.summary || '',
              link: v.link || '',
              fixedBy: fixedBy,
              fixable: !!fixedBy,
              state: v.state || v.vulnerabilityState || 'OBSERVED',
              accepted: acceptedHere,
              component: {
                name: comp.name || '',
                version: comp.version || '',
                source: comp.source || '',
                location: comp.location || '',
                fixedBy: comp.fixedBy || comp.fixed_by || '',
              },
              image: ref,
              imageOs: im.os,
              priority: pr.score,
              reasons: pr.reasons,
              workloads: [],
              livePods: 0,
            };
            byCve[key] = row;
            rows.push(row);
            im.cves += 1;
            if (fixedBy) im.fixable += 1;
            if (sev.rank === 4) im.critical += 1;
            if (sev.rank === 3) im.important += 1;
            if (acceptedHere) accepted += 1;
          }
          if (row.workloads.indexOf(wkey) === -1) row.workloads.push(wkey);
          row.livePods += livePods;
          if (livePods > 0 && row.reasons.indexOf('running') === -1) {
            const re = scoreVuln(v, { livePods: livePods });
            row.priority = Math.max(row.priority, re.score);
            row.reasons = re.reasons;
          }
        }
      }
    }
  }

  rows.sort((a, b) => (b.sevRank - a.sevRank) || (b.priority - a.priority) || a.cve.localeCompare(b.cve));
  const imageList = Object.keys(images).map((k) => images[k])
    .sort((a, b) => (b.critical - a.critical) || (b.cves - a.cves));

  return {
    rows: rows,
    images: imageList,
    accepted: accepted,
    parseErrors: (parsed && parsed.errors) || [],
    workloads: records.length,
    onlyFixable: !!o.onlyFixable,
  };
}

/* Summary numbers, computed only over CVEs that are still someone's problem. Deferred and
   false positive CVEs are counted separately rather than folded in, because a number that
   quietly includes accepted risk is a number that will be challenged in the first review. */
function summarizeVulns(imported) {
  const rows = (imported && imported.rows) || [];
  const active = rows.filter((r) => !r.accepted);
  const s = {
    total: rows.length, active: active.length, accepted: rows.length - active.length,
    critical: 0, important: 0, moderate: 0, low: 0, unknown: 0,
    fixable: 0, kev: 0, running: 0, unfixableCritical: 0,
    images: (imported && imported.images && imported.images.length) || 0,
    workloads: (imported && imported.workloads) || 0,
    topPriority: active.slice().sort((a, b) => b.priority - a.priority).slice(0, 10),
  };
  for (const r of active) {
    if (r.sevRank === 4) s.critical += 1;
    else if (r.sevRank === 3) s.important += 1;
    else if (r.sevRank === 2) s.moderate += 1;
    else if (r.sevRank === 1) s.low += 1;
    else s.unknown += 1;
    if (r.fixable) s.fixable += 1;
    if (r.cisaKev) s.kev += 1;
    if (r.livePods > 0) s.running += 1;
    if (r.sevRank === 4 && !r.fixable) s.unfixableCritical += 1;
  }
  // The only honest headline number here is the fixable share. There is no "vulnerability
  // posture score" because the denominator would be the set of CVEs that happen to exist in
  // your images today, which changes every time a feed updates, so a rising score could mean
  // you patched something or could mean a scanner went quiet. Percent fixable is stable and
  // means exactly one thing: how much of this you could clear right now if you chose to.
  s.fixablePct = s.active ? Math.round((s.fixable / s.active) * 100) : 0;
  return s;
}

/* Tie a CVE back to the manifest that pulls the image, so the operator knows which file to
   edit. This is the whole reason to run vulnerability data through this tool rather than
   reading it in the ACS console: the console tells you the image is bad, it does not tell
   you which line of which file in your repository put it there. */
function correlateVulns(files, imported) {
  const byImage = {};
  for (const im of ((imported && imported.images) || [])) byImage[im.ref] = im;
  const matches = [];
  const unmatchedImages = {};
  for (const k of Object.keys(byImage)) unmatchedImages[k] = true;

  for (const f of (files || [])) {
    let docs = [];
    try { docs = parseFileText(f.name, f.text).docs || []; } catch (e) { continue; }
    for (const doc of docs) {
      if (!doc || typeof doc !== 'object') continue;
      const conts = containersOf(podSpec(doc)) || [];
      for (const wrap of conts) {
        const c = wrap.c;
        const image = c && c.image;
        if (!image) continue;
        for (const ref of Object.keys(byImage)) {
          // Match on the full reference, or on repository when the manifest omits the
          // registry or uses a different tag. A tag mismatch is itself worth reporting:
          // it means the manifest and the running workload disagree.
          const refRepo = String(ref).split('@')[0].replace(/:[^:/]+$/, '');
          const imgRepo = String(image).split('@')[0].replace(/:[^:/]+$/, '');
          const exact = ref === image;
          const sameRepo = refRepo === imgRepo ||
            refRepo.endsWith('/' + imgRepo) || imgRepo.endsWith('/' + refRepo);
          if (exact || sameRepo) {
            delete unmatchedImages[ref];
            matches.push({
              file: f.name, obj: nameOf(doc),
              container: c.name || '', manifestImage: image, scannedImage: ref,
              exact: exact,
              drift: !exact,
              cves: byImage[ref].cves, critical: byImage[ref].critical,
              fixable: byImage[ref].fixable,
            });
          }
        }
      }
    }
  }
  return { matches: matches, unmatchedImages: Object.keys(unmatchedImages) };
}

/* Fetch vulnerability data from Central.
 *
 * The response is a stream, not a JSON document, so this reads text and parses lines. Calling
 * res.json() on it fails, which is the second way this endpoint bites people after not
 * knowing it exists at all.
 *
 * The timeout parameter is the server side one from the proto. A large cluster export is
 * genuinely slow, and a browser that gives up at 30 seconds while Central is still streaming
 * looks identical to an empty result. */
async function fetchVulnWorkloads(centralUrl, token, opts) {
  const base = normalizeBase(centralUrl);
  if (!base) throw new Error('Enter the ACS Central URL, for example https://central-stackrox.apps.example.com');
  if (!token) throw new Error('Enter an ACS API token.');
  const o = opts || {};
  const parts = [];
  if (o.query) parts.push(String(o.query).trim());
  if (o.namespace) parts.push('Namespace:' + o.namespace);
  if (o.cluster) parts.push('Cluster:' + o.cluster);
  if (o.deployment) parts.push('Deployment:' + o.deployment);
  const q = parts.filter(Boolean).join('+');
  const params = [];
  if (q) params.push('query=' + encodeURIComponent(q));
  params.push('timeout=' + (o.timeout || 300));
  const url = base + '/v1/export/vuln-mgmt/workloads?' + params.join('&');

  const headers = { Accept: 'application/json' };
  headers.Authorization = 'Bearer ' + token;
  let res;
  try { res = await fetch(url, { headers: headers, mode: 'cors', credentials: 'omit' }); }
  catch (e) { throw new Error(explainFetchError(e, url)); }
  if (res.status === 401) throw new Error('401 Unauthorized. The token was rejected. Create an API token under Platform Configuration, Integrations, Authentication Tokens.');
  if (res.status === 403) throw new Error('403 Forbidden. The token needs a role with read access to Image and Deployment. An Analyst or Continuous Integration role usually has it; a token scoped only to Alert does not, which is a common reason this returns nothing while /v1/alerts works.');
  if (res.status === 404) throw new Error('404 Not Found. The vulnerability export endpoint is /v1/export/vuln-mgmt/workloads and exists in ACS 3.74 and later. On an older Central use roxctl or the GraphQL API instead.');
  if (!res.ok) {
    let body = '';
    try { body = (await res.text()).slice(0, 300); } catch (e) {}
    throw new Error(res.status + ' ' + res.statusText + (body ? ': ' + body : ''));
  }
  const text = await res.text();
  const parsed = parseVulnExport(text);
  const imported = importVulnFindings(parsed, o);
  imported.query = q;
  return imported;
}

function vulnFallbackCommand(centralUrl, opts) {
  const base = normalizeBase(centralUrl) || 'https://central-stackrox.apps.example.com';
  const o = opts || {};
  const parts = [];
  if (o.query) parts.push(String(o.query).trim());
  if (o.namespace) parts.push('Namespace:' + o.namespace);
  if (o.cluster) parts.push('Cluster:' + o.cluster);
  const q = parts.filter(Boolean).join('+');
  const qs = (q ? 'query=' + encodeURIComponent(q) + '&' : '') + 'timeout=300';
  const host = base.replace(/^https?:\/\//, '');
  const C = curlFlags(o.insecure);
  return tlsPreamble(o.insecure).concat([
    '',
    '# Vulnerability data does NOT come from /v1/alerts. An image CVE is not a policy',
    '# violation, so an empty alert list tells you nothing about your CVE exposure.',
    '# The export below is the endpoint that actually carries CVEs.',
    '',
    'export ROX_API_TOKEN=<paste your ACS API token>',
    'export ROX_ENDPOINT=' + base,
    '',
    '# Streams NDJSON: one {"result":{"deployment":...,"images":[...]}} per line.',
    C + ' -H "Authorization: Bearer $ROX_API_TOKEN" \\',
    '  "$ROX_ENDPOINT/v1/export/vuln-mgmt/workloads?' + qs + '" -o acs_vulns.ndjson',
    '',
    '# Sanity check before you drop it on the page. If this prints 0, the export is empty',
    '# and the cause is scope or permissions, not this tool.',
    'wc -l acs_vulns.ndjson',
    '',
    '# The token needs read on Image and Deployment. A token scoped only to Alert will',
    '# return 403 here while /v1/alerts keeps working, which is a confusing failure mode.',
    '',
    '# Or let the bundled script sweep every store at once:',
    '#   ./scripts/acs_pull_all.sh -o findings',
    '',
    '# Single image instead of the whole cluster:',
    '# roxctl -e ' + host + ':443 image scan --image <registry/repo:tag> -o json > image_scan.json',
  ]).join('\n');
}

/* Remediating a CVE is not a YAML edit, and pretending otherwise would be the single most
 * dangerous thing this tool could do.
 *
 * ACS gives you a component level fixedBy: "openssl is fixed in 3.0.14". It does not and
 * cannot tell you which image tag contains that package version. Deriving one from the other
 * requires knowing how the image is built, and a tool that guesses will happily point a
 * production Deployment at a tag that does not exist, or at one that fixes the CVE and breaks
 * the application. So there is no auto fix for a CVE here.
 *
 * What the tool can do honestly:
 *   - tell you exactly which file and which container line pulls the affected image
 *   - rank what to rebuild first, with the reasoning shown
 *   - apply a new image reference that YOU supply, which is a text edit like any other
 * That last one is a real fix with a real confirmation, and the value comes from you, not
 * from a guess. */
function applyImagePin(doc, containerName, newImage) {
  if (!newImage || !String(newImage).trim()) throw new Error('Provide the replacement image reference.');
  const conts = containersOf(podSpec(doc)) || [];
  let changed = 0;
  for (const wrap of conts) {
    const c = wrap.c;
    if (containerName && c.name !== containerName) continue;
    if (c.image === newImage) continue;
    c.image = String(newImage).trim();
    changed += 1;
  }
  if (!changed) throw new Error('No container matched ' + (containerName || '(any)') + ' in this object.');
  return changed;
}

/* The deliverable for the vulnerability side: a worklist grouped by image, because you
   rebuild an image once and clear every CVE in it, not one CVE at a time. Grouping by CVE
   produces a list that looks like work and cannot be actioned. */
function buildVulnWorklist(imported, correlation) {
  const rows = (imported && imported.rows) || [];
  const images = (imported && imported.images) || [];
  const matches = (correlation && correlation.matches) || [];
  const fileFor = {};
  for (const m of matches) {
    if (!fileFor[m.scannedImage]) fileFor[m.scannedImage] = [];
    const entry = m.file + '  (' + m.obj + ', container ' + (m.container || '?') + ')' +
      (m.drift ? '   [manifest says ' + m.manifestImage + ']' : '');
    if (fileFor[m.scannedImage].indexOf(entry) === -1) fileFor[m.scannedImage].push(entry);
  }
  const out = [];
  out.push('# Image remediation worklist');
  out.push('');
  out.push('Generated by ' + ACS_TOOL + '. Source: ACS /v1/export/vuln-mgmt/workloads.');
  out.push('');
  out.push('Rebuild the image once and every fixable CVE in it clears together. That is why');
  out.push('this is grouped by image and not by CVE.');
  out.push('');
  out.push('No command in this file has been run. Nothing has been applied to a cluster.');
  out.push('');

  const ranked = images.slice().sort((a, b) => (b.critical - a.critical) || (b.fixable - a.fixable) || (b.cves - a.cves));
  for (const im of ranked) {
    const mine = rows.filter((r) => r.image === im.ref && !r.accepted);
    if (!mine.length) continue;
    out.push('## ' + im.ref);
    out.push('');
    out.push('* Operating system: ' + (im.os || 'not reported'));
    out.push('* Last scanned: ' + (im.scanTime || 'not reported'));
    out.push('* CVEs: ' + mine.length + '   Critical: ' + im.critical + '   Fixable: ' + im.fixable);
    out.push('* Used by: ' + (im.workloads.join(', ') || 'no running workload found'));
    if (fileFor[im.ref]) {
      out.push('* Declared in:');
      for (const f of fileFor[im.ref]) out.push('    - ' + f);
    } else {
      out.push('* Declared in: not found in the manifests you loaded. Either the manifest is');
      out.push('  outside the set, or the workload was created outside git.');
    }
    out.push('');
    const fixable = mine.filter((r) => r.fixable).sort((a, b) => b.priority - a.priority);
    const stuck = mine.filter((r) => !r.fixable).sort((a, b) => b.priority - a.priority);
    if (fixable.length) {
      out.push('### Fixable now (' + fixable.length + ')');
      out.push('');
      out.push('| CVE | Severity | Priority | Component | Installed | Fixed in | KEV |');
      out.push('|---|---|---|---|---|---|---|');
      for (const r of fixable.slice(0, 100)) {
        out.push('| ' + r.cve + ' | ' + r.sevLabel + ' | ' + r.priority.toFixed(1) + ' | ' +
          r.component.name + ' | ' + r.component.version + ' | ' + r.fixedBy + ' | ' +
          (r.cisaKev ? 'yes' : '') + ' |');
      }
      out.push('');
      const pkgs = {};
      for (const r of fixable) {
        if (!pkgs[r.component.name] || pkgs[r.component.name] < r.fixedBy) pkgs[r.component.name] = r.fixedBy;
      }
      out.push('Packages to bring forward in the base image or the build:');
      out.push('');
      for (const p of Object.keys(pkgs).sort()) out.push('* ' + p + ' to ' + pkgs[p] + ' or later');
      out.push('');
    }
    if (stuck.length) {
      out.push('### No fix published yet (' + stuck.length + ')');
      out.push('');
      out.push('Rebuilding will not clear these. They need a compensating control, a different');
      out.push('component, or an accepted risk with an expiry date.');
      out.push('');
      for (const r of stuck.slice(0, 50)) {
        out.push('* ' + r.cve + '  ' + r.sevLabel + '  priority ' + r.priority.toFixed(1) +
          '  in ' + r.component.name + ' ' + r.component.version +
          (r.cisaKev ? '  KNOWN EXPLOITED' : ''));
      }
      out.push('');
    }
  }

  const acceptedRows = rows.filter((r) => r.accepted);
  if (acceptedRows.length) {
    out.push('## Already accepted in ACS (' + acceptedRows.length + ')');
    out.push('');
    out.push('Deferred or marked false positive by somebody with the authority to do it.');
    out.push('Listed for the record, excluded from the counts above.');
    out.push('');
    for (const r of acceptedRows.slice(0, 100)) {
      out.push('* ' + r.cve + '  ' + r.sevLabel + '  ' + r.state + '  in ' + r.image);
    }
    out.push('');
  }
  return out.join('\n');
}


/* ------------------------------------------------- reporting, shared surface
 *
 * The report generator lives here rather than in the HTML for the same reason the
 * policy catalogue does: the browser page, the CLI and the tests must produce byte
 * identical output. A report that differs depending on which surface produced it is a
 * report nobody can use as evidence.
 */

function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Anchor helper. Every href in a generated report goes through this, including the
   static reference list, so there is exactly one place where a link can be emitted and
   exactly one scheme check. Anything rejected renders as inert text. */
function anchor(url, label) {
  const u = safeUrl(url);
  const text = escHtml(label == null ? url : label);
  return u ? '<a href="' + escHtml(u) + '" rel="noreferrer noopener">' + text + '</a>' : text;
}

function buildFindingsJson(st) {
  const files = st.files || [], findings = st.findings || [];
  const before = computePosture(files, findings, false);
  const after = computePosture(files, findings, true);
  const out = {
    tool: ACS_TOOL,
    generated: new Date().toISOString(),
    scope: { files: files.length, documents: files.reduce(function (n, f) { return n + f.docs.length; }, 0) },
    posture: { current: before, projected: after },
    findings: findings.map(function (f) {
      return {
        id: f.policy.id, acsPolicy: f.policy.acsPolicy, severity: f.policy.severity,
        score: f.policy.score, category: f.policy.categories[0], file: f.file, object: f.obj,
        detail: f.detail, path: f.path, fixKind: f.fixKind,
        confirmedByAcs: !!f.confirmedByAcs,
        standards: { cis: f.policy.cis, nist: f.policy.nist, pss: f.policy.pss, stig: f.policy.stig },
      };
    }),
    acsOnly: st.onlyInAcs || [],
  };
  if (st.vulns) {
    out.vulnerabilities = {
      source: 'ACS /v1/export/vuln-mgmt/workloads',
      priorityScale: { min: 0, max: PRIORITY_MAX,
        note: 'CVSS plus named bounded adjustments. Not a CVSS score.' },
      summary: summarizeVulns(st.vulns),
      images: st.vulns.images,
      cves: st.vulns.rows,
      manifestCorrelation: st.vulnCorr || null,
    };
  }
  return out;
}

/* Sections in the report collapse, with the count in the header.
 *
 * The report is read by somebody who did not run the scan, often in a ticket, and a
 * thousand row table with no way to fold it is a document people scroll past rather than
 * read. Open by default so nothing is hidden from a reader who just wants to read; the
 * count is what lets them decide which ones to close. */
function reportSection(title, count, body, hot) {
  if (!body) return '';
  return '<details class="rsec" open><summary>' + escHtml(title) +
    (count === null || count === undefined ? '' :
      ' <span class="cnt' + (hot ? ' hot' : '') + '">' + escHtml(String(count)) + '</span>') +
    '</summary>' + body + '</details>';
}

function buildHtmlReport(st) {
  const files = st.files || [], findings = st.findings || [];
  const before = computePosture(files, findings, false);
  const after = computePosture(files, findings, true);
  const date = new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
  const E = escHtml;

  const sevChip = function (s) {
    return '<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-weight:700;font-size:11px;' +
      (s === 'Critical' ? 'background:#fde8e8;color:#b91c1c' : s === 'High' ? 'background:#fef0e6;color:#c2540a'
        : s === 'Medium' ? 'background:#fdf6dd;color:#92700c' : 'background:#e7f6ec;color:#166534') + '">' + s + '</span>';
  };

  const rows = findings.map(function (f, i) {
    const s = sevLabel(f.policy.severity);
    return '<tr><td>' + (i + 1) + '</td><td style="font-family:monospace;font-weight:700">' + E(f.policy.id) + '</td>' +
      '<td>' + sevChip(s) + '</td><td>' + f.policy.score.toFixed(1) + '</td>' +
      '<td><b>' + E(f.policy.acsPolicy) + '</b><br>' + E(f.detail) + '</td>' +
      '<td>' + E(f.obj) + '</td><td style="font-family:monospace;font-size:11px">' + E(f.file) + '</td>' +
      '<td>' + (f.fixKind === 'manual' ? 'Manual' : 'Auto') + (f.confirmedByAcs ? '<br><b>live in ACS</b>' : '') + '</td></tr>' +
      '<tr><td></td><td colspan="7" style="background:var(--sub);font-size:12px">' +
      '<b>Why:</b> ' + E(f.policy.rationale) + '<br><b>Do:</b> ' + E(f.policy.remediation) +
      '<br><b>Standards:</b> ' + citationsOf(f.policy).map(E).join(' | ') + '</td></tr>';
  }).join('');

  /* Posture, but only when something was actually scanned.
   *
   * The denominator comes from what was scanned. Scan nothing and it is empty, so the
   * score is 100 out of 100, Grade A. A report is the artifact that outlives the session
   * and gets attached to a ticket, so a green A over an empty scan is the version of this
   * defect that does the most damage. Say what happened instead. */
  /* Declared before postureHtml, which reads it. Building the posture section earlier in
     the function than this left a temporal dead zone that only fired when manifests were
     actually present, so the report ran fine on ACS only data and threw on a real scan. */
  const cats = [];
  const seen = {};
  Object.keys(before.catScores).concat(Object.keys(after.catScores)).forEach(function (c) {
    if (!seen[c]) { seen[c] = 1; cats.push(c); }
  });
  cats.sort();

  let postureHtml;
  if (!files.length) {
    postureHtml =
      '<h2>Summary</h2>' +
      '<div class="note"><b>No posture score: no manifests were scanned.</b><br>' +
      'A score is passed weight over total applicable weight, and the denominator comes ' +
      'from what was scanned. With nothing scanned it is empty, and the arithmetic returns ' +
      '100 out of 100, Grade A. That would read as clean when it actually means unmeasured, ' +
      'so no number is given.' +
      (st.acs && st.acs.total
        ? ' The ACS violations below are unaffected and stand on their own.'
        : '') +
      '<br>To score a posture, run this again with the YAML these workloads come from, or ' +
      'with a workload export from <code>oc get deployment,daemonset,statefulset,cronjob ' +
      '-A -o json</code>.</div>';
  } else {
    postureHtml =
      '<h2>Summary</h2><div class="grid">' +
      '<div class="cardx"><div class="muted">CURRENT POSTURE</div><div class="big">' + before.score + ' / 100</div><div>Grade ' + before.grade + '</div></div>' +
      '<div class="cardx"><div class="muted">AFTER AUTO FIXES</div><div class="big">' + after.score + ' / 100</div><div>Grade ' + after.grade + ' (+' + (after.score - before.score) + ')</div></div>' +
      '<div class="cardx"><div class="muted">FINDINGS</div><div class="big">' + findings.length + '</div><div>' +
        before.counts.Critical + ' critical, ' + before.counts.High + ' high</div></div>' +
      (st.acs ? '<div class="cardx"><div class="muted">CONFIRMED LIVE</div><div class="big">' +
        findings.filter(function (f) { return f.confirmedByAcs; }).length + '</div><div>present in the cluster too</div></div>' : '') +
      '</div>' +
      '<h2>Posture by category</h2><table><tr><th>Category</th><th>Now</th><th>After auto fixes</th><th>Gain</th></tr>' +
      cats.map(function (c) {
        const b = before.catScores[c] === undefined ? 100 : before.catScores[c];
        const a = after.catScores[c] === undefined ? 100 : after.catScores[c];
        return '<tr><td>' + E(c) + '</td><td>' + b + '</td><td>' + a + '</td><td>' + (a > b ? '+' + (a - b) : '0') + '</td></tr>';
      }).join('') + '</table>';
  }

  /* Fixes that are correct and can still stop a workload. Naming them once in the report
     matters because the report is what a reviewer reads before approving a change. */
  const riskyFindings = (findings || []).filter(function (f) { return f.policy.runtimeRisk; });
  const riskHtml = riskyFindings.length ? (
    '<h2>Fixes that can stop the workload</h2>' +
    '<p class="muted">These are classified as automatic because the edit itself is ' +
    'unambiguous. That is a statement about the YAML, not about your application. Each one ' +
    'below is correct hardening that can crash loop a workload which was relying on the ' +
    'thing being removed. Test in a namespace you do not care about first.</p>' +
    '<table><tr><th>ID</th><th>Policy</th><th>Object</th><th>What can break</th></tr>' +
    riskyFindings.map(function (f) {
      return '<tr><td><b>' + E(f.policy.id) + '</b></td><td>' + E(f.policy.acsPolicy) + '</td>' +
        '<td>' + E(f.obj) + '</td><td>' + E(f.policy.runtimeRisk) + '</td></tr>';
    }).join('') + '</table>'
  ) : '';

  const critN = findings.filter(function (f) { return sevLabel(f.policy.severity) === 'Critical'; }).length;
  const findingsHtml = files.length
    ? reportSection('Findings in your manifests',
        findings.length + (critN ? ', ' + critN + ' critical' : ''),
        '<table><tr><th>#</th><th>ID</th><th>Severity</th><th>Score</th><th>Policy and finding</th><th>Object</th><th>File</th><th>Fix</th></tr>' + rows + '</table>',
        critN > 0)
    : '';

  /* ACS violations.
   *
   * This section did not exist. A run with an ACS export and no manifests produced a
   * report of about five kilobytes containing a heading, a method note and nothing else,
   * while the page it came from was showing dozens of violations. The report is the thing
   * people keep, so anything visible in the page has to reach it. */
  let acsHtml = '';
  if (st.acs && st.acs.total) {
    const all = (st.acs.imported || []).concat(st.acs.unmatched || []);
    const byObj = {};
    for (const f of (findings || [])) byObj[f.obj] = true;
    const vrow = function (r) {
      const fx = violationFixability(r, !!byObj[r.obj]);
      const sev = ACS_SEVERITY[r.acsSeverity] ? ACS_SEVERITY[r.acsSeverity].label : 'Low';
      return '<tr>' +
        '<td><span class="sev ' + E(sev) + '">' + E(sev) + '</span></td>' +
        '<td>' + (r.policy ? r.policy.score.toFixed(1) : '&mdash;') + '</td>' +
        '<td>' + (r.policy ? '<b>' + E(r.policy.id) + '</b> ' : '') + E(r.acsPolicyName || '') + '</td>' +
        '<td>' + E(r.obj || '') + '</td>' +
        '<td>' + E(r.namespace || '') + '</td>' +
        '<td>' + E(r.state || '') + '</td>' +
        '<td>' + E(r.detail || '') + '</td>' +
        '<td>' + E(fx.kind) + (fx.kind === 'platform'
          ? ' <span class="muted">(' + (r.platformSource === 'acs' ? 'ACS reported' : 'namespace match') + ')</span>'
          : '') + '</td></tr>';
    };
    /* Worst first. An audit report read top to bottom should start with what matters,
       and an unmatched violation has no score, so it sorts last rather than as a zero. */
    const byScore = function (x, y) {
      const a = x.policy ? x.policy.score : -1, b = y.policy ? y.policy.score : -1;
      return b - a;
    };
    const user = all.filter(function (r) { return !r.isPlatform; }).sort(byScore);
    const plat = all.filter(function (r) { return r.isPlatform; }).sort(byScore);
    const head = '<tr><th>Severity</th><th>Score</th><th>ACS policy</th><th>Object</th><th>Namespace</th><th>State</th><th>Violation</th><th>Fix route</th></tr>';
    acsHtml = reportSection('Violations reported by ACS',
      st.acs.total + ' total, ' + st.acs.user + ' yours, ' + st.acs.platform + ' platform',
      '<p class="muted">' + st.acs.total + ' violation(s) imported: ' + st.acs.user +
        ' on your workloads, ' + st.acs.platform + ' on platform components. ' +
        (st.acs.platformFlagPresent
          ? 'ACS supplied the platform component flag, so that split is authoritative.'
          : 'ACS did not supply the platform component flag, so the split is inferred from the namespace and may be wrong in either direction.') +
        '</p>' +
      (user.length
        ? '<h3>Your workloads (' + user.length + ')</h3><table>' + head + user.map(vrow).join('') + '</table>'
        : '<p class="muted">No violations on your own workloads in this export.</p>') +
      (plat.length
        ? '<h3>Platform components (' + plat.length + ')</h3>' +
          '<p class="muted">Listed for completeness and refused by default. The owning ' +
          'operator reverts manual edits, so a patch changes nothing except how hard the ' +
          'drift is to find. The supported routes are a policy exception with an expiry, a ' +
          'configuration change through whatever the operator exposes, or a case with Red ' +
          'Hat.</p><table>' + head + plat.map(vrow).join('') + '</table>'
        : ''),
      st.acs.user > 0);
  }

  /* Vulnerability section, only when CVE data was supplied. Kept visually separate from
     the posture score for the same reason it is separate in the UI: the posture
     denominator is fixed by what was scanned, CVE counts move whenever a feed updates. */
  let vulnHtml = '';
  if (st.vulns && st.vulns.rows && st.vulns.rows.length) {
    const vs = summarizeVulns(st.vulns);
    const vrows = st.vulns.rows.filter(function (r) { return !r.accepted; })
      .sort(function (a, b) { return b.priority - a.priority; }).slice(0, 300)
      .map(function (r) {
        return '<tr><td>' + E(r.sevLabel) + '</td><td>' + r.priority.toFixed(1) + '</td>' +
          '<td>' + anchor(r.link, r.cve) + (r.cisaKev ? ' <b>KEV</b>' : '') + '</td>' +
          '<td>' + E(r.component.name) + ' ' + E(r.component.version) + '</td>' +
          '<td>' + (r.fixedBy ? E(r.fixedBy) : 'no fix yet') + '</td>' +
          '<td style="font-family:monospace;font-size:11px">' + E(r.image) + '</td>' +
          '<td style="font-size:11px">' + E(r.reasons.join('; ')) + '</td></tr>';
      }).join('');
    vulnHtml =
      '<h2>Image vulnerabilities</h2>' +
      '<p class="muted">Reported separately from the posture score above, and deliberately so. ' +
      'The posture denominator is derived from what was scanned and does not move on its own. ' +
      'CVE counts change every time a vulnerability feed updates with nothing in your manifests ' +
      'changing, so combining them would produce a number that moves for reasons you did not cause.</p>' +
      '<div class="grid">' +
      '<div class="cardx"><div class="muted">ACTIVE CVES</div><div class="big">' + vs.active + '</div><div>' +
        vs.critical + ' critical, ' + vs.important + ' important</div></div>' +
      '<div class="cardx"><div class="muted">KNOWN EXPLOITED</div><div class="big">' + vs.kev + '</div><div>on the CISA KEV catalog</div></div>' +
      '<div class="cardx"><div class="muted">FIXABLE NOW</div><div class="big">' + vs.fixablePct + '%</div><div>' + vs.fixable + ' of ' + vs.active + '</div></div>' +
      '<div class="cardx"><div class="muted">ACCEPTED</div><div class="big">' + vs.accepted + '</div><div>deferred in ACS, excluded above</div></div>' +
      '</div>' +
      '<p class="muted">Priority runs 0 to ' + PRIORITY_MAX + ', not 0 to 10. Clamping to 10 would make every ' +
      'critical tie at the top and destroy the ordering where it matters most. It is CVSS plus named, ' +
      'bounded adjustments, all listed in the last column. It is not a CVSS score.</p>' +
      '<table><tr><th>Severity</th><th>Priority</th><th>CVE</th><th>Component</th><th>Fixed in</th>' +
      '<th>Image</th><th>Why it ranks here</th></tr>' + vrows + '</table>' +
      (st.vulns.rows.filter(function (r) { return !r.accepted; }).length > 300
        ? '<p class="muted">Showing the top 300 by priority. The JSON export carries all of them.</p>' : '');
  }


  return '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ACS Audit Report</title><style>' +
    ':root{--bg:#fff;--fg:#1c2430;--muted:#667085;--line:#e3e8ef;--panel:#f0f3f7;--sub:#fafbfc;--acc:#1f6feb;--card:#dde3ea}' +
    'body.dark{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--panel:#161b22;--sub:#161b22;--acc:#58a6ff;--card:#30363d}' +
    'body{font-family:Segoe UI,system-ui,Arial,sans-serif;background:var(--bg);color:var(--fg);max-width:1120px;margin:0 auto;padding:34px 26px;line-height:1.55}' +
    'h1{font-size:23px;border-bottom:3px solid var(--acc);padding-bottom:9px}h2{font-size:16px;margin-top:30px;color:var(--acc)}' +
    'table{width:100%;border-collapse:collapse;font-size:13px;margin-top:9px}th{background:var(--panel);text-align:left;padding:8px}' +
    'td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}' +
    '.big{font-size:38px;font-weight:800}.grid{display:flex;gap:24px;flex-wrap:wrap;margin-top:11px}' +
    '.cardx{border:1px solid var(--card);border-radius:10px;padding:16px 22px;min-width:190px}' +
    '.muted{color:var(--muted);font-size:12.5px}a{color:var(--acc)}details.rsec{margin:18px 0}details.rsec>summary{cursor:pointer;list-style:none;font-size:18px;font-weight:600;margin:0 0 8px;display:flex;align-items:center;gap:10px;user-select:none}details.rsec>summary::-webkit-details-marker{display:none}details.rsec>summary::before{content:"\\25B8";font-size:12px;color:var(--muted);display:inline-block;transition:transform .12s}details.rsec[open]>summary::before{transform:rotate(90deg)}summary .cnt{font-size:12px;font-weight:400;color:var(--muted);border:1px solid var(--card);border-radius:10px;padding:1px 9px}summary .cnt.hot{color:#cf222e;border-color:#cf222e}.note{border-left:3px solid #d4a72c;background:var(--panel);padding:10px 13px;border-radius:0 6px 6px 0;font-size:13px;margin:10px 0}.sev{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10.5px;font-weight:700}.sev.Critical{background:#67060c;color:#ffb3ad}.sev.High{background:#5a2d0c;color:#ffc999}.sev.Medium{background:#4d3800;color:#f2d24b}.sev.Low{background:#0f3d1e;color:#7ee2a8}h3{font-size:14px;margin:14px 0 6px}' +
    '#tg{position:fixed;top:13px;right:15px;background:var(--panel);color:var(--fg);border:1px solid var(--card);border-radius:6px;padding:6px 13px;cursor:pointer;font-size:13px}' +
    '</style></head><body><button id="tg">Dark mode</button>' +
    '<h1>Red Hat ACS Audit Report</h1>' +
    '<p class="muted">Generated ' + E(date) + ' by ' + E(ACS_TOOL) + '. Scope: ' + files.length + ' file(s), ' +
      files.reduce(function (n, f) { return n + f.docs.length; }, 0) + ' YAML document(s).' +
      (st.acs ? ' Cross checked against an ACS export of ' + st.acs.total + ' violation(s).' : '') +
      (st.source ? ' Source: ' + E(st.source) + '.' : '') + '</p>' +
    postureHtml +
    acsHtml +
    findingsHtml +
    riskHtml +
    vulnHtml +
    '<h2>Method</h2><p>Each policy mirrors a Red Hat ACS default security policy: same name, same ACS severity, same categories and lifecycle stage, with the ACS remediation guidance carried through. Severity drives a weighted posture score in which every applicable policy and object pair is one check, weighted Critical 18, High 10, Medium 5 and Low 2. Posture is passed weight over total applicable weight, and the denominator is derived only from what was scanned rather than what was found, so the current and projected numbers are directly comparable. CVSS style scores are for ranking configuration weakness classes, not instance specific vulnerability scoring. STIG references are mapping aids and must be verified against the current DISA release before they are cited in an accreditation package.</p>' +
    '<h2>Limits</h2><p>This is static analysis of manifest text. It does not query a cluster and does not replace ACS, admission control such as Pod Security Admission or Kyverno, or runtime enforcement. ACS policies that evaluate build metadata or runtime process behaviour cannot be assessed from YAML. Image CVEs appear here only when an ACS vulnerability export was supplied; this tool performs no scanning of its own, so an absence of CVEs below means none were imported, not that none exist.</p>' +
    '<h2>References</h2><ul>' + ACS_REFERENCES.map(function (r) { return '<li>' + anchor(r[1], r[0]) + '</li>'; }).join('') + '</ul>' +
    /* Sorting.
     *
     * The report is a standalone file that outlives the session, and the first thing
     * anybody does with a findings table is reorder it: worst first, or grouped by
     * namespace, or by the file they own. Without this they export to a spreadsheet to do
     * it, and the spreadsheet is what gets circulated instead of the report.
     *
     * Applied to every table generically rather than wired per table, so one added later
     * is sortable without anybody remembering to do it. Numeric columns are detected from
     * the values rather than declared, because a declaration is one more thing to keep in
     * step with the markup. */
    '<script>(function(){' +
    'function cmp(a,b,i,num){var x=a.cells[i].textContent.trim(),y=b.cells[i].textContent.trim();' +
    'if(num){var nx=parseFloat(x.replace(/[^0-9.\\-]/g,"")),ny=parseFloat(y.replace(/[^0-9.\\-]/g,""));' +
    'if(isNaN(nx))nx=-Infinity;if(isNaN(ny))ny=-Infinity;return nx-ny;}' +
    'return x.localeCompare(y,undefined,{numeric:true});}' +
    'Array.prototype.forEach.call(document.querySelectorAll("table"),function(tb){' +
    'var head=tb.rows[0];if(!head)return;' +
    'Array.prototype.forEach.call(head.cells,function(th,i){' +
    'th.style.cursor="pointer";th.title="Sort by "+th.textContent.trim();' +
    'var base=th.textContent;th.addEventListener("click",function(){' +
    'var rows=Array.prototype.slice.call(tb.rows,1);if(!rows.length)return;' +
    'var num=rows.every(function(r){var v=r.cells[i]?r.cells[i].textContent.trim():"";' +
    'return v===""||v==="\\u2014"||/^[0-9]+(\\.[0-9]+)?$/.test(v);});' +
    'var dir=th.getAttribute("data-dir")==="1"?-1:1;' +
    'Array.prototype.forEach.call(head.cells,function(o){o.removeAttribute("data-dir");' +
    'o.textContent=o.textContent.replace(/ [\\u25b2\\u25bc]$/,"");});' +
    'th.setAttribute("data-dir",dir===1?"1":"0");' +
    'th.textContent=base.replace(/ [\\u25b2\\u25bc]$/,"")+(dir===1?" \\u25b2":" \\u25bc");' +
    'rows.sort(function(a,b){return cmp(a,b,i,num)*dir;});' +
    'rows.forEach(function(r){tb.appendChild(r);});});});});' +
    '})();<\/script>' +
    '<script>(function(){var t=document.getElementById("tg");function ap(m){document.body.classList.toggle("dark",m==="dark");t.textContent=m==="dark"?"Light mode":"Dark mode";try{localStorage.setItem("acsRepTheme",m)}catch(e){}}' +
    't.addEventListener("click",function(){ap(document.body.classList.contains("dark")?"light":"dark")});' +
    'var s="light";try{s=localStorage.getItem("acsRepTheme")||"light"}catch(e){}ap(s)})();<\/script>' +
    '</body></html>';
}


/* ============================================================ fixing a violation
 *
 * An ACS violation and a local finding are not the same thing, and the difference
 * decides whether anything can be fixed automatically.
 *
 *   Matched to a policy AND the manifest is loaded
 *       Normal path. The fix is applied to your YAML with a diff and a confirmation.
 *
 *   Matched to a policy, manifest NOT loaded
 *       Common when you pulled from ACS but the repository is elsewhere. Previously a
 *       dead end. Now the tool emits a strategic merge patch built from the violation
 *       alone: ACS told us the kind, the name and the namespace, and the policy tells us
 *       the field to set. That patch is applyable through GitOps without ever seeing the
 *       original manifest.
 *
 *   On a platform component
 *       Never auto fixed. These are OpenShift, the operators, or ACS itself. The operator
 *       that owns the object reverts your change on its next reconcile, so a "fix" here
 *       does nothing except make the drift harder to see. The honest outputs are an ACS
 *       policy exception with an expiry, a supported configuration change, or a Red Hat
 *       case.
 *
 *   Unmatched, or a runtime or build policy
 *       Nothing to write. Reported, never guessed at.
 */

/* Container level fixes need a container name, and a violation is sometimes the only
   place it appears. ACS phrases these consistently enough to parse, and when it does not
   the patch is emitted with the name left blank and flagged, rather than invented. */
function containerFromViolation(rec) {
  const text = [rec.detail].concat(rec.violations || []).join(' ');
  const m = text.match(/[Cc]ontainer\s+['"]([^'"]+)['"]/) ||
            text.match(/[Cc]ontainer\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+(?:is|has|runs|does)/);
  return m ? m[1] : '';
}

/* Which policies can be expressed as a patch with no sight of the original manifest.
   Pod level settings need nothing but the object. Container level ones need a name. */
const VIOLATION_PATCHES = {
  'ACS.001': { level: 'container', apply: (c) => { c.securityContext = c.securityContext || {}; c.securityContext.privileged = false; } },
  'ACS.002': { level: 'container', apply: (c) => { c.securityContext = c.securityContext || {}; c.securityContext.readOnlyRootFilesystem = true; } },
  'ACS.003': { level: 'container', apply: (c) => { c.securityContext = c.securityContext || {}; c.securityContext.allowPrivilegeEscalation = false; } },
  'ACS.004': { level: 'pod', apply: (p) => { p.hostNetwork = false; } },
  'ACS.005': { level: 'pod', apply: (p) => { p.hostPID = false; } },
  'ACS.006': { level: 'pod', apply: (p) => { p.hostIPC = false; } },
  'ACS.007': { level: 'container', apply: (c) => { c.securityContext = c.securityContext || {}; c.securityContext.capabilities = { drop: ['ALL'] }; } },
  'ACS.008': { level: 'container', apply: (c) => { c.securityContext = c.securityContext || {}; c.securityContext.capabilities = { drop: ['ALL'] }; } },
  'ACS.009': { level: 'pod', apply: (p) => { p.securityContext = p.securityContext || {}; p.securityContext.runAsNonRoot = true; } },
  'ACS.016': { level: 'pod', apply: (p) => { p.automountServiceAccountToken = false; } },
};

function violationFixability(rec, filesLoaded, opts) {
  const o = opts || {};
  if (rec.isPlatform && !o.overridePlatform) {
    const guessed = rec.platformSource !== 'acs';
    return { fixable: false, kind: 'platform', platformSource: rec.platformSource,
      overridable: true,
      why: guessed
        ? 'Treated as a platform component because the namespace "' + rec.namespace +
          '" matches the platform pattern. ACS did not send the platformComponent field, ' +
          'so this is a guess rather than something ACS told us. If you own this workload, ' +
          'override it and the normal fix routes apply. If it really is platform, patching ' +
          'it changes nothing except how hard the drift is to see, because the owning ' +
          'operator reverts manual edits.'
        : 'ACS reports this as a platform component, which is authoritative: ACS knows what ' +
          'the cluster operators own. The owning operator reverts manual edits, so a patch ' +
          'here changes nothing except how hard the drift is to find. The supported routes ' +
          'are a policy exception with an expiry, a configuration change through whatever ' +
          'the operator exposes, or a case with Red Hat.' };
  }
  if (!rec.matched || !rec.policy) {
    return { fixable: false, kind: 'unmatched',
      why: 'No policy in this catalogue matches "' + rec.acsPolicyName + '". It may be a custom policy, or one this tool does not model. Nothing is guessed at.' };
  }
  const p = rec.policy;
  if (p.fixKind === 'manual') {
    return { fixable: false, kind: 'manual', why: p.remediation };
  }
  const overrideNote = (rec.isPlatform && o.overridePlatform)
    ? ' You have overridden the platform classification for this one. If the object really ' +
      'is operator managed, the operator will revert whatever you apply, and the change will ' +
      'look deliberate to whoever reviews the drift later.'
    : '';
  if (filesLoaded) {
    return { fixable: true, kind: 'inplace', overridden: !!overrideNote,
      why: 'The manifest is loaded, so this is fixed in your YAML with a diff and a confirmation.' + overrideNote };
  }
  if (!VIOLATION_PATCHES[p.id]) {
    return { fixable: false, kind: 'needs-manifest',
      why: 'This fix needs to see the original manifest. Load the file, or pull the workload with oc get -o json, then it becomes fixable.' };
  }
  return { fixable: true, kind: 'patch', overridden: !!overrideNote,
    why: 'Emitted as a strategic merge patch built from the violation. Apply it through GitOps.' + overrideNote };
}

/* Build a strategic merge patch for one violation, with no manifest required. */
function buildViolationPatch(rec, opts) {
  /* Pass the caller's options through. Re-deriving fixability here WITHOUT them meant an
     overridden platform record was re-judged as platform, refused, and silently produced
     no patch, so the override appeared to do nothing at all. */
  const f = violationFixability(rec, false, opts || {});
  if (!f.fixable || f.kind !== 'patch') return null;
  const spec = VIOLATION_PATCHES[rec.policy.id];
  const parts = String(rec.obj || '').split('/');
  const kind = parts[0] || 'Deployment';
  const name = parts.slice(1).join('/') || 'unknown';

  const patch = {
    apiVersion: kind === 'CronJob' ? 'batch/v1' : kind === 'Job' ? 'batch/v1' : kind === 'Pod' ? 'v1' : 'apps/v1',
    kind: kind,
    metadata: { name: name, namespace: rec.namespace && rec.namespace !== 'unknown' ? rec.namespace : undefined },
  };
  if (!patch.metadata.namespace) delete patch.metadata.namespace;

  const podSpecOut = {};
  if (spec.level === 'pod') spec.apply(podSpecOut);
  else {
    const cname = containerFromViolation(rec);
    const c = { name: cname };
    spec.apply(c);
    podSpecOut.containers = [c];
  }

  if (kind === 'Pod') patch.spec = podSpecOut;
  else if (kind === 'CronJob') patch.spec = { jobTemplate: { spec: { template: { spec: podSpecOut } } } };
  else patch.spec = { template: { spec: podSpecOut } };

  const needsName = spec.level === 'container' && !containerFromViolation(rec);
  return { patch: patch, policy: rec.policy, rec: rec, needsContainerName: needsName };
}

/* The deliverable: patches for everything fixable, and a written account of everything
   that is not, with the reason. A bundle that silently omits what it could not do is how
   an operator ends up believing a cluster is clean. */
/* The identity of a violation, in one place.
 *
 * Deduplication on import, the checkbox on a row, and --select on the command line all
 * have to agree on what "the same violation" means, or a selection made in the page will
 * not correspond to the thing the CLI fixes. An alert id is the natural key. Records
 * without one, a roxctl report for instance, fall back to the tuple that actually
 * identifies a violation.
 */
function violationKey(rec) {
  if (!rec) return '';
  return rec.acsAlertId || (rec.acsPolicyName + '|' + rec.obj + '|' + rec.namespace);
}

/* Wrap prose for a comment block. Long single line comments in a YAML header are worse
   than no comment: people stop reading at the edge of the terminal. */
function wrapAt(text, width) {
  const words = String(text).split(/\s+/);
  const out = []; let line = '';
  for (const w of words) {
    if (line && (line + ' ' + w).length > width) { out.push(line); line = w; }
    else line = line ? line + ' ' + w : w;
  }
  if (line) out.push(line);
  return out;
}

function buildViolationFixBundle(acs, opts) {
  const o = opts || {};
  const mode = resolveFixMode(o.mode);
  const filesByObj = o.filesByObj || {};

  /* Report mode produces the account of what could be fixed and by which route, and no
     patch files at all. The point is that nothing leaves this function in report mode
     that anyone could apply, deliberately or otherwise. */
  const emitPatches = modeAllows(mode, 'patches');
  const all = ((acs && acs.imported) || []).concat((acs && acs.unmatched) || []);

  /* A selection, when one is given, decides which violations are in scope. Undefined means
     all of them, so every existing caller is unaffected. An EMPTY selection means none,
     and must not be confused with "no selection given": that distinction is the whole
     point of letting somebody choose, and collapsing it would silently fix everything at
     the moment they had deliberately chosen nothing. */
  const sel = o.selected == null ? null
    : (o.selected instanceof Set ? o.selected : new Set(Array.from(o.selected)));
  const recs = sel === null ? all : all.filter(function (r) { return sel.has(violationKey(r)); });
  const deselected = all.length - recs.length;

  const patches = [];
  const skipped = [];
  const inplace = [];
  const seen = {};

  /* Platform classifications the operator has explicitly overridden, by violation key.
     A Set rather than a boolean: overriding is a per finding judgement about one object
     you claim to own, not a global "ignore the platform rule" switch. */
  const over = o.overridden == null ? null
    : (o.overridden instanceof Set ? o.overridden : new Set(Array.from(o.overridden)));
  const isOver = (rec) => !!(over && over.has(violationKey(rec)));

  for (const rec of recs) {
    const loaded = !!filesByObj[rec.obj];
    const f = violationFixability(rec, loaded, { overridePlatform: isOver(rec) });
    if (f.kind === 'inplace') { inplace.push({ rec: rec, why: f.why }); continue; }
    if (!f.fixable) { skipped.push({ rec: rec, kind: f.kind, why: f.why }); continue; }
    const built = buildViolationPatch(rec, { overridePlatform: isOver(rec) });
    if (!built) { skipped.push({ rec: rec, kind: 'nopatch', why: 'No patch template for ' + rec.policy.id }); continue; }
    const key = rec.namespace + '|' + rec.obj + '|' + rec.policy.id;
    if (seen[key]) continue;
    seen[key] = 1;
    patches.push(built);
  }

  /* One file per object, merging every policy that applies to it, because you apply a
     patch to an object once. Ten files for the same Deployment is not ten fixes. */
  const byObj = {};
  for (const b of patches) {
    const key = b.rec.namespace + '|' + b.rec.obj;
    if (!byObj[key]) byObj[key] = { rec: b.rec, patch: b.patch, policies: [],
                                    needsContainerName: false, overridden: isOver(b.rec) };
    else byObj[key].patch = mergePatchObjects(byObj[key].patch, b.patch);
    byObj[key].policies.push(b.policy.id);
    if (b.needsContainerName) byObj[key].needsContainerName = true;
  }

  const files = Object.keys(byObj).map(function (k) {
    const g = byObj[k];
    const safe = (g.rec.namespace + '_' + g.rec.obj).replace(/[^A-Za-z0-9]/g, '_');
    const header = [
      '# Strategic merge patch generated by ' + ACS_TOOL,
      '# Built from an ACS violation, not from a manifest, so verify before applying.',
      '# Object:   ' + g.rec.obj + '  in namespace ' + g.rec.namespace,
      '# Cluster:  ' + (g.rec.cluster || 'not reported'),
      '# Covers:   ' + g.policies.sort().join(', '),
      '# This file is data, not a command. Nothing here has been applied.',
    ];
    if (g.overridden) {
      header.push('#');
      header.push('# OVERRIDE: this object was classified as a platform component and you chose');
      header.push('# to patch it anyway. If it is operator managed, the operator will revert');
      header.push('# this, and the resulting drift will look like a deliberate change to whoever');
      header.push('# reviews it. Confirm you own this object before applying.');
    }
    const risks = g.policies.map(function (pid) {
      const pol = ACS_POLICIES.filter(function (x) { return x.id === pid; })[0];
      return pol && pol.runtimeRisk ? { id: pid, note: pol.runtimeRisk } : null;
    }).filter(Boolean);
    if (risks.length) {
      header.push('#');
      header.push('# CAN STOP THE WORKLOAD. This patch is correct hardening, and applying it');
      header.push('# without checking the workload can crash loop it. Test in a namespace you');
      header.push('# do not care about before this goes anywhere real.');
      for (const r of risks) {
        header.push('#');
        header.push('#   ' + r.id + ':');
        for (const line of wrapAt(r.note, 72)) header.push('#     ' + line);
      }
    }
    if (g.needsContainerName) {
      header.push('#');
      header.push('# WARNING: the container name could not be read from the violation text, so');
      header.push('# it is blank below. A strategic merge patch keys the containers array on');
      header.push('# name; applying this as is would ADD a nameless container rather than');
      header.push('# patching yours. Fill it in before you apply this.');
    }
    return { name: 'violation-patches/' + safe + '.yaml',
             text: header.join('\n') + '\n' + jsyaml.dump(g.patch, { noRefs: true, lineWidth: 120 }),
             obj: g.rec.obj, namespace: g.rec.namespace, policies: g.policies.slice().sort(),
             needsContainerName: g.needsContainerName };
  });

  const emitted = emitPatches ? files : [];
  /* Name the object, not just the file. In report mode this list is the entire output, and
     a reader deciding whether to re-run in manual mode needs to know which workloads are
     in scope. A flattened filename like batch_Deployment_batch_runner.yaml is not that:
     the separator and the name separator are the same character, so you cannot tell where
     the namespace ends and the object begins. */
  buildViolationFixReport.lastWouldBe = emitPatches ? [] :
    files.map(function (f) {
      return '**' + f.obj + '** in `' + f.namespace + '` covering ' + f.policies.join(', ') +
             '  \n  would be written to `' + f.name + '`' +
             (f.needsContainerName ? '  **container name missing, see the file header**' : '');
    });
  return { mode: mode, files: emitted, patches: patches, skipped: skipped, inplace: inplace,
           suppressed: emitPatches ? 0 : files.length,
           selected: recs.length, deselected: deselected, total: all.length,
           report: buildViolationFixReport(emitted, skipped, inplace, mode,
                                           emitPatches ? 0 : files.length,
                                           { selected: recs.length, deselected: deselected,
                                             total: all.length }) };
}

function mergePatchObjects(a, b) {
  const out = structuredClone(a);
  (function merge(dst, src) {
    for (const k of Object.keys(src)) {
      if (Array.isArray(src[k])) {
        if (k === 'containers' && Array.isArray(dst[k])) {
          for (const sc of src[k]) {
            const dc = dst[k].find(function (x) { return x.name === sc.name; });
            if (dc) merge(dc, sc); else dst[k].push(sc);
          }
        } else dst[k] = src[k];
      } else if (src[k] && typeof src[k] === 'object') {
        dst[k] = dst[k] && typeof dst[k] === 'object' ? dst[k] : {};
        merge(dst[k], src[k]);
      } else dst[k] = src[k];
    }
  })(out, b);
  return out;
}

function buildViolationFixReport(files, skipped, inplace, mode, suppressed, scope) {
  const m = resolveFixMode(mode);
  const L = [];
  L.push('# Fixing ACS violations');
  L.push('');
  L.push('Generated by ' + ACS_TOOL + ' on ' + new Date().toISOString() + '.');
  L.push(modeBanner(m));
  L.push('No command was run. Nothing was applied to any cluster.');
  L.push('');

  /* Say what was left out. A report that silently covers a subset reads exactly like a
     report that covers everything, and the person reading it six months from now has no
     way to tell which one they are holding. */
  if (scope && scope.deselected) {
    L.push('## Scope: ' + scope.selected + ' of ' + scope.total + ' violation(s) were selected');
    L.push('');
    L.push(scope.deselected + ' violation(s) were deliberately left out of this run and are not');
    L.push('described anywhere below. This document covers the selection, not the cluster.');
    L.push('');
  } else if (scope && scope.total) {
    L.push('Scope: all ' + scope.total + ' imported violation(s).');
    L.push('');
  }
  if (scope && scope.total && scope.selected === 0) {
    L.push('**Nothing was selected, so nothing was drafted.** This is not the same as nothing');
    L.push('being fixable. Select the violations you want and run it again.');
    L.push('');
  }
  if (suppressed) {
    L.push('## Report mode: ' + suppressed + ' patch(es) were NOT written');
    L.push('');
    L.push('This run was asked to report, so nothing applyable was produced. ' + suppressed +
      ' violation(s) could have had a patch generated. Re-run in manual mode to get them:');
    L.push('');
    L.push('    node acs_cli.js --mode manual --alerts <file> --violation-fixes');
    L.push('');
    L.push('They are listed below so you can see the scope of the work without holding a');
    L.push('file that somebody could apply by accident.');
    L.push('');
  }
  L.push('## Patches ' + (suppressed ? 'that would be emitted (' + suppressed + ')' : 'emitted (' + files.length + ')'));
  L.push('');
  if (!files.length && !suppressed) L.push('None.');
  for (const f of files) {
    L.push('* `' + f.name + '`' + (f.needsContainerName ? '  **container name missing, fill it in**' : ''));
  }
  if (suppressed && !files.length) {
    for (const i of (buildViolationFixReport.lastWouldBe || [])) L.push('* ' + i);
  }
  L.push('');
  if (inplace.length) {
    L.push('## Fixed in your YAML instead (' + inplace.length + ')');
    L.push('');
    L.push('The manifest for these is loaded, so they are fixed there with a diff and a');
    L.push('confirmation rather than emitted as a patch.');
    L.push('');
    for (const i of inplace) L.push('* ' + i.rec.policy.id + '  ' + i.rec.obj + '  in ' + i.rec.namespace);
    L.push('');
  }

  const groups = {};
  for (const sk of skipped) (groups[sk.kind] = groups[sk.kind] || []).push(sk);
  const titles = {
    platform: 'Platform components, not yours to fix',
    manual: 'Need a human decision',
    unmatched: 'No matching policy in this catalogue',
    'needs-manifest': 'Need the original manifest',
    nopatch: 'No patch template',
  };
  for (const k of Object.keys(groups)) {
    L.push('## ' + (titles[k] || k) + ' (' + groups[k].length + ')');
    L.push('');
    if (groups[k][0]) { L.push(groups[k][0].why); L.push(''); }
    for (const sk of groups[k].slice(0, 200)) {
      L.push('* **' + (sk.rec.policy ? sk.rec.policy.id + '** ' : '') + sk.rec.acsPolicyName +
        '  in `' + sk.rec.obj + '` (' + sk.rec.namespace + ')');
    }
    if (groups[k].length > 200) L.push('* and ' + (groups[k].length - 200) + ' more');
    L.push('');
  }
  return L.join('\n');
}

/* ================================================== merging multiple exports
 *
 * acs_pull_all.sh writes six files and you are meant to drop all of them at once. Each
 * import used to replace the last, so dropping the whole folder left you looking at
 * whichever file happened to land last and silently discarded the rest.
 *
 * These merge instead, deduplicating on identity rather than on object equality, because
 * the same alert appears in both 01_alerts_list.json and 02_alerts_full.json and only the
 * second has violation text. Later, richer records win.
 */

function mergeAcsImports(a, b) {
  if (!a) return b;
  if (!b) return a;
  const out = { imported: [], unmatched: [], total: 0, hydratable: 0,
                platform: 0, user: 0,
                platformFlagPresent: !!(a.platformFlagPresent || b.platformFlagPresent) };
  const byId = {};
  const order = [];
  const absorb = (rec) => {
    const key = violationKey(rec);
    const prev = byId[key];
    if (!prev) { byId[key] = rec; order.push(key); return; }
    /* Prefer the hydrated one. This is the whole reason 01 and 02 both exist: the list is
       fast and empty of detail, the per id fetch has the violation text. */
    if (!prev.hydrated && rec.hydrated) byId[key] = rec;
    else if (prev.hydrated && rec.hydrated && rec.violations.length > prev.violations.length) byId[key] = rec;
  };
  for (const src of [a, b]) {
    for (const r of (src.imported || [])) absorb(r);
    for (const r of (src.unmatched || [])) absorb(r);
  }
  for (const k of order) {
    const r = byId[k];
    (r.matched ? out.imported : out.unmatched).push(r);
    if (r.isPlatform) out.platform += 1; else out.user += 1;
    if (!r.hydrated && r.acsAlertId) out.hydratable += 1;
  }
  out.total = out.imported.length + out.unmatched.length;
  return out;
}

function mergeVulnImports(a, b) {
  if (!a) return b;
  if (!b) return a;
  const rows = [];
  const seen = {};
  for (const src of [a, b]) {
    for (const r of (src.rows || [])) {
      const key = r.cve + '|' + r.image + '|' + r.component.name + '|' + r.component.version;
      if (seen[key]) {
        /* Same CVE seen from two exports. Keep the record that knows more: a workload
           export knows how many pods run it, an image export does not. */
        const prev = seen[key];
        for (const w of r.workloads) if (prev.workloads.indexOf(w) === -1) prev.workloads.push(w);
        prev.livePods = Math.max(prev.livePods, r.livePods);
        if (r.priority > prev.priority) { prev.priority = r.priority; prev.reasons = r.reasons; }
        continue;
      }
      seen[key] = r;
      rows.push(r);
    }
  }
  const images = {};
  for (const src of [a, b]) for (const im of (src.images || [])) {
    if (!images[im.ref]) images[im.ref] = im;
    else {
      const p = images[im.ref];
      for (const w of im.workloads) if (p.workloads.indexOf(w) === -1) p.workloads.push(w);
    }
  }
  /* Recount per image from the merged rows rather than summing, which would double count
     an image that appeared in two exports. */
  for (const ref of Object.keys(images)) {
    const mine = rows.filter((r) => r.image === ref);
    images[ref].cves = mine.length;
    images[ref].fixable = mine.filter((r) => r.fixable).length;
    images[ref].critical = mine.filter((r) => r.sevRank === 4).length;
    images[ref].important = mine.filter((r) => r.sevRank === 3).length;
  }
  rows.sort((x, y) => (y.sevRank - x.sevRank) || (y.priority - x.priority) || x.cve.localeCompare(y.cve));
  return {
    rows: rows,
    images: Object.keys(images).map((k) => images[k])
      .sort((x, y) => (y.critical - x.critical) || (y.cves - x.cves)),
    accepted: rows.filter((r) => r.accepted).length,
    parseErrors: (a.parseErrors || []).concat(b.parseErrors || []),
    workloads: (a.workloads || 0) + (b.workloads || 0),
  };
}

/* ==================================================================== fix mode
 *
 * Three modes, chosen explicitly, enforced identically by the CLI, both HTML pages and
 * every artifact they produce.
 *
 *   report   Analyse and report. No fix artifact of any kind is produced. Not a patch,
 *            not a corrected manifest, nothing that could be applied by accident.
 *   manual   Produce the material a human needs to make the change themselves: patches,
 *            diffs, annotated guidance. Nothing is modified. The output is a proposal.
 *   auto     Apply the safe fixes. Still previewed and still confirmed, but the tool
 *            does the editing.
 *
 * WHY THIS IS A SECURITY CONTROL AND NOT A CONVENIENCE
 *
 * A remediation tool that can write without the operator having chosen to write is a new
 * risk, not a mitigation. The failure is not the tool doing something malicious, it is a
 * tired engineer at the end of an incident clicking the obvious button and producing a
 * change to a production manifest they did not intend and cannot immediately explain.
 * That change then goes through review with a plausible looking diff attached to it.
 *
 * The controls that follow from that:
 *   - report is the default everywhere. The safe state is the one you get by doing
 *     nothing, not the one you get by remembering a flag.
 *   - the mode is never inferred from another option. Asking for patches does not put
 *     you in manual mode; you say manual and then ask for patches.
 *   - the mode is recorded in every artifact, so a reviewer can see which path produced
 *     the file in front of them without having to ask.
 *   - a mode that permits writing cannot be reached by a default, a fallback, or an
 *     unrecognised value. An unknown mode is an error, never a silent downgrade to
 *     something permissive.
 */
const FIX_MODES = ['report', 'manual', 'auto'];

const FIX_MODE_INFO = {
  report: {
    label: 'Report only',
    writes: false, patches: false, edits: false,
    summary: 'Analyse and report. Nothing that could be applied is produced.',
  },
  manual: {
    label: 'Manual fix',
    writes: true, patches: true, edits: false,
    summary: 'Produce patches and guidance for a human to review and apply. Nothing is modified.',
  },
  auto: {
    label: 'Auto fix',
    writes: true, patches: true, edits: true,
    summary: 'Apply the safe fixes, with a preview and a confirmation before each change.',
  },
};

/* Resolve a mode. Unknown values throw rather than defaulting, because a typo that
   silently lands you in a writing mode is exactly the failure this exists to prevent.
   Absent is fine and means report: the safe state is the one you get for free. */
function resolveFixMode(mode) {
  if (mode === undefined || mode === null || mode === '') return 'report';
  const m = String(mode).trim().toLowerCase();
  if (FIX_MODES.indexOf(m) === -1) {
    throw new Error('Unknown fix mode "' + mode + '". Use one of: ' + FIX_MODES.join(', ') +
      '. Refusing to guess, because guessing wrong here means writing when you asked not to.');
  }
  return m;
}

function modeAllows(mode, what) {
  const info = FIX_MODE_INFO[resolveFixMode(mode)];
  return !!info[what];
}

/* One sentence for the top of any artifact, so the file itself records which path
   produced it. A reviewer holding a patch should not have to ask how it was made. */
function modeBanner(mode) {
  const m = resolveFixMode(mode);
  const i = FIX_MODE_INFO[m];
  return 'Mode: ' + m + ' (' + i.label + '). ' + i.summary;
}

/* ------------------------------------------------------------------- fixes */

function defaultDenyPolicy(ns) {
  return {
    apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy',
    metadata: { name: 'default-deny-with-dns', namespace: ns },
    spec: {
      podSelector: {}, policyTypes: ['Ingress', 'Egress'],
      egress: [{
        to: [{ namespaceSelector: {}, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
        ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }],
      }],
    },
  };
}

function findingKey(f) { return f.file + '|' + f.obj + '|' + f.policy.id; }

function dumpDocs(docs) {
  return docs.map((d) => jsyaml.dump(d, { noRefs: true, lineWidth: 120 })).join('---\n');
}

/* Apply exactly one policy to one object and return the rewritten documents plus a
   description of what changed. One policy at a time is what makes preview, confirm and undo
   possible per fix rather than all or nothing. */
function applyOneFix(fileDocs, finding) {
  const policy = finding.policy;
  if (!policy.fix) return null;
  const docs = structuredClone(fileDocs);
  const changes = [];
  let beforeDoc = null, afterDoc = null;
  for (let i = 0; i < docs.length; i++) {
    if (nameOf(docs[i]) !== finding.obj) continue;
    const snapshot = structuredClone(fileDocs[i]);
    try {
      const ch = policy.fix(docs[i]);
      if (ch && ch.length) {
        changes.push(...(Array.isArray(ch) ? ch : [ch]));
        beforeDoc = snapshot;
        afterDoc = docs[i];
      }
    } catch (e) { return null; }
  }
  if (!changes.length) return null;
  return { docs, changes, yaml: dumpDocs(docs), beforeDoc, afterDoc };
}

/* A strategic merge patch, for teams whose manifests are templated by Helm or Kustomize and
   therefore cannot be edited in place. Contains only the changed fields plus enough identity
   for the patch to be routed to the right object. */
function buildMergePatch(beforeDoc, afterDoc) {
  /* Kubernetes merges most object arrays, containers and volumes among them, on the name
     key rather than by position. So the patch carries only the elements that changed,
     each identified by its name. Emitting the whole array instead would work, but it
     would also overwrite any field that drifted between the scan and the apply, which is
     exactly the kind of silent clobbering a patch is supposed to avoid. */
  function diffArray(a, b) {
    const keyed = b.length && b.every((x) => x && typeof x === 'object' && typeof x.name === 'string');
    if (!keyed) return b;   /* an atomic list, replaced wholesale */
    const out = [];
    for (const bi of b) {
      const ai = (Array.isArray(a) ? a : []).find((x) => x && x.name === bi.name);
      if (JSON.stringify(ai) === JSON.stringify(bi)) continue;
      const sub = diffObj(ai || {}, bi);
      sub.name = bi.name;
      out.push(sub);
    }
    return out;
  }
  function diffObj(a, b) {
    if (b === null || typeof b !== 'object') return b;
    if (Array.isArray(b)) return diffArray(a, b);
    const out = {};
    for (const k of Object.keys(b)) {
      const av = a ? a[k] : undefined;
      const bv = b[k];
      if (JSON.stringify(av) === JSON.stringify(bv)) continue;
      out[k] = diffObj(av, bv);
    }
    return out;
  }
  const patch = diffObj(beforeDoc, afterDoc) || {};
  patch.apiVersion = afterDoc.apiVersion;
  patch.kind = afterDoc.kind;
  patch.metadata = Object.assign({ name: afterDoc.metadata && afterDoc.metadata.name }, patch.metadata || {});
  if (afterDoc.metadata && afterDoc.metadata.namespace) patch.metadata.namespace = afterDoc.metadata.namespace;
  return patch;
}

/* --------------------------------------------------------------- line diff */

/* Minimal LCS line diff. Enough to show a reviewer exactly what a fix will do before they
   confirm it, which is the entire point of the confirmation step. */
function diffLines(beforeText, afterText) {
  const a = beforeText.split('\n');
  const b = afterText.split('\n');
  const n = a.length, m = b.length;
  const lcs = [];
  for (let i = 0; i <= n; i++) lcs.push(new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ t: ' ', text: a[i], an: i + 1, bn: j + 1 }); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ t: '-', text: a[i], an: i + 1 }); i++; }
    else { out.push({ t: '+', text: b[j], bn: j + 1 }); j++; }
  }
  while (i < n) { out.push({ t: '-', text: a[i], an: i + 1 }); i++; }
  while (j < m) { out.push({ t: '+', text: b[j], bn: j + 1 }); j++; }
  return out;
}

/* Trim a diff to changed regions with surrounding context, so a one line fix does not render
   four hundred unchanged lines and bury the change. */
function compactDiff(diff, context) {
  const ctx = context === undefined ? 3 : context;
  const keep = new Set();
  diff.forEach((d, i) => {
    if (d.t === ' ') return;
    for (let k = Math.max(0, i - ctx); k <= Math.min(diff.length - 1, i + ctx); k++) keep.add(k);
  });
  const out = [];
  let gap = false;
  diff.forEach((d, i) => {
    if (keep.has(i)) { out.push(d); gap = false; }
    else if (!gap) { out.push({ t: '@', text: '...' }); gap = true; }
  });
  return out;
}

const ACS_REFERENCES = [
  ['Red Hat ACS default security policies', 'https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.6/html/operating/default-security-policies'],
  ['Red Hat ACS managing security policies', 'https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.6/html/operating/managing-security-policies'],
  ['StackRox upstream default policy definitions', 'https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files'],
  ['CIS Kubernetes Benchmark', 'https://www.cisecurity.org/benchmark/kubernetes'],
  ['NIST SP 800-53 Rev 5', 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'],
  ['Kubernetes Pod Security Standards', 'https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
  ['DISA STIGs, Kubernetes and OpenShift', 'https://public.cyber.mil/stigs/downloads/'],
  ['CVSS v3.1 specification', 'https://www.first.org/cvss/v3.1/specification-document'],
];

function citationsOf(p) {
  const bits = [];
  if (p.cis && p.cis !== 'n/a') bits.push('CIS ' + p.cis);
  if (p.nist && p.nist !== 'n/a') bits.push('NIST 800-53: ' + p.nist);
  if (p.pss && p.pss !== 'n/a') bits.push('PSS: ' + p.pss);
  if (p.stig && p.stig !== 'n/a') bits.push('STIG: ' + p.stig);
  return bits;
}

/* Dual mode: plain script in the browser, CommonJS module under Node for the tests. */

/* ------------------------------------------------- recognising our own output
 *
 * The findings JSON this tool writes is derived output. Dropping it back in is a
 * reasonable thing to try, and the honest answer is no rather than a partial yes: the
 * findings carry a file name and an object name but not the manifest, so nothing could be
 * fixed from them and any posture recomputed from them would be a copy of the number
 * already in the file. What the file deserves is a message that says what it is and what
 * to load instead, not "expected Kubernetes or OpenShift objects", which describes
 * everything the file is not and none of what it is.
 */
function describeUnloadable(text) {
  let j;
  try { j = JSON.parse(text); } catch (e) { return null; }
  if (!j || typeof j !== 'object') return null;

  if (j.tool && j.findings && j.posture) {
    return 'This is a findings export written by ' + String(j.tool) + ' itself' +
      (j.generated ? ' on ' + String(j.generated).slice(0, 10) : '') + '.\n\n' +
      'It is a record of a previous run, not an input. It names the objects and the files ' +
      'they came from but does not contain the manifests, so nothing in it can be rescanned ' +
      'or fixed.\n\n' +
      'Load the sources instead: the YAML directory, the workloads export, ' +
      '02_alerts_full.json, and 03_vuln_workloads.ndjson.';
  }
  if (j.runs && j.version && String(j.version).indexOf('2.1') === 0) {
    return 'This is a SARIF file, which is a report format for a security tab in a CI ' +
      'system. It is output rather than input. Load the ACS exports or your YAML instead.';
  }
  if (j.kind === 'Status' && j.status === 'Failure') {
    return 'This is a Kubernetes API error, not data:\n\n  ' +
      String(j.message || j.reason || 'no message') + '\n\n' +
      'The command that produced it failed. Check the token, the namespace and the RBAC, ' +
      'then re-run the export.';
  }
  if (j.error || j.Error) {
    const e = j.error || j.Error;
    return 'This file contains an API error rather than data:\n\n  ' +
      String((e && (e.message || e.msg)) || e) + '\n\n' +
      'Re-run the export that produced it.';
  }
  if (Object.keys(j).length === 0) return 'This file is an empty JSON object. The export ' +
    'that produced it returned nothing, which usually means the search filter matched no ' +
    'records rather than that there is nothing to find.';
  return null;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ACS_VERSION: ACS_VERSION, ACS_TOOL: ACS_TOOL, wrapAt: wrapAt,
    violationKey: violationKey,
    describeUnloadable: describeUnloadable,
    ACS_TOOL, ACS_SEVERITY, ACS_POLICIES, WORKLOADS,
    sevLabel, sevWeight, sevRank,
    podSpec, containersOf, nameOf, nsOf,
    parseFileText, scanFiles, computePosture, policyApplies,
    matchPolicy, importAcsViolations, correlate, alertEntity, buildAlertQuery,
    PRIORITY_MAX,
    safeUrl, SAFE_URL_SCHEMES, tlsPreamble, curlFlags,
    PLATFORM_SCOPES, looksPlatform, PLATFORM_NS_RE,
    FIX_MODES, FIX_MODE_INFO, resolveFixMode, modeAllows, modeBanner,
    mergeAcsImports, mergeVulnImports,
    violationFixability, buildViolationPatch, buildViolationFixBundle,
    containerFromViolation, VIOLATION_PATCHES,
    normalizeBase, explainFetchError, fetchAcsAlerts, acsFallbackCommand,
    fetchOpenShiftWorkloads, openshiftFallbackCommand, sanitizeLiveObject, LIVE_KINDS,
    importKubeJson, looksLikeKubeObject,
    VULN_SEVERITY, vulnSeverity, vulnIsAccepted, parseVulnExport, imageRef, scoreVuln,
    importVulnFindings, summarizeVulns, correlateVulns, fetchVulnWorkloads,
    vulnFallbackCommand, applyImagePin, buildVulnWorklist,
    defaultDenyPolicy, findingKey, applyOneFix, dumpDocs, buildMergePatch,
    escHtml, anchor, buildHtmlReport, buildFindingsJson,
    diffLines, compactDiff, citationsOf, ACS_REFERENCES,
  };
}
