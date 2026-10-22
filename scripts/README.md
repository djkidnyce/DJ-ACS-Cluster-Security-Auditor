# scripts

Pull every finding ACS has, low to critical, from outside the browser.

| File | For |
|---|---|
| `acs_preflight.sh` | **Run this first.** Identifies which server you are talking to, tests the token, and lists what it can actually read. |
| `acs_pull_via_oc.sh` | Uses your existing `oc` session to find Central, tunnel to it, get the CA and pull the data. |
| `acs_pull_over_ssh.ps1` | PowerShell. Runs the commands on an SSH bastion and brings the output back. |
| `acs_pull_all.sh` | macOS, Linux, WSL, Git Bash. Written for bash 3.2 so it runs on a stock macOS shell. |
| `acs_pull_all.ps1` | Windows PowerShell and PowerShell 7. |
| `acs_rollout.sh` | After the fixes are applied: what is running, which revision it is on, what changed it, and the command to put it back. Prints commands, never runs them. |
| `acs_resources.sh` | What to set CPU and memory requests and limits to, measured rather than guessed. Thanos over fourteen days, or `oc adm top` sampled on a cron. Prints YAML, never applies it. |

## acs_resources.sh

ACS.013 and ACS.014 report a missing request or limit, and the automatic fix inserts a value
flagged PLACEHOLDER because the tool cannot know the right number. This produces the number.

```sh
./acs_resources.sh recommend -n prod            # Thanos first, samples as the fallback
./acs_resources.sh sample -n prod               # one sample, for cron
./acs_resources.sh report -n prod               # read the samples back
```

With monitoring access it queries Thanos for fourteen days of history and answers
immediately. Without it, sample on a schedule and read it back when the window has filled:

```sh
*/15 * * * * cd /path && ./acs_resources.sh sample -n prod >/dev/null 2>&1
```

Requests come from the 50th percentile, limits from the 99th times a headroom multiplier,
both editable at the top of the file.

**The memory limit is never left below the observed peak.** Memory is not compressible, so
exceeding the limit is an OOM kill rather than a slowdown, and a long tailed distribution can
put the 99th percentile well under the real maximum. With 99 samples at 100Mi and one at
800Mi, a naive p99 times headroom gives a 150Mi limit and the next spike kills the container.
The script clamps the limit above the peak and says it did.

CPU is different and the output treats it differently. Exceeding a CPU limit throttles rather
than kills, which is survivable but is its own outage for anything latency sensitive, so the
Thanos path also reads `container_cpu_cfs_throttled_periods_total` and tells you which
containers are **already being throttled** before you put a ceiling on them.

It also states the window and the observation count on every run, because a recommendation
from forty minutes of samples and one from a fortnight look identical once they are YAML. Under
a day of data it says so in the output.

## acs_rollout.sh

This is the one you reach for after applying fixes, when pods are in CrashLoopBackOff and
you need to know what to put back.

It never writes. Every call it makes is a read: `get`, `rollout history`. It does not run
`rollout undo`, `rollback`, `apply`, `patch`, `delete` or `scale`. It prints the commands
and you run the ones you want. The test suite drives it against a fake `oc` that refuses
every write verb and asserts none was ever issued, because on this script that promise is
the whole design rather than a nice property.

```sh
./acs_rollout.sh plan                       # start here
./acs_rollout.sh broken -n prod             # workloads with unhealthy pods, and why
./acs_rollout.sh touched                    # workloads the auditor changed, healthy or not
./acs_rollout.sh history -n prod deployment/api
./acs_rollout.sh snapshot -o ./rollback     # write the lot to files, reads only
./acs_rollout.sh undo -n prod deployment/api --to-revision 6
./acs_rollout.sh restore ./rollback/workloads.json -n prod cronjob/nightly
```

`broken` and `touched` answer different questions and the difference matters. `broken` is
triage by symptom whatever the cause, so it includes workloads this tool never touched.
`touched` reads the `acs-auditor/applied` annotation, so it includes a workload that took a
bad fix and has not restarted yet. `plan` prints both and calls out the overlap, which is
where to start.

It handles Deployment, StatefulSet, DaemonSet and DeploymentConfig, and does not pretend
they roll back the same way. Deployments, StatefulSets and DaemonSets take
`oc rollout undo`. A DeploymentConfig takes `oc rollback` with `--to-version`, and printing
the wrong verb for one is worse than printing nothing because it looks authoritative and
fails at the worst moment.

`restore` is for the kinds with no rollout at all, CronJobs and Jobs, and for a workload
whose old revisions `revisionHistoryLimit` already pruned. It reads a capture rather than
the cluster, strips the fields the server owns, and needs no `oc` on PATH, which is the
point: it has to work on the machine that cannot reach the cluster.

Two things about revisions that cost people time:

A rollback does not delete revisions. It creates a new one carrying the old spec, so the
numbers keep climbing and the revision you rolled back from is still there. Roll back from
7 to 3 and you get an 8 that looks like 3.

`revisionHistoryLimit` defaults to 10 and prunes silently. `--to-revision` on a revision
that has been pruned answers `unable to find specified revision in history`, and no flag
brings it back. That is what `snapshot` is for: capture the history while it still exists.

## PowerShell through an SSH bastion

The usual federal shape: your workstation cannot reach the cluster, a bastion can.

```powershell
# workloads only, no ACS needed
.\acs_pull_over_ssh.ps1 -JumpHost dj@bastion.example.com -Mode workloads

# everything
$env:ROX_API_TOKEN = '<ACS token>'
.\acs_pull_over_ssh.ps1 -JumpHost dj@bastion -Mode all -Namespace prod

# then, locally
node ..\acs_cli.js --workloads acs_ssh_*\workloads.json --vulns acs_ssh_*\vuln_workloads.ndjson --report
```

`oc` and `curl` run on the bastion, which needs its own `oc login`. This script will not
forward cluster credentials for you. The report is built locally.

**The ACS token goes over stdin, never as an argument.** An ssh command line is visible in
`ps` to every user on the bastion and lands in the remote shell history. The remote script
starts with `read -r ROX_API_TOKEN`, so the value only ever exists in that process.

Alerts are hydrated on the bastion rather than shipped as a bare list, because
`/v1/alerts` has no violation text in it. That needs `jq` on the bastion; without it the
script says so and returns the un-hydrated list rather than pretending.

## Can I just use oc?

Not for the data itself. `oc` talks to the Kubernetes API server, and ACS findings are
not Kubernetes objects. There is no CRD holding CVEs. The ACS operator installs `Central`
and `SecuredCluster` custom resources and both are install configuration:
`oc get central -o yaml` returns replica counts, exposure settings and a version, never a
finding. Verified against `operator/api/v1alpha1/central_types.go`.

`oc` is still the right tool for everything around the call, which is what
`acs_pull_via_oc.sh` automates:

| What oc gives you | Command |
|---|---|
| Which namespace ACS is in | `oc get central --all-namespaces` |
| The route | `oc -n stackrox get route central -o jsonpath='{.spec.host}'` |
| A tunnel when the route is unreachable | `oc -n stackrox port-forward svc/central 18443:443` |
| The CA, so TLS verification works | `oc -n stackrox get secret central-tls -o jsonpath='{.data.ca\.pem}' \| base64 -d` |
| The admin password | `oc -n stackrox get secret central-htpasswd -o jsonpath='{.data.password}' \| base64 -d` |

```sh
export ROX_API_TOKEN=<ACS token>      # or pass --admin to use central-htpasswd
./acs_pull_via_oc.sh -q 'Namespace:prod'
```

**`oc whoami -t` will not authenticate you to ACS.** It is an OpenShift token and ACS
does not accept it for its API. Use an ACS API token, or `--admin`.

Two things that script handles which bite people doing it by hand:

* Through a port forward the hostname will not match the certificate. It pins with
  `--resolve central.<ns>.svc` against the CA from the secret, rather than reaching
  for `-k` on a connection carrying a credential.
* It adds `--noproxy` for the tunnel. The moment the URL stops being `127.0.0.1`, curl
  consults `HTTPS_PROXY` and tries to CONNECT through the corporate proxy to a name that
  only exists inside the cluster. It fails with `403 from proxy after CONNECT`, which
  reads like an authentication problem and is not one. This bites hardest in federal and
  enterprise networks, where a proxy is always set.

## Start here if anything is not working

```sh
export ROX_API_TOKEN=<token>
./acs_preflight.sh https://central-stackrox.apps.<cluster>
```

ACS Central and the OpenShift API server are two different servers with two different
token systems, and they are easy to confuse because both live on the same cluster and
both take a bearer token.

| | OpenShift API | ACS Central |
|---|---|---|
| URL | `https://api.<cluster>:6443` | `https://central-stackrox.apps.<cluster>` (443) |
| Paths look like | `/apis/user.openshift.io/v1/users/~` | `/v1/export/vuln-mgmt/workloads` |
| Token from | `oc whoami -t` | ACS console, Platform Configuration, Integrations, Authentication Tokens |

If you are seeing `/apis/user.openshift.io/...` you are on the cluster API. ACS endpoints
do not exist there. Find the real one with:

```sh
oc get route central -n stackrox -o jsonpath='{.spec.host}'
```

The preflight also catches the permission trap: a token scoped only to `Alert` passes
authentication, works fine on `/v1/alerts`, and returns 403 on the vulnerability export.
Without checking the status code that reads as "no vulnerabilities".

```bash
export ROX_ENDPOINT=https://central-stackrox.apps.example.com
export ROX_API_TOKEN=<token>       # never pass this as an argument
./acs_pull_all.sh -o findings
```

```powershell
$env:ROX_ENDPOINT  = 'https://central-stackrox.apps.example.com'
$env:ROX_API_TOKEN = '<token>'
.\acs_pull_all.ps1 -OutDir findings
```

## Why a script and not one curl

There is no single endpoint that returns everything. ACS keeps policy violations and
vulnerability data in different stores, reached by different endpoints, returning
different document shapes. A sweep has to hit all of them.

| Output | Endpoint | Why it is separate |
|---|---|---|
| `01_alerts_list.json` | `GET /v1/alerts` | Policy violations, paged. `storage.ListAlert`, so **no violation text**. |
| `02_alerts_full.json` | `GET /v1/alerts/{id}` | The same alerts hydrated. **This is the one to use.** |
| `03_vuln_workloads.ndjson` | `GET /v1/export/vuln-mgmt/workloads` | Image CVEs for running workloads. |
| `04_all_images.ndjson` | `GET /v1/export/images` | Every image Central knows, including ones with no running deployment. Store 3 misses those. |
| `05_nodes.ndjson` | `GET /v1/export/nodes` | Node CVEs. Neither of the above carries them. |
| `06_snoozed.ndjson` | `GET /v1/export/images?query=CVE Snoozed:true` | Deferred and snoozed CVEs, excluded from the default views. |

## How "everything" is actually achieved

**By leaving filters out, not by adding them.** There is no severity term, no
`Violation State` term and no `Lifecycle Stage` term in the query. Omitting a term
returns every value for it. Adding `Severity:LOW_SEVERITY,...,CRITICAL_SEVERITY`
would look more thorough and be strictly worse: it silently drops anything ACS
introduces later.

Note this differs from the ACS console, which defaults to active violations only.
A full sweep returns `ACTIVE`, `RESOLVED` and `ATTEMPTED`, so your totals will be
higher than the console. That is correct, not a bug.

**Pagination is a loop, not a big number.** ACS applies a server side page size. The
script pages until a short page comes back, and compares the total against
`/v1/alertscount` so a partial answer is reported rather than presented as complete.

## Security notes

* **TLS verification is on by default.** The token is effectively read access to your
  entire security posture; disabling verification hands it to anyone on the path.
  In bash use `--cacert <file>` with your internal CA. PowerShell uses the Windows
  certificate store, so import the CA there rather than passing a file. `--insecure`
  and `-Insecure` exist for lab use and warn loudly.
* **The token is never an argument.** It comes from the environment, and the bash
  version writes it to a mode 600 header file rather than a command line, because
  arguments are visible in `ps` to every user on the box.
* **Every call is a GET.** Nothing is written to a cluster. Nothing is applied.
* **Detail fetching is bounded** (`-j`, default 4 concurrent). Central is a security
  control. Do not flood it for the sake of a report.

## The token needs more than Alert access

A token scoped only to `Alert` gets a clean run on steps 1 and 2 and a `403` on
step 3, which reads as "no vulnerabilities" if you are not watching. The vulnerability
exports need read on **Image** and **Deployment**. An Analyst role covers it.

## Verified against

Endpoint paths, query syntax and response shapes were taken from the upstream
StackRox protocol definitions, not inferred from behaviour:
`api/v1/alert_service.proto`, `api/v1/pagination.proto`, `storage/alert.proto`,
`api/v1/vuln_mgmt_service.proto`, `api/v1/image_service.proto`,
`api/v1/node_service.proto`, `storage/image.proto`, `storage/vulnerability.proto`,
`storage/cve.proto`. Confirm against your own ACS version before relying on them.

Platform and cluster CVEs (Kubernetes, Istio, OpenShift components) are **not**
covered here. In current ACS those are reached through the GraphQL API rather than a
documented REST export, and this script does not guess at an endpoint it has not
verified.


## acs_summary.sh

Summarise a pull directory without Node.

```bash
./acs_summary.sh findings/acs_findings_20260821_143022 -o findings.md
```

Needs jq and nothing else. It exists because Node cannot be installed everywhere, and a
hardened host in a controlled enclave is exactly the machine where curl and jq are all you
get.

It reports what ACS said: violations by severity, policy and namespace, the split between
your workloads and platform components, how many arrived with no `platformComponent` field
at all, CVEs by Red Hat severity, how many have a published fix, and the images to rebuild
ranked by critical count.

It does not compute a posture score and does not draft fixes. Both need the policy engine.
A score is measured over scanned manifests, and this script has no manifests and no
scanner, so any number it printed would be invented. It says as much in its own output and
points at the page, which needs a browser and no runtime.
