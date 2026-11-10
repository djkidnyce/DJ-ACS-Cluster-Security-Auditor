#!/usr/bin/env bash
#
# acs_rollout.sh  --  see what is running, which revision it is on, what changed it, and
# what the command to put it back would be.
#
# IT NEVER WRITES. Every call it makes is a read: get, describe, rollout history. It does
# not run rollout undo, rollback, apply, patch, delete or scale. It prints the commands and
# you run the ones you want. That is the same promise the rest of this tool makes, and here
# it matters more than anywhere else: this script's whole job is deciding what to revert,
# and a script that acts on its own guess is one bad guess away from taking out a workload
# that was fine.
#
# WHY THIS EXISTS
#
#   After a batch of fixes lands you have pods in CrashLoopBackOff and
#   CreateContainerConfigError and no list of what was touched. oc rollout history prints a
#   CHANGE-CAUSE column that is almost always <none>, so the revisions tell you nothing
#   about which one carried which change. Since 1.8.0 the auditor writes that column, and
#   writes a matching annotation onto the pod template so it travels into the ReplicaSet or
#   ControllerRevision for that revision. This script reads both back.
#
#   It was previously a page of jq pasted into a terminal, which is how a quote gets eaten
#   and jq answers "null (null) cannot be negated" at three in the morning. A file cannot be
#   mangled by a paste.
#
# SUBCOMMANDS
#
#   history [-n NS] [KIND/NAME]
#       Revision history for one workload or for everything in scope, with the change cause
#       and the auditor reference against each revision.
#
#   broken [-n NS]
#       Every workload with at least one unhealthy pod, why, and the command to put it back
#       one revision. Triage by symptom, whatever the cause.
#
#   touched [-n NS]
#       Every workload carrying an auditor annotation, healthy or not. This is the blast
#       radius rather than the symptom list: a workload that took a bad fix and has not
#       restarted yet is on this list and not on the other one.
#
#   plan [-n NS]
#       Both of the above in one pass, labelled separately, with the overlap called out.
#
#   snapshot [-n NS] [-o DIR]
#       Write the lot to files so it can be read on a machine that cannot reach the
#       cluster, or kept with the change ticket. Reads only.
#
#   undo -n NS KIND/NAME [--to-revision N]
#       Print the command. Prints nothing else and runs nothing.
#
#   restore FILE -n NS KIND/NAME
#       Print one object out of an earlier capture, stripped of the fields the server owns,
#       so it can be applied. For CronJobs and Jobs and anything else with no rollout to
#       undo, and for a workload whose old revisions revisionHistoryLimit already pruned.
#       FILE is a snapshot workloads.json, or the workloads.json captured beside your ACS
#       findings.
#
# WHAT IT COVERS
#   Deployment and DeploymentConfig, StatefulSet and DaemonSet. They do not roll back the
#   same way and the script does not pretend they do: Deployments and StatefulSets and
#   DaemonSets take oc rollout undo, DeploymentConfigs take oc rollback, Deployments keep
#   ReplicaSets and StatefulSets and DaemonSets keep ControllerRevisions, and a
#   DeploymentConfig keeps ReplicationControllers.
#
# REQUIREMENTS
#   oc (or kubectl, see OC below) and jq.
#
# WRITTEN FOR bash 3.2 and for /bin/sh. No mapfile, no associative arrays, no process
# substitution, no bash only parameter expansion. This project has already shipped a script
# that worked under bash and silently dropped arguments under dash.
set -eu

ANNOT="acs-auditor/applied"
OC="${OC:-oc}"
NS=""
ALL_NS=1
OUTDIR=""
TO_REV=""
RESTORE_FILE=""
DRIFT_ALL=0

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "$1 not found on PATH." >&2
  # $* here is the arguments of need, not of the script, which made this line suggest
  # running the script with the name of the missing binary as its subcommand.
  if [ "$1" = "$OC" ]; then
    echo "If you use kubectl instead of oc, set OC=kubectl and run it again." >&2
  fi
  exit 2
}

# Real help, rather than the file's own comment header.
#
# This used to be `sed -n '2,50p' "$0"`, which printed the top of this file complete with
# the leading hash marks. Run with no subcommand, it looked exactly like a script that had
# failed to execute and echoed its source instead, and that is precisely how it was
# reported. The hardcoded line range had also gone stale: the header grew past line 50 when
# restore was added, so the last subcommand was cut off mid sentence. A fixed line number
# pointing into a file that grows is the same trap as indexing a table column by position.
usage() {
  cat <<'TXT'
acs_rollout.sh  --  what is running, which revision it is on, what changed it, and the
command to put it back.

IT PRINTS COMMANDS. IT NEVER RUNS THEM. Every call it makes is a read.

USAGE
  acs_rollout.sh <subcommand> [options]

SUBCOMMANDS
  plan                     broken workloads, auditor touched workloads, and the overlap
  broken                   workloads with unhealthy pods, why, and how to go back
  touched                  workloads carrying an auditor annotation, healthy or not
  drift                    hardening an earlier revision had and the running one does not
  history [KIND/NAME]      revision history, with the change cause against each revision
  snapshot                 write the lot to files, readable where the cluster is not
  undo KIND/NAME           print the rollback command for one workload
  restore FILE KIND/NAME   print one object from a capture, ready for you to apply

OPTIONS
  -n, --namespace NS       one namespace. Omit it for every namespace
  -o, --out DIR            where snapshot writes. Default acs_rollout_<timestamp>
      --to-revision N      target revision, for undo
      --all                for drift: every workload, not only annotated ones
  -h, --help               this text

EXAMPLES
  acs_rollout.sh plan
  acs_rollout.sh broken -n prod
  acs_rollout.sh touched -n prod
  acs_rollout.sh drift -n prod
  acs_rollout.sh drift -n prod --all
  acs_rollout.sh history -n prod deployment/payments-api
  acs_rollout.sh snapshot -o ./rollback
  acs_rollout.sh undo -n prod deployment/payments-api --to-revision 6
  acs_rollout.sh restore ./rollback/workloads.json -n prod cronjob/nightly

ENVIRONMENT
  OC                       cluster client. Default oc. Set OC=kubectl to use kubectl

Deployment, StatefulSet and DaemonSet take oc rollout undo. DeploymentConfig takes
oc rollback. This prints whichever is right for the kind in front of it.
TXT
  echo
  echo "Why each subcommand exists, at length, is in the comment header of this file:"
  echo "  less $0"
  exit "${1:-2}"
}

CMD="${1:-}"
[ -n "$CMD" ] || usage
case "$CMD" in
  -h|--help|help) usage 0 ;;
esac
shift || true

TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="${2:-}"; ALL_NS=0; shift 2 || usage ;;
    -o|--out)       OUTDIR="${2:-}"; shift 2 || usage ;;
    --to-revision)  TO_REV="${2:-}"; shift 2 || usage ;;
    --all)          DRIFT_ALL=1; shift ;;
    -h|--help)      usage 0 ;;
    -*)             echo "Unknown option: $1" >&2; usage ;;
    *)
      if [ "$CMD" = "restore" ] && [ -z "$RESTORE_FILE" ]; then
        RESTORE_FILE="$1"
      else
        TARGET="$1"
      fi
      shift ;;
  esac
done

need jq
# restore reads a file that was captured earlier. Demanding a cluster client for it would
# make the one subcommand meant for a machine that cannot reach the cluster the one
# subcommand that refuses to run there.
case "$CMD" in
  restore) : ;;
  *) need "$OC" ;;
esac

# Namespace arguments for a read. Built once, quoted at the point of use.
if [ "$ALL_NS" -eq 1 ]; then NSARGS="--all-namespaces"; else NSARGS="-n $NS"; fi

# Every kind that has a rollout, and how each one is put back. Kept as one string rather
# than an associative array so this runs on bash 3.2 and on dash.
#   kind|undo verb|what holds its old revisions
KINDS='deployment|rollout undo|ReplicaSet
statefulset|rollout undo|ControllerRevision
daemonset|rollout undo|ControllerRevision
deploymentconfig|rollback|ReplicationController'

undo_verb() {
  echo "$KINDS" | while IFS='|' read -r k verb _hold; do
    [ "$k" = "$1" ] && { echo "$verb"; break; }
  done
}

history_holder() {
  echo "$KINDS" | while IFS='|' read -r k _verb hold; do
    [ "$k" = "$1" ] && { echo "$hold"; break; }
  done
}

lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

# A pod with no controller behind it has no rollout and no previous revision. Offering
# "oc rollout history pod/x" for one is worse than saying nothing: it reads as a real
# instruction and answers with an error that sends somebody looking for the wrong problem.
has_rollout() {
  case "$(lower "$1")" in
    deployment|statefulset|daemonset|deploymentconfig|dc) return 0 ;;
    *) return 1 ;;
  esac
}

# The command that puts ONE workload back, printed rather than run. A DeploymentConfig does
# not take rollout undo, and printing the wrong verb for it is worse than printing nothing:
# it looks authoritative and fails at the worst moment.
undo_command() {
  _ns="$1"; _kind="$(lower "$2")"; _name="$3"; _rev="${4:-}"
  case "$_kind" in
    deploymentconfig|dc)
      if [ -n "$_rev" ]; then
        echo "$OC rollback dc/$_name --to-version=$_rev -n $_ns"
      else
        echo "$OC rollback dc/$_name -n $_ns"
      fi
      ;;
    deployment|statefulset|daemonset)
      if [ -n "$_rev" ]; then
        echo "$OC rollout undo $_kind/$_name -n $_ns --to-revision=$_rev"
      else
        echo "$OC rollout undo $_kind/$_name -n $_ns"
      fi
      ;;
    *)
      echo "no rollout to undo"
      ;;
  esac
}

# ---------------------------------------------------------------- reading the cluster
#
# One get for the workloads and one for the pods and their owners, rather than one per
# workload. A cluster with four hundred deployments is a normal cluster, and four hundred
# sequential round trips is a script somebody kills halfway through.

get_workloads() {
  # Kinds that do not exist on a plain Kubernetes cluster make the whole get fail, so
  # DeploymentConfig is asked for separately and its absence is not an error.
  $OC get deployment,statefulset,daemonset $NSARGS -o json 2>/dev/null || echo '{"items":[]}'
}

get_dcs() {
  $OC get deploymentconfig $NSARGS -o json 2>/dev/null || echo '{"items":[]}'
}

get_pods_and_owners() {
  $OC get pods,replicasets,replicationcontrollers $NSARGS -o json 2>/dev/null || echo '{"items":[]}'
}

# Every field is treated as possibly absent. A triage script that throws on one odd object
# is useless exactly when it is needed, which is while something is on fire.
WORKLOAD_JQ='
  [ .items[]? | . as $w
    | ($w.metadata // {}) as $m
    | ($w.spec.template.metadata.annotations // {}) as $ta
    | { ns:       ($m.namespace // "?"),
        kind:     ($w.kind // "?"),
        name:     ($m.name // "?"),
        revision: (($m.annotations // {})["deployment.kubernetes.io/revision"] // ""),
        cause:    (($m.annotations // {})["kubernetes.io/change-cause"] // ""),
        stamp:    ($ta[$ANNOT] // ""),
        ready:    (($w.status.readyReplicas // $w.status.numberReady // 0)),
        want:     (($w.spec.replicas // $w.status.desiredNumberScheduled // 0)) } ]'

# A pod knows its owner but not its workload. A Deployment owns a ReplicaSet which owns the
# pod, and a DeploymentConfig owns a ReplicationController which owns the pod, so the
# middle object has to be resolved or every broken pod reports its ReplicaSet and you are
# left doing the mapping by eye at the worst possible time.
BROKEN_JQ='
  ([ .items[]? | select((.kind // "") == "ReplicaSet" or (.kind // "") == "ReplicationController")
     | { key: ((.metadata.namespace // "?") + "/" + (.metadata.name // "?")),
         value: (((.metadata.ownerReferences // [])[0]) // null) } ] | from_entries) as $owners
  | [ .items[]? | select((.kind // "") == "Pod") | . as $p
      | ($p.status.containerStatuses // []) as $cs
      | ($cs | map(select((.ready // false) == false))) as $bad
      | select(($bad | length) > 0)
      | (($p.metadata.ownerReferences // [])[0] // null) as $own
      | (if $own == null then null
         elif ($own.kind == "ReplicaSet" or $own.kind == "ReplicationController")
         then ($owners[(($p.metadata.namespace // "?") + "/" + ($own.name // ""))] // null)
         else $own end) as $work
      | { ns:    ($p.metadata.namespace // "?"),
          pod:   ($p.metadata.name // "?"),
          kind:  (($work.kind // $own.kind) // "Pod"),
          name:  (($work.name // $own.name) // ($p.metadata.name // "?")),
          why:   ([ $bad[] | ((.state.waiting.reason // .state.terminated.reason // "NotReady")
                   + (if (.state.waiting.message // .state.terminated.message // "") != ""
                      then ": " + ((.state.waiting.message // .state.terminated.message)
                                   | split("\n")[0] | .[0:160])
                      else "" end)) ] | unique | join("; ")),
          restarts: ([ $bad[] | (.restartCount // 0) ] | max) } ]
  | group_by(.ns + "/" + .kind + "/" + .name)
  | [ .[] | { ns: .[0].ns, kind: .[0].kind, name: .[0].name,
              pods: (. | length),
              restarts: ([ .[].restarts ] | max),
              why: ([ .[].why ] | unique | join(" | ")) } ]'

workloads_json() {
  { get_workloads; get_dcs; } | jq -s --arg ANNOT "$ANNOT" \
    '{items: (map(.items // []) | add)}' | jq --arg ANNOT "$ANNOT" "$WORKLOAD_JQ"
}

broken_json() { get_pods_and_owners | jq "$BROKEN_JQ"; }

# ---------------------------------------------------------------- output helpers

rule() { echo "------------------------------------------------------------------------"; }

# The reference the auditor wrote, or an honest blank. An empty change cause is not a sign
# that nothing happened, it is a sign that whatever happened did not say so, and those are
# different claims.
say_stamp() {
  if [ -n "$1" ]; then echo "    changed by: $1"
  else echo "    changed by: not recorded (no auditor annotation on this workload)"; fi
}

print_history() {
  _ns="$1"; _kind="$(lower "$2")"; _name="$3"
  echo "  $_kind/$_name in $_ns"
  case "$_kind" in
    deploymentconfig|dc)
      $OC rollout history dc/"$_name" -n "$_ns" 2>&1 | sed 's/^/    /' || true
      ;;
    *)
      $OC rollout history "$_kind/$_name" -n "$_ns" 2>&1 | sed 's/^/    /' || true
      ;;
  esac
}

# ---------------------------------------------------------------- subcommands

cmd_history() {
  if [ -n "$TARGET" ]; then
    _kind="$(lower "${TARGET%%/*}")"; _name="${TARGET#*/}"
    [ "$_kind" != "$_name" ] || { echo "Give it as KIND/NAME, for example deployment/api" >&2; exit 2; }
    [ "$ALL_NS" -eq 0 ] || { echo "history for one workload needs -n NAMESPACE" >&2; exit 2; }
    print_history "$NS" "$_kind" "$_name"
    echo
    echo "  To put it back one revision:"
    echo "    $(undo_command "$NS" "$_kind" "$_name")"
    echo "  To a specific one:"
    echo "    $(undo_command "$NS" "$_kind" "$_name" N)"
    return 0
  fi
  echo "Revision history for every workload in scope."
  echo
  workloads_json | jq -r '.[] | [.ns, (.kind|ascii_downcase), .name, .revision, .stamp] | @tsv' |
  while IFS="$(printf '\t')" read -r ns kind name rev stamp; do
    rule
    echo "  $kind/$name in $ns${rev:+   (current revision $rev)}"
    say_stamp "$stamp"
    print_history "$ns" "$kind" "$name" | sed '1d'
  done
}

cmd_broken() {
  echo "Workloads with at least one unhealthy pod."
  echo "Whatever the cause. Not every one of these was touched by the auditor."
  echo
  _rows="$(broken_json | jq -r '.[] | [.ns, (.kind|ascii_downcase), .name, (.pods|tostring), (.restarts|tostring), .why] | @tsv')"
  if [ -z "$_rows" ]; then
    echo "  Every pod is ready. Nothing here needs rolling back."
    return 0
  fi
  printf '%s\n' "$_rows" |
  while IFS="$(printf '\t')" read -r ns kind name pods restarts why; do
    rule
    echo "  $kind/$name in $ns"
    echo "    unhealthy pods: $pods, restarts: $restarts"
    echo "    why: $why"
    if has_rollout "$kind"; then
      echo "    see what the revisions are first:"
      echo "      $OC rollout history $kind/$name -n $ns"
      echo "    then put it back one revision:"
      echo "      $(undo_command "$ns" "$kind" "$name")"
    else
      echo "    nothing owns this pod, so there is no revision to go back to."
      echo "    Reapply it from a capture:"
      echo "      $0 restore <workloads.json> -n $ns pod/$name"
      echo "    or delete it and let whatever should own it recreate it. Find out why it"
      echo "    is unowned before either."
    fi
  done
  return 0
}

cmd_touched() {
  echo "Workloads carrying an auditor annotation."
  echo "This is the blast radius rather than the symptom list. A workload that took a bad"
  echo "fix and has not restarted yet is here and not in the broken list."
  echo
  workloads_json | jq -r '.[] | select(.stamp != "") | [.ns, (.kind|ascii_downcase), .name, .stamp, (.ready|tostring), (.want|tostring)] | @tsv' |
  while IFS="$(printf '\t')" read -r ns kind name stamp ready want; do
    rule
    echo "  $kind/$name in $ns"
    echo "    changed by: $stamp"
    echo "    ready: $ready of $want"
    echo "    put it back one revision:"
    echo "      $(undo_command "$ns" "$kind" "$name")"
  done
  echo
  echo "The reference after the version resolves to a row in the READ_THIS_FIRST.md that"
  echo "came with the corrected YAML. That row says which policies were applied and which"
  echo "of them can stop a workload."
}

cmd_plan() {
  cmd_broken
  echo
  cmd_touched
  echo
  rule
  echo "Overlap"
  _tmp="$(mktemp "${TMPDIR:-/tmp}/acs_rollout.XXXXXX")"
  trap 'rm -f "$_tmp"' EXIT INT TERM
  workloads_json | jq -r '.[] | select(.stamp != "") | (.ns + "/" + (.kind|ascii_downcase) + "/" + .name)' | sort > "$_tmp"
  _both=""
  if [ -s "$_tmp" ]; then
    _both="$(broken_json | jq -r '.[] | (.ns + "/" + (.kind|ascii_downcase) + "/" + .name)' | sort | grep -Fxf "$_tmp" || true)"
  fi
  rm -f "$_tmp"
  if [ -n "$_both" ]; then
    echo "  Broken AND touched by the auditor. Start here:"
    printf '%s\n' "$_both" | sed 's/^/    /'
  else
    echo "  Nothing is both broken and annotated by the auditor."
    echo "  If workloads are broken, look for another cause before rolling anything back."
  fi
}

cmd_snapshot() {
  _dir="${OUTDIR:-acs_rollout_$(date -u +%Y%m%d-%H%M%S)}"
  mkdir -p "$_dir"
  echo "Writing to $_dir. Reads only." >&2

  get_workloads > "$_dir/workloads.json"
  get_dcs       > "$_dir/deploymentconfigs.json"
  get_pods_and_owners > "$_dir/pods_and_owners.json"
  workloads_json > "$_dir/index.json"
  broken_json    > "$_dir/broken.json"

  # The per workload histories, because rollout history is the one thing that cannot be
  # reconstructed from the object later: the old ReplicaSets it reads are pruned by
  # revisionHistoryLimit, which defaults to 10, and they go without warning.
  : > "$_dir/history.txt"
  workloads_json | jq -r '.[] | [.ns, (.kind|ascii_downcase), .name] | @tsv' |
  while IFS="$(printf '\t')" read -r ns kind name; do
    {
      echo "=== $kind/$name in $ns"
      $OC rollout history "$kind/$name" -n "$ns" 2>&1 || true
      echo
    } >> "$_dir/history.txt"
  done

  { cmd_plan; } > "$_dir/plan.txt" 2>&1 || true
  { cmd_drift; } > "$_dir/drift.txt" 2>&1 || true

  cat > "$_dir/READ_ME.txt" <<TXT
Rollout snapshot taken $(date -u +"%Y-%m-%d %H:%M:%SZ") by acs_rollout.sh.

Nothing here was written to a cluster. Every file is the result of a read.

  index.json            one row per workload: namespace, kind, name, current revision,
                        change cause, and the auditor annotation if it carries one
  history.txt           oc rollout history for each workload, captured now because the
                        old revisions behind it are pruned by revisionHistoryLimit
                        (default 10) and go without warning
  broken.json           workloads with unhealthy pods, and why
  plan.txt              the broken list and the auditor touched list, and their overlap
  workloads.json        the raw objects
  deploymentconfigs.json
  pods_and_owners.json  pods with the ReplicaSets and ReplicationControllers needed to
                        map a broken pod back to the workload that owns it

The commands in plan.txt are printed, not run. Read them before running any of them.

A rollback does not delete revisions, it creates a new one that carries the old spec, so
the numbers keep climbing and the revision you rolled back FROM is still in the history.
TXT
  echo "$_dir"
}

cmd_undo() {
  [ -n "$TARGET" ] || { echo "undo needs KIND/NAME, for example deployment/api" >&2; exit 2; }
  [ "$ALL_NS" -eq 0 ] || { echo "undo needs -n NAMESPACE" >&2; exit 2; }
  _kind="$(lower "${TARGET%%/*}")"; _name="${TARGET#*/}"
  [ "$_kind" != "$_name" ] || { echo "Give it as KIND/NAME, for example deployment/api" >&2; exit 2; }

  echo "# Read this before running it. This script does not run it for you."
  echo "#"
  echo "# What it is on now:"
  print_history "$NS" "$_kind" "$_name" | sed 's/^/# /'
  echo "#"
  echo "# The command:"
  undo_command "$NS" "$_kind" "$_name" "$TO_REV"
  echo
  echo "# After it runs, watch it rather than assuming:"
  if [ "$_kind" = "deploymentconfig" ] || [ "$_kind" = "dc" ]; then
    echo "#   $OC rollout status dc/$_name -n $NS"
  else
    echo "#   $OC rollout status $_kind/$_name -n $NS --timeout=120s"
  fi
  echo "#   $OC get pods -n $NS | grep $_name"
  echo "#"
  echo "# If it answers 'unable to find specified revision in history', that revision was"
  echo "# pruned by revisionHistoryLimit, which defaults to 10. It is gone from the cluster."
  echo "# Reapply the manifest instead."
}

# The fields a server owns. Applying an object with these still on it either fails or
# resurrects state that belonged to a different instance of the object. status is the one
# that looks harmless and is not: it is a report about a thing that no longer exists.
CLEAN_JQ='
  del(.metadata.uid, .metadata.resourceVersion, .metadata.generation,
      .metadata.creationTimestamp, .metadata.managedFields, .metadata.selfLink,
      .metadata.ownerReferences, .status)
  | del(.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"],
        .metadata.annotations["deployment.kubernetes.io/revision"])'

PICK_JQ='[ (.items // [.])[]
  | select(((.kind // "") | ascii_downcase) == $kind)
  | select((.metadata.namespace // "") == $ns)
  | select((.metadata.name // "") == $name) ]'

cmd_restore() {
  [ -n "$RESTORE_FILE" ] || { echo "restore needs a capture file" >&2; exit 2; }
  [ -f "$RESTORE_FILE" ] || { echo "no such file: $RESTORE_FILE" >&2; exit 2; }
  [ -n "$TARGET" ] || { echo "restore needs KIND/NAME" >&2; exit 2; }
  [ "$ALL_NS" -eq 0 ] || { echo "restore needs -n NAMESPACE" >&2; exit 2; }
  _kind="$(lower "${TARGET%%/*}")"; _name="${TARGET#*/}"
  [ "$_kind" != "$_name" ] || { echo "Give it as KIND/NAME, for example cronjob/nightly" >&2; exit 2; }

  _n="$(jq --arg ns "$NS" --arg kind "$_kind" --arg name "$_name" "$PICK_JQ | length" "$RESTORE_FILE" 2>/dev/null || echo 0)"
  if [ "$_n" = "0" ]; then
    echo "Not in that file: $_kind/$_name in $NS" >&2
    echo "What it does hold:" >&2
    jq -r '[ (.items // [.])[] | ((.metadata.namespace // "?") + " " + ((.kind // "?")|ascii_downcase) + "/" + (.metadata.name // "?")) ] | sort | .[]' "$RESTORE_FILE" 2>/dev/null | sed 's/^/  /' >&2 || true
    exit 1
  fi

  echo "# $_kind/$_name in $NS, out of $RESTORE_FILE, server owned fields removed."
  echo "# Read it before applying it. Nothing here has been applied for you."
  echo "#"
  echo "#   $OC apply -f this-file.yaml"
  echo "#"
  echo "# This replaces the whole object. Anything other than this tool that changed it"
  echo "# since the capture gets replaced too."
  jq --arg ns "$NS" --arg kind "$_kind" --arg name "$_name" "$PICK_JQ[0] | $CLEAN_JQ" "$RESTORE_FILE"
}


# ---------------------------------------------------------------- drift
#
# A fix that was applied and then overwritten looks exactly like a fix that was never
# applied: the finding is back, the YAML on disk is correct, and the annotation is still
# sitting on the object because whatever replaced the template wrote its own.
#
# This does not try to work out which policies you applied. It cannot: the annotation
# records a run, not a list of policies, so reading hardening out of it would be a guess,
# and a guess here reports drift on a policy you deliberately left alone.
#
# It compares the live pod template against the template kept in every historical revision
# instead. A property that is satisfied in some earlier revision and not in the current one
# was lost, and the cluster is the evidence. Nothing is inferred and nothing is assumed
# about intent.
#
# One get per kind for the whole scope rather than one per workload, for the same reason
# the rest of this file works that way.
PROFILE_JQ='
  def conts: ((.containers // []) + (.initContainers // []));
  def capdrop: ((.securityContext.capabilities.drop // []) | map(ascii_upcase | sub("^CAP_";"")));
  def profile:
    . as $ps | ($ps | conts) as $cs |
    { "ACS.013 cpu request":    ($cs | all((.resources.requests.cpu // "") != "")),
      "ACS.013 cpu limit":      ($cs | all((.resources.limits.cpu // "") != "")),
      "ACS.014 memory request": ($cs | all((.resources.requests.memory // "") != "")),
      "ACS.014 memory limit":   ($cs | all((.resources.limits.memory // "") != "")),
      "ACS.001 not privileged": ($cs | all((.securityContext.privileged // false) != true)),
      "ACS.002 read only root": ($cs | all((.securityContext.readOnlyRootFilesystem // false) == true)),
      "ACS.003 no privilege escalation": ($cs | all((.securityContext.allowPrivilegeEscalation // true) == false)),
      "ACS.008 drops ALL capabilities":  ($cs | all(capdrop | index("ALL") != null)),
      "ACS.009 runs as non root": ((($ps.securityContext.runAsNonRoot // false) == true)
                                   or ($cs | all((.securityContext.runAsNonRoot // false) == true))),
      "ACS.016 no token automount": (($ps.automountServiceAccountToken // true) == false),
      "ACS.019 no privileged host port": ($cs | all(((.ports // []) | all(((.hostPort // 0) == 0) or ((.hostPort // 0) >= 1024))))),
      "host network not shared": (($ps.hostNetwork // false) != true),
      "host PID not shared":     (($ps.hostPID // false) != true),
      "host IPC not shared":     (($ps.hostIPC // false) != true) };
'

DRIFT_JQ='
  (((.[0].items // []) + (.[1].items // []))) as $works
  | (.[2].items // []) as $rss
  | (.[3].items // []) as $crs
  | (.[4].items // []) as $rcs
  | [ $works[]
      | . as $w
      | ($w.metadata // {}) as $m
      | ($m.namespace // "?") as $ns
      | ($w.kind // "?") as $kind
      | ($m.name // "?") as $name
      | ($w.spec.template // {}) as $tpl
      | (($tpl.metadata.annotations // {})[$ANNOT] // "") as $stamp
      | select($stamp != "" or $ALLW == "1")
      | (($m.annotations // {})["deployment.kubernetes.io/revision"] // "") as $rev
      | (($tpl.spec // {}) | profile) as $now
      | ( if $kind == "Deployment" then
            [ $rss[] | select((.metadata.namespace // "?") == $ns)
              | select(((.metadata.ownerReferences // [])[]? | select(.kind == "Deployment") | .name) == $name)
              | { rev: ((.metadata.annotations // {})["deployment.kubernetes.io/revision"] // "0"),
                  stamp: (((.spec.template.metadata.annotations // {})[$ANNOT]) // ""),
                  prof: ((.spec.template.spec // {}) | profile) } ]
          elif $kind == "StatefulSet" or $kind == "DaemonSet" then
            [ $crs[] | select((.metadata.namespace // "?") == $ns)
              | select(((.metadata.ownerReferences // [])[]? | select(.kind == $kind) | .name) == $name)
              | { rev: ((.revision // 0) | tostring),
                  stamp: (((.data.spec.template.metadata.annotations // {})[$ANNOT]) // ""),
                  prof: ((.data.spec.template.spec // {}) | profile) } ]
          elif $kind == "DeploymentConfig" then
            [ $rcs[] | select((.metadata.namespace // "?") == $ns)
              | select(((.metadata.annotations // {})["openshift.io/deployment-config.name"] // "") == $name)
              | { rev: ((.metadata.annotations // {})["openshift.io/deployment-config.latest-version"] // "0"),
                  stamp: (((.spec.template.metadata.annotations // {})[$ANNOT]) // ""),
                  prof: ((.spec.template.spec // {}) | profile) } ]
          else [] end ) as $hist
      | ( [ $now | keys[] ] | map(. as $k
            | ( [ $hist[] | select(.prof[$k] == true) ] | sort_by(.rev | tonumber) | last ) as $best
            | select(($now[$k] == false) and ($best != null))
            | { key: $k, bestRev: $best.rev, bestStamp: $best.stamp } ) ) as $lost
      | select(($lost | length) > 0)
      | { ns: $ns, kind: ($kind | ascii_downcase), name: $name, rev: $rev, stamp: $stamp,
          revisions: ($hist | length), lost: $lost } ]
  | sort_by(.ns, .name)
  | .[]
  | [ .ns, .kind, .name, .rev, .stamp, (.revisions|tostring),
      ([ .lost[] | (.key + "~" + .bestRev + "~" + .bestStamp) ] | join("|")) ]
  | join("\u001f")'

get_rs()  { $OC get replicasets          $NSARGS -o json 2>/dev/null || echo '{"items":[]}'; }
get_crs() { $OC get controllerrevisions  $NSARGS -o json 2>/dev/null || echo '{"items":[]}'; }
get_rcs() { $OC get replicationcontrollers $NSARGS -o json 2>/dev/null || echo '{"items":[]}'; }

# Who wrote the live object last, and when. managedFields is the only record of this the API
# keeps, and it is what separates a person at a console from a controller: kubectl-edit and
# oc-edit are a human, kubectl-client-side-apply is somebody applying a manifest, and an
# operator or GitOps controller writes under its own name.
print_writers() {
  _ns="$1"; _kind="$2"; _name="$3"
  $OC get "$_kind/$_name" -n "$_ns" -o json 2>/dev/null |
    jq -r '(.metadata.managedFields // [])[]
           | "      " + (.manager // "?") + "  " + (.operation // "?") + "  " + (.time // "no timestamp")' ||
    echo "      could not read managedFields"
}

cmd_drift() {
  echo "Hardening that an earlier revision had and the running one does not."
  echo
  echo "This compares the live pod template against the template stored in every revision"
  echo "the cluster still keeps. It does not read your exceptions and it does not know which"
  echo "policies you chose, so it reports only what the cluster can prove was lost: a"
  echo "property that held in an earlier revision and does not hold now."
  echo
  echo "It is read only. The rollback commands below are printed, never run."
  echo
  _found=0
  { get_workloads; get_dcs; get_rs; get_crs; get_rcs; } |
  jq -s -r --arg ANNOT "$ANNOT" --arg ALLW "$DRIFT_ALL" "$PROFILE_JQ$DRIFT_JQ" |
  # Unit separator, not tab. Tab is IFS whitespace, so read collapses two consecutive tabs
  # into one and an empty field in the middle disappears, shifting every field after it. A
  # StatefulSet has no revision annotation, so its revision field is empty and this bug
  # reported its auditor reference as a revision number. US is not whitespace.
  while IFS="$(printf '\037')" read -r ns kind name rev stamp revisions lost; do
    _found=1
    rule
    echo "  $kind/$name in $ns"
    echo "    current revision: ${rev:-unknown}   revisions kept: $revisions"
    say_stamp "$stamp"
    echo "    lost since an earlier revision:"
    _diffstamp=0; _samestamp=0; _other=""
    printf '%s\n' "$lost" | tr '|' '\n' | while IFS='~' read -r key bestrev beststamp; do
      [ -n "$key" ] || continue
      echo "      $key   last held at revision $bestrev"
    done
    # Whether a later auditor run replaced the template, or something edited it afterwards,
    # is one fact about the workload rather than one per property. Said once.
    _beststamps="$(printf '%s\n' "$lost" | tr '|' '\n' | sed -n 's/^[^~]*~[^~]*~\(.*\)$/\1/p' | sort -u)"
    _verdict="unknown"
    if [ -n "$stamp" ]; then
      if printf '%s\n' "$_beststamps" | grep -qvxF "$stamp"; then _verdict="replaced"; else _verdict="edited"; fi
    fi
    echo
    case "$_verdict" in
      edited)
        echo "    The revision that still had it carries the SAME auditor reference as the"
        echo "    live object, so the auditor was not what replaced it. Something edited the"
        echo "    template afterwards. The writer list below is where to look."
        ;;
      replaced)
        echo "    The revision that still had it carries a DIFFERENT auditor reference, so a"
        echo "    later auditor apply replaced the template. A full manifest apply writes the"
        echo "    whole pod template, so an export that did not include this fix removes it."
        echo "    Re-export with every policy you want selected, or apply the per fix"
        echo "    patches, which touch only the fields their own fix changed."
        printf '%s\n' "$_beststamps" | sed 's/^/      had: /'
        echo "      live: $stamp"
        ;;
      *)
        echo "    The live object carries no auditor reference, so this tool cannot say"
        echo "    whether the auditor ever wrote this template. Treat the revision numbers"
        echo "    above as the evidence and the writer list below as the lead."
        ;;
    esac
    echo
    echo "    who wrote the live object last:"
    print_writers "$ns" "$kind" "$name"
    echo "      (kubectl-edit or oc-edit is a person at a console. client-side-apply is"
    echo "       somebody applying a manifest, possibly an older export. Terraform, helm,"
    echo "       argocd-application-controller or an operator name means that tool owns the"
    echo "       field and will undo this again: the value belongs in its config, not in"
    echo "       the cluster. An unfamiliar name is a lead, not a dead end.)"
    echo "    put it back to the revision that still had it:"
    echo "      $(undo_command "$ns" "$kind" "$name" "$(printf '%s\n' "$lost" | tr '|' '\n' | sed -n '1s/^[^~]*~\([^~]*\)~.*/\1/p')")"
  done
  echo
  echo "Nothing above means no workload in scope lost a property it previously had. It does"
  echo "NOT mean the workloads are hardened: a fix that was never applied at all never held"
  echo "in any revision, so it cannot show up here. Run an audit for that."
  echo
  echo "A revision that is gone cannot be compared. revisionHistoryLimit defaults to 10, so"
  echo "a workload that has rolled more than ten times since the fix has already pruned the"
  echo "evidence and will look clean here."
}

case "$CMD" in
  history)  cmd_history ;;
  broken)   cmd_broken ;;
  touched)  cmd_touched ;;
  drift)    cmd_drift ;;
  plan)     cmd_plan ;;
  snapshot) cmd_snapshot ;;
  undo)     cmd_undo ;;
  restore)  cmd_restore ;;
  *)        echo "Unknown subcommand: $CMD" >&2; usage ;;
esac
