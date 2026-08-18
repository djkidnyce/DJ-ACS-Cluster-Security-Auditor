# Contributing

## Before anything else

Run the tests. All of them.

```bash
node test/run_tests.js

# the whole page tests need jsdom, and skip cleanly without it
npm install jsdom && node test/run_tests.js
```

A red suite is a blocked change, not a warning.

## The one architectural rule

**Policy logic lives in exactly one file: `acs_policies.js`.** Both HTML pages, the CLI
and every test load it. Nothing reimplements a check.

This is not a style preference. The failure it prevents is specific: the GUI reports a
finding, the CLI in CI does not, and nobody notices for months because the two were never
compared. If a surface cannot reach the engine, fix the loading, not the logic.

## Adding a policy

1. Add the entry to `acs_policies.js`. One place only.
2. Add a fixture that trips it and one that does not.
3. Add a test asserting the check fires correctly on both.
4. If it has a fix, assert valid YAML out, idempotency, and no collateral change.
5. Confirm the posture denominator grows. A new policy that leaves the total unchanged
   never entered the denominator.
6. Add the citations. A finding without a standard behind it is an opinion.

### Choosing `fixKind`

| Value | Use when |
|---|---|
| `auto` | Exactly one correct change, no plausible downside |
| `generate` | The right answer is a new object rather than an edit |
| `manual` | The answer depends on context the scanner cannot see |

**When in doubt, `manual`.** An over eager auto fix that breaks a workload costs you the
entire tool, because the team turns it off, and a switched off scanner protects nobody.

## Things that will get a change rejected

* Any code path that produces something applyable without an explicit mode. `report` is
  the default and the mode is never inferred. If you find yourself upgrading the mode
  based on what was requested, stop.
* Gating only a button rather than the handler behind it. A disabled attribute is a UI
  hint, not a control.
* `exec`, `eval`, or the `Function` constructor anywhere in a shipped file.
* Anything that writes to a cluster. This tool is read only against clusters, always.
* Disabling TLS verification by default in generated commands.
* Adding a runtime network dependency. Dependencies are vendored with published hashes.

## Writing a test that is worth having

Check out the broken behaviour and prove your test fails against it. A test you have
never seen fail is a test you have no evidence about.

This is not theoretical. A regression test written during development passed against both
the buggy engine and the fixed one, because the fixture got everything fixed and both
paths reached 100. The error cancelled itself out.

## Style

Two space indent, single quotes, semicolons. Comments explain **why**, not what. No
external formatter, no linter config, no build step. Keep it that way: the tool has to
run on a machine with no package manager.
