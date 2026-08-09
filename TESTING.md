# Testing

Use two layers of tests:

1. automated plugin tests, which are safe and repeatable;
2. runtime acceptance tests against a disposable or carefully controlled agent workspace.

Do not run destructive acceptance tests against valuable files without backups.

## Automated tests

From the plugin directory:

```bash
npm run check
```

This runs:

```text
build
-> example policy validation
-> node --test
```

Also validate the live operator policy:

```bash
npm run policy:check -- /home/openclaw/.openclaw/permissions.json
```

## Runtime acceptance principles

- Use a test agent/workspace when possible.
- Ask the model to use exactly one named tool per test.
- Explicitly forbid `exec` when testing filesystem tools.
- Verify filesystem state on the host after mutation tests.
- Test absolute and relative paths separately.
- Treat OpenClaw filesystem-safety failures and plugin policy denials as different layers; record which one blocked the operation.
- Clean only files created by the test. Avoid restoring an entire live workspace from an old backup if other plugins may have changed legitimate state.
- Keep real-agent cross-agent tests minimal when long-term memory automatically captures conversations.

## Filesystem baseline

The example policy should produce these outcomes:

| Case | Expected |
|---|---|
| read `/workspace/AGENTS.md` | ALLOW |
| write/edit/delete/move `AGENTS.md` | DENY |
| read `/workspace/DREAMS.md` | ALLOW |
| write/edit/delete/move `DREAMS.md` | DENY |
| read/write/edit `USER.md`, `IDENTITY.md`, `SOUL.md`, `MEMORY.md` | ALLOW |
| delete/move those profile files | DENY |
| `/workspace/draft/**` filesystem mutations | ALLOW |
| arbitrary mutation elsewhere in `/workspace` | DENY |
| main read `/workspace/openclaw-src/**` | ALLOW |
| main mutate `/workspace/openclaw-src/**` | DENY |
| non-main read/mutate `/workspace/openclaw-src/**` | DENY |
| file-tool access to `/tmp`, `/var/tmp`, `/run`, `/var/run` | DENY |

## Path normalization cases

Test at least:

```text
/workspace/draft/../AGENTS.md
```

Expected normalized policy target:

```text
/workspace/AGENTS.md
```

and DENY for mutation.

Test escape beyond workspace:

```text
/workspace/draft/../../tmp/test.txt
```

Expected normalized policy target:

```text
/tmp/test.txt
```

and DENY by the temp/runtime zone.

Repeat important cases with relative paths:

```text
draft/../AGENTS.md
```

## Absolute-path compatibility

With stock OpenClaw memory flush/provenance enabled, verify that an absolute mutation such as:

```text
/workspace/draft/absolute-test.txt
```

succeeds inside the draft zone. This exercises the post-authorization `/workspace/...` to workspace-relative execution rewrite.

Then verify a denied absolute path remains denied before rewriting:

```text
/workspace/AGENTS.md
```

## Nested directory creation

A `write` below an allowed directory may create missing parent directories:

```text
/workspace/draft/new-dir/deeper/test.txt
```

Expected: ALLOW and parents created.

The equivalent below a denied namespace:

```text
/workspace/memory/new-dir/deeper/test.txt
```

must be DENY, and no intermediate directories should be left behind.

Repeat with `apply_patch` Add File.

## `apply_patch` matrix

Test each operation independently:

- Add File in allowed draft -> ALLOW
- Update File in allowed draft -> ALLOW
- Delete File in allowed draft -> ALLOW
- Move within allowed draft -> ALLOW
- Delete protected profile/instruction file -> DENY
- Move protected source to allowed draft -> DENY
- Move allowed source to protected destination -> DENY
- mixed patch containing one allowed and one denied target -> DENY whole call
- traversal in source and destination -> normalize before policy

A move-only OpenClaw update may require a non-empty update chunk. Use unchanged context when necessary.

## Daily memory namespace

The example allows:

```text
/workspace/memory/YYYY-MM-DD.md
/workspace/memory/memory-YYYY-MM-DD.md
```

Expected:

- read/write/edit -> ALLOW
- delete/move -> DENY
- clear file content via edit -> ALLOW while file remains present
- arbitrary names such as `notes.md` -> DENY
- suffix variants such as `YYYY-MM-DD-extra.md` -> DENY
- nested plugin/internal directories -> DENY, including read

The filename regex is a namespace guard, not a full Gregorian calendar validator.

## Direct filesystem symlink and hardlink cases

These remain primarily OpenClaw filesystem-layer tests.

Verify the stock OpenClaw filesystem layer rejects unsafe symlink escapes and hardlink aliases before protected content can be modified through direct filesystem tools.

Record the blocking layer. A stock OpenClaw sandbox-root/symlink/hardlink rejection is a system-level PASS even when it is not an `agent-permissions` denial.

## Cross-agent source test

For an agent other than `main`, request a read of:

```text
/workspace/openclaw-src/package.json
```

Expected: `agent-permissions` DENY before filesystem lookup, even if that agent has no source bind.

Prefer automated regression coverage for the full non-main matrix instead of polluting a real user's production memory.

## Generic tools

With the example policy:

- read-only network capability -> ALLOW
- session inspection -> ALLOW
- semantic-memory read -> ASK and may offer Allow always
- semantic-memory write -> ASK per call, no Allow always
- external write/browser/process -> ASK per call
- unknown tool -> ASK, no permanent trust by default

After a memory-read `Allow always`, verify:

- same agent + same tool + same capability -> ALLOW on a later call;
- another agent -> ASK;
- static DENY still wins if configured.

## Exec command-policy baseline

Run exec tests only after filesystem behavior is stable.

Baseline with `exec.default = ask`:

- ordinary unknown command -> ASK;
- approval UI offers Allow once / Deny, not Allow always;
- an explicit deny regex blocks before approval;
- an explicit ask regex asks even if a later allow regex would match;
- an explicit allow regex with default `match: full` must consume the entire command;
- multiline or appended shell text must not accidentally match a narrow full allow;
- missing/unresolved command parameter -> DENY fail-closed.

## Exec path-policy matrix (2.0.5)

When `exec.paths` is configured, command authorization and path authorization are independent. The strictest result wins.

Minimum focused runtime matrix:

| Command | Expected reason |
|---|---|
| `cat /workspace/openclaw-src/package.json` for an allowed main mapping | ALLOW silently |
| `cat /workspace/memory/.dreams/test.md` when memory internals are not path-allowed | ASK/DENY according to exec-path policy |
| `id` when `id` is in `pathless.allow` and command policy allows it | ALLOW silently |
| `rg needle` when `rg` is not trusted pathless and no explicit target is present | ASK |
| `cat /workspace/draft/../memory/.dreams/test.md` | normalize first, then ASK/DENY |
| `rm /workspace/draft/example` when path is allowed but command is not silently allowed | ASK |

Do not press Allow during negative tests unless execution itself is part of the test. Deny the approval and verify no side effect occurred.

### Relative exec paths

If command policy otherwise allows the command, verify explicit relative targets such as:

```text
draft/file.txt
./draft/file.txt
```

are normalized below `virtualWorkspaceRoot` before `exec.paths` matching.

Traversal must normalize before matching:

```text
draft/../memory/.dreams/test.md
```

must not inherit trust from the `draft` prefix.

### No-target / implicit-current-directory behavior

A silently allowed command with no detected explicit path target is permitted by the path layer only when every simple command word in the shell chain is listed in:

```json
"pathless": {
  "allow": ["id", "pwd", "uname"]
}
```

Use one trusted pathless command such as `id` as a positive test.

Use a filesystem-search command such as `rg needle` with no explicit target as a negative test. It should ASK rather than silently searching the current workspace.

### Ambiguous shell syntax

Path analysis is intentionally conservative. Dynamic shell constructs, unresolved expansions, glob-like path expansions, malformed quoting, background operators, and similar ambiguity should not silently pass an `exec.paths` guard.

Keep automated tests for syntax variants; runtime testing need only sample representative cases.

### Physical workspace verification

For otherwise-silent `/workspace/**` exec targets, 2.0.5 performs host-side physical verification when a host mapping is available.

For the ordinary agent workspace, the runtime `workspaceDir` mapping is used.

For an external bind such as:

```text
/home/openclaw/openclaw -> /workspace/openclaw-src
```

declare:

```json
"physicalMappings": [
  {
    "id": "openclaw-source-bind",
    "virtual": "/workspace/openclaw-src",
    "host": "/home/openclaw/openclaw",
    "agents": ["main"]
  }
]
```

Then verify a normal file below that bind can be read silently when both command and lexical path policy allow it.

Automated tests should also verify a symlink below an allowed mapping that resolves outside its physical host root becomes ASK rather than a silent ALLOW.

Non-workspace container paths such as `/etc` are not host-realpathed because the host and sandbox namespaces are different; they remain governed by lexical `exec.paths` plus command policy.

### Exec-path limitations

The exec path analyzer is deliberately not a full shell parser. Ambiguous input asks instead of attempting broad interpretation.

Physical verification detects path/symlink mismatches for mapped workspace paths, but it does not turn shell execution into a complete hostile-code sandbox. Hardlink aliasing and behavior after an operator-approved arbitrary shell command still require Docker/OpenClaw isolation and physical mount design.

## Fail-closed tests

In a disposable environment, verify that these conditions block calls with `failClosed=true`:

- invalid policy JSON;
- unknown policy field;
- duplicate rule ID;
- malformed regex;
- invalid learned-policy file;
- filesystem tool with no resolvable path;
- exec tool with no resolvable command.
