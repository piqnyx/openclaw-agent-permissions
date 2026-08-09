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

## Symlink and hardlink cases

These are primarily OpenClaw filesystem-layer tests, not plugin canonicalization tests.

Verify the stock OpenClaw filesystem layer rejects unsafe symlink escapes and hardlink aliases before protected content can be modified.

Record the blocking layer. A stock OpenClaw error such as a sandbox-root/symlink/hardlink rejection is a system-level PASS even though it is not an `agent-permissions` denial.

## Cross-agent test

For an agent other than `main`, request a read of:

```text
/workspace/openclaw-src/package.json
```

Expected: `agent-permissions` DENY before filesystem lookup, even if that agent has no source bind.

Keep real-agent tests minimal if a long-term memory plugin automatically captures conversations. Cover the full non-main read/write/edit/delete/move matrix in automated tests instead of polluting a user's production memory.

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

## Exec tests

Run exec tests only after filesystem behavior is stable.

Baseline with `exec.default = ask`:

- ordinary command -> ASK;
- approval UI offers Allow once / Deny, not Allow always;
- an explicit deny regex blocks before approval;
- an explicit ask regex asks even if a later allow regex would match;
- an explicit allow regex with default `match: full` must consume the entire command;
- multiline or appended shell text must not accidentally match a narrow full allow;
- missing/unresolved command parameter -> DENY fail-closed.

Remember: approved shell commands are not restricted by filesystem zones.

## Fail-closed tests

In a disposable environment, verify that these conditions block calls with `failClosed=true`:

- invalid policy JSON;
- unknown policy field;
- duplicate rule ID;
- malformed regex;
- invalid learned-policy file;
- filesystem tool with no resolvable path;
- exec tool with no resolvable command.
