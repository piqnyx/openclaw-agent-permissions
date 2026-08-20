# OpenClaw Agent Permissions

A fail-closed, operator-owned permission policy plugin for sandboxed OpenClaw agents.

`agent-permissions` adds policy for three authorities that should not be confused with each other:

- filesystem tools such as `read`, `write`, `edit`, `apply_patch`, copy, delete, and move;
- shell execution through `exec` / `bash`, including an independent shell path guard;
- generic tools such as memory, browser, network, session, messaging, and MCP tools.

The plugin is designed for multi-agent OpenClaw installations where agents share the same gateway but must have different capabilities.

> [!IMPORTANT]
> This plugin is an authorization layer, not a replacement for Docker/OpenClaw sandboxing. `filesystem.zones` and `exec.paths` are independent controls. An operator-approved arbitrary shell command remains a separate authority, so use physical read-only mounts, container isolation, dropped capabilities, and conservative policy as independent defenses.

## Why this exists

OpenClaw exposes powerful tools to agents. A useful installation often needs more nuance than “everything allowed” or “everything denied”:

- let an agent read most of its workspace but mutate only a dedicated working area;
- make instruction files readable but immutable;
- allow profile files to be edited but not deleted or moved;
- allow only canonical daily memory files while hiding internal memory-plugin state;
- expose a source tree read-only to one agent and deny it to every other agent;
- allow reviewed read-only shell inspection without silently exposing every workspace path;
- ask before shell commands with side effects or uncertain path behavior;
- allow selected generic tools silently while requiring approval for external mutations;
- remember selected generic approvals per agent without turning them into global trust.

This plugin implements those decisions in structured JSON policy that remains outside agent workspaces.

## Tested baseline

Release `2.0.5` is tested with:

- OpenClaw `2026.7.2`;
- OpenClaw source commit `50c7444`;
- Node.js 22+;
- sandbox-visible workspace root `/workspace`.

Version 2.0.5 adds an independent `exec.paths` guard, configurable no-target command trust, and host-side physical verification for silently allowed mapped workspace paths. Policies that omit `exec.paths` retain the previous 2.0.4 exec-path behavior.

## Architecture

A useful mental model is:

```text
model/tool call
      |
      v
agent-permissions before_tool_call hook
      |
      +--> identify agent/session/tool/capability
      |
      +--> normalize sandbox-visible paths
      |
      +--> filesystem tool?
      |      `--> filesystem.zones
      |
      +--> exec/bash?
      |      +--> exec command policy
      |      +--> exec.paths lexical target policy
      |      +--> optional mapped physical verification
      |      `--> strictest result wins
      |
      +--> generic tool?
      |      `--> tools policy / learned approval
      |
      +--> DENY ------------------------------> blocked
      |
      +--> ASK -------------------------------> OpenClaw approval UI
      |                                          | allow once
      |                                          | allow always (only where enabled)
      |                                          ` deny
      |
      +--> ALLOW
      |
      +--> optional post-authorization filesystem-mutation path rewrite
      |
      v
OpenClaw tool implementation
      |
      v
OpenClaw filesystem safety + Docker/container boundaries
```

The policy is reloaded when the policy file changes. Ordinary policy edits therefore do not require reinstalling the plugin or restarting the gateway.

Plugin JavaScript is loaded by the gateway process. After upgrading/pulling plugin code, restart the gateway before runtime-testing the new code. Docker bind changes require the relevant sandbox/container recreation.

## Independent permission layers

### 1. Docker / OpenClaw sandbox

This controls what physically exists and what the container can do.

Examples:

- workspace mounted at `/workspace`;
- source tree mounted read-only at `/workspace/openclaw-src`;
- dropped Linux capabilities;
- read-only container root;
- network mode;
- OpenClaw's own workspace path, symlink, and hardlink protections.

### 2. Filesystem policy

This plugin evaluates recognized direct filesystem tools against ordered path zones.

Filesystem operations are:

- `read`
- `write`
- `delete`
- `move`
- `execute`

`execute` here means a tool explicitly profiled as `fs.execute`. It does **not** mean shell `exec`.

### 3. Exec command policy

This decides which shell command strings may run silently, must ask, or are denied.

It is intentionally separate from filesystem zones.

### 4. Exec path policy

`exec.paths` decides where an otherwise-silent shell command may target files. It does not make a command safer and it does not inherit `filesystem.zones`.

This independence allows deployments such as:

```text
direct filesystem tools: broad workspace read
silent exec:              only /tmp and a source tree
```

or the reverse.

### 5. Code mode

`codeMode` decides what happens when the gateway hides the tool catalog behind a sandboxed guest and the model sends a program instead of a command. It replaces layers 3 and 4 for that one call, because a program has no command line for them to read. The tool calls the program then makes arrive separately and go through every layer as usual.

### 6. Generic-tool policy

Non-filesystem, non-exec tools use the `tools` policy and optional learned approvals.

## Installation

Extract or copy the plugin to an operator-owned directory, for example:

```text
/home/openclaw/plugins/agent-permissions
```

The directory should contain at least:

```text
agent-permissions/
├── dist/
├── src/
├── test/
├── scripts/
├── openclaw.plugin.json
├── package.json
└── permissions.example.json
```

Configure OpenClaw to load that path and enable the plugin:

```json
{
  "plugins": {
    "load": {
      "paths": [
        "/home/openclaw/plugins/agent-permissions"
      ]
    },
    "entries": {
      "agent-permissions": {
        "enabled": true,
        "config": {
          "policyPath": "/home/openclaw/.openclaw/permissions.json",
          "virtualWorkspaceRoot": "/workspace",
          "approvalTimeoutMs": 540000,
          "logDecisions": true,
          "failClosed": true
        }
      }
    }
  }
}
```

Copy and edit the example policy:

```bash
cp permissions.example.json /home/openclaw/.openclaw/permissions.json
chmod 600 /home/openclaw/.openclaw/permissions.json
```

Validate before restart:

```bash
npm run check
npm run policy:check -- /home/openclaw/.openclaw/permissions.json
openclaw config validate
```

See [INSTALL.md](INSTALL.md) for the complete installation, upgrade, sandbox, and physical-mapping notes.

## Plugin configuration

| Option | Default | Meaning |
|---|---:|---|
| `policyPath` | `/home/openclaw/.openclaw/permissions.json` | Host-side JSON policy. Keep it outside agent workspaces. |
| `virtualWorkspaceRoot` | `/workspace` | Sandbox-visible root used to resolve relative paths. |
| `approvalTimeoutMs` | `540000` | Approval timeout in milliseconds. Valid range: 1000–600000. |
| `logDecisions` | `true` | Log ALLOW/ASK/DENY decisions. |
| `failClosed` | `true` | Block calls if policy loading or evaluation fails. |

## Policy file

The current policy schema version is `3`.

Top-level structure:

```json
{
  "version": 3,
  "defaults": { "effect": "ask" },
  "learning": {},
  "filesystem": {},
  "exec": {},
  "codeMode": {},
  "tools": {},
  "toolProfiles": {}
}
```

Unknown fields are rejected. Duplicate rule IDs, malformed matchers, invalid effects, unsupported filesystem operations, invalid exec-path structures, and invalid learned-policy entries fail validation.

Validate any policy with:

```bash
npm run policy:check -- /path/to/permissions.json
```

## Matchers

Path, agent, session, and tool matchers accept one of:

```json
"literal/glob/string/**"
```

or:

```json
{ "exact": "/workspace/AGENTS.md" }
```

```json
{ "glob": "/workspace/draft/**" }
```

```json
{ "regex": "^/workspace/draft(?:/.*)?$" }
```

Regex flags are limited to `i`, `m`, `s`, and `u`.

A plain string is treated as a glob, not a regex.

## Path normalization

Filesystem policy evaluates sandbox-visible POSIX paths.

Before matching:

- backslashes are converted to `/`;
- relative paths are resolved below `virtualWorkspaceRoot`;
- `.` and `..` are lexically normalized;
- NUL-containing paths are rejected;
- `~` is intentionally not guessed as the sandbox home directory.

Examples with `virtualWorkspaceRoot=/workspace`:

```text
draft/file.txt                    -> /workspace/draft/file.txt
/workspace/draft/../AGENTS.md     -> /workspace/AGENTS.md
draft/../../tmp/file.txt          -> /tmp/file.txt
```

Exec explicit path operands use the same sandbox-visible model. Path authorization is applied to the normalized target, not a misleading prefix.

For direct filesystem tools, symlink/hardlink safety remains primarily OpenClaw's filesystem-layer responsibility. For silently allowed mapped `/workspace/**` exec targets, 2.0.5 adds the physical verification described below.

## Filesystem zones

Example:

```json
{
  "id": "workspace-draft",
  "path": {
    "regex": "^/workspace/draft(?:/.*)?$"
  },
  "read": "allow",
  "write": "allow",
  "delete": "allow",
  "move": "allow",
  "execute": "allow"
}
```

Each operation can be `allow`, `ask`, or `deny`.

### Zone precedence

Zones are ordered.

For each operation/path target, the **first matching zone that defines that operation wins**.

This makes narrow rules easy to place before broad fallbacks:

```text
canonical daily memory files  -> allow read/write
all other /workspace/memory   -> deny everything
all other /workspace          -> allow read, deny mutation
```

A zone may also be scoped by:

- `agents`
- `sessions`
- `allowAlways`

Example agent-specific source access:

```json
{
  "id": "source-main-readonly",
  "path": { "regex": "^/workspace/openclaw-src(?:/.*)?$" },
  "agents": ["main"],
  "read": "allow",
  "write": "deny",
  "delete": "deny",
  "move": "deny",
  "execute": "deny"
},
{
  "id": "source-deny-others",
  "path": { "regex": "^/workspace/openclaw-src(?:/.*)?$" },
  "read": "deny",
  "write": "deny",
  "delete": "deny",
  "move": "deny",
  "execute": "deny"
}
```

The first rule applies only to `main`; other agents fall through to the explicit deny rule.

## Multi-target filesystem calls are atomic from the policy perspective

A single filesystem tool call may reference multiple targets. The plugin evaluates every extracted target and combines effects with this strictness:

```text
deny > ask > allow
```

If one target is denied, the whole call is blocked before the filesystem tool runs.

This is important for compound patches and copy/move operations.

## `apply_patch` semantics

`apply_patch` is parsed before execution so policy can preserve operation semantics.

The plugin recognizes:

- `*** Add File:` -> `write`
- `*** Update File:` -> `write`
- `*** Delete File:` -> `delete`
- `*** Move to:` -> `move` on source and destination, plus `write` on destination
- unified `---` / `+++` headers for add/delete/update/move cases

Example:

```text
*** Begin Patch
*** Update File: /workspace/draft/a.txt
*** Move to: /workspace/AGENTS.md
@@
 old
*** End Patch
```

Even though the source may be writable, the destination is checked independently. If `/workspace/AGENTS.md` is protected, the whole patch is denied.

If a recognized filesystem tool does not expose a resolvable target path, it is denied fail-closed rather than approved without path policy.

## Copy and move tools

Known copy tools check:

- `read` on the source;
- `write` on the destination.

Known move/rename tools expose both source and destination paths to policy. `apply_patch` moves also preserve source/destination semantics as described above.

## Absolute `/workspace/...` mutation compatibility

OpenClaw `2026.7.2` contains a memory-write provenance path that can call host-side `realpath()` on sandbox-visible absolute mutation paths such as:

```text
/workspace/draft/file.txt
```

The host may not have `/workspace`, causing an unrelated `ENOENT` before the tool operation completes.

`agent-permissions` works around that issue without changing the model-facing path contract:

1. the original path is normalized and authorized as `/workspace/...`;
2. DENY/ASK/ALLOW is decided against that sandbox-visible path;
3. **only after authorization**, known filesystem mutation parameters are rewritten from `/workspace/foo` to workspace-relative `foo` for execution;
4. reads, shell exec/process calls, denied calls, and policy matching are not rewritten.

This means agents can naturally use absolute sandbox paths while stock OpenClaw memory provenance continues to work.

The rewrite covers known mutation path fields and patch headers only. Arbitrary content strings are never rewritten.

## Daily memory pattern

The example policy allows only these two file-name forms below `/workspace/memory`:

```text
/workspace/memory/YYYY-MM-DD.md
/workspace/memory/memory-YYYY-MM-DD.md
```

They may be read and edited but not deleted or moved through direct filesystem tools.

Everything else below `/workspace/memory` is denied in the example filesystem policy, including plugin-internal directories such as `dreaming/` or `.dreams/`.

The example exec-path policy likewise allows only the canonical daily files, selected top-level profile/instruction files, draft, and the explicitly mapped source tree inside `/workspace`. It does not silently allow the `/workspace/memory` parent directory.

The daily-file regex validates filename shape and basic month/day ranges. It is intentionally not a full Gregorian calendar validator; a syntactically shaped but impossible date can still match.

## Learning / Allow always

Learned approvals are optional and stored outside agent workspaces.

Example:

```json
{
  "learning": {
    "enabled": true,
    "path": "/home/openclaw/.openclaw/permissions.learned.json"
  }
}
```

The learned file uses schema version `2` and is written atomically with mode `0600`.

### Filesystem learning

Filesystem learned approvals are:

- agent-scoped;
- operation-scoped;
- exact-path scoped.

Approving READ forever on one path does not approve WRITE, DELETE, MOVE, or another path.

Static DENY rules still win.

### Generic-tool learning

Generic-tool learned approvals are scoped to:

- agent ID;
- tool name;
- capability.

Parameters may change after a generic tool is permanently approved, so enable `allowAlways` only where that scope is acceptable.

### Exec learning

Exec deliberately does **not** support `Allow always`.

Durable shell trust must be written explicitly as an `exec.allow` regex rule so it remains visible and reviewable in operator policy.

## Exec command policy

Example skeleton:

```json
{
  "exec": {
    "default": "ask",
    "allowAlways": false,
    "deny": [],
    "ask": [],
    "allow": []
  }
}
```

Command-rule evaluation order:

```text
deny -> ask -> allow -> default
```

Regex behavior:

- `deny` entries default to `match: "search"`;
- `ask` entries default to `match: "search"`;
- `allow` entries default to `match: "full"`.

`full` means the regex must consume the entire command, including multiline input.

Example explicit allow:

```json
{
  "id": "allow-uname",
  "regex": "^uname -a$",
  "match": "full",
  "description": "Allow exactly uname -a"
}
```

Do not treat command regex policy as a parser for arbitrary shell syntax. Keep default ASK and make silent allows conservative.

If an exec command cannot be extracted from the expected parameters, the plugin denies it fail-closed.

## Exec path policy (`exec.paths`)

Version 2.0.5 adds an optional path guard inside `exec`:

```json
{
  "exec": {
    "default": "ask",
    "allowAlways": false,
    "paths": {
      "default": "ask",
      "pathless": {
        "allow": ["pwd", "id", "uname"]
      },
      "physicalMappings": [],
      "deny": [],
      "ask": [],
      "allow": []
    },
    "deny": [],
    "ask": [],
    "allow": []
  }
}
```

`exec.paths` is independent from `filesystem.zones`.

### Exec path flow

For an exec call:

```text
1. analyze explicit filesystem-looking shell operands
2. normalize lexical paths and traversal
3. evaluate exec.paths: deny -> ask -> allow -> default
4. evaluate ordinary exec command policy
5. if both are otherwise ALLOW, physically verify mapped /workspace targets
6. final strictness: DENY > ASK > ALLOW
```

A path ALLOW never upgrades a command ASK or DENY.

Examples:

```text
rm /workspace/draft/x
```

may have an allowed path but still ASK because `rm` is not silently allowed by command policy.

```text
cat /workspace/memory/.dreams/state.md
```

may match a read-only command allow but still ASK/DENY because the path is not silently allowed.

### Exec path rules

Path rules use the same matcher forms and may be scoped by:

- `agents`
- `sessions`
- `tools`

Example:

```json
{
  "id": "source-main",
  "path": { "regex": "^/workspace/openclaw-src(?:/.*)?$" },
  "agents": ["main"]
}
```

`exec.paths.default` is normally best kept at `ask`.

Do not broadly allow `/workspace` merely to make recursive inspection convenient. A recursive tool explicitly targeting `/workspace` could then walk descendants that were intentionally omitted from narrower exec-path allows.

### Relative paths and traversal

Explicit relative path operands resolve under `virtualWorkspaceRoot`.

Examples:

```text
draft/file.txt                  -> /workspace/draft/file.txt
./draft/file.txt                -> /workspace/draft/file.txt
draft/../memory/.dreams/x.md    -> /workspace/memory/.dreams/x.md
```

Normalization happens before path matching, so an allowed lexical prefix cannot be used to smuggle a traversal into another namespace.

### Ambiguous and dynamic shell syntax

The exec path analyzer is deliberately conservative and is not a full shell parser.

Dynamic shell expressions, malformed quoting, background operators, redirection/process-substitution ambiguity, path expansions/globs, and other unresolved cases become ASK instead of silent ALLOW.

This design prefers an unnecessary approval over guessing that a shell expression cannot access an unintended path.

### No explicit path: `pathless.allow`

Some trusted commands legitimately need no explicit filesystem target:

```text
id
pwd
uname
```

Other commands can implicitly use the current directory when no target is supplied:

```text
rg needle
ls
find
```

To avoid silently treating both groups the same, 2.0.5 requires explicit command-word trust when no path target is detected:

```json
"pathless": {
  "allow": [
    "pwd",
    "id",
    "whoami",
    "groups",
    "uname"
  ]
}
```

For a simple shell chain with no detected paths, every command word must appear in `pathless.allow` before the path layer can preserve a silent ALLOW.

`pathless.allow` is policy, not hardcoded command knowledge. Different deployments can choose different trust sets.

### Physical mappings

Lexical normalization cannot by itself detect a symlink inside an allowed workspace tree that resolves somewhere else.

For otherwise-silent `/workspace/**` exec targets, the plugin therefore performs best-effort host-side physical verification when a host mapping is available.

The ordinary agent workspace uses OpenClaw's runtime `workspaceDir` mapping.

External binds below `/workspace` need an explicit mapping. For example, if Docker mounts:

```text
/home/openclaw/openclaw:/workspace/openclaw-src:ro
```

configure:

```json
"physicalMappings": [
  {
    "id": "openclaw-source-bind",
    "description": "Main-only OpenClaw source bind",
    "virtual": "/workspace/openclaw-src",
    "host": "/home/openclaw/openclaw",
    "agents": ["main"]
  }
]
```

The most specific matching `virtual` prefix is selected.

The physical guard resolves the mapped host root and the deepest existing ancestor of the requested target. If symlink resolution escapes the mapped root or maps the requested virtual path to a different physical virtual target, silent ALLOW becomes ASK.

Host-side physical verification is intentionally not applied to normal container paths such as `/etc`, `/usr`, `/proc`, or `/tmp`, because the host namespace is not the sandbox namespace.

Physical verification does not provide complete hardlink-alias detection and does not convert arbitrary shell execution into a hostile-code sandbox.

## Code mode (`codeMode`)

OpenClaw can put the tool catalog behind a QuickJS-WASI guest and expose only `exec` and `wait`. The model then writes a program that reaches tools through a bridge, which turns a dozen round trips into one.

That outer call carries a program, so the exec layers have nothing true to say about it:

- `exec.deny` / `exec.ask` / `exec.allow` regexes are matched against source code. A program with `rm -rf` inside a string literal matches; a program that does real damage through the bridge does not.
- `exec.paths` operands are whatever the gateway's path extractor found in the program text. A live gateway produced `paths=/workspace/Basic/Pascal` from a program that merely named old languages.
- The physical and `pathless.allow` guards then downgrade whatever survives, so in practice every program asks.

`codeMode` answers that one call directly instead:

```json
"codeMode": {
  "description": "code-mode program; the tool calls it makes are policed individually",
  "default": "allow",
  "agents": ["main"]
}
```

Fields, all optional: `default` (`allow` / `ask` / `deny`, default `ask`), `description` (the reason shown in the log and the approval dialog), and `agents` / `sessions` / `tools`, which are ordinary [matchers](#matchers) with the same meaning they have everywhere else.

**Omit the section and nothing changes**: a program keeps being judged by the exec rules exactly as before. The same is true when `agents` or `sessions` exclude the call — it falls through rather than inheriting a blanket answer meant for somebody else.

What the section does *not* touch:

- **Shell commands.** A payload is treated as a program only when it carries a `code` or a `language` field. Anything else is an ordinary exec call.
- **The program's own tool calls.** Each bridge call arrives as its own `before_tool_call` with its real capability and its real paths, and is matched by the same zones, exec rules and tool rules as ever. That is what an `allow` here rests on.
- **Permanent approval.** A code-mode decision never offers *allow always*; the section itself is the standing answer.

Because `allow` here means "do not read this program", it is only as strong as the guest's isolation. Confirm that the guest is sealed — no `require`, no `process`, no filesystem — before granting it, and prefer scoping the section to the agents that actually run in code mode.

## Generic tool policy

Generic rules can match by:

- tool name;
- capability;
- operation;
- agent/session/tool context;
- selected string parameters.

Known built-in capabilities include:

- `memory.read`
- `memory.write`
- `network.read`
- `browser`
- `external.write`
- `process`
- `session.read`

Example ASK rule:

```json
{
  "id": "memory-read-approval",
  "capabilities": ["memory.read"],
  "allowAlways": true,
  "description": "Ask before explicit semantic-memory reads"
}
```

Example allow rule by tool-name regex:

```json
{
  "id": "allow-selected-read-tools",
  "tools": [
    { "regex": "^mcp__example_(?:search|read)$" }
  ],
  "description": "Allow selected read-only MCP tools"
}
```

Unknown tools can safely default to ASK:

```json
{
  "tools": {
    "default": "ask",
    "defaultAllowAlways": false
  }
}
```

If `defaultAllowAlways` is enabled for a default ASK, a learned generic approval is scoped by agent ID, tool name, and capability. Parameters may vary on later calls, so enable it only when that scope is acceptable.

## Built-in tool profiles

The plugin ships profiles for common OpenClaw tool names, including:

- filesystem: `read`, `write`, `edit`, `apply_patch`, copy, delete, move/rename, list/glob/grep variants;
- shell/process: `bash`, `exec`, `process`;
- memory: common memory tools and OpenViking read/write tools;
- network/browser: `web_search`, `web_fetch`, `browser`;
- messaging/session tools.

Tool names that are not built in can be mapped with `toolProfiles`.

Example custom filesystem tool:

```json
{
  "toolProfiles": {
    "my_file_writer": {
      "capability": "fs.write",
      "operation": "write",
      "pathParams": ["path"]
    }
  }
}
```

Example custom copy-like tool:

```json
{
  "toolProfiles": {
    "my_copy": {
      "capability": "fs.write",
      "operation": "copy",
      "pathOperations": {
        "read": ["source"],
        "write": ["destination"]
      }
    }
  }
}
```

Selectors support nested fields and `[]` array traversal, for example `files[].path`.

## Recommended workspace policy

The shipped example uses this direct-filesystem model:

```text
/workspace
├── AGENTS.md                  read-only
├── DREAMS.md                  read-only
├── USER.md                    read/write, no delete/move
├── IDENTITY.md                read/write, no delete/move
├── SOUL.md                    read/write, no delete/move
├── MEMORY.md                  read/write, no delete/move
├── memory/
│   ├── YYYY-MM-DD.md          read/write, no delete/move
│   ├── memory-YYYY-MM-DD.md   read/write, no delete/move
│   └── everything else       deny all
├── draft/                     unrestricted filesystem working area
└── openclaw-src/              main agent read-only; other agents deny
```

All other `/workspace` paths are readable by default through direct filesystem tools in the example, but arbitrary mutations are denied unless a narrower zone permits them.

The example `exec.paths` is intentionally narrower and does not silently allow the whole workspace tree.

## Recommended Docker relationship

For a main agent that may read OpenClaw source, mount source physically read-only:

```json
{
  "binds": [
    "/home/openclaw/openclaw:/workspace/openclaw-src:ro"
  ],
  "dangerouslyAllowExternalBindSources": true,
  "dangerouslyAllowReservedContainerTargets": true,
  "readOnlyRoot": true,
  "network": "bridge"
}
```

Do not give other agents that bind if they should not see the source. Keep the explicit policy deny as defense in depth.

If shell inspection of this bind may be silently allowed, keep the matching `exec.paths.physicalMappings` entry synchronized with the real Docker source path.

No separate bind is required for `/workspace/draft`; it is an ordinary subdirectory of the agent workspace.

## Logging

With `logDecisions=true`, decisions are logged in a compact form similar to:

```text
agent-permissions: DENY agent=main write capability=fs.write operation=write paths=/workspace/AGENTS.md rule=workspace-core-readonly
```

Exec path decisions include the normalized detected paths and the rule that produced the final outcome, for example an `exec-path-default`, `exec-path-ambiguous`, or `exec-path-physical` suffix.

Approval persistence also logs learned ALLOW events.

Do not put secrets in rule descriptions; descriptions may be surfaced in logs or approval UI.

## Failure behavior

With `failClosed=true` (recommended), errors such as these block the tool call:

- unreadable policy file;
- invalid JSON;
- schema validation failure;
- unresolved path for a recognized filesystem tool;
- unresolved command for a recognized exec tool;
- malformed learned-policy file;
- internal policy evaluation failure.

Set `failClosed=false` only if you intentionally prefer availability over authorization safety.

## Security boundaries and limitations

This plugin is designed to reduce accidental or cooperative-agent misuse and to make operator intent explicit. It is not a complete hostile-code sandbox.

Important limits:

1. **Filesystem and shell are separate authorities.** `filesystem.zones` do not automatically constrain shell commands; use `exec.paths` when you want a silent-shell path boundary.
2. **Approved arbitrary shell commands remain powerful.** An operator approval can authorize behavior beyond what conservative static analysis can prove.
3. **Physical isolation still matters.** Use Docker/OpenClaw sandboxing and read-only mounts for resources that must remain immutable.
4. **Exec path analysis is conservative, not complete shell parsing.** Ambiguous expressions ASK rather than receiving a silent ALLOW.
5. **Mapped physical verification is best-effort.** It catches mapped path/symlink mismatches but not every possible hardlink or runtime aliasing scenario.
6. **Tool profiles must match reality.** A custom filesystem-mutating tool must be profiled correctly or it will be treated as a generic tool.
7. **Generic permanent approval is broader than filesystem permanent approval.** It is scoped by agent/tool/capability rather than exact parameters.
8. **Policy is only as good as its ordering and mappings.** Narrow zones belong before broad fallbacks, and external physical mappings must match the real mount source.
9. **`codeMode: allow` trusts the guest, not the program.** The program is never inspected; the guarantee comes from the sandboxed guest and from every bridge call being policed on its own. A guest that can reach the host directly makes this setting a blanket exec allow.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.

## Testing

Run the automated suite:

```bash
npm run check
```

This performs:

1. build;
2. example-policy validation;
3. Node test suite.

Then run the focused runtime acceptance matrix in [TESTING.md](TESTING.md).

The 2.0.5 acceptance coverage includes:

- absolute and relative filesystem paths;
- `..` traversal normalization;
- multi-target `apply_patch` denial;
- patch add/update/delete/move semantics;
- nested directory creation;
- direct-filesystem read-only source access;
- cross-agent source denial in automated coverage;
- memory namespace allowlist behavior;
- stock OpenClaw filesystem symlink/hardlink protections;
- generic approval and learning behavior;
- exec command regex behavior;
- exec-path default ASK for restricted workspace targets;
- positive `pathless.allow` behavior;
- implicit-current-directory no-target ASK behavior;
- exec traversal normalization;
- command ASK overriding a path ALLOW;
- external-bind physical mapping and mapped symlink escape regression coverage.

## Upgrade notes

### From 2.0.4 to 2.0.5

Version 2.0.5 adds optional exec-path authorization. Existing policies without `exec.paths` retain the previous path behavior for exec.

To adopt the new guard deliberately:

- add `exec.paths` with a conservative default such as `ask`;
- add narrow path ALLOW rules for intended silent shell inspection;
- add `pathless.allow` for commands trusted to run without explicit filesystem targets;
- add `physicalMappings` for external binds below `/workspace` that may be silently accessed through exec;
- validate the live policy;
- restart the gateway because plugin code changed;
- run the focused exec-path runtime tests in [TESTING.md](TESTING.md).

Always diff your live `/home/openclaw/.openclaw/permissions.json` before replacing it with an example policy. The example is a template, not an automatic migration.

## License

MIT. See [LICENSE](LICENSE).
