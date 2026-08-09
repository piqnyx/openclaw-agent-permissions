# OpenClaw Agent Permissions

A fail-closed, operator-owned permission policy plugin for sandboxed OpenClaw agents.

`agent-permissions` adds one policy layer for three authorities that should not be confused with each other:

- filesystem tools such as `read`, `write`, `edit`, `apply_patch`, copy, delete, and move;
- shell execution through `exec` / `bash`;
- generic tools such as memory, browser, network, session, messaging, and MCP tools.

The plugin is designed for multi-agent OpenClaw installations where agents share the same gateway but must have different capabilities.

> [!IMPORTANT]
> This plugin is an authorization layer, not a replacement for Docker/OpenClaw sandboxing. Filesystem zones do not restrict arbitrary shell commands after an `exec` call has been approved. Use physical read-only mounts, container isolation, dropped capabilities, and a conservative exec policy as independent controls.

## Why this exists

OpenClaw exposes powerful tools to agents. A useful installation often needs more nuance than “everything allowed” or “everything denied”:

- let an agent read most of its workspace but mutate only a dedicated working area;
- make instruction files readable but immutable;
- allow profile files to be edited but not deleted or moved;
- allow only canonical daily memory files while hiding internal memory-plugin state;
- expose a source tree read-only to one agent and deny it to every other agent;
- ask before shell execution;
- allow selected read-only tools silently while requiring approval for external mutations;
- remember some approvals per agent without turning them into global trust.

This plugin implements those decisions in a structured JSON policy that remains outside agent workspaces.

## Tested baseline

Release `2.0.4` is built from the `2.0.3` runtime and documents the tested policy used with:

- OpenClaw `2026.7.2`;
- OpenClaw source commit `50c7444`;
- Node.js 22+;
- sandbox-visible workspace root `/workspace`.

The `2.0.4` release does not change runtime authorization logic from `2.0.3`; it refreshes public documentation, package metadata, the example policy, and the acceptance-test guide.

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
      +--> evaluate filesystem / exec / generic-tool policy
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
      +--> optional post-authorization mutation-path compatibility rewrite
      |
      v
OpenClaw tool implementation
      |
      v
OpenClaw filesystem safety + Docker/container boundaries
```

The policy is reloaded when the policy file changes. Normal operation does not require a gateway restart after every policy edit, although sandbox bind changes do require container recreation.

## Three independent permission layers

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

This plugin evaluates recognized filesystem tools against ordered path zones.

Filesystem operations are:

- `read`
- `write`
- `delete`
- `move`
- `execute`

`execute` here means a tool explicitly profiled as `fs.execute`. It does **not** mean shell `exec`.

### 3. Exec and generic-tool policy

Shell commands and non-filesystem tools are evaluated independently. An approved shell command is not constrained by filesystem zones; Docker and the exec policy remain the relevant boundary.

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

See [INSTALL.md](INSTALL.md) for the complete installation and sandbox notes.

## Plugin configuration

| Option | Default | Meaning |
|---|---:|---|
| `policyPath` | `/home/openclaw/.openclaw/permissions.json` | Host-side JSON policy. Keep it outside agent workspaces. |
| `virtualWorkspaceRoot` | `/workspace` | Sandbox-visible root used to resolve relative file paths. |
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
  "tools": {},
  "toolProfiles": {}
}
```

Unknown fields are rejected. Duplicate rule IDs, malformed matchers, invalid effects, unsupported filesystem operations, and invalid learned-policy entries fail validation.

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

This is important because policy must authorize the normalized target, not a misleading prefix.

Symlink and hardlink canonicalization is intentionally not reimplemented by this plugin. OpenClaw's filesystem layer and the sandbox remain responsible for their physical safety checks.

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

## Multi-target calls are atomic from the policy perspective

A single tool call may reference multiple filesystem targets. The plugin evaluates every extracted target and combines effects with this strictness:

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

They may be read and edited but not deleted or moved.

Everything else below `/workspace/memory` is denied in the example policy, including plugin-internal directories such as `dreaming/` or `.dreams/`.

The example regex validates filename shape and basic month/day ranges. It is intentionally not a full Gregorian calendar validator; for example, a syntactically shaped but impossible date can still match. Stock OpenClaw generates real dates, so the policy focuses on limiting the namespace rather than implementing a calendar parser in regex.

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

Parameters may change after a generic tool is permanently approved, so enable `allowAlways` only for capabilities where that scope is acceptable.

### Exec learning

Exec deliberately does **not** support `Allow always`.

Durable shell trust must be written explicitly as an `exec.allow` regex rule so it remains visible and reviewable in the operator policy.

## Exec policy

Example default:

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

Evaluation order:

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

Example deny:

```json
{
  "id": "deny-private-key-read",
  "regex": "(?:^|[;&|]\\s*)cat\\s+[^\\n]*(?:id_rsa|id_ed25519)",
  "match": "search",
  "description": "Block obvious private-key reads"
}
```

Do not treat regex policy as a parser for arbitrary shell syntax. The safest default is ASK, with a small number of exact/full allows for commands you genuinely trust.

If an exec command cannot be extracted from the expected parameters, the plugin denies it fail-closed.

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

The shipped example uses this model:

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

All other `/workspace` paths are readable by default in the example, but arbitrary mutations are denied unless a narrower zone permits them.

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

No separate bind is required for `/workspace/draft`; it is an ordinary subdirectory of the agent workspace.

## Logging

With `logDecisions=true`, decisions are logged in a compact form similar to:

```text
agent-permissions: DENY agent=main write capability=fs.write operation=write paths=/workspace/AGENTS.md rule=workspace-core-readonly
```

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

1. **Approved shell commands are a separate authority.** Filesystem zones do not constrain arbitrary shell text.
2. **Physical isolation still matters.** Use Docker/OpenClaw sandboxing and read-only mounts for resources that must remain immutable.
3. **Symlink/hardlink safety is delegated to OpenClaw's filesystem layer.** The plugin performs lexical path normalization and policy matching; it does not reimplement filesystem canonicalization.
4. **Regex is not a shell parser.** Keep exec allows narrow and prefer ASK by default.
5. **Tool profiles must match reality.** A custom filesystem-mutating tool must be profiled correctly or it will be treated as a generic tool.
6. **Generic permanent approval is broader than filesystem permanent approval.** It is scoped by agent/tool/capability rather than exact parameters.
7. **Policy is only as good as its ordering.** Narrow zones belong before broad fallbacks.

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

Then run the runtime acceptance matrix in [TESTING.md](TESTING.md).

The acceptance tests intentionally include:

- absolute and relative paths;
- `..` traversal normalization;
- multi-target `apply_patch` denial;
- patch add/update/delete/move semantics;
- nested directory creation;
- read-only source access;
- cross-agent source denial;
- memory namespace allowlist behavior;
- stock OpenClaw symlink/hardlink protections;
- approval and learning behavior;
- exec regex behavior.

## Upgrade notes

### From 2.0.3 to 2.0.4

Runtime authorization code is unchanged. Replace the public-support files and review the refreshed example policy, especially:

- `/workspace/draft` replaces stale `scratch` documentation;
- both `YYYY-MM-DD.md` and `memory-YYYY-MM-DD.md` are allowed daily-note formats;
- all other `/workspace/memory/**` content is denied, including reads;
- public repository/package metadata is included.

Always diff your live `/home/openclaw/.openclaw/permissions.json` before replacing it with an example policy. The example is a template, not an automatic migration.

## License

MIT. See [LICENSE](LICENSE).
