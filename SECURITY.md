# Security Policy

## Threat model

`agent-permissions` is intended to reduce accidental or cooperative-agent misuse and to make operator authorization explicit and auditable.

It is **not** intended to contain arbitrary malicious code after the operator has granted unrestricted shell/process authority.

The security model assumes multiple independent layers:

1. Docker/OpenClaw sandboxing provides the physical container boundary.
2. Read-only binds protect immutable external resources.
3. `agent-permissions` authorizes recognized filesystem, exec, and generic tool calls.
4. Operator approval remains required where policy returns ASK.

## Important boundaries

### Filesystem zones and exec paths are independent

`filesystem.zones` authorize recognized direct filesystem tools. They do not automatically constrain shell commands.

Version 2.0.5 adds an independent `exec.paths` guard for shell commands that would otherwise be silently allowed by exec command policy. This separation is intentional: an installation may permit direct filesystem tools in one namespace while allowing silent shell inspection in a different namespace.

For exec, command policy and path policy are combined fail-closed. A path ALLOW never upgrades an unsafe command; the strictest result wins.

An operator-approved arbitrary shell command is still a separate authority. Docker/container controls remain necessary for resources that must be physically protected.

### Exec path analysis

`exec.paths` performs conservative lexical analysis, not a complete shell parse.

It normalizes detected explicit path operands before policy matching. Relative paths resolve below the configured virtual workspace root when they can be resolved safely. Dynamic or ambiguous analysis becomes ASK rather than silent ALLOW.

Commands with no detected explicit filesystem target require explicit command-word trust in `exec.paths.pathless.allow` before the path layer permits a silent ALLOW. This prevents commands that implicitly use the current working directory from silently roaming the workspace merely because their command regex is read-only.

### Physical verification of mapped workspace paths

For otherwise-silent `/workspace/**` exec targets, 2.0.5 performs best-effort host-side physical verification when a host mapping is available.

The ordinary agent workspace uses the runtime host `workspaceDir`. External binds below the virtual workspace should be declared with `exec.paths.physicalMappings`, for example:

```json
{
  "id": "openclaw-source-bind",
  "virtual": "/workspace/openclaw-src",
  "host": "/home/openclaw/openclaw",
  "agents": ["main"]
}
```

The most specific matching virtual prefix is used. Symlink resolution that escapes the selected physical host root or changes the expected virtual target becomes ASK before silent shell execution.

Host-side physical verification is intentionally not applied to ordinary container paths such as `/etc`, `/usr`, `/proc`, or `/tmp`, because host paths with those names are not the sandbox namespace.

### Symlinks and hardlinks

For direct filesystem tools, OpenClaw's filesystem safety layer and the operating system/container boundary remain responsible for symlink and hardlink enforcement.

For silently allowed mapped `/workspace/**` exec targets, the plugin additionally verifies physical path/symlink consistency as described above.

This does **not** provide complete hardlink-alias detection or turn shell execution into a hostile-code sandbox. Use physical read-only mounts and container isolation where aliasing or arbitrary approved shell execution must not cross a security boundary.

### Tool profiles

A custom tool that mutates files must be mapped to an appropriate filesystem capability and path selectors. Otherwise it is evaluated as a generic tool and will not receive filesystem-zone semantics.

### Learned approvals

Filesystem learned approvals are exact-path, operation-scoped, and agent-scoped. Generic-tool learned approvals are agent/tool/capability scoped and can therefore cover changing parameters.

Exec permanent approvals are intentionally unsupported; durable shell trust belongs in explicit operator-owned regex rules.

## Recommended deployment

- keep `failClosed=true`;
- keep the policy and learned-policy files outside agent workspaces;
- protect policy files with restrictive permissions;
- use read-only Docker binds for immutable external trees;
- avoid duplicate plugin installations;
- keep `exec.default=ask` unless you have a narrowly reviewed rule set;
- if using `exec.paths`, keep its default conservative and explicitly trust only intended path namespaces;
- keep `pathless.allow` limited to commands that are genuinely safe without explicit filesystem targets;
- declare `physicalMappings` for silently allowed external binds below `/workspace`;
- place narrow filesystem zones before broad fallbacks;
- validate policy before gateway restart;
- restart the gateway after plugin-code upgrades;
- keep backups before destructive acceptance tests.

## Reporting a vulnerability

Please open a GitHub issue only for non-sensitive defects.

For a vulnerability that would expose secrets, cross an agent boundary, bypass a DENY rule, or permit unauthorized filesystem mutation, use GitHub's private vulnerability reporting feature when available rather than posting exploit details publicly.

Include:

- OpenClaw version and commit if known;
- plugin version;
- relevant policy fragment with secrets removed;
- tool name and parameters;
- expected result;
- actual result;
- whether the block/failure came from `agent-permissions`, OpenClaw filesystem safety, Docker, or the operating system.
