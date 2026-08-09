# Installation and Upgrade

This guide assumes OpenClaw is installed for the `openclaw` user and the plugin will live at:

```text
/home/openclaw/plugins/agent-permissions
```

Adjust paths for your installation.

## Requirements

- OpenClaw compatible with the plugin API used by `2026.7.2` or newer compatible builds
- Node.js 22+
- a sandbox-visible workspace root, normally `/workspace`
- an operator-owned policy file outside agent workspaces

## Fresh installation

Extract the plugin release archive:

```bash
mkdir -p /home/openclaw/plugins/agent-permissions
tar -xzf agent-permissions-v2.0.5.tar.gz \
  -C /home/openclaw/plugins/agent-permissions \
  --strip-components=1
```

If you use a ZIP release asset instead, extract it so `package.json`, `openclaw.plugin.json`, `dist/`, and the other plugin files are directly below `/home/openclaw/plugins/agent-permissions`.

Set ownership if necessary:

```bash
chown -R openclaw:openclaw /home/openclaw/plugins/agent-permissions
```

Create the live policy from the example:

```bash
cp /home/openclaw/plugins/agent-permissions/permissions.example.json \
  /home/openclaw/.openclaw/permissions.json
chmod 600 /home/openclaw/.openclaw/permissions.json
chown openclaw:openclaw /home/openclaw/.openclaw/permissions.json
```

Edit the policy for your agents, tool names, mounts, and approval model before enabling the plugin.

## OpenClaw configuration

Add the plugin load path:

```json
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
```

Do not keep a second installed copy under another extension directory; duplicate plugin copies make runtime behavior difficult to reason about.

## Recommended sandbox layout

The example policy assumes:

```text
/workspace/
├── AGENTS.md
├── DREAMS.md
├── USER.md
├── IDENTITY.md
├── SOUL.md
├── MEMORY.md
├── memory/
├── draft/
└── openclaw-src/   # optional, main-only read-only bind
```

`/workspace/draft` is a normal workspace directory. It does not need a separate Docker bind.

Keep normal container runtime locations such as `/tmp`, `/var/tmp`, `/run`, and `/var/run` as container/runtime space. Direct filesystem-tool access and shell access are independent policy decisions.

## Exec path guard in 2.0.5

Version 2.0.5 adds an independent `exec.paths` layer. It does not reuse `filesystem.zones`.

The intended separation is:

```text
filesystem.zones  -> direct filesystem tools
exec command rules -> which shell commands may run silently
exec.paths         -> where an otherwise-silent shell command may access files
```

The strictest exec result wins. A path ALLOW never makes an unsafe command safe.

When `exec.paths` is enabled:

- explicit shell path operands are normalized before matching;
- ambiguous or dynamic path analysis becomes ASK;
- relative paths resolve below `virtualWorkspaceRoot` when they can be resolved safely;
- no-target commands require explicit trust in `exec.paths.pathless.allow` before they can remain silent;
- silently allowed `/workspace/**` targets receive best-effort physical verification against their host mapping.

## Optional read-only OpenClaw source bind

If one agent needs source visibility, mount it physically read-only:

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

Current OpenClaw requires the dangerous bind-source/target override flags when an operator-owned external source is mounted below the reserved `/workspace` target.

If `exec.paths` silently allows that external bind, declare its host mapping so physical verification does not incorrectly assume it belongs to the normal agent workspace:

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

`virtual` is the sandbox-visible mount prefix. `host` is the operator-known host source. Mapping rules may be agent-scoped; the most specific matching virtual prefix is used.

Do not mount the source into agents that should never see it. Keep an explicit policy deny for those agents as defense in depth.

Changing Docker binds, tmpfs settings, image, or other sandbox container configuration requires sandbox recreation.

## Policy reload versus plugin-code reload

The policy file is reloaded when it changes, so ordinary policy edits do not require reinstalling the plugin.

Plugin JavaScript is loaded by the gateway process. After pulling or replacing plugin code, rebuild if needed and restart the gateway before runtime testing the new code.

## Validate before restart

From the plugin directory:

```bash
cd /home/openclaw/plugins/agent-permissions
npm run check
npm run policy:check -- /home/openclaw/.openclaw/permissions.json
openclaw config validate
```

All three should pass before the gateway is restarted.

## Restart

Use the gateway lifecycle commands appropriate for your installation, for example:

```bash
openclaw gateway stop
openclaw gateway start
```

Then inspect startup logs and confirm that `agent-permissions` loaded the expected policy path.

## Upgrade from 2.0.4

Version 2.0.5 changes runtime authorization behavior for exec only when `exec.paths` is configured. Existing 2.0.4 policies without `exec.paths` retain the previous exec-path behavior.

Recommended migration:

1. update the plugin files;
2. keep your existing live policy;
3. add `exec.paths` deliberately rather than replacing the entire policy from the example;
4. add `pathless.allow` for commands that are trusted to run without explicit filesystem targets;
5. add `physicalMappings` for silently allowed external binds below `/workspace`;
6. run `npm run check` and `policy:check`;
7. restart the gateway because plugin code changed;
8. perform the focused runtime checks in [TESTING.md](TESTING.md).

Do **not** blindly replace your live `/home/openclaw/.openclaw/permissions.json` with `permissions.example.json`. Diff them and migrate intentionally.

## Policy file permissions

Recommended:

```bash
chmod 600 /home/openclaw/.openclaw/permissions.json
```

If learning is enabled, the plugin writes the learned file with mode `0600` automatically.

## Clean rollback

To roll back code, restore the previous release/commit and restart the gateway. To disable the plugin without deleting it, set its OpenClaw plugin entry to disabled and restart the gateway.

Keep a backup of the policy and OpenClaw configuration before changing plugin load paths or sandbox mounts.
