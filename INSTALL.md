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

Extract the plugin:

```bash
mkdir -p /home/openclaw/plugins/agent-permissions
tar -xzf agent-permissions-v2.0.4.tar.gz \
  -C /home/openclaw/plugins/agent-permissions \
  --strip-components=1
```

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

Keep normal container runtime locations such as `/tmp`, `/var/tmp`, `/run`, and `/var/run` as container/runtime space. The example filesystem policy denies direct file-tool access to them; shell access remains subject to the independent exec policy.

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

Do not mount the source into agents that should never see it. Keep the policy deny for those agents as defense in depth.

Changing Docker binds, tmpfs settings, image, or other sandbox container configuration requires sandbox recreation.

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

## Upgrade from 2.0.3

`2.0.4` keeps the `2.0.3` runtime authorization implementation. It primarily refreshes documentation, metadata, and the example policy.

If you are overlaying only the release-support files, extract the overlay archive directly over the installed directory:

```bash
tar -xzf agent-permissions-v2.0.4-overlay.tar.gz \
  -C /home/openclaw/plugins/agent-permissions
```

Then restore ownership if needed and run the validation commands above.

Do **not** blindly replace your live `/home/openclaw/.openclaw/permissions.json` with `permissions.example.json`. Diff them and migrate intentionally.

## Policy file permissions

Recommended:

```bash
chmod 600 /home/openclaw/.openclaw/permissions.json
```

If learning is enabled, the plugin writes the learned file with mode `0600` automatically.

## Clean rollback

To disable the plugin without deleting it, set its OpenClaw plugin entry to disabled and restart the gateway. Keep a backup of the policy and OpenClaw configuration before changing plugin load paths or sandbox mounts.
