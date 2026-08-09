# Gateway-side local tool inputs

OpenClaw agents can see sandbox paths such as `/workspace/draft/file.md`, while native plugin and MCP tools often execute in the Gateway process and therefore see host paths instead. Release 2.0.6 adds an operator-owned bridge for this case without teaching the generic policy engine about any specific third-party tool.

Two independent policy sections are used:

- `pathMappings` describes how sandbox-visible path trees map to Gateway-host trees.
- `localInputs` declares which parameter of which tool is a local filesystem input and which filesystem permission that input requires.

The model continues to use sandbox-visible paths. Host paths are never required in prompts or tool arguments produced by the model.

## Example

```json
{
  "pathMappings": [
    {
      "id": "agent-workspace",
      "description": "Current agent workspace",
      "virtual": "/workspace",
      "host": "/home/openclaw/.openclaw/workspace/{agentId}"
    },
    {
      "id": "openclaw-source-bind",
      "description": "Optional main-only source bind",
      "virtual": "/workspace/openclaw-src",
      "host": "/home/openclaw/openclaw",
      "agents": ["main"]
    }
  ],
  "localInputs": [
    {
      "id": "openviking-add-resource-source",
      "description": "OpenViking add_resource may consume local files or remote URLs",
      "tools": ["add_resource"],
      "selector": "source",
      "operation": "read",
      "remotePrefixes": ["http://", "https://", "git@", "ssh://", "git://"],
      "unmappedHint": "Sandbox-only paths such as /tmp are not visible to Gateway-side tools. Copy the file under /workspace/draft and retry."
    }
  ]
}
```

`{agentId}` is expanded only from the host-authoritative agent identity supplied by OpenClaw. The rendered value is restricted to a safe path segment.

When multiple mappings cover a path, the longest `virtual` prefix wins. This lets `/workspace` map dynamically per agent while a nested bind such as `/workspace/openclaw-src` maps somewhere else.

## Authorization order

For a declared local input such as `add_resource.source=/workspace/draft/doc.md`:

1. the sandbox-visible path is normalized;
2. the matching `pathMappings` entry is selected;
3. the host path is physically verified, including symlink escape checks;
4. the sandbox-visible path is checked against `filesystem.zones` using the configured `operation`;
5. normal generic-tool policy is evaluated;
6. only after authorization is complete is the declared parameter rewritten to the verified host path for the actual Gateway-side tool call.

A learned generic-tool approval therefore does not bypass filesystem policy.

## Remote and unsupported URI inputs

Values starting with a configured `remotePrefixes` entry are left untouched and are not treated as local files. This is useful for tools that accept both a local path and a remote URL.

Other URI schemes are denied fail-closed instead of being guessed as local paths. Add another remote prefix only when the target tool is known to handle that prefix as a remote source.

## Sandbox-only paths such as `/tmp`

A Gateway-side tool cannot normally read a file that exists only inside the sandbox `/tmp`. Do not invent a host mapping for such a tmpfs.

Use an `unmappedHint` to tell the agent how to recover, for example by copying the artifact to `/workspace/draft/...` and retrying the Gateway-side tool.

## Generic use

Nothing in the engine is specific to OpenViking. A future tool can be added by declaring its path-bearing parameter:

```json
{
  "id": "example-import-file",
  "tools": ["some_import_tool"],
  "selector": "input.file",
  "operation": "read",
  "mappingIds": ["agent-workspace"]
}
```

`selector` uses the same dotted/array selector style as the rest of the policy engine. `mappingIds` is optional; when omitted, every context-matching top-level path mapping is eligible.

Legacy `exec.paths.physicalMappings` remains supported for 2.0.5 policies, but top-level `pathMappings` is the preferred reusable mapping layer in 2.0.6 and is also consumed by exec physical verification.
