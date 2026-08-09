# Contributing

Contributions are welcome when they preserve the plugin's core design: explicit operator policy, fail-closed handling, predictable precedence, and separation between filesystem, exec, and generic-tool authority.

## Development setup

Requirements:

- Node.js 22+
- a checkout of this repository

Run:

```bash
npm run check
```

before submitting changes.

## Design rules

Please keep these invariants intact:

1. Authorize sandbox-visible paths before any execution compatibility rewrite.
2. A denied call must never be rewritten into an executable form first.
3. Compound filesystem tools must preserve operation semantics for every source/destination target.
4. Multi-target policy strictness remains `deny > ask > allow`.
5. Unresolved filesystem targets and unresolved exec commands fail closed.
6. Filesystem permissions must not be described or implemented as restrictions on arbitrary approved shell commands.
7. Permanent exec approval remains explicit policy, not learned UI state.
8. Agent-specific rules must not silently become global.
9. Unknown policy fields should fail validation instead of being ignored.

## Tests

Add regression tests for every authorization bug.

A useful security regression test should prove both sides when applicable:

- allowed target succeeds;
- adjacent protected target is denied;
- filesystem state remains unchanged after denial.

For path bugs, include absolute, relative, and traversal forms where relevant.

For `apply_patch`, test operation semantics rather than only checking path extraction.

## Documentation

Update README/TESTING/CHANGELOG whenever behavior, policy schema, built-in tool profiles, or compatibility assumptions change.

Do not document an OpenClaw or Docker behavior as if it were enforced by this plugin unless the plugin actually performs that enforcement.
