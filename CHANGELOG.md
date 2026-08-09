# Changelog

## 2.0.5

- add an independent `exec.paths` policy layer so silently allowed shell commands can be restricted by sandbox-visible filesystem targets without coupling shell authorization to `filesystem.zones`
- combine exec command and path decisions fail-closed with `DENY > ASK > ALLOW`; path permission never upgrades an unsafe or unknown command
- normalize explicit absolute and relative exec path operands before matching, including lexical `.` / `..` traversal
- treat dynamic/ambiguous shell path analysis and path expansions conservatively as ASK
- add configurable `exec.paths.pathless.allow` command-word trust for commands that can safely run without an explicit filesystem target; unproven no-target commands ASK
- add host-side physical verification for silently allowed `/workspace/**` exec targets to catch symlink aliases before shell execution
- add configurable `exec.paths.physicalMappings` for external sandbox binds such as `/workspace/openclaw-src` -> `/home/openclaw/openclaw`, with optional agent scoping and longest-prefix selection
- keep non-workspace container paths lexical because host `/etc`, `/usr`, `/tmp`, and similar paths are not the sandbox namespace
- fix `policy:check` so it validates the final 2.0.5 schema, including `pathless` and physical mappings
- expand automated regression coverage from the 2.0.4 baseline and verify the new exec guard in live OpenClaw runtime tests

## 2.0.4

- runtime authorization logic remains unchanged from 2.0.3
- replace stale `scratch` documentation with the tested `/workspace/draft` layout
- document both canonical daily-note forms: `YYYY-MM-DD.md` and `memory-YYYY-MM-DD.md`
- change the shipped example policy so all other `/workspace/memory/**` content is denied, including reads
- add a complete public operator manual, security model, contribution guide, and expanded runtime acceptance matrix
- add public GitHub package metadata and repository hygiene files
- make the example MCP allowlist deployment-neutral instead of assuming a specific Firecrawl installation

## 2.0.3

- Preserve the sandbox-facing `/workspace` policy model while working around an OpenClaw memory-write-provenance bug for sandbox-absolute filesystem mutation paths.
- Authorize canonical sandbox-visible paths first, then rewrite only allowed/approved filesystem mutation execution parameters from `/workspace/...` to workspace-relative form.
- Cover write/edit/delete/move/copy/apply_patch compatibility rewriting; read, exec and process calls remain untouched.
- Add regression tests proving deny/traversal policy is evaluated before any execution rewrite.

## 2.0.2

- final workspace layout: persistent `/workspace/scratch`, read-only `/workspace/openclaw-src`, stock container tmpfs retained
- removed the host-backed `/tmp` architecture and per-file Docker RO overlays from the recommended design
- direct file-tool access to `/tmp`, `/var/tmp`, `/run`, and `/var/run` is explicitly denied as shell-only runtime space
- `USER.md`, `IDENTITY.md`, `SOUL.md`, and `MEMORY.md` are writable but non-deletable/non-movable
- date-shaped `memory/memory-YYYY-MM-DD.md` notes are writable; other workspace memory content remains read-only
- recognized filesystem calls with unresolved target paths now fail closed
- host-side OpenClaw `derivedPaths` under an agent workspace are mapped back to sandbox-visible `/workspace` paths
- compound filesystem calls carry operation/path targets separately
- `apply_patch` Delete now checks `delete`, Move checks `move`, and Add/Update checks `write`
- copy tools check source `read` separately from destination `write`
- exec `Allow always` removed: durable shell trust must be expressed as explicit regex allow rules
- ASK rules default to no permanent trust unless explicitly enabled
- matchless tool rules are rejected by policy validation
- pending `Allow always` callbacks capture the learned store active when the request was created
- mutation approvals are shown as critical severity
- packaged `dist/` entrypoint receives a runtime smoke test
- test suite expanded beyond the v2.0.1 baseline

## 2.0.1

- agent-scoped, operation-scoped exact-path filesystem learning
- structured learned-policy format v2, mode 0600
- unknown tools no longer offer permanent trust by default
- permanent trust disabled when agent identity is unavailable
- agent/session scoping for filesystem zones
- agent/session/tool scoping for exec regex entries
- exact full-command regex matching, safe even with multiline regex flags
- stricter policy validation with unknown-field and duplicate-id rejection
- current Firecrawl allowlist narrowed to the six configured tools
- OpenViking read/write tool profiles expanded
- session/conversation tool profiles expanded
- deprecated OpenClaw `timeoutBehavior` removed
- approval description bounded below current OpenClaw limit
- `policy:check` operator validation command
