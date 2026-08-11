# Changelog

## 2.0.13

- treat a trailing slash on an already-authorized mapped directory as the same physical virtual target during exec path verification
- preserve the original shell command and lexical path for policy matching, logging, and execution; only the final physical identity comparison ignores trailing separators
- keep symlink escape, mapping-scope, and fail-closed physical verification behavior unchanged

## 2.0.12

- reduce false ASK results for read-only diagnostics using ordinary backslashes inside quoted grep/find patterns
- allow only harmless redirections to `/dev/null` plus `1>&2` / `2>&1` in exec path analysis
- recognize `find` pattern operands such as `-name`, `-path`, and `-regex` as predicates rather than filesystem targets
- preserve fail-closed ASK for command substitution, backticks, real file redirection, background/process-substitution ambiguity, and actual path globs

## 2.0.11

- add one visible blank line before and after the common approval action section so Telegram/Web separate the requested action from surrounding approval metadata
- keep the existing wrap-safe Unicode separators, 300-character preferred action budget, secret-safe generic tool rendering, and authorization semantics unchanged

## 2.0.10

- replace side-wall approval boxes with wrap-safe Unicode section separators that remain readable in Telegram and Web when clients reflow long lines
- remove artificial command wrapping and continuation markers; only real command newlines remain explicitly marked with `↵`
- increase preferred visible action content from 190 to 300 characters while dynamically reserving room for policy and permanent-approval metadata
- keep the same unified presentation for exec, filesystem, OpenViking `remove_resource`, MCP, generic, and future unknown-tool approvals
- keep authorization, learning, fail-closed behavior, tool parameter secrecy, and approval semantics unchanged

## 2.0.9

- render every ASK through one compact approval presentation for exec, filesystem, OpenViking, MCP, generic, and future unknown tools
- put the actual requested action first inside a visible Unicode frame so Web and Telegram approval surfaces remain understandable without surrounding chat context
- show exec command text directly, including visible newline/tab/control-character markers and bounded head/tail truncation for long commands
- keep tool parameters hidden by default; unknown MCP/future tools expose the exact tool name without dumping arbitrary arguments or secrets
- retain the allowlisted `remove_resource` URI/recursive/wait details inside the same common request frame
- show permanent-approval availability and scope consistently for ASK rules with and without `Allow always`
- keep authorization, learning, fail-closed semantics, policy matching, and execution parameter rewriting unchanged

## 2.0.8

- show allowlisted OpenViking `remove_resource` target URI, recursive flag, and wait flag in approval prompts
- sanitize and bound displayed approval detail values without dumping arbitrary tool parameters
- keep `memory.write` classification and per-call approval semantics unchanged

## 2.0.7

- classify OpenViking `remove_resource` as a built-in `memory.write` tool with operation `remove_resource`
- keep `remove_resource` out of `localInputs`: it authorizes a Viking resource URI, not a sandbox-local filesystem source path
- add regression coverage proving the shipped memory-write policy treats `remove_resource` as a per-call ASK with no Allow always
- refresh committed `dist/profiles.js` alongside source so linked production installs load the same built-in profile

## 2.0.6

- add reusable top-level `pathMappings` that map sandbox-visible paths to physically verified gateway-host paths, including `{agentId}` host templates for multi-agent workspaces
- add generic top-level `localInputs` rules that declare which tool parameter contains a local path, which filesystem operation it requires, which remote prefixes bypass local mapping, and optional remediation text
- authorize local tool inputs through the existing filesystem zones before rewriting any tool parameter, preventing learned generic-tool approvals from bypassing protected filesystem paths
- rewrite only declared local-input parameters after authorization so gateway-side tools can consume files that agents know as `/workspace/...`
- reject unmapped sandbox-only paths fail-closed and support operator guidance such as copying `/tmp` artifacts into `/workspace/draft` before retrying
- reject undeclared URI schemes instead of accidentally treating them as local paths
- reuse top-level mappings for exec physical verification, so one dynamic `/workspace -> .../{agentId}` mapping covers every agent while longer mappings still win for nested external binds
- preserve legacy `exec.paths.physicalMappings` for backward compatibility
- add regression coverage for per-agent mapping, remote resource sources, protected filesystem zones, unmapped `/tmp`, unsupported URI schemes, parameter rewriting, and exec physical verification

## 2.0.5

- add an independent `exec.paths` policy layer so silently allowed shell commands can be restricted by sandbox-visible filesystem targets without coupling shell authorization to `filesystem.zones`
- combine exec command and exec path decisions fail-closed with `DENY > ASK > ALLOW`; path permission never upgrades an unsafe or unknown command
- normalize explicit absolute and relative exec path operands before matching, including lexical `.` / `..` traversal
- treat dynamic/ambiguous shell/path constructs conservatively as ASK
- add configurable `exec.paths.pathless.allow` command-word trust for commands that can safely run without explicit filesystem targets; unproven no-target commands ASK
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