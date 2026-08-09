import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LearnedRuleStore, evaluatePolicy } from "../src/policy.js";
import { validatePolicy } from "../src/exec-no-target.js";
import { buildCallContext } from "../src/profiles.js";
import { extractPatchPaths, extractPatchTargets, normalizeToolPath } from "../src/paths.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const basePolicy = validatePolicy(JSON.parse(fs.readFileSync(path.join(root, "permissions.example.json"), "utf8")));
function call(toolName, params = {}, ctx = { agentId: "main" }, policy = basePolicy, eventExtra = {}) {
  return buildCallContext({ toolName, params, ...eventExtra }, ctx, policy, "/workspace");
}
function decision(toolName, params = {}, ctx = { agentId: "main" }, policy = basePolicy, store = null, eventExtra = {}) {
  const c = call(toolName, params, ctx, policy, eventExtra);
  return { call: c, decision: evaluatePolicy(policy, c, store) };
}
function tempStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ap-learned-"));
  return new LearnedRuleStore(path.join(dir, "learned.json"));
}

// Filesystem policy

test("filesystem protects core files and permits selected profile content edits", () => {
  assert.equal(decision("read", { path: "/workspace/AGENTS.md" }).decision.effect, "allow");
  assert.equal(decision("write", { path: "/workspace/AGENTS.md" }).decision.effect, "deny");
  assert.equal(decision("edit", { path: "/workspace/DREAMS.md" }).decision.effect, "deny");
  for (const name of ["USER.md", "IDENTITY.md", "SOUL.md", "MEMORY.md"]) {
    assert.equal(decision("edit", { path: `/workspace/${name}` }).decision.effect, "allow");
    assert.equal(decision("delete_file", { path: `/workspace/${name}` }).decision.effect, "deny");
  }
});

test("workspace draft is fully mutable while the rest of workspace is read-only by default", () => {
  assert.equal(decision("read", { path: "/workspace" }).decision.effect, "allow");
  assert.equal(decision("write", { path: "/workspace/random.txt" }).decision.effect, "deny");
  assert.equal(decision("write", { path: "/workspace/draft/x.txt" }).decision.effect, "allow");
  assert.equal(decision("delete_file", { path: "/workspace/draft/x.txt" }).decision.effect, "allow");
  assert.equal(decision("move", { from: "/workspace/draft/a", to: "/workspace/draft/b" }).decision.effect, "allow");
});


test("filesystem default is deny outside explicitly described zones", () => {
  assert.equal(decision("read", { path: "/etc/passwd" }).decision.effect, "deny");
  assert.equal(decision("write", { path: "/data/unconfigured.txt" }).decision.effect, "deny");
});

test("container tmpfs/runtime paths are intentionally shell-only for filesystem tools", () => {
  for (const rootPath of ["/tmp", "/var/tmp", "/run", "/var/run"]) {
    assert.equal(decision("read", { path: rootPath }).decision.effect, "deny");
    assert.equal(decision("write", { path: `${rootPath}/x` }).decision.effect, "deny");
  }
});

test("OpenClaw source bind is read-only for main and denied to other agents", () => {
  const source = "/workspace/openclaw-src/src/a.ts";
  assert.equal(decision("read", { path: "/workspace/openclaw-src" }, { agentId: "main" }).decision.effect, "allow");
  assert.equal(decision("read", { path: source }, { agentId: "main" }).decision.effect, "allow");
  assert.equal(decision("write", { path: source }, { agentId: "main" }).decision.effect, "deny");
  assert.equal(decision("edit", { path: source }, { agentId: "main" }).decision.effect, "deny");
  assert.equal(decision("delete_file", { path: source }, { agentId: "main" }).decision.effect, "deny");

  assert.equal(decision("read", { path: source }, { agentId: "igor" }).decision.effect, "deny");
  assert.equal(decision("write", { path: source }, { agentId: "igor" }).decision.effect, "deny");
  assert.equal(decision("edit", { path: source }, { agentId: "igor" }).decision.effect, "deny");
  assert.equal(decision("delete_file", { path: source }, { agentId: "igor" }).decision.effect, "deny");
  assert.equal(decision("move", { from: source, to: "/workspace/draft/stolen.ts" }, { agentId: "igor" }).decision.effect, "deny");
});

test("daily memory naming is enforced and all other memory content is inaccessible", () => {
  for (const filePath of [
    "/workspace/memory/2026-08-08.md",
    "/workspace/memory/memory-2026-08-08.md"
  ]) {
    assert.equal(decision("read", { path: filePath }).decision.effect, "allow");
    assert.equal(decision("write", { path: filePath }).decision.effect, "allow");
    assert.equal(decision("edit", { path: filePath }).decision.effect, "allow");
    assert.equal(decision("delete_file", { path: filePath }).decision.effect, "deny");
    assert.equal(decision("move", { from: filePath, to: "/workspace/draft/moved.md" }).decision.effect, "deny");
  }
  for (const filePath of [
    "/workspace/memory/nope.md",
    "/workspace/memory/dreaming/internal.json",
    "/workspace/memory/.dreams/state.json"
  ]) {
    assert.equal(decision("read", { path: filePath }).decision.effect, "deny");
    assert.equal(decision("write", { path: filePath }).decision.effect, "deny");
  }
});

test("filesystem zones can be agent scoped", () => {
  const p = structuredClone(basePolicy);
  p.filesystem.zones.unshift({
    id: "main-work-rw",
    agents: [{ exact: "main" }],
    path: { regex: "^/work(?:/.*)?$" },
    read: "allow", write: "allow", delete: "ask", move: "allow"
  });
  p.filesystem.zones.unshift({
    id: "igor-work-ro",
    agents: [{ exact: "igor" }],
    path: { regex: "^/work(?:/.*)?$" },
    read: "allow", write: "deny", delete: "deny", move: "deny"
  });
  validatePolicy(p);
  assert.equal(decision("write", { path: "/work/a" }, { agentId: "main" }, p).decision.effect, "allow");
  assert.equal(decision("write", { path: "/work/a" }, { agentId: "igor" }, p).decision.effect, "deny");
});

test("mixed apply_patch uses strictest filesystem effect", () => {
  const patch = `*** Begin Patch\n*** Update File: USER.md\n@@\n-a\n+b\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** End Patch`;
  assert.equal(decision("apply_patch", { patch }).decision.effect, "deny");
});

test("apply_patch extracts add update delete and move targets", () => {
  const patch = `*** Begin Patch\n*** Add File: a.txt\n+x\n*** Update File: b.txt\n*** Move to: c.txt\n@@\n-x\n+y\n*** Delete File: d.txt\n*** End Patch`;
  assert.deepEqual(extractPatchPaths(patch, "/workspace"), [
    "/workspace/a.txt", "/workspace/b.txt", "/workspace/c.txt", "/workspace/d.txt"
  ]);
});

test("apply_patch keeps delete and move semantics per target", () => {
  const deletePatch = `*** Begin Patch\n*** Delete File: USER.md\n*** End Patch`;
  assert.deepEqual(extractPatchTargets(deletePatch, "/workspace"), [
    { operation: "delete", path: "/workspace/USER.md" }
  ]);
  assert.equal(decision("apply_patch", { patch: deletePatch }).decision.effect, "deny");

  const movePatch = `*** Begin Patch\n*** Update File: draft/a.txt\n*** Move to: draft/b.txt\n@@\n-a\n+b\n*** End Patch`;
  const moveDecision = decision("apply_patch", { patch: movePatch });
  assert.equal(moveDecision.decision.effect, "allow");
  assert.ok(moveDecision.call.fsTargets.some((target) => target.operation === "move"));

  const forbiddenMove = `*** Begin Patch\n*** Update File: USER.md\n*** Move to: draft/user-copy.md\n*** End Patch`;
  assert.equal(decision("apply_patch", { patch: forbiddenMove }).decision.effect, "deny");
});

test("sandbox-visible parsed patch paths take precedence over host derivedPaths", () => {
  const patch = `*** Begin Patch\n*** Update File: USER.md\n@@\n-a\n+b\n*** End Patch`;
  const out = decision("apply_patch", { patch }, { agentId: "main" }, basePolicy, null, { derivedPaths: ["/home/openclaw/.openclaw/workspace/main/USER.md"] });
  assert.deepEqual(out.call.paths, ["/workspace/USER.md"]);
  assert.equal(out.decision.effect, "allow");
});

test("derivedPaths are used only as fallback", () => {
  const out = decision("apply_patch", {}, { agentId: "main" }, basePolicy, null, { derivedPaths: ["USER.md"] });
  assert.deepEqual(out.call.paths, ["/workspace/USER.md"]);
});

test("path normalization is lexical and unresolved home paths do not become workspace paths", () => {
  assert.equal(normalizeToolPath("a/../b", "/workspace"), "/workspace/b");
  assert.equal(normalizeToolPath("~/x", "/workspace"), "~/x");
});

// Exec policy


test("recognized exec tools with unresolved command parameters are denied", () => {
  const out = decision("exec", { script: "id" });
  assert.equal(out.decision.effect, "deny");
  assert.equal(out.decision.ruleId, "<exec-unresolved-command>");
});

test("exec precedence is deny then ask then allow then default", () => {
  const p = structuredClone(basePolicy);
  p.exec = {
    default: "ask",
    allowAlways: false,
    deny: [{ id: "deny-delete", regex: "(?:^|[;&|]\\s*)rm\\b", match: "search" }],
    ask: [{ id: "ask-curl", regex: "\\bcurl\\b", match: "search" }],
    allow: [{ id: "allow-rg", regex: "\\s*rg(?:\\s+[^;&|<>]+)?\\s*", match: "full" }]
  };
  validatePolicy(p);
  assert.equal(decision("exec", { command: "rg foo /workspace" }, { agentId: "main" }, p).decision.effect, "allow");
  assert.equal(decision("exec", { command: "rg foo /workspace && rm x" }, { agentId: "main" }, p).decision.effect, "deny");
  assert.equal(decision("exec", { command: "curl https://example.com" }, { agentId: "main" }, p).decision.effect, "ask");
  assert.equal(decision("exec", { command: "python -V" }, { agentId: "main" }, p).decision.effect, "ask");
});

test("exec rules can be scoped by agent and tool", () => {
  const p = structuredClone(basePolicy);
  p.exec.allow = [{ id: "main-id", agents: [{ exact: "main" }], tools: [{ exact: "exec" }], regex: "id", match: "full" }];
  validatePolicy(p);
  assert.equal(decision("exec", { command: "id" }, { agentId: "main" }, p).decision.effect, "allow");
  assert.equal(decision("exec", { command: "id" }, { agentId: "igor" }, p).decision.effect, "ask");
  assert.equal(decision("bash", { command: "id" }, { agentId: "main" }, p).decision.effect, "ask");
});

test("exec persistent approval is deliberately disabled; regex allow rules are the durable mechanism", () => {
  const p = structuredClone(basePolicy);
  p.exec.allowAlways = true;
  assert.throws(() => validatePolicy(p), /exec\.allowAlways=true.*unsupported/);
});

test("exec ASK entries cannot opt back into allow-always", () => {
  const p = structuredClone(basePolicy);
  p.exec.ask.push({ id: "bad-persist", regex: "id", allowAlways: true });
  assert.throws(() => validatePolicy(p), /allowAlways=true.*unsupported/);
});

// Generic tools

test("example MCP allowlist is exact and deployment-neutral", () => {
  for (const name of ["search", "read"]) {
    assert.equal(decision(`mcp__example_${name}`, {}).decision.effect, "allow");
  }
  for (const name of ["mcp__example_write", "mcp__firecrawl_search", "mcp__future_tool"]) {
    const out = decision(name, {});
    assert.equal(out.decision.effect, "ask");
    assert.equal(out.decision.allowAlways, false);
  }
});

test("real OpenViking read tools ask with allow-always; write tools ask per-call", () => {
  for (const name of ["memory_recall", "ov_search", "ov_read", "ov_multi_read", "ov_list", "openviking_tool_result_search"]) {
    const out = decision(name, {});
    assert.equal(out.call.capability, "memory.read");
    assert.equal(out.decision.effect, "ask");
    assert.equal(out.decision.allowAlways, true);
  }
  for (const name of ["memory_store", "memory_forget", "add_resource", "add_skill"]) {
    const out = decision(name, {});
    assert.equal(out.call.capability, "memory.write");
    assert.equal(out.decision.effect, "ask");
    assert.equal(out.decision.allowAlways, false);
  }
});

test("unknown tools ask but do not offer permanent trust by default", () => {
  const out = decision("future_unknown_tool", { anything: "x" });
  assert.equal(out.decision.effect, "ask");
  assert.equal(out.decision.allowAlways, false);
});

test("session and conversation reads are classified read-only", () => {
  assert.equal(decision("sessions_list", {}).decision.effect, "allow");
  assert.equal(decision("conversations_list", {}).decision.effect, "allow");
  assert.equal(decision("conversations_send", {}).decision.effect, "ask");
});

// Learned approvals

test("filesystem allow-always is tool-agnostic but operation- and path-specific", () => {
  const p = structuredClone(basePolicy);
  p.filesystem.zones.unshift({ id: "data-ask", path: { regex: "^/data(?:/.*)?$" }, read: "ask", write: "ask", delete: "deny", move: "deny", allowAlways: true });
  const store = tempStore();
  const first = decision("read", { path: "/data/a.txt" }, { agentId: "main" }, p, store);
  assert.equal(first.decision.effect, "ask");
  store.persist(first.call, first.decision);
  assert.equal(decision("read_file", { path: "/data/a.txt" }, { agentId: "main" }, p, store).decision.effect, "allow");
  assert.equal(decision("read", { path: "/data/b.txt" }, { agentId: "main" }, p, store).decision.effect, "ask");
  assert.equal(decision("write", { path: "/data/a.txt" }, { agentId: "main" }, p, store).decision.effect, "ask");
  assert.equal(decision("read", { path: "/data/a.txt" }, { agentId: "igor" }, p, store).decision.effect, "ask");
});

test("multi-path filesystem learning persists only ASK paths", () => {
  const p = structuredClone(basePolicy);
  p.toolProfiles.multi_reader = { capability: "fs.read", operation: "read", pathParams: ["paths[]"] };
  p.filesystem.zones.unshift({ id: "allowed", path: { exact: "/data/allowed" }, read: "allow" });
  p.filesystem.zones.unshift({ id: "asked", path: { exact: "/data/asked" }, read: "ask", allowAlways: true });
  validatePolicy(p);
  const store = tempStore();
  const first = decision("multi_reader", { paths: ["/data/allowed", "/data/asked"] }, { agentId: "main" }, p, store);
  assert.equal(first.decision.effect, "ask");
  assert.deepEqual(first.decision.askPaths, ["/data/asked"]);
  store.persist(first.call, first.decision);
  assert.equal(decision("read", { path: "/data/asked" }, { agentId: "main" }, p, store).decision.effect, "allow");
});

test("learned tool allow is agent-scoped and capability-sensitive", () => {
  const store = tempStore();
  const first = decision("memory_search", { query: "one" }, { agentId: "main" }, basePolicy, store);
  store.persist(first.call, first.decision);
  assert.equal(decision("memory_search", { query: "two" }, { agentId: "main" }, basePolicy, store).decision.effect, "allow");
  assert.equal(decision("memory_search", { query: "two" }, { agentId: "igor" }, basePolicy, store).decision.effect, "ask");
  const changed = structuredClone(basePolicy);
  changed.toolProfiles.memory_search = { capability: "external.write", operation: "search" };
  validatePolicy(changed);
  assert.equal(decision("memory_search", { query: "two" }, { agentId: "main" }, changed, store).decision.effect, "ask");
});

test("hard deny wins even if a matching filesystem grant already exists", () => {
  const p = structuredClone(basePolicy);
  p.filesystem.zones.unshift({ id: "agents-ask-temp", path: { exact: "/workspace/AGENTS.md" }, read: "allow", write: "ask", allowAlways: true });
  validatePolicy(p);
  const store = tempStore();
  const asked = decision("write", { path: "/workspace/AGENTS.md" }, { agentId: "main" }, p, store);
  store.persist(asked.call, asked.decision);
  const hardened = structuredClone(basePolicy);
  assert.equal(decision("write", { path: "/workspace/AGENTS.md" }, { agentId: "main" }, hardened, store).decision.effect, "deny");
});

// Validation and extension safety

test("toolProfiles remain extensible including fs.execute without pretending it controls shell exec", () => {
  const p = structuredClone(basePolicy);
  p.toolProfiles.future_runner = { capability: "fs.execute", operation: "execute", pathParams: ["target"] };
  p.filesystem.zones.unshift({
    id: "direct-execute-test",
    path: { regex: "^/workspace/draft(?:/.*)?$" },
    execute: "allow"
  });
  validatePolicy(p);
  assert.equal(decision("future_runner", { target: "/workspace/draft/script" }, { agentId: "main" }, p).decision.effect, "allow");
  assert.equal(decision("future_runner", { target: "/workspace/openclaw-src/script" }, { agentId: "main" }, p).decision.effect, "deny");
});

test("policy validation rejects unknown fields and duplicate ids", () => {
  const typo = structuredClone(basePolicy);
  typo.filesystem.zones[0].wriet = "allow";
  assert.throws(() => validatePolicy(typo), /unknown field/);
  const duplicate = structuredClone(basePolicy);
  duplicate.tools.ask.push({ ...duplicate.tools.ask[0] });
  assert.throws(() => validatePolicy(duplicate), /duplicate/);
});

test("learned file is structured version 2 and mode 0600", () => {
  const store = tempStore();
  const first = decision("memory_search", { query: "one" });
  store.persist(first.call, first.decision);
  const parsed = JSON.parse(fs.readFileSync(store.filePath, "utf8"));
  assert.equal(parsed.version, 2);
  assert.equal(parsed.allow[0].kind, "tool");
  assert.equal(fs.statSync(store.filePath).mode & 0o777, 0o600);
});

test("exec full-match remains full even with multiline regex flag", () => {
  const p = structuredClone(basePolicy);
  p.exec.allow = [{ id: "safe-echo", regex: "echo safe", flags: "m", match: "full" }];
  validatePolicy(p);
  assert.equal(decision("exec", { command: "echo safe" }, { agentId: "main" }, p).decision.effect, "allow");
  assert.equal(decision("exec", { command: "echo safe\nrm -rf /tmp/x" }, { agentId: "main" }, p).decision.effect, "ask");
});


test("recognized filesystem tools with unresolved targets are denied", () => {
  const out = decision("write", { content: "x" });
  assert.equal(out.decision.effect, "deny");
  assert.equal(out.decision.ruleId, "<filesystem-unresolved-path>");
});

test("host-side derived workspace paths map back to sandbox-visible workspace paths", () => {
  const ctx = { agentId: "main", workspaceDir: "/home/openclaw/.openclaw/workspace/main" };
  const out = decision(
    "apply_patch",
    {},
    ctx,
    basePolicy,
    null,
    { derivedPaths: ["/home/openclaw/.openclaw/workspace/main/USER.md"] }
  );
  assert.deepEqual(out.call.paths, ["/workspace/USER.md"]);
  assert.equal(out.decision.effect, "allow");
});

test("copy tools require read on source and write on destination", () => {
  const denied = decision("copy_file", { source: "/workspace/draft/a", destination: "/workspace/AGENTS.md" });
  assert.equal(denied.decision.effect, "deny");

  const fromReadonly = decision("copy_file", { source: "/workspace/AGENTS.md", destination: "/workspace/draft/agents-copy.md" });
  assert.equal(fromReadonly.decision.effect, "allow");
  assert.deepEqual(fromReadonly.call.fsTargets, [
    { operation: "read", path: "/workspace/AGENTS.md" },
    { operation: "write", path: "/workspace/draft/agents-copy.md" }
  ]);
});

test("tool ASK rules without selectors are rejected and allow-always defaults off", () => {
  const invalid = structuredClone(basePolicy);
  invalid.tools.ask.push({ id: "oops" });
  assert.throws(() => validatePolicy(invalid), /at least one match selector/);

  const p = structuredClone(basePolicy);
  p.tools.ask.push({ id: "explicit-unknown", tools: [{ exact: "ask_me" }] });
  validatePolicy(p);
  const out = decision("ask_me", {}, { agentId: "main" }, p);
  assert.equal(out.decision.effect, "ask");
  assert.equal(out.decision.allowAlways, false);
});

test("malformed learned entries fail closed instead of being silently ignored", () => {
  const store = tempStore();
  fs.writeFileSync(store.filePath, JSON.stringify({ version: 2, allow: [{ kind: "tool", agentId: null, toolName: "x", capability: "tool" }] }), { mode: 0o600 });
  assert.throws(() => store.matchesTool("main", "x", "tool"), /invalid/);
});
