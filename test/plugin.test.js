import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import plugin from "../src/index.js";

function setup(mutator = null, config = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-perms-"));
  const policy = JSON.parse(fs.readFileSync(new URL("../permissions.example.json", import.meta.url), "utf8"));
  policy.learning.path = path.join(dir, "learned.json");
  if (mutator) mutator(policy);
  const policyPath = path.join(dir, "permissions.json");
  fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2));
  let hook;
  const logs = [];
  const api = {
    pluginConfig: { policyPath, virtualWorkspaceRoot: "/workspace", logDecisions: true, ...config },
    logger: { info: (message) => logs.push(message), warn: (message) => logs.push(message) },
    on(name, fn) { if (name === "before_tool_call") hook = fn; }
  };
  plugin.register(api);
  return { hook, policyPath, learnedPath: policy.learning.path, workspaceDir: dir, logs };
}

test("memory ASK exposes allow-always and persists agent-scoped trust", async () => {
  const { hook, learnedPath } = setup();
  const asked = await hook({ toolName: "memory_search", params: { query: "one" } }, { agentId: "main" });
  assert.deepEqual(asked.requireApproval.allowedDecisions, ["allow-once", "allow-always", "deny"]);
  assert.equal(Object.hasOwn(asked.requireApproval, "timeoutBehavior"), false);
  await asked.requireApproval.onResolution("allow-always");
  assert.equal(fs.statSync(learnedPath).mode & 0o777, 0o600);
  assert.equal(await hook({ toolName: "memory_search", params: { query: "two" } }, { agentId: "main" }), undefined);
  assert.ok((await hook({ toolName: "memory_search", params: { query: "two" } }, { agentId: "igor" })).requireApproval);
});


test("pending allow-always persists to the store captured when approval was requested", async () => {
  const { hook, policyPath, learnedPath } = setup();
  const asked = await hook({ toolName: "memory_search", params: { query: "one" } }, { agentId: "main" });

  const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
  const replacementLearnedPath = path.join(path.dirname(learnedPath), "replacement-learned.json");
  policy.learning.path = replacementLearnedPath;
  fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2));

  await asked.requireApproval.onResolution("allow-always");
  assert.equal(fs.existsSync(learnedPath), true);
  assert.equal(fs.existsSync(replacementLearnedPath), false);
});

test("filesystem allow-always applies across read tools but not write", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({ id: "data-ask", path: { regex: "^/data(?:/.*)?$" }, read: "ask", write: "ask", delete: "deny", move: "deny", allowAlways: true });
  });
  const asked = await hook({ toolName: "read", params: { path: "/data/a" } }, { agentId: "main" });
  assert.deepEqual(asked.requireApproval.allowedDecisions, ["allow-once", "allow-always", "deny"]);
  await asked.requireApproval.onResolution("allow-always");
  assert.equal(await hook({ toolName: "read_file", params: { path: "/data/a" } }, { agentId: "main" }), undefined);
  assert.ok((await hook({ toolName: "write", params: { path: "/data/a" } }, { agentId: "main" })).requireApproval);
});

test("unknown tool ASK does not offer allow-always", async () => {
  const { hook } = setup();
  const asked = await hook({ toolName: "future_unknown_tool", params: {} }, { agentId: "main" });
  assert.deepEqual(asked.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});


test("recognized exec tool fails closed when command cannot be extracted", async () => {
  const { hook } = setup();
  const denied = await hook({ toolName: "exec", params: { script: "id" } }, { agentId: "main" });
  assert.equal(denied.block, true);
  assert.match(denied.blockReason, /command could not be resolved/);
});

test("exec does not offer allow-always by default", async () => {
  const { hook } = setup();
  const asked = await hook({ toolName: "exec", params: { command: "python -V" } }, { agentId: "main" });
  assert.deepEqual(asked.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});

test("exec allow-always is rejected by policy validation", async () => {
  const { hook } = setup((policy) => { policy.exec.allowAlways = true; });
  const out = await hook({ toolName: "exec", params: { command: "id" } }, { agentId: "main" });
  assert.equal(out.block, true);
  assert.match(out.blockReason, /exec\.allowAlways=true.*unsupported/);
});

test("filesystem hard deny returns a block", async () => {
  const { hook } = setup();
  const denied = await hook({ toolName: "write", params: { path: "/workspace/AGENTS.md" } }, { agentId: "main" });
  assert.equal(denied.block, true);
  assert.match(denied.blockReason, /AGENTS\.md|write policy/);
});

test("recognized filesystem tools fail closed when no target path can be extracted", async () => {
  const { hook } = setup();
  const denied = await hook({ toolName: "write", params: { content: "x" } }, { agentId: "main" });
  assert.equal(denied.block, true);
  assert.match(denied.blockReason, /target could not be resolved/);
});

test("invalid hot reload fails closed", async () => {
  const { hook, policyPath } = setup();
  fs.writeFileSync(policyPath, "{broken", "utf8");
  const out = await hook({ toolName: "mcp__firecrawl_search", params: {} }, { agentId: "main" });
  assert.equal(out.block, true);
});

test("invalid learned file fails closed once learning is consulted", async () => {
  const { hook, learnedPath } = setup();
  fs.writeFileSync(learnedPath, "{broken", { mode: 0o600 });
  const out = await hook({ toolName: "memory_search", params: {} }, { agentId: "main" });
  assert.equal(out.block, true);
});

test("failClosed=false allows on engine failure", async () => {
  const { hook, policyPath } = setup(null, { failClosed: false });
  fs.writeFileSync(policyPath, "{broken", "utf8");
  assert.equal(await hook({ toolName: "mcp__firecrawl_search", params: {} }, { agentId: "main" }), undefined);
});

test("legacy event.context fallback still carries agent identity", async () => {
  const { hook } = setup();
  const asked = await hook({ toolName: "memory_search", params: {}, context: { agentId: "main", sessionKey: "s" } }, undefined);
  assert.match(asked.requireApproval.description, /Agent: main/);
});

test("approval descriptions stay within current OpenClaw cap", async () => {
  const { hook } = setup();
  const asked = await hook({ toolName: "memory_search", params: { query: "x".repeat(2000) } }, { agentId: "main" });
  assert.ok(asked.requireApproval.description.length <= 512);
});

test("allow-always is never offered when agent identity is unavailable", async () => {
  const { hook } = setup();
  const asked = await hook({ toolName: "memory_search", params: { query: "x" } }, {});
  assert.deepEqual(asked.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});

test("allowed sandbox-absolute write is authorized first then rewritten workspace-relative", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
  });
  const out = await hook(
    { toolName: "write", params: { path: "/workspace/draft/a.txt", content: "one" } },
    { agentId: "main" }
  );
  assert.deepEqual(out, { params: { path: "draft/a.txt", content: "one" } });
});

test("relative filesystem mutation remains relative and needs no adjusted params", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
  });
  const out = await hook(
    { toolName: "write", params: { path: "draft/a.txt", content: "one" } },
    { agentId: "main" }
  );
  assert.equal(out, undefined);
});

test("filesystem compatibility rewrite covers edit delete move and copy", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
  });

  assert.deepEqual(
    await hook({ toolName: "edit", params: { path: "/workspace/draft/a.txt", oldText: "a", newText: "b" } }, { agentId: "main" }),
    { params: { path: "draft/a.txt", oldText: "a", newText: "b" } }
  );
  assert.deepEqual(
    await hook({ toolName: "delete_file", params: { path: "/workspace/draft/a.txt" } }, { agentId: "main" }),
    { params: { path: "draft/a.txt" } }
  );
  assert.deepEqual(
    await hook({ toolName: "move", params: { source: "/workspace/draft/a.txt", destination: "/workspace/draft/b.txt" } }, { agentId: "main" }),
    { params: { source: "draft/a.txt", destination: "draft/b.txt" } }
  );
  assert.deepEqual(
    await hook({ toolName: "copy_file", params: { source: "/workspace/AGENTS.md", destination: "/workspace/draft/agents.txt" } }, { agentId: "main" }),
    { params: { source: "AGENTS.md", destination: "draft/agents.txt" } }
  );
});

test("apply_patch rewrites only patch target headers under /workspace", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
  });
  const patch = [
    "*** Begin Patch",
    "*** Update File: /workspace/draft/a.txt",
    "@@",
    "-old /workspace/draft/not-a-target.txt",
    "+new /workspace/draft/not-a-target.txt",
    "*** End Patch"
  ].join("\n");
  const out = await hook({ toolName: "apply_patch", params: { patch } }, { agentId: "main" });
  assert.equal(out.params.patch.includes("*** Update File: draft/a.txt"), true);
  assert.equal(out.params.patch.includes("+new /workspace/draft/not-a-target.txt"), true);
});

test("ASK filesystem calls may carry adjusted execution params without weakening approval", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "pending-write",
      path: { regex: "^/workspace/pending(?:/.*)?$" },
      write: "ask",
      allowAlways: false
    });
  });
  const out = await hook(
    { toolName: "write", params: { path: "/workspace/pending/a.txt", content: "x" } },
    { agentId: "main" }
  );
  assert.ok(out.requireApproval);
  assert.deepEqual(out.params, { path: "pending/a.txt", content: "x" });
});

test("DENY is evaluated before compatibility rewrite and traversal cannot escape policy", async () => {
  const { hook } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
  });
  const denied = await hook(
    { toolName: "write", params: { path: "/workspace/draft/../AGENTS.md", content: "x" } },
    { agentId: "main" }
  );
  assert.equal(denied.block, true);
  assert.equal(Object.hasOwn(denied, "params"), false);
});

test("read and exec paths are never compatibility-rewritten", async () => {
  const { hook, workspaceDir } = setup((policy) => {
    policy.filesystem.zones.unshift({
      id: "draft-rw",
      path: { regex: "^/workspace/draft(?:/.*)?$" },
      read: "allow",
      write: "allow",
      delete: "allow",
      move: "allow"
    });
    policy.exec.allow = [{ id: "cat-draft", regex: "cat /workspace/draft/a\\.txt", match: "full" }];
  });
  assert.equal(
    await hook({ toolName: "read", params: { path: "/workspace/draft/a.txt" } }, { agentId: "main" }),
    undefined
  );
  assert.equal(
    await hook({ toolName: "exec", params: { command: "cat /workspace/draft/a.txt" } }, { agentId: "main", workspaceDir }),
    undefined
  );
});
