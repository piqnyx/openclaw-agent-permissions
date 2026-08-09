import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { evaluatePolicy, validatePolicy } from "../src/exec-physical.js";
import { buildCallContext } from "../src/profiles.js";

function policyWithPaths(physicalMappings = []) {
  return validatePolicy({
    version: 3,
    defaults: { effect: "ask" },
    filesystem: { default: "deny", allowAlways: false, zones: [] },
    exec: {
      default: "ask",
      allowAlways: false,
      paths: {
        default: "ask",
        physicalMappings,
        deny: [],
        ask: [],
        allow: [
          { id: "system", path: { regex: "^/(?:etc|usr|tmp)(?:/.*)?$" } },
          { id: "draft", path: { regex: "^/workspace/draft(?:/.*)?$" } },
          { id: "source", path: { regex: "^/workspace/openclaw-src(?:/.*)?$" }, agents: ["main"] }
        ]
      },
      deny: [],
      ask: [],
      allow: [
        { id: "read", regex: "^\\s*(?:cat|head|rg)(?:\\s+[^;&|<>]+)*\\s*$", match: "full" }
      ]
    },
    tools: { default: "ask", defaultAllowAlways: true, deny: [], ask: [], allow: [] },
    toolProfiles: {}
  });
}

function decide(command, workspaceDir, physicalMappings = []) {
  const policy = policyWithPaths(physicalMappings);
  const ctx = { agentId: "main", ...(workspaceDir ? { workspaceDir } : {}) };
  const call = buildCallContext({ toolName: "exec", params: { command } }, ctx, policy, "/workspace");
  return { call, decision: evaluatePolicy(policy, call, null, "/workspace") };
}

test("physical workspace guard permits ordinary paths whose host mapping stays stable", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ap-physical-"));
  fs.mkdirSync(path.join(workspace, "draft"), { recursive: true });
  fs.writeFileSync(path.join(workspace, "draft", "a.txt"), "x");
  assert.equal(decide("cat /workspace/draft/a.txt", workspace).decision.effect, "allow");
});

test("physical workspace guard turns symlink aliases into ASK before silent exec allow", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ap-physical-"));
  fs.mkdirSync(path.join(workspace, "draft"), { recursive: true });
  fs.mkdirSync(path.join(workspace, "memory", ".dreams"), { recursive: true });
  fs.writeFileSync(path.join(workspace, "memory", ".dreams", "state.json"), "secret");
  fs.symlinkSync("../memory/.dreams/state.json", path.join(workspace, "draft", "link"));
  const out = decide("cat /workspace/draft/link", workspace);
  assert.equal(out.decision.effect, "ask");
  assert.match(out.decision.ruleId, /exec-path-physical/);
  assert.match(out.decision.reason, /symlink outside|physically resolves/);
});

test("workspace path without a host workspace mapping cannot be silently allowed", () => {
  assert.equal(decide("cat /workspace/draft/a.txt").decision.effect, "ask");
});

test("container-system paths remain governed lexically because host realpath is not the sandbox namespace", () => {
  assert.equal(decide("cat /etc/os-release").decision.effect, "allow");
});

test("explicit physical mapping permits an external bind mounted below /workspace", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ap-workspace-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "ap-external-"));
  fs.writeFileSync(path.join(external, "package.json"), "{}");
  const mappings = [
    { id: "openclaw-source", virtual: "/workspace/openclaw-src", host: external, agents: ["main"] }
  ];
  assert.equal(decide("cat /workspace/openclaw-src/package.json", workspace, mappings).decision.effect, "allow");
});

test("explicit physical mapping still asks when a symlink escapes the mapped host tree", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ap-workspace-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "ap-external-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ap-outside-"));
  fs.writeFileSync(path.join(outside, "secret.txt"), "secret");
  fs.symlinkSync(path.join(outside, "secret.txt"), path.join(external, "link"));
  const mappings = [
    { id: "openclaw-source", virtual: "/workspace/openclaw-src", host: external, agents: ["main"] }
  ];
  const out = decide("cat /workspace/openclaw-src/link", workspace, mappings);
  assert.equal(out.decision.effect, "ask");
  assert.match(out.decision.ruleId, /exec-path-physical/);
});

test("physical mapping validation rejects duplicate ids and relative host paths", () => {
  assert.throws(() => policyWithPaths([
    { id: "dup", virtual: "/workspace/a", host: "/tmp/a" },
    { id: "dup", virtual: "/workspace/b", host: "/tmp/b" }
  ]), /duplicate/);
  assert.throws(() => policyWithPaths([
    { id: "bad", virtual: "/workspace/a", host: "relative/path" }
  ]), /absolute host path/);
});
