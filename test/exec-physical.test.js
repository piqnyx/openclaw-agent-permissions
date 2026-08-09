import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { evaluatePolicy, validatePolicy } from "../src/exec-physical.js";
import { buildCallContext } from "../src/profiles.js";

function policyWithPaths() {
  return validatePolicy({
    version: 3,
    defaults: { effect: "ask" },
    filesystem: { default: "deny", allowAlways: false, zones: [] },
    exec: {
      default: "ask",
      allowAlways: false,
      paths: {
        default: "ask",
        deny: [],
        ask: [],
        allow: [
          { id: "system", path: { regex: "^/(?:etc|usr|tmp)(?:/.*)?$" } },
          { id: "draft", path: { regex: "^/workspace/draft(?:/.*)?$" } }
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

function decide(command, workspaceDir) {
  const policy = policyWithPaths();
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
  assert.match(out.decision.reason, /physically resolves/);
});

test("workspace path without a host workspace mapping cannot be silently allowed", () => {
  assert.equal(decide("cat /workspace/draft/a.txt").decision.effect, "ask");
});

test("container-system paths remain governed lexically because host realpath is not the sandbox namespace", () => {
  assert.equal(decide("cat /etc/os-release").decision.effect, "allow");
});
