import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, validatePolicy } from "../src/exec-no-target.js";
import { buildCallContext } from "../src/profiles.js";

function makePolicy(withPaths = true) {
  const exec = {
    default: "ask",
    allowAlways: false,
    deny: [],
    ask: [],
    allow: [
      { id: "readonly", regex: "^\\s*(?:id|rg|cat)(?:\\s+[^;&|<>]+)*\\s*$", match: "full" }
    ]
  };
  if (withPaths) {
    exec.paths = {
      default: "ask",
      deny: [],
      ask: [],
      allow: [
        { id: "tmp", path: { regex: "^/tmp(?:/.*)?$" } }
      ]
    };
  }
  return validatePolicy({
    version: 3,
    defaults: { effect: "ask" },
    filesystem: { default: "deny", allowAlways: false, zones: [] },
    exec,
    tools: { default: "ask", defaultAllowAlways: false, deny: [], ask: [], allow: [] },
    toolProfiles: {}
  });
}

function decide(command, policy = makePolicy()) {
  const call = buildCallContext({ toolName: "exec", params: { command } }, { agentId: "main", workspaceDir: "/tmp" }, policy, "/workspace");
  return evaluatePolicy(policy, call, null, "/workspace");
}

test("exec path guard asks when a command has no explicit path operands", () => {
  for (const command of ["rg needle", "cat secret", "id"]) {
    const out = decide(command);
    assert.equal(out.effect, "ask");
    assert.match(out.ruleId, /exec-path-no-targets/);
  }
});

test("explicit allowed paths still permit a matching readonly command", () => {
  assert.equal(decide("cat /tmp/x").effect, "allow");
});

test("no-target guard is disabled when exec.paths is absent", () => {
  assert.equal(decide("id", makePolicy(false)).effect, "allow");
});
