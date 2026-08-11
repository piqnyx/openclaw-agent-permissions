import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, extractPathlessCommandWords, validatePolicy } from "../src/exec-no-target.js";
import { buildCallContext } from "../src/profiles.js";

function makePolicy(withPaths = true, withPathless = true) {
  const exec = {
    default: "ask",
    allowAlways: false,
    deny: [],
    ask: [],
    allow: [
      {
        id: "readonly",
        regex: "^\\s*(?:id|pwd|uname|rg|cat)(?:\\s+[^;&|<>]+)*(?:\\s*(?:&&|\\|\\||;|\\|)\\s*(?:id|pwd|uname|rg|cat)(?:\\s+[^;&|<>]+)*)*\\s*$",
        match: "full"
      }
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
    if (withPathless) exec.paths.pathless = { allow: ["id", "pwd", "uname"] };
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

test("pathless command words are extracted from simple shell chains", () => {
  assert.deepEqual(extractPathlessCommandWords("id && uname | pwd"), ["id", "uname", "pwd"]);
  assert.equal(extractPathlessCommandWords("/usr/bin/id"), null);
});

test("configured pathless commands may pass with no explicit filesystem targets", () => {
  for (const command of ["id", "pwd", "uname", "id && uname", "pwd ; id && uname"]) {
    assert.equal(decide(command).effect, "allow");
  }
});

test("untrusted implicit recursive cwd commands still ask as ambiguous", () => {
  for (const command of ["rg needle", "id && rg needle"]) {
    const out = decide(command);
    assert.equal(out.effect, "ask");
    assert.match(out.ruleId, /exec-path-ambiguous/);
  }
});

test("bare relative file operands are path-checked instead of treated as pathless", () => {
  const out = decide("cat secret");
  assert.equal(out.effect, "ask");
  assert.match(out.ruleId, /exec-path-default/);
});

test("explicit allowed paths still permit a matching readonly command", () => {
  assert.equal(decide("cat /tmp/x").effect, "allow");
});

test("missing pathless configuration keeps no-target exec fail-closed", () => {
  assert.equal(decide("id", makePolicy(true, false)).effect, "ask");
});

test("no-target guard is disabled when exec.paths is absent", () => {
  assert.equal(decide("id", makePolicy(false)).effect, "allow");
});

test("pathless validation rejects unknown fields invalid names and duplicates", () => {
  const unknown = makePolicy();
  unknown.exec.paths.pathless.extra = true;
  assert.throws(() => validatePolicy(unknown), /exec\.paths\.pathless\.extra: unknown field/);

  const invalid = makePolicy();
  invalid.exec.paths.pathless.allow.push("bad command");
  assert.throws(() => validatePolicy(invalid), /simple command names/);

  const duplicate = makePolicy();
  duplicate.exec.paths.pathless.allow.push("id");
  assert.throws(() => validatePolicy(duplicate), /duplicate command names/);
});
