import test from "node:test";
import assert from "node:assert/strict";
import { analyzeExecPaths, evaluatePolicy, validatePolicy } from "../src/exec-paths.js";
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
        deny: [
          { id: "deny-secrets", path: { regex: "^/secret(?:/.*)?$" } }
        ],
        ask: [],
        allow: [
          { id: "allow-system", path: { regex: "^/(?:etc|usr|tmp)(?:/.*)?$" } },
          { id: "allow-draft", path: { regex: "^/workspace/draft(?:/.*)?$" } },
          { id: "allow-source-main", agents: ["main"], path: { regex: "^/workspace/openclaw-src(?:/.*)?$" } }
        ]
      },
      deny: [
        { id: "deny-rm", regex: "(?:^|[;&|]\\s*)rm\\b", match: "search" }
      ],
      ask: [],
      allow: [
        { id: "allow-read-chain", regex: "^\\s*(?:cat|head|rg)(?:\\s+[^;&|<>]+)*(?:\\s*(?:&&|\\|\\||;|\\|)\\s*(?:cat|head|rg)(?:\\s+[^;&|<>]+)*)*\\s*$", match: "full" }
      ]
    },
    tools: { default: "ask", defaultAllowAlways: true, deny: [], ask: [], allow: [] },
    toolProfiles: {}
  });
}

function decide(command, policy = policyWithPaths(), ctx = { agentId: "main" }) {
  const call = buildCallContext({ toolName: "exec", params: { command } }, ctx, policy, "/workspace");
  return { call, decision: evaluatePolicy(policy, call, null, "/workspace") };
}

test("exec path analyzer normalizes traversal before matching", () => {
  const out = analyzeExecPaths("cat /workspace/draft/../../../etc/passwd", "/workspace");
  assert.equal(out.ambiguous, false);
  assert.deepEqual(out.paths, ["/etc/passwd"]);
});

test("exec path analyzer supports read-only chains and ignores URI arguments", () => {
  const out = analyzeExecPaths("rg 'name' /workspace/draft/a.txt | head -n 2 https://example.com/x", "/workspace");
  assert.equal(out.ambiguous, false);
  assert.deepEqual(out.paths, ["/workspace/draft/a.txt"]);
});

test("dynamic shell constructs and path globs are fail-closed to ASK", () => {
  assert.equal(analyzeExecPaths('cat "$(printf /etc/passwd)"').ambiguous, true);
  assert.equal(analyzeExecPaths("cat /etc/*.conf").ambiguous, true);
  assert.equal(decide('cat "$(printf /etc/passwd)"').decision.effect, "ask");
});

test("exec paths are independent from filesystem zones", () => {
  const out = decide("cat /etc/os-release");
  assert.equal(out.decision.effect, "allow");
  assert.deepEqual(out.call.paths, ["/etc/os-release"]);
});

test("command ALLOW plus unlisted path becomes ASK", () => {
  const out = decide("cat /workspace/memory/.dreams/state.json");
  assert.equal(out.decision.effect, "ask");
  assert.match(out.decision.ruleId, /exec-path-default/);
});

test("exec path deny wins even when command regex allows", () => {
  const out = decide("cat /secret/token.txt");
  assert.equal(out.decision.effect, "deny");
  assert.equal(out.decision.ruleId, "deny-secrets");
});

test("command deny still wins for an allowed path", () => {
  const out = decide("rm /tmp/x");
  assert.equal(out.decision.effect, "deny");
  assert.equal(out.decision.ruleId, "deny-rm");
});

test("agent-scoped exec path rules remain agent-scoped", () => {
  assert.equal(decide("cat /workspace/openclaw-src/package.json", policyWithPaths(), { agentId: "main" }).decision.effect, "allow");
  assert.equal(decide("cat /workspace/openclaw-src/package.json", policyWithPaths(), { agentId: "igor" }).decision.effect, "ask");
});

test("exec path validation rejects unknown fields and duplicate IDs", () => {
  const badField = policyWithPaths();
  badField.exec.paths.nope = true;
  assert.throws(() => validatePolicy(badField), /exec\.paths\.nope: unknown field/);

  const duplicate = policyWithPaths();
  duplicate.exec.paths.ask.push({ id: "allow-draft", path: "/workspace/**" });
  assert.throws(() => validatePolicy(duplicate), /duplicate 'allow-draft'/);
});

test("absence of exec.paths preserves 2.0.4 exec behavior", () => {
  const p = policyWithPaths();
  delete p.exec.paths;
  validatePolicy(p);
  assert.equal(decide("cat /workspace/memory/.dreams/state.json", p).decision.effect, "allow");
});
