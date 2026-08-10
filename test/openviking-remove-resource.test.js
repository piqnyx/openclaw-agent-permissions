import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCallContext } from "../src/profiles.js";
import { evaluatePolicy, validatePolicy } from "../src/local-input-policy.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const policy = validatePolicy(JSON.parse(fs.readFileSync(path.join(root, "permissions.example.json"), "utf8")));

test("OpenViking remove_resource is a first-class per-call memory mutation", () => {
  const call = buildCallContext(
    {
      toolName: "remove_resource",
      params: {
        uri: "viking://resources/workspace",
        recursive: true,
        wait: true,
      },
    },
    { agentId: "main" },
    policy,
    "/workspace",
  );

  assert.equal(call.capability, "memory.write");
  assert.equal(call.operation, "remove_resource");
  assert.deepEqual(call.paths, []);
  assert.deepEqual(call.fsTargets, []);

  const decision = evaluatePolicy(policy, call, null, "/workspace");
  assert.equal(decision.effect, "ask");
  assert.equal(decision.ruleId, "memory-write-approval");
  assert.equal(decision.allowAlways, false);
  assert.deepEqual(call.localInputCandidates, []);
});
