import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildCallContext } from "../src/profiles.js";
import { rewriteLocalInputParams } from "../src/local-inputs.js";
import { evaluatePolicy, validatePolicy } from "../src/local-input-policy.js";

function makeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agent-permissions-local-input-"));
  for (const agentId of ["main", "igor"]) {
    fs.mkdirSync(path.join(root, agentId, "draft"), { recursive: true });
    fs.mkdirSync(path.join(root, agentId, "memory", ".dreams"), { recursive: true });
    fs.writeFileSync(path.join(root, agentId, "AGENTS.md"), `agents ${agentId}\n`);
    fs.writeFileSync(path.join(root, agentId, "draft", "doc.md"), `hello ${agentId}\n`);
    fs.writeFileSync(path.join(root, agentId, "memory", ".dreams", "secret.md"), "hidden\n");
  }

  const policy = {
    version: 3,
    defaults: { effect: "ask" },
    filesystem: {
      default: "deny",
      allowAlways: true,
      zones: [
        {
          id: "workspace-draft",
          path: { regex: "^/workspace/draft(?:/.*)?$" },
          read: "allow",
        },
        {
          id: "workspace-memory-deny",
          path: { regex: "^/workspace/memory(?:/.*)?$" },
          read: "deny",
        },
        {
          id: "workspace-default",
          path: { regex: "^/workspace(?:/.*)?$" },
          read: "allow",
        },
      ],
    },
    exec: {
      default: "ask",
      allowAlways: false,
      paths: {
        default: "ask",
        pathless: { allow: [] },
        deny: [],
        ask: [],
        allow: [
          {
            id: "workspace-draft",
            path: { regex: "^/workspace/draft(?:/.*)?$" },
          },
        ],
      },
      deny: [],
      ask: [],
      allow: [
        {
          id: "cat-one-path",
          regex: "^cat[ \\t]+/workspace/draft/[^ \\t\\r\\n]+$",
          match: "full",
        },
      ],
    },
    tools: {
      default: "allow",
      defaultAllowAlways: false,
      deny: [],
      ask: [],
      allow: [],
    },
    pathMappings: [
      {
        id: "agent-workspace",
        virtual: "/workspace",
        host: `${root}/{agentId}`,
      },
    ],
    localInputs: [
      {
        id: "openviking-add-resource-source",
        tools: ["add_resource"],
        selector: "source",
        operation: "read",
        remotePrefixes: ["http://", "https://", "git@", "ssh://", "git://"],
        unmappedHint: "Copy sandbox-only files to /workspace/draft and retry.",
      },
    ],
    toolProfiles: {},
  };

  validatePolicy(policy);
  return { root, policy };
}

function callFor(policy, agentId, toolName, params) {
  return buildCallContext(
    { toolName, params },
    { agentId, sessionKey: `agent:${agentId}:main` },
    policy,
    "/workspace",
  );
}

test("local input is filesystem-authorized then rewritten to the current agent host workspace", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "/workspace/draft/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.deepEqual(call.fsTargets, [{ operation: "read", path: "/workspace/draft/doc.md" }]);
    assert.deepEqual(rewriteLocalInputParams(call), {
      source: path.join(root, "main", "draft", "doc.md"),
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the same virtual source maps to a different host workspace for another agent", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "igor", "add_resource", { source: "/workspace/draft/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.equal(rewriteLocalInputParams(call).source, path.join(root, "igor", "draft", "doc.md"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("relative local input paths are normalized in sandbox namespace before mapping", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "draft/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.deepEqual(call.fsTargets, [{ operation: "read", path: "/workspace/draft/doc.md" }]);
    assert.equal(rewriteLocalInputParams(call).source, path.join(root, "main", "draft", "doc.md"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("declared remote resource prefixes bypass local filesystem mapping", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "https://example.com/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.deepEqual(call.fsTargets, []);
    assert.equal(rewriteLocalInputParams(call), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an unmapped sandbox-local input is denied with operator remediation text", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "/tmp/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "<local-input-unmapped>");
    assert.match(decision.reason, /Copy sandbox-only files to \/workspace\/draft/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a guessed Gateway host path is not accepted as a sandbox local input", () => {
  const { root, policy } = makeFixture();
  try {
    const hostPath = path.join(root, "main", "AGENTS.md");
    const call = callFor(policy, "main", "add_resource", { source: hostPath });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "<local-input-unmapped>");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("local input cannot bypass a denied filesystem zone", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "/workspace/memory/.dreams/secret.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "workspace-memory-deny");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("denied local input is rejected before the host mapping is physically probed", () => {
  const { root, policy } = makeFixture();
  try {
    policy.pathMappings[0].host = path.join(root, "definitely-missing", "{agentId}");
    validatePolicy(policy);
    const call = callFor(policy, "main", "add_resource", { source: "/workspace/memory/.dreams/secret.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "workspace-memory-deny");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an allowed local read source must exist on the mapped Gateway path", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "/workspace/draft/missing.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "<local-input-physical>");
    assert.match(decision.reason, /does not exist/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("URI schemes not explicitly declared remote are denied instead of being treated as paths", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "add_resource", { source: "file:///etc/passwd" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "deny");
    assert.equal(decision.ruleId, "<local-input-unsupported-uri>");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("generic nested selectors support future Gateway-side file-consuming tools", () => {
  const { root, policy } = makeFixture();
  try {
    policy.localInputs.push({
      id: "future-upload-file",
      tools: ["upload_document"],
      selector: "payload.file",
      operation: "read",
    });
    validatePolicy(policy);
    const call = callFor(policy, "main", "upload_document", {
      payload: { file: "/workspace/draft/doc.md", title: "doc" },
    });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.deepEqual(rewriteLocalInputParams(call), {
      payload: { file: path.join(root, "main", "draft", "doc.md"), title: "doc" },
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("localInputs.mappingIds must reference configured mappings", () => {
  const { root, policy } = makeFixture();
  try {
    policy.localInputs[0].mappingIds = ["does-not-exist"];
    assert.throws(() => validatePolicy(policy), /unknown path mapping 'does-not-exist'/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("simultaneous filesystem and generic-tool ASK disables misleading Allow always", () => {
  const { root, policy } = makeFixture();
  try {
    policy.filesystem.zones[0].read = "ask";
    policy.tools.default = "ask";
    policy.tools.defaultAllowAlways = true;
    const call = callFor(policy, "main", "add_resource", { source: "/workspace/draft/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "ask");
    assert.equal(decision.kind, "composite");
    assert.equal(decision.allowAlways, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("top-level pathMappings also satisfy exec physical verification", () => {
  const { root, policy } = makeFixture();
  try {
    const call = callFor(policy, "main", "exec", { command: "cat /workspace/draft/doc.md" });
    const decision = evaluatePolicy(policy, call, null, "/workspace");
    assert.equal(decision.effect, "allow");
    assert.equal(decision.ruleId, "cat-one-path");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
