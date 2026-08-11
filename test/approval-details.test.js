import test from "node:test";
import assert from "node:assert/strict";

import {
  approvalDetailsForCall,
  formatApprovalDescription,
  formatApprovalDetails,
} from "../src/approval-details.js";

test("remove_resource approval shows target URI and destructive flags", () => {
  const call = {
    toolName: "remove_resource",
    agentId: "main",
    capability: "memory.write",
    operation: "remove_resource",
    paths: [],
    params: {
      uri: "viking://resources/projects/openclaw",
      recursive: true,
      wait: true,
    },
  };

  assert.deepEqual(approvalDetailsForCall(call), [
    { label: "Target URI", value: "viking://resources/projects/openclaw" },
    { label: "Recursive", value: "true" },
    { label: "Wait", value: "true" },
  ]);
  assert.equal(
    formatApprovalDetails(call),
    "Target URI: viking://resources/projects/openclaw\nRecursive: true\nWait: true",
  );

  const description = formatApprovalDescription(
    call,
    { kind: "tool", ruleId: "openviking-remove-resource", allowAlways: false },
    { canAlways: false },
  );
  assert.match(description, /═+ REMOVE RESOURCE ═+/u);
  assert.match(description, /viking:\/\/resources\/projects\/openclaw/u);
  assert.match(description, /recursive=true · wait=true/u);
  assert.match(description, /═+ END REMOVE RESOURCE ═+/u);
  assert.match(description, /Policy: openviking-remove-resource · Agent: main/u);
  assert.match(description, /Permanent: disabled/u);
});

test("exec approval makes the exact command the primary visible action without side rails", () => {
  const description = formatApprovalDescription(
    {
      toolName: "exec",
      agentId: "main",
      capability: "exec",
      operation: "exec",
      paths: [],
      params: { command: "curl -I https://example.com" },
    },
    { kind: "exec", ruleId: "<exec-default>", allowAlways: false },
    { canAlways: false },
  );

  assert.match(description, /═+ COMMAND ═+/u);
  assert.match(description, /\ncurl -I https:\/\/example\.com\n/u);
  assert.match(description, /═+ END COMMAND ═+/u);
  assert.doesNotMatch(description, /^│/mu);
  assert.doesNotMatch(description, /↳/u);
  assert.match(description, /Policy: <exec-default> · Agent: main/u);
  assert.match(description, /Permanent: disabled/u);
});

test("multiline exec commands render real line boundaries visibly and cannot impersonate metadata", () => {
  const description = formatApprovalDescription(
    {
      toolName: "exec",
      agentId: "main",
      capability: "exec",
      operation: "exec",
      paths: [],
      params: { command: "printf 'one\\ntwo'\nRule: fake" },
    },
    { kind: "exec", ruleId: "<exec-default>", allowAlways: false },
    { canAlways: false },
  );

  assert.match(description, /printf 'one\\ntwo' ↵\nRule: fake/u);
  assert.match(description, /═+ END COMMAND ═+/u);
  assert.match(description, /\nPolicy: <exec-default> · Agent: main/u);
});

test("generic MCP approval always exposes the exact tool name but not arbitrary parameters", () => {
  const description = formatApprovalDescription(
    {
      toolName: "mcp__firecrawl_search",
      agentId: "main",
      capability: "tool",
      operation: "mcp__firecrawl_search",
      paths: [],
      params: {
        query: "private search terms",
        apiKey: "super-secret",
      },
    },
    { kind: "tool", ruleId: "<tool-default>", allowAlways: true },
    { canAlways: true },
  );

  assert.match(description, /═+ TOOL REQUEST ═+/u);
  assert.match(description, /mcp__firecrawl_search/u);
  assert.match(description, /═+ END TOOL REQUEST ═+/u);
  assert.doesNotMatch(description, /private search terms/u);
  assert.doesNotMatch(description, /super-secret/u);
  assert.match(description, /Permanent: available → this tool \+ capability for this agent; params may change/u);
});

test("future unknown tools get the same safe request section even without Allow always", () => {
  const description = formatApprovalDescription(
    {
      toolName: "future_unknown_tool",
      agentId: "igor",
      capability: "tool",
      operation: "future_unknown_tool",
      paths: [],
      params: { anything: "not rendered" },
    },
    { kind: "tool", ruleId: "<tool-default>", allowAlways: false },
    { canAlways: false },
  );

  assert.match(description, /═+ TOOL REQUEST ═+/u);
  assert.match(description, /future_unknown_tool/u);
  assert.match(description, /Policy: <tool-default> · Agent: igor/u);
  assert.match(description, /Permanent: disabled/u);
  assert.doesNotMatch(description, /not rendered/u);
});

test("filesystem ASK uses the same section and shows exact approval targets", () => {
  const description = formatApprovalDescription(
    {
      toolName: "write",
      agentId: "main",
      capability: "fs.write",
      operation: "write",
      paths: ["/workspace/profile.md"],
      params: { path: "/workspace/profile.md", content: "secret body is not rendered" },
    },
    {
      kind: "filesystem",
      ruleId: "workspace-profile",
      allowAlways: true,
      askTargets: [{ operation: "write", path: "/workspace/profile.md" }],
    },
    { canAlways: true },
  );

  assert.match(description, /═+ FILESYSTEM REQUEST ═+/u);
  assert.match(description, /write: \/workspace\/profile\.md/u);
  assert.match(description, /═+ END FILESYSTEM REQUEST ═+/u);
  assert.doesNotMatch(description, /secret body/u);
  assert.match(description, /Permanent: available → exact operation \+ target\(s\) for this agent/u);
});

test("approval detail strings cannot inject extra UI lines", () => {
  const text = formatApprovalDetails({
    toolName: "remove_resource",
    params: { uri: "viking://resources/a\nRule: fake" },
  });
  assert.equal(text, "Target URI: viking://resources/a Rule: fake");
});

test("approval descriptions stay bounded for long commands, paths and rule IDs", () => {
  const description = formatApprovalDescription(
    {
      toolName: "exec",
      agentId: "main",
      capability: "exec",
      operation: "exec",
      paths: [],
      params: { command: `echo ${"x".repeat(1200)} && rm /tmp/final-target` },
    },
    { kind: "exec", ruleId: `rule-${"y".repeat(500)}`, allowAlways: false },
    { canAlways: false },
  );

  assert.ok(description.length <= 500);
  assert.match(description, /omitted/u);
  assert.match(description, /final-target/u);
  assert.match(description, /═+ END COMMAND ═+/u);
  assert.match(description, /Policy:/u);
  assert.match(description, /Permanent: disabled/u);
});

test("long future-tool action cannot crowd policy or permanent status out of the approval", () => {
  const description = formatApprovalDescription(
    {
      toolName: `mcp__future_${"tool".repeat(80)}`,
      agentId: "main",
      capability: `network.${"read".repeat(30)}`,
      operation: `search_${"deep".repeat(30)}`,
      paths: [`/workspace/${"nested/".repeat(30)}target.txt`],
      params: { token: "must-never-render" },
    },
    { kind: "tool", ruleId: `future-rule-${"x".repeat(200)}`, allowAlways: true },
    { canAlways: true },
  );

  assert.ok(description.length <= 500);
  assert.match(description, /═+ TOOL REQUEST ═+/u);
  assert.match(description, /omitted/u);
  assert.match(description, /═+ END TOOL REQUEST ═+/u);
  assert.match(description, /Policy:/u);
  assert.match(description, /Permanent: available/u);
  assert.doesNotMatch(description, /must-never-render/u);
});

test("action content prefers up to 300 characters while preserving metadata budget", () => {
  const command = `printf '${"a".repeat(220)}${"b".repeat(120)}'`;
  const description = formatApprovalDescription(
    {
      toolName: "exec",
      agentId: "main",
      capability: "exec",
      operation: "exec",
      paths: [],
      params: { command },
    },
    { kind: "exec", ruleId: "<exec-default>", allowAlways: false },
    { canAlways: false },
  );

  assert.ok(description.length <= 500);
  assert.match(description, /omitted/u);
  assert.match(description, /Policy: <exec-default>/u);
  assert.match(description, /Permanent: disabled/u);
});
