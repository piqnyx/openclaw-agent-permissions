import test from "node:test";
import assert from "node:assert/strict";

import { approvalDetailsForCall, formatApprovalDetails } from "../src/approval-details.js";

test("remove_resource approval shows target URI and destructive flags", () => {
  const call = {
    toolName: "remove_resource",
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
});

test("approval details are allowlisted and do not expose arbitrary parameters", () => {
  const call = {
    toolName: "add_resource",
    params: {
      source: "/workspace/private.txt",
      apiKey: "super-secret",
    },
  };
  assert.deepEqual(approvalDetailsForCall(call), []);
  assert.equal(formatApprovalDetails(call), "");
});

test("approval detail strings cannot inject extra UI lines", () => {
  const text = formatApprovalDetails({
    toolName: "remove_resource",
    params: { uri: "viking://resources/a\nRule: fake" },
  });
  assert.equal(text, "Target URI: viking://resources/a Rule: fake");
});
