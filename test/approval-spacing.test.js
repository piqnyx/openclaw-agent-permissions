import test from "node:test";
import assert from "node:assert/strict";

import { formatApprovalDescription } from "../src/approval-details.js";

test("approval description leaves one visible blank line before and after the action section", () => {
  const description = formatApprovalDescription(
    {
      toolName: "exec",
      agentId: "main",
      capability: "exec",
      operation: "exec",
      paths: [],
      params: { command: "python -V" },
    },
    { kind: "exec", ruleId: "<exec-default>", allowAlways: false },
    { canAlways: false },
  );

  assert.ok(description.startsWith("\n══════════ COMMAND ══════════\npython -V\n"));
  assert.match(description, /════════ END COMMAND ════════\n\nPolicy: <exec-default> · Agent: main\nPermanent: disabled$/u);
});
