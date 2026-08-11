import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { analyzeExecPaths } from "../src/exec-paths.js";

const matrix = JSON.parse(
  fs.readFileSync(new URL("./exec-policy-audit-cases.json", import.meta.url), "utf8"),
);

// This matrix intentionally exercises parser classification only. Final ALLOW/ASK/DENY
// for operator policy lives in permissions.json and is tested in the live acceptance pass.
test("audit matrix parser never treats command names or network operands as filesystem paths", () => {
  assert.deepEqual(analyzeExecPaths("mkfs.ext4 /dev/sda", "/workspace").paths, ["/dev/sda"]);
  assert.deepEqual(analyzeExecPaths("ping -c 1 1.1.1", "/workspace").paths, []);
  assert.deepEqual(analyzeExecPaths("ping example.com", "/workspace").paths, []);
});

test("audit matrix keeps known ambiguous shell/path forms fail-closed", () => {
  const ambiguousCases = [
    "printf hi > /workspace/draft/output.txt",
    "cat $(printf /etc/passwd)",
    "cat /workspace/draft/*.txt",
    "du -sh /workspace/draft/*",
    "rg name",
    "find -name *.js",
  ];
  for (const command of ambiguousCases) {
    const out = analyzeExecPaths(command, "/workspace");
    assert.equal(out.ambiguous, true, `${command}: expected parser ambiguity`);
  }
});

test("audit case inventory remains non-empty in every classification bucket", () => {
  for (const key of ["harmless", "ask", "denyCandidates"]) {
    assert.ok(Array.isArray(matrix[key]) && matrix[key].length > 0, `${key} must contain cases`);
  }
});
