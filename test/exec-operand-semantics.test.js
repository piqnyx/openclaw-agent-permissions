import test from "node:test";
import assert from "node:assert/strict";

import { analyzeExecPaths } from "../src/exec-paths.js";

function expect(command, paths, ambiguous = false) {
  const out = analyzeExecPaths(command, "/workspace");
  assert.deepEqual(out.paths, paths, `${command}: paths`);
  assert.equal(out.ambiguous, ambiguous, `${command}: ${out.reasons.join(", ")}`);
  return out;
}

test("command names and network-looking operands are not guessed to be relative files", () => {
  expect("mkfs.ext4 /dev/sda", ["/dev/sda"]);
  expect("ping -c 1 1.1.1", []);
  expect("ping example.com", []);
  expect("date +%Y-%m-%d", []);
});

test("bare relative files are detected for file-reading commands", () => {
  expect("cat README", ["/workspace/README"]);
  expect('cat "README" /workspace/draft/a.txt', ["/workspace/README", "/workspace/draft/a.txt"]);
  expect("diff LEFT /workspace/draft/right.txt", ["/workspace/LEFT", "/workspace/draft/right.txt"]);
  expect("sha256sum SECRET /workspace/draft/a.txt", ["/workspace/SECRET", "/workspace/draft/a.txt"]);
  expect("ls draft", ["/workspace/draft"]);
});

test("file-bearing options and grep file operands are classified without treating patterns as paths", () => {
  expect("grep -f PATTERNS /workspace/draft/a.txt", ["/workspace/PATTERNS", "/workspace/draft/a.txt"]);
  expect("grep -E PATTERN README", ["/workspace/README"]);
  expect("grep -e PATTERN README", ["/workspace/README"]);
  expect("wc --files0-from LIST", ["/workspace/LIST"]);
  expect("realpath --relative-to BASE TARGET", ["/workspace/BASE", "/workspace/TARGET"]);
});

test("ordinary option values are not mistaken for files", () => {
  expect("head -n 10 README", ["/workspace/README"]);
  expect('stat -c "%n" README', ["/workspace/README"]);
  expect("cut -d : -f 1 DATA", ["/workspace/DATA"]);
  expect("diff --label old --label new LEFT RIGHT", ["/workspace/LEFT", "/workspace/RIGHT"]);
  expect("cmp -n 10 LEFT RIGHT", ["/workspace/LEFT", "/workspace/RIGHT"]);
});

test("jq distinguishes filter/variable values from input files", () => {
  expect("jq '.name' DATA", ["/workspace/DATA"]);
  expect("jq --arg key value '.[$key]' DATA", ["/workspace/DATA"]);
  expect("jq --rawfile blob PAYLOAD '. + $blob' DATA", ["/workspace/PAYLOAD", "/workspace/DATA"]);
  expect("jq -L MODULES '.x' DATA", ["/workspace/MODULES", "/workspace/DATA"]);
});

test("find roots stop at the expression and path-valued predicates remain protected", () => {
  expect('find src -type f -name "*.js"', ["/workspace/src"]);
  expect('find src other -type f -path "*/openviking/*"', ["/workspace/src", "/workspace/other"]);
  expect("find / -newer REFERENCE", ["/", "/workspace/REFERENCE"]);
  expect("find /workspace -samefile OTHER", ["/workspace", "/workspace/OTHER"]);
});

test("recursive commands with implicit cwd remain fail-closed", () => {
  let out = expect('find -name "*.js"', [], true);
  assert.ok(out.reasons.includes("implicit recursive cwd access"));

  out = expect("rg name", [], true);
  assert.ok(out.reasons.includes("implicit recursive cwd access"));

  out = expect("rg -f PATTERNS", ["/workspace/PATTERNS"], true);
  assert.ok(out.reasons.includes("implicit recursive cwd access"));

  out = expect("grep -r name", [], true);
  assert.ok(out.reasons.includes("implicit recursive cwd access"));

  expect("grep -r name /tmp", ["/tmp"]);

  out = expect("du", [], true);
  assert.ok(out.reasons.includes("implicit recursive cwd access"));
  expect("du README", ["/workspace/README"]);
});

test("globbed file operands stay fail-closed", () => {
  let out = expect("cat README*", [], true);
  assert.ok(out.reasons.includes("path expansion or glob"));

  out = expect("du -sh /workspace/draft/* 2>/dev/null", [], true);
  assert.ok(out.reasons.includes("path expansion or glob"));
});

test("production readonly diagnostics from the approval audit stay unambiguous", () => {
  expect(
    'grep -B 5 -A 20 "remote\\|apiUrl\\|model.*rerank" /workspace/openclaw-src/packages/memory-host-sdk/src/host/backend-config.ts | head -60',
    ["/workspace/openclaw-src/packages/memory-host-sdk/src/host/backend-config.ts"],
  );
  expect(
    'grep -ri "rerank" /workspace/openclaw-src/ --include="*.ts" -l 2>/dev/null | head -20',
    ["/workspace/openclaw-src/"],
  );
  expect(
    'grep -ri "rerank" /workspace/openclaw-src/src/plugins/openviking/ --include="*.ts" -l 2>/dev/null || echo "NOT_FOUND"',
    ["/workspace/openclaw-src/src/plugins/openviking/"],
  );
  expect(
    'find / -name "config.yaml" -path "*openviking*" 2>/dev/null | head -5',
    ["/"],
  );
  expect(
    'find /workspace -name "ov.conf" -o -name "openviking.conf" -o -name "config.yaml" -path "*/openviking/*" 2>/dev/null | head -5',
    ["/workspace"],
  );
});
