import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { resolveMappedPath } from "../src/path-mappings.js";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ap-trailing-slash-"));
  const source = path.join(root, "source");
  fs.mkdirSync(path.join(source, "src", "plugins", "openviking"), { recursive: true });
  const mappings = [
    {
      id: "openclaw-source-bind",
      virtual: "/workspace/openclaw-src",
      host: source,
      agents: ["main"],
    },
  ];
  const call = { agentId: "main", toolName: "exec" };
  return { root, source, mappings, call };
}

test("physical mapping treats a trailing slash as the same mapped directory", () => {
  const { root, source, mappings, call } = fixture();
  try {
    const rootDir = resolveMappedPath(mappings, call, "/workspace/openclaw-src/");
    assert.equal(rootDir.ok, true);
    assert.equal(rootDir.hostPath, source);

    const nested = resolveMappedPath(
      mappings,
      call,
      "/workspace/openclaw-src/src/plugins/openviking/",
    );
    assert.equal(nested.ok, true);
    assert.equal(nested.hostPath, path.join(source, "src", "plugins", "openviking"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("trailing slash equivalence does not weaken symlink escape detection", () => {
  const { root, source, mappings, call } = fixture();
  try {
    const outside = path.join(root, "outside");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(source, "escape"));

    const escaped = resolveMappedPath(mappings, call, "/workspace/openclaw-src/escape/");
    assert.equal(escaped.ok, false);
    assert.equal(escaped.code, "escape");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
