import test from "node:test";
import assert from "node:assert/strict";
import plugin from "../dist/index.js";

test("packaged dist entrypoint loads as an OpenClaw plugin", () => {
  assert.equal(plugin.id, "agent-permissions");
  assert.equal(typeof plugin.register, "function");
});
