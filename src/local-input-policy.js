import fs from "node:fs";
import {
  LearnedRuleStore,
  evaluatePolicy as evaluateBasePolicy,
  validatePolicy as validateBasePolicy,
} from "./exec-no-target.js";
import { prepareLocalInputs, validateLocalInputs } from "./local-inputs.js";
import { validatePathMappings } from "./path-mappings.js";

function stripLocalInputPolicy(policy) {
  const copy = structuredClone(policy);
  delete copy.pathMappings;
  delete copy.localInputs;
  return copy;
}

export function validatePolicy(policy) {
  validatePathMappings(policy?.pathMappings);
  validateLocalInputs(policy?.localInputs);
  validateBasePolicy(stripLocalInputPolicy(policy));
  return policy;
}

function filesystemCapability(operation) {
  if (operation === "read") return "fs.read";
  if (operation === "write") return "fs.write";
  if (operation === "delete") return "fs.delete";
  if (operation === "move") return "fs.move";
  if (operation === "execute") return "fs.execute";
  return null;
}

function evaluateLocalInputFilesystem(policy, call, learnedStore, virtualWorkspaceRoot) {
  const targets = Array.isArray(call.fsTargets) ? call.fsTargets : [];
  if (targets.length === 0) return null;

  let firstAsk = null;
  for (const target of targets) {
    const capability = filesystemCapability(target.operation);
    if (!capability) {
      return {
        kind: "filesystem",
        operation: target.operation,
        effect: "deny",
        ruleId: "<local-input-invalid-operation>",
        reason: `unsupported local-input filesystem operation: ${String(target.operation)}`,
        allowAlways: false,
        askPaths: [],
        askTargets: [],
      };
    }

    const fsCall = {
      ...call,
      capability,
      operation: target.operation,
      paths: [target.path],
      fsTargets: [target],
    };
    const decision = evaluateBasePolicy(policy, fsCall, learnedStore, virtualWorkspaceRoot);
    if (decision.effect === "deny") return decision;
    if (decision.effect === "ask" && !firstAsk) firstAsk = decision;
  }
  return firstAsk;
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const preparationDecision = prepareLocalInputs(policy, call, virtualWorkspaceRoot);
  if (preparationDecision) return preparationDecision;

  const localFsDecision = evaluateLocalInputFilesystem(policy, call, learnedStore, virtualWorkspaceRoot);
  if (localFsDecision?.effect === "deny") return localFsDecision;

  const toolDecision = evaluateBasePolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (toolDecision.effect === "deny") return toolDecision;
  if (localFsDecision?.effect === "ask") return localFsDecision;
  return toolDecision;
}

export class PolicyLoader {
  constructor(policyPath) { this.policyPath = policyPath; this.cacheKey = null; this.cached = null; }
  load() {
    const stat = fs.statSync(this.policyPath, { bigint: true });
    if (!stat.isFile()) throw new Error(`policy path is not a regular file: ${this.policyPath}`);
    const key = `${stat.mtimeNs}:${stat.size}:${stat.ino}`;
    if (this.cached && this.cacheKey === key) return this.cached;
    const parsed = validatePolicy(JSON.parse(fs.readFileSync(this.policyPath, "utf8")));
    this.cached = parsed;
    this.cacheKey = key;
    return parsed;
  }
}

export { LearnedRuleStore };
