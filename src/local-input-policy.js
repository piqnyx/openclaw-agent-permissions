import fs from "node:fs";
import {
  LearnedRuleStore,
  evaluatePolicy as evaluateBasePolicy,
  validatePolicy as validateBasePolicy,
} from "./exec-no-target.js";
import {
  analyzeLocalInputs,
  resolveLocalInputMappings,
  validateLocalInputs,
} from "./local-inputs.js";
import { validatePathMappings } from "./path-mappings.js";

function stripLocalInputPolicy(policy) {
  const copy = structuredClone(policy);
  delete copy.pathMappings;
  delete copy.localInputs;
  return copy;
}

function validateMappingReferences(policy) {
  const mappingIds = new Set((policy.pathMappings ?? []).map((mapping) => mapping.id));
  for (let i = 0; i < (policy.localInputs ?? []).length; i++) {
    const input = policy.localInputs[i];
    for (const mappingId of input.mappingIds ?? []) {
      if (!mappingIds.has(mappingId)) {
        throw new Error(`localInputs[${i}].mappingIds: unknown path mapping '${mappingId}'`);
      }
    }
  }
}

export function validatePolicy(policy) {
  validatePathMappings(policy?.pathMappings);
  validateLocalInputs(policy?.localInputs);
  validateMappingReferences(policy ?? {});
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

  const asks = [];
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
    if (decision.effect === "ask") asks.push(decision);
  }

  if (asks.length === 0) return null;
  if (asks.length === 1) return asks[0];

  const askTargets = asks.flatMap((decision) => decision.askTargets ?? []);
  return {
    kind: "filesystem",
    operation: "mixed",
    effect: "ask",
    ruleId: [...new Set(asks.map((decision) => decision.ruleId))].join(","),
    reason: asks.map((decision) => decision.reason).join("; "),
    allowAlways: asks.every((decision) => decision.allowAlways === true),
    askPaths: [...new Set(askTargets.map((target) => target.path))],
    askTargets,
  };
}

function mergeAskDecisions(localFsDecision, toolDecision) {
  const fsAsk = localFsDecision?.effect === "ask" ? localFsDecision : null;
  const toolAsk = toolDecision?.effect === "ask" ? toolDecision : null;
  if (!fsAsk) return toolDecision;
  if (!toolAsk) return fsAsk;

  return {
    kind: "composite",
    effect: "ask",
    ruleId: `${fsAsk.ruleId}+${toolAsk.ruleId}`,
    reason: `${fsAsk.reason}; ${toolAsk.reason}`,
    allowAlways: false,
  };
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const analysisDecision = analyzeLocalInputs(policy, call, virtualWorkspaceRoot);
  if (analysisDecision) return analysisDecision;

  const localFsDecision = evaluateLocalInputFilesystem(policy, call, learnedStore, virtualWorkspaceRoot);
  if (localFsDecision?.effect === "deny") return localFsDecision;

  const toolDecision = evaluateBasePolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (toolDecision.effect === "deny") return toolDecision;

  // Resolve host paths only after both the sandbox-visible filesystem target and
  // the generic tool itself have survived static DENY policy. This avoids probing
  // host paths for calls that authorization would reject anyway.
  const mappingDecision = resolveLocalInputMappings(policy, call);
  if (mappingDecision) return mappingDecision;

  return mergeAskDecisions(localFsDecision, toolDecision);
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
