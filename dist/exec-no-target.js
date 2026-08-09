import {
  LearnedRuleStore,
  PolicyLoader,
  evaluatePolicy as evaluatePhysicalPolicy,
  validatePolicy,
} from "./exec-physical.js";

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const decision = evaluatePhysicalPolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (call.capability !== "exec" || !policy.exec?.paths || decision.effect !== "allow") return decision;

  if (Array.isArray(call.paths) && call.paths.length > 0) return decision;

  return {
    kind: "exec",
    effect: "ask",
    ruleId: `${decision.ruleId}+<exec-path-no-targets>`,
    reason: `${decision.reason}; no explicit filesystem path operands were detected, so implicit cwd or bare relative targets cannot be proven safe`,
    allowAlways: false,
    command: decision.command,
  };
}

export { LearnedRuleStore, PolicyLoader, validatePolicy };
