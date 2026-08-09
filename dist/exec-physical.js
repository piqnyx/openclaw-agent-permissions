import fs from "node:fs";
import path from "node:path";
import {
  LearnedRuleStore,
  PolicyLoader,
  evaluatePolicy as evaluateExecPathPolicy,
  validatePolicy,
} from "./exec-paths.js";

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function deepestExistingAncestor(target) {
  let current = target;
  const suffix = [];
  while (true) {
    try {
      fs.lstatSync(current);
      return { ancestor: current, suffix };
    } catch (err) {
      if (err?.code !== "ENOENT" && err?.code !== "ENOTDIR") throw err;
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    suffix.unshift(path.basename(current));
    current = parent;
  }
}

function physicalWorkspaceGuard(call, virtualWorkspaceRoot = "/workspace") {
  const lexicalPaths = Array.isArray(call.paths) ? call.paths : [];
  const virtualRoot = path.posix.normalize(String(virtualWorkspaceRoot).replaceAll("\\", "/"));
  const virtualPrefix = virtualRoot.endsWith("/") ? virtualRoot : `${virtualRoot}/`;
  const workspaceTargets = lexicalPaths.filter((target) => target === virtualRoot || target.startsWith(virtualPrefix));
  if (workspaceTargets.length === 0) return { effect: "allow", reason: "no workspace paths require physical verification" };

  if (typeof call.workspaceDir !== "string" || !call.workspaceDir || !path.isAbsolute(call.workspaceDir)) {
    return { effect: "ask", reason: "host workspace mapping is unavailable for physical exec-path verification" };
  }

  let hostRoot;
  try {
    hostRoot = fs.realpathSync.native(call.workspaceDir);
  } catch (err) {
    return { effect: "ask", reason: `host workspace root cannot be resolved physically: ${String(err)}` };
  }

  for (const lexical of workspaceTargets) {
    const relativePosix = lexical === virtualRoot ? "" : path.posix.relative(virtualRoot, lexical);
    const hostCandidate = path.resolve(call.workspaceDir, ...relativePosix.split("/").filter(Boolean));
    let ancestorInfo;
    let realAncestor;
    try {
      ancestorInfo = deepestExistingAncestor(hostCandidate);
      if (!ancestorInfo) return { effect: "ask", reason: `cannot resolve an existing ancestor for ${lexical}` };
      realAncestor = fs.realpathSync.native(ancestorInfo.ancestor);
    } catch (err) {
      return { effect: "ask", reason: `physical exec-path verification failed for ${lexical}: ${String(err)}` };
    }

    if (!isInside(hostRoot, realAncestor)) {
      return { effect: "ask", reason: `${lexical} resolves through a workspace symlink outside the host workspace` };
    }

    const realCandidate = path.resolve(realAncestor, ...ancestorInfo.suffix);
    if (!isInside(hostRoot, realCandidate)) {
      return { effect: "ask", reason: `${lexical} resolves outside the host workspace` };
    }

    const physicalRelative = path.relative(hostRoot, realCandidate).split(path.sep).join("/");
    const physicalVirtual = physicalRelative ? path.posix.join(virtualRoot, physicalRelative) : virtualRoot;
    if (physicalVirtual !== lexical) {
      return { effect: "ask", reason: `${lexical} physically resolves to ${physicalVirtual}` };
    }
  }

  return { effect: "allow", reason: "workspace paths are physically consistent with their lexical targets" };
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const decision = evaluateExecPathPolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (call.capability !== "exec" || !policy.exec?.paths || decision.effect !== "allow") return decision;

  const physical = physicalWorkspaceGuard(call, virtualWorkspaceRoot);
  if (physical.effect === "allow") return decision;
  return {
    kind: "exec",
    effect: "ask",
    ruleId: `${decision.ruleId}+<exec-path-physical>`,
    reason: `${decision.reason}; ${physical.reason}`,
    allowAlways: false,
    command: decision.command,
  };
}

export { LearnedRuleStore, PolicyLoader, validatePolicy };
