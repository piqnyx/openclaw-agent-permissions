import fs from "node:fs";
import path from "node:path";
import { validateMatcher } from "./matchers.js";
import { resolveMappedPath } from "./path-mappings.js";
import {
  LearnedRuleStore,
  PolicyLoader,
  evaluatePolicy as evaluateExecPathPolicy,
  validatePolicy as validateExecPathPolicy,
} from "./exec-paths.js";

const PHYSICAL_MAPPING_KEYS = new Set(["id", "description", "virtual", "host", "agents"]);

function asArray(value) { return Array.isArray(value) ? value : [value]; }
function assertObject(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: must be object`);
}
function validateMatcherList(value, where) {
  if (value === undefined) return;
  const list = asArray(value);
  if (list.length === 0) throw new Error(`${where}: empty matcher list`);
  list.forEach((matcher, i) => validateMatcher(matcher, `${where}[${i}]`));
}

function validatePhysicalMappings(mappings) {
  if (mappings === undefined) return;
  if (!Array.isArray(mappings)) throw new Error("exec.paths.physicalMappings must be array");
  const ids = new Set();
  for (let i = 0; i < mappings.length; i++) {
    const mapping = mappings[i];
    const where = `exec.paths.physicalMappings[${i}]`;
    assertObject(mapping, where);
    for (const key of Object.keys(mapping)) {
      if (!PHYSICAL_MAPPING_KEYS.has(key)) throw new Error(`${where}.${key}: unknown field`);
    }
    if (typeof mapping.id !== "string" || !mapping.id) throw new Error(`${where}.id: required`);
    if (ids.has(mapping.id)) throw new Error(`${where}.id: duplicate '${mapping.id}'`);
    ids.add(mapping.id);
    if (mapping.description !== undefined && typeof mapping.description !== "string") {
      throw new Error(`${where}.description: string required`);
    }
    if (typeof mapping.virtual !== "string" || !mapping.virtual.startsWith("/") || mapping.virtual.includes("\0")) {
      throw new Error(`${where}.virtual: absolute POSIX path required`);
    }
    const normalizedVirtual = path.posix.normalize(mapping.virtual.replaceAll("\\", "/"));
    if (normalizedVirtual !== mapping.virtual || (mapping.virtual.length > 1 && mapping.virtual.endsWith("/"))) {
      throw new Error(`${where}.virtual: normalized absolute POSIX path required`);
    }
    if (typeof mapping.host !== "string" || !mapping.host || mapping.host.includes("\0") || !path.isAbsolute(mapping.host)) {
      throw new Error(`${where}.host: absolute host path required`);
    }
    validateMatcherList(mapping.agents, `${where}.agents`);
  }
}

function stripPhysicalMappings(policy) {
  const copy = structuredClone(policy);
  if (copy?.exec?.paths && typeof copy.exec.paths === "object" && !Array.isArray(copy.exec.paths)) {
    delete copy.exec.paths.physicalMappings;
  }
  return copy;
}

export function validatePolicy(policy) {
  validatePhysicalMappings(policy?.exec?.paths?.physicalMappings);
  validateExecPathPolicy(stripPhysicalMappings(policy));
  return policy;
}

function physicalWorkspaceGuard(policy, call, virtualWorkspaceRoot = "/workspace") {
  const lexicalPaths = Array.isArray(call.paths) ? call.paths : [];
  const virtualRoot = path.posix.normalize(String(virtualWorkspaceRoot).replaceAll("\\", "/"));
  const virtualPrefix = virtualRoot.endsWith("/") ? virtualRoot : `${virtualRoot}/`;
  const workspaceTargets = lexicalPaths.filter((target) => target === virtualRoot || target.startsWith(virtualPrefix));
  if (workspaceTargets.length === 0) return { effect: "allow", reason: "no workspace paths require physical verification" };

  const configuredMappings = [
    ...(policy.pathMappings ?? []),
    ...(policy.exec?.paths?.physicalMappings ?? []),
  ];

  for (const lexical of workspaceTargets) {
    let resolved = resolveMappedPath(configuredMappings, call, lexical);
    if (!resolved.ok && typeof call.workspaceDir === "string" && call.workspaceDir && path.isAbsolute(call.workspaceDir)) {
      resolved = resolveMappedPath([
        { id: "<workspaceDir>", virtual: virtualRoot, host: call.workspaceDir },
      ], call, lexical);
    }
    if (!resolved.ok) {
      return { effect: "ask", reason: `physical exec-path verification failed for ${lexical}: ${resolved.reason}` };
    }
  }

  return { effect: "allow", reason: "workspace paths are physically consistent with their configured mappings" };
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const decision = evaluateExecPathPolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (call.capability !== "exec" || !policy.exec?.paths || decision.effect !== "allow") return decision;

  const physical = physicalWorkspaceGuard(policy, call, virtualWorkspaceRoot);
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

export { LearnedRuleStore, PolicyLoader };
