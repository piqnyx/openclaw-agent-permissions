import fs from "node:fs";
import path from "node:path";
import { matchAny, validateMatcher } from "./matchers.js";
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

function mappingApplies(mapping, call, lexical) {
  if (mapping.agents !== undefined && !(typeof call.agentId === "string" && matchAny(mapping.agents, call.agentId))) return false;
  return lexical === mapping.virtual || lexical.startsWith(`${mapping.virtual}/`);
}

function selectPhysicalMapping(policy, call, lexical, virtualRoot) {
  const explicit = (policy.exec?.paths?.physicalMappings ?? [])
    .filter((mapping) => mappingApplies(mapping, call, lexical))
    .sort((a, b) => b.virtual.length - a.virtual.length)[0];
  if (explicit) return { id: explicit.id, virtual: explicit.virtual, host: explicit.host };

  if (typeof call.workspaceDir !== "string" || !call.workspaceDir || !path.isAbsolute(call.workspaceDir)) return null;
  return { id: "<workspaceDir>", virtual: virtualRoot, host: call.workspaceDir };
}

function physicalWorkspaceGuard(policy, call, virtualWorkspaceRoot = "/workspace") {
  const lexicalPaths = Array.isArray(call.paths) ? call.paths : [];
  const virtualRoot = path.posix.normalize(String(virtualWorkspaceRoot).replaceAll("\\", "/"));
  const virtualPrefix = virtualRoot.endsWith("/") ? virtualRoot : `${virtualRoot}/`;
  const workspaceTargets = lexicalPaths.filter((target) => target === virtualRoot || target.startsWith(virtualPrefix));
  if (workspaceTargets.length === 0) return { effect: "allow", reason: "no workspace paths require physical verification" };

  for (const lexical of workspaceTargets) {
    const mapping = selectPhysicalMapping(policy, call, lexical, virtualRoot);
    if (!mapping) {
      return { effect: "ask", reason: `host mapping is unavailable for physical exec-path verification of ${lexical}` };
    }

    let hostRoot;
    try {
      hostRoot = fs.realpathSync.native(mapping.host);
    } catch (err) {
      return { effect: "ask", reason: `physical mapping ${mapping.id} host root cannot be resolved: ${String(err)}` };
    }

    const relativePosix = lexical === mapping.virtual ? "" : path.posix.relative(mapping.virtual, lexical);
    const hostCandidate = path.resolve(mapping.host, ...relativePosix.split("/").filter(Boolean));
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
      return { effect: "ask", reason: `${lexical} resolves through a symlink outside physical mapping ${mapping.id}` };
    }

    const realCandidate = path.resolve(realAncestor, ...ancestorInfo.suffix);
    if (!isInside(hostRoot, realCandidate)) {
      return { effect: "ask", reason: `${lexical} resolves outside physical mapping ${mapping.id}` };
    }

    const physicalRelative = path.relative(hostRoot, realCandidate).split(path.sep).join("/");
    const physicalVirtual = physicalRelative ? path.posix.join(mapping.virtual, physicalRelative) : mapping.virtual;
    if (physicalVirtual !== lexical) {
      return { effect: "ask", reason: `${lexical} physically resolves to ${physicalVirtual} via mapping ${mapping.id}` };
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
