import { LearnedRuleStore, PolicyLoader, evaluatePolicy } from "./exec-paths.js";
import { buildCallContext, rewriteAllowedFilesystemMutationParams } from "./profiles.js";

function clamp(value, max) {
  const text = String(value);
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
}
function preview(call) {
  const pathPart = call.paths.length ? ` paths=${call.paths.join(",")}` : "";
  return `${call.toolName} capability=${call.capability} operation=${call.operation}${pathPart}`;
}
function rememberText(decision, call) {
  if (!decision.allowAlways) return "Permanent approval disabled for this rule.";
  if (decision.kind === "filesystem") return `Always remembers only the ASK operation/path target(s), for agent ${call.agentId ?? "unknown"}.`;
  if (decision.kind === "exec") return `Always remembers this exact command for this agent.`;
  return `Always remembers this tool + capability for this agent; parameters may change.`;
}

function register(api) {
  const cfg = api.pluginConfig ?? {};
  const policyPath = cfg.policyPath ?? "/home/openclaw/.openclaw/permissions.json";
  const virtualWorkspaceRoot = cfg.virtualWorkspaceRoot ?? "/workspace";
  const approvalTimeoutMs = cfg.approvalTimeoutMs ?? 540000;
  const logDecisions = cfg.logDecisions !== false;
  const failClosed = cfg.failClosed !== false;
  const loader = new PolicyLoader(policyPath);
  let learnedStore = null;

  function loadAll() {
    const policy = loader.load();
    if (policy.learning?.enabled !== false) {
      const learnedPath = policy.learning?.path ?? `${policyPath}.learned.json`;
      if (!learnedStore || learnedStore.filePath !== learnedPath) learnedStore = new LearnedRuleStore(learnedPath);
    } else {
      learnedStore = null;
    }
    return policy;
  }

  try {
    const policy = loadAll();
    api.logger.info(`agent-permissions: policy v${policy.version} loaded from ${policyPath}`);
  } catch (err) {
    api.logger.warn(`agent-permissions: initial policy load failed: ${String(err)}`);
  }

  api.on("before_tool_call", async (event, hookContext) => {
    try {
      const policy = loadAll();
      const call = buildCallContext(event, hookContext, policy, virtualWorkspaceRoot);
      const decision = evaluatePolicy(policy, call, learnedStore, virtualWorkspaceRoot);
      if (logDecisions) api.logger.info(`agent-permissions: ${decision.effect.toUpperCase()} agent=${call.agentId ?? "?"} ${preview(call)} rule=${decision.ruleId ?? "<default>"}`);
      if (decision.effect === "deny") return { block: true, blockReason: `agent-permissions denied ${call.toolName}: ${decision.reason}` };

      // OpenClaw 2026.7.2 memory-write provenance evaluates sandbox-absolute
      // filesystem mutation paths with host-side realpath(). After authorization
      // has already been decided against the canonical /workspace path, rewrite
      // only execution parameters to workspace-relative form. This preserves the
      // model-facing sandbox contract and leaves reads, exec and process untouched.
      const executionParams = rewriteAllowedFilesystemMutationParams(call, policy, virtualWorkspaceRoot);
      if (decision.effect === "allow") return executionParams ? { params: executionParams } : undefined;

      const approvalStore = learnedStore;
      const canAlways = Boolean(approvalStore && decision.allowAlways && typeof call.agentId === "string" && call.agentId.length > 0);
      const pathText = call.paths.length ? `\nPaths: ${call.paths.join(", ")}` : "";
      return {
        ...(executionParams ? { params: executionParams } : {}),
        requireApproval: {
          title: clamp(`Allow ${call.toolName}?`, 80),
          description: clamp(`Rule: ${decision.ruleId ?? "<default>"}\nAgent: ${call.agentId ?? "unknown"}\nCapability: ${call.capability}${pathText}\n${rememberText({ ...decision, allowAlways: canAlways }, call)}`, 480),
          severity: ["exec", "fs.write", "fs.delete", "fs.move", "external.write", "memory.write", "browser", "process"].includes(call.capability) ? "critical" : "warning",
          timeoutMs: approvalTimeoutMs,
          allowedDecisions: canAlways ? ["allow-once", "allow-always", "deny"] : ["allow-once", "deny"],
          onResolution: canAlways ? async (resolution) => {
            if (resolution !== "allow-always") return;
            try {
              approvalStore.persist(call, decision);
              api.logger.info(`agent-permissions: learned ALLOW agent=${call.agentId ?? "?"} ${preview(call)} kind=${decision.kind}`);
            } catch (err) {
              api.logger.warn(`agent-permissions: persist allow-always failed: ${String(err)}`);
            }
          } : undefined
        }
      };
    } catch (err) {
      api.logger.warn(`agent-permissions: policy engine failure on ${event?.toolName ?? "?"}: ${String(err)}`);
      if (!failClosed) return undefined;
      return { block: true, blockReason: `agent-permissions fail-closed: ${String(err)}` };
    }
  }, { priority: 100 });
}

export default {
  id: "agent-permissions",
  name: "Agent Permissions Policy",
  description: "Unified filesystem, exec-regex and tool permission policy for OpenClaw.",
  register
};
