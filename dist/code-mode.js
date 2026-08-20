/**
 * Recognizing a code-mode call.
 *
 * OpenClaw can hide the tool catalog behind a QuickJS-WASI guest and expose only
 * `exec` and `wait`. The model then writes a program that calls tools through a
 * bridge, and every one of those calls arrives at this plugin as its own
 * `before_tool_call` with its own capability and paths -- a read of
 * /workspace/USER.md is still a read of /workspace/USER.md, matched by whichever
 * filesystem zone covers it.
 *
 * The outer call is the odd one: it carries a program, not a command. Exec regexes
 * would be matched against source code, and the path operands would be whatever the
 * gateway's extractor mistook for a path inside it -- a live gateway produced
 * `paths=/workspace/Basic/Pascal` from a program mentioning old languages. Rules
 * written for a shell cannot say anything true about a program.
 *
 * Detection is deliberately narrow. A payload this does not recognize stays an
 * ordinary exec call and is judged by the exec rules exactly as before, so being
 * wrong here costs an approval prompt, never a permission.
 */
export function isCodeModeCall(call) {
  if (call?.capability !== "exec") return false;
  const params = call.params ?? {};
  // `code` carries the program on its own; `language` accompanies it and also marks
  // the variant that reuses `command` as the carrier.
  return typeof params.code === "string" || typeof params.language === "string";
}
