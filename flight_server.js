/**
 * Flow-typed JS module mimicking React-server reply-decoding shapes.
 *
 * Purpose: regression fixture for the tree-sitter grammar fix. Function
 * declarations here use Flow-style generic parameters
 *   `function name<T>(...)`
 * which the plain `tree-sitter-javascript` grammar misparses as a
 * less-than expression — the entire function node is silently dropped
 * from the AST and never makes it into scored-functions' extracted
 * function list. Routing `.js` extensions through `tree-sitter-typescript`
 * (the `tsx` variant) parses these correctly since TypeScript's syntax
 * is a strict superset of JS that includes generics.
 *
 * The vulnerabilities below are intentional — they call attacker-
 * controlled inputs into shell commands and into pickle-style
 * deserialisers, modelled after CVE-2025-55182 (React2Shell). If the
 * grammar fix works, these functions appear in chains; if it doesn't,
 * they remain invisible.
 */

const { exec, execSync } = require("child_process");
const vm = require("vm");

// Flow generic — function name<T>(...). Plain JS grammar drops this.
// Sink: command injection via exec on attacker-controlled `host`.
function decodeReplyFromBusboy<T>(parts: Array<string>): T {
  const host = parts[0] || "";
  const cmd = `wget -q ${host} -O /tmp/payload`;
  exec(cmd);
  return resolveModelChunk(parts);
}

function resolveModelChunk<T>(parts: Array<string>): T {
  return reviveModel(parts.join("|"));
}

function reviveModel<T>(serialized: string): T {
  return parseModelString(serialized);
}

// Vulnerability: indirect-eval pickle-style deserialisation
function parseModelString<T>(s: string): T {
  // Sink: vm.runInNewContext on attacker data. CWE-94 RCE.
  return vm.runInNewContext(s);
}

// Outlined model getter — mirrors the React2Shell sink. Constructs
// shell command from attacker-controlled `ref`.
function getOutlinedModel<T>(ref: string): T {
  const out = execSync(`cat /var/models/${ref}`, { encoding: "utf-8" });
  return JSON.parse(out);
}

// Plain JS function (no generics) — this one DOES parse under both
// grammars. Acts as a control: if the JS-grammar path were active,
// only this function would be extracted; the five generic-typed ones
// would all be missing.
function resolveField(name) {
  return decodeReplyFromBusboy([name, "extra"]);
}

module.exports = { resolveField };
