/**
 * Allow-rule parsing for Claude Code permission rules.
 *
 * A rule is `Tool` or `Tool(specifier)`; for Bash the specifier is the
 * command text, e.g. `Bash(npm test)`, `Bash(git log *)`. A trailing
 * `:*` on the specifier is a wildcard suffix: it matches the bare
 * command too, so detection scans the command text without it while
 * the original rule text is preserved for display and rewriting.
 */

export interface ParsedRule {
  tool: string;
  /** Specifier text as written, or null for a bare tool name. */
  specifier: string | null;
  /** Command text to run detectors over (specifier minus a trailing `:*`). */
  commandText: string | null;
  /** True when the specifier ended with `:*`. */
  wildcardSuffix: boolean;
  raw: string;
}

const RULE_RE = /^([A-Za-z][A-Za-z0-9_-]*)(?:\((.*)\))?$/s;

export function parseRule(rule: string): ParsedRule | null {
  const trimmed = rule.trim();
  if (trimmed.length === 0) return null;
  const m = RULE_RE.exec(trimmed);
  if (!m) return null;
  const tool = m[1];
  const specifier = m[2] === undefined ? null : m[2];
  let wildcardSuffix = false;
  let commandText: string | null = specifier;
  if (specifier !== null && specifier.endsWith(":*")) {
    wildcardSuffix = true;
    commandText = specifier.slice(0, -2);
  }
  return { tool, specifier, commandText, wildcardSuffix, raw: trimmed };
}

/** Rebuild a rule string after its command text was rewritten. */
export function rebuildRule(parsed: ParsedRule, newCommandText: string): string {
  if (parsed.specifier === null) return parsed.tool;
  const specifier = parsed.wildcardSuffix ? `${newCommandText}:*` : newCommandText;
  return `${parsed.tool}(${specifier})`;
}
