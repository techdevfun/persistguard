/**
 * Secret detectors for command text inside agent allow rules.
 *
 * Every detector returns the exact span of the secret value inside the
 * command text. Callers replace exactly that span when redacting, so
 * the command shape survives and no secret value is ever printed:
 * `preview` shows at most the first 4 + last 2 characters of a token,
 * or only the key name for a password assignment.
 *
 * Detectors are heuristic. A password that looks like an ordinary word
 * next to no host will be missed; a high-entropy string that is not a
 * secret can be flagged. Findings are graded HIGH / MEDIUM for that
 * reason, and the README says so in plain language.
 */

export const REDACTED = "<REDACTED-BY-PERSISTGUARD>";

export type Severity = "HIGH" | "MEDIUM";

export interface RawFinding {
  detector: string;
  type: string;
  severity: Severity;
  /** Exact secret value (internal only - never printed or serialized). */
  value: string;
  start: number;
  end: number;
  preview: string;
}

interface Pattern {
  type: string;
  severity: Severity;
  regex: RegExp;
  /** Group index holding the secret value. */
  valueGroup: number;
  preview: (value: string, match: RegExpExecArray) => string;
}

function tokenPreview(value: string): string {
  if (value.length <= 6) return "****";
  return `${value.slice(0, 4)}...${value.slice(-2)}`;
}

const KNOWN_PREFIX: Pattern[] = [
  {
    type: "github-pat",
    severity: "HIGH",
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "github-token",
    severity: "HIGH",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "openai-key",
    severity: "HIGH",
    regex: /\bsk-proj-[A-Za-z0-9_-]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "openai-key",
    severity: "HIGH",
    regex: /\bsk-[A-Za-z0-9_-]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "aws-access-key",
    severity: "HIGH",
    regex: /\bAKIA[0-9A-Z]{16}\b/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "slack-token",
    severity: "HIGH",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "npm-token",
    severity: "HIGH",
    regex: /\bnpm_[A-Za-z0-9]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "square-token",
    severity: "HIGH",
    regex: /\bsq0at-[A-Za-z0-9_-]{10,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "supabase-key",
    severity: "HIGH",
    regex: /\bsbp_[A-Za-z0-9]{20,}/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
  {
    type: "jwt",
    severity: "HIGH",
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gd,
    valueGroup: 0,
    preview: tokenPreview,
  },
];

const STRUCTURED: Pattern[] = [
  {
    // postgres://user:password@host - the value is the password only.
    type: "credential-url",
    severity: "HIGH",
    regex: /([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\s/:@]+):([^\s/@]+)@([^\s/]+)/gd,
    valueGroup: 3,
    preview: (_value, m) => `${m[1]}://${m[2]}:****@${m[4]}`,
  },
  {
    // curl -u user:password https://... / --user user:password
    type: "basic-auth-password",
    severity: "HIGH",
    regex: /(?:^|\s)(?:-u|--user)[=\s]+([^\s:]+):([^\s]+)/gd,
    valueGroup: 2,
    preview: (_value, m) => `${m[1]}:****`,
  },
  {
    // Authorization: Bearer <token> / Basic <credentials>
    type: "authorization-header",
    severity: "HIGH",
    regex: /Authorization:\s*(?:Bearer|Basic)\s+([^\s"']+)/gd,
    valueGroup: 1,
    preview: tokenPreview,
  },
  {
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /--password[=\s]+([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "--password=****",
  },
  {
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /\bPGPASSWORD[=\s]+([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "PGPASSWORD=****",
  },
  {
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /\bMYSQL_PWD[=\s]+([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "MYSQL_PWD=****",
  },
  {
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /\bpassword[=:][ \t]*([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "password=****",
  },
  {
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /\bpasswd[=:][ \t]*([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "passwd=****",
  },
  {
    // sshpass -p <secret> / sshpass -p<secret>
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /\bsshpass\s+-p\s*([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "sshpass -p ****",
  },
  {
    // mysql -p<secret> / mysql -p <secret> (mysql/psql-shaped only)
    type: "password-assignment",
    severity: "MEDIUM",
    regex: /-p\s*([^\s"']+)/gd,
    valueGroup: 1,
    preview: () => "-p ****",
  },
];

const KNOWN_COMMANDS = /\b(curl|wget|psql|mysql|mariadb|sshpass|ssh|scp|ftp)\b/;
const HOST_RE = /\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b/i;
// Token characters only - no `=`, so a `KEY=value` pair is never
// swallowed whole: the value after `=` is matched on its own, and a
// known-prefix token after `?token=` keeps its own span (the dedupe
// below then keeps the known-prefix finding, not this one).
const TOKEN_RE = /[A-Za-z0-9_\-+/]{20,}=*/g;

function charClasses(token: string): number {
  let classes = 0;
  if (/[a-z]/.test(token)) classes++;
  if (/[A-Z]/.test(token)) classes++;
  if (/[0-9]/.test(token)) classes++;
  if (/[_+\/=.-]/.test(token)) classes++;
  return classes;
}

function spansOverlap(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return aStart < bEnd && bStart < aEnd;
}

/**
 * Run every detector over one command string. Returns findings sorted
 * by position, with overlapping spans deduplicated (first detector
 * wins, so a token inside a credential URL is reported once).
 */
export function detectSecrets(command: string): RawFinding[] {
  const found: RawFinding[] = [];
  const isMysqlShaped = /\b(mysql|psql|mariadb|pg_dump|mysqldump)\b/.test(command);

  const collect = (pattern: Pattern): void => {
    pattern.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.regex.exec(command)) !== null) {
      const value = m[pattern.valueGroup];
      if (value === undefined || value.length === 0) continue;
      if (value === REDACTED) continue;
      // Group 0 spans the whole match. For a value group, take the
      // capture group's own span (RegExp `d` flag): searching for the
      // value text would find its FIRST occurrence, which is wrong
      // when the value also appears earlier in the match - e.g.
      // postgres://secret:secret@host must redact the password
      // (second occurrence), not the username.
      let start: number;
      if (pattern.valueGroup === 0) {
        start = m.index;
      } else {
        const groupSpan = m.indices?.[pattern.valueGroup];
        if (groupSpan === undefined) continue;
        start = groupSpan[0];
      }
      const end = start + value.length;
      found.push({
        detector: pattern.type,
        type: pattern.type,
        severity: pattern.severity,
        value,
        start,
        end,
        preview: pattern.preview(value, m),
      });
    }
  };

  for (const p of KNOWN_PREFIX) collect(p);
  for (const p of STRUCTURED) {
    // The bare `-p` pattern only fires for mysql/psql-shaped commands,
    // so `grep -p` or `npm -p` never flags.
    if (p.type === "password-assignment" && p.regex.source.startsWith("-p") && !isMysqlShaped) {
      continue;
    }
    collect(p);
  }

  // High-entropy token next to a public host or a known command.
  // This is the shape generic scanners miss: a password/token inside
  // a command with no recognizable key format.
  if (KNOWN_COMMANDS.test(command) || HOST_RE.test(command)) {
    TOKEN_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TOKEN_RE.exec(command)) !== null) {
      const token = m[0];
      if (token === REDACTED) continue;
      if (charClasses(token) < 3) continue;
      // Skip tokens that are part of a URL host or a file path.
      const before = command[m.index - 1];
      if (before === "/" || before === "." || before === "@" || before === ":") continue;
      found.push({
        detector: "high-entropy-token",
        type: "high-entropy-token",
        severity: "MEDIUM",
        value: token,
        start: m.index,
        end: m.index + token.length,
        preview: tokenPreview(token),
      });
    }
  }

  // Deduplicate overlapping spans: sort by start, then longest first.
  found.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: RawFinding[] = [];
  for (const f of found) {
    if (kept.some((k) => spansOverlap(f.start, f.end, k.start, k.end))) continue;
    kept.push(f);
  }
  kept.sort((a, b) => a.start - b.start);
  return kept;
}

/** Replace every finding's secret value in `text` with the placeholder. */
export function redactText(text: string, findings: RawFinding[]): string {
  const ordered = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  for (const f of ordered) {
    out = out.slice(0, f.start) + REDACTED + out.slice(f.end);
  }
  return out;
}
