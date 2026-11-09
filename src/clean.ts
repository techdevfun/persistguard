/**
 * `persistguard clean` - rewrite detected secret values out of
 * persisted allow rules.
 *
 * Dry-run by default: print what would change. With `--write`, rewrite
 * each flagged settings file, replacing each detected secret value
 * with `<REDACTED-BY-PERSISTGUARD>` (command shape and all non-secret
 * rules preserved; JSON re-serialised with 2-space indent; a `.bak`
 * copy is written next to the file first, and the rewritten file is
 * re-parsed - on failure the `.bak` is restored and the run fails
 * loudly). The tool refuses to rewrite a file tracked by git unless
 * `--force` is given: rewriting a tracked file does not un-leak
 * history, and the tool says so.
 *
 * Always prints a rotation checklist afterwards: redaction is not
 * rotation, and it never un-leaks history.
 */

import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { detectSecrets, redactText, type RawFinding } from "./detect.js";
import { parseRule } from "./rules.js";
import {
  displayPath,
  findSettingsFiles,
  isTracked,
  scanDir,
  toPublicFinding,
  type PublicFinding,
  type ScanResult,
} from "./scan.js";

export interface CleanFileResult {
  file: string;
  findings: PublicFinding[];
  tracked: boolean;
  changed: boolean;
  bak: string | null;
}

export interface CleanResult {
  mode: "dry-run" | "write";
  files: CleanFileResult[];
  totals: { findings: number; high: number; medium: number };
  types: string[];
  exitCode: number;
  lines: string[];
  error?: string;
}

export function rotationChecklist(types: string[]): string[] {
  const lines = [
    "Rotation checklist - redaction does not un-leak history:",
    "  Rotate or revoke every credential listed above. If the file was",
    "  ever committed, the secret lives in git history: rotate it and",
    "  rewrite history with git filter-repo (this tool does not do that).",
  ];
  if (types.length > 0) {
    lines.splice(
      1,
      0,
      ...types.map((t) => `  - ${t}: rotate/revoke this credential`),
    );
  }
  return lines;
}

interface RawRuleFindings {
  list: string;
  ruleIndex: number;
  rule: string;
  commandText: string;
  raw: RawFinding[];
}

/** Re-detect per rule, keeping raw spans for the rewrite. */
function rawFindingsForFile(dir: string, abs: string): { display: string; rules: RawRuleFindings[]; error?: string } {
  const display = displayPath(dir, abs);
  let text: string;
  try {
    text = readFileSync(abs, "utf8");
  } catch (err) {
    return { display, rules: [], error: `unreadable file: ${(err as Error).message}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    return { display, rules: [], error: `invalid JSON: ${(err as Error).message}` };
  }
  const rules: RawRuleFindings[] = [];
  const permissions =
    parsed !== null && typeof parsed === "object" && "permissions" in parsed
      ? (parsed as { permissions?: unknown }).permissions
      : undefined;
  if (permissions !== null && typeof permissions === "object") {
    for (const list of ["allow", "ask", "deny"]) {
      const entries = (permissions as Record<string, unknown>)[list];
      if (!Array.isArray(entries)) continue;
      entries.forEach((entry, ruleIndex) => {
        if (typeof entry !== "string") return;
        const parsedRule = parseRule(entry);
        if (!parsedRule || parsedRule.commandText === null) return;
        const raw = detectSecrets(parsedRule.commandText);
        if (raw.length > 0) rules.push({ list, ruleIndex, rule: entry, commandText: parsedRule.commandText, raw });
      });
    }
  }
  return { display, rules };
}

function redactedRule(rule: string, raw: RawFinding[]): string {
  const parsedRule = parseRule(rule);
  if (!parsedRule || parsedRule.commandText === null) return rule;
  const shift = rule.indexOf(parsedRule.commandText);
  const adjusted = raw.map((f) => ({ ...f, start: f.start + shift, end: f.end + shift }));
  return redactText(rule, adjusted);
}

export function cleanDir(dir: string, opts: { write?: boolean; force?: boolean } = {}): CleanResult {
  const resolved = resolve(dir);
  const scan: ScanResult = scanDir(resolved);
  const files = findSettingsFiles(resolved);
  const perFile = files.map((abs) => {
    const raw = rawFindingsForFile(resolved, abs);
    const publicFindings: PublicFinding[] = [];
    for (const r of raw.rules) {
      // Detector spans are relative to the command text; shift them
      // to the full rule string before redacting the rule for output.
      const shift = r.rule.indexOf(r.commandText);
      for (const hit of r.raw) {
        publicFindings.push(
          toPublicFinding(raw.display, r.list, r.ruleIndex, r.rule, {
            ...hit,
            start: hit.start + shift,
            end: hit.end + shift,
          }),
        );
      }
    }
    return { abs, display: raw.display, raw, publicFindings, tracked: isTracked(resolved, abs) };
  });

  const totals = {
    findings: scan.totals.findings,
    high: scan.totals.high,
    medium: scan.totals.medium,
  };
  const types = [...new Set(scan.files.flatMap((f) => f.findings.map((x) => x.type)))].sort();
  const mode = opts.write ? "write" : "dry-run";
  const lines: string[] = [];

  if (totals.findings === 0) {
    lines.push("persistguard clean: no findings - nothing to redact.");
    return {
      mode,
      files: perFile.map((p) => ({ file: p.display, findings: [], tracked: p.tracked, changed: false, bak: null })),
      totals,
      types,
      exitCode: 0,
      lines,
    };
  }

  if (!opts.write) {
    lines.push(`persistguard clean (dry run - nothing written): ${totals.findings} finding(s) in ${perFile.filter((p) => p.publicFindings.length > 0).length} file(s)`);
    for (const p of perFile) {
      if (p.publicFindings.length === 0) continue;
      lines.push(`${p.display} (${p.publicFindings.length} finding(s))`);
      // Never print the raw rule: the public finding already holds
      // the rule with the secret replaced by the placeholder.
      for (const f of p.publicFindings) {
        lines.push(`  [${f.severity}] ${f.type}  rule #${f.ruleIndex} (${f.list}) (preview: ${f.preview})`);
        lines.push(`    -> ${f.rule}`);
      }
      if (p.tracked) {
        lines.push("  NOTE: this file is tracked by git - --write will refuse without --force.");
        lines.push("  Rewriting a tracked file does not un-leak history.");
      }
    }
    lines.push(...rotationChecklist(types));
    return {
      mode,
      files: perFile.map((p) => ({ file: p.display, findings: p.publicFindings, tracked: p.tracked, changed: false, bak: null })),
      totals,
      types,
      exitCode: 0,
      lines,
    };
  }

  // --write: refuse the whole run when any flagged file is tracked
  // and --force was not given. Change nothing in that case.
  const blocked = perFile.filter((p) => p.publicFindings.length > 0 && p.tracked && !opts.force);
  if (blocked.length > 0) {
    lines.push("persistguard clean: refused - these files are tracked by git:");
    for (const p of blocked) lines.push(`  ${p.display}`);
    lines.push("Rewriting a tracked file does not un-leak history.");
    lines.push("Re-run with --force if you understand that, or remove the file from git first.");
    lines.push(...rotationChecklist(types));
    return {
      mode,
      files: perFile.map((p) => ({ file: p.display, findings: p.publicFindings, tracked: p.tracked, changed: false, bak: null })),
      totals,
      types,
      exitCode: 2,
      lines,
      error: "tracked file without --force",
    };
  }

  const results: CleanFileResult[] = [];
  for (const p of perFile) {
    if (p.publicFindings.length === 0) {
      results.push({ file: p.display, findings: [], tracked: p.tracked, changed: false, bak: null });
      continue;
    }
    const bakPath = `${p.abs}.bak`;
    const text = readFileSync(p.abs, "utf8");
    const parsed = JSON.parse(text) as { permissions?: Record<string, unknown> };
    const permissions = parsed.permissions as Record<string, string[]> | undefined;
    if (permissions) {
      for (const r of p.raw.rules) {
        const list = permissions[r.list];
        if (Array.isArray(list) && typeof list[r.ruleIndex] === "string") {
          list[r.ruleIndex] = redactedRule(list[r.ruleIndex], r.raw);
        }
      }
    }
    const rewritten = `${JSON.stringify(parsed, null, 2)}\n`;
    try {
      copyFileSync(p.abs, bakPath);
      writeFileSync(p.abs, rewritten, "utf8");
      // Re-parse after rewrite; restore the backup on failure.
      JSON.parse(readFileSync(p.abs, "utf8"));
    } catch (err) {
      try {
        copyFileSync(bakPath, p.abs);
      } catch {
        // Best effort restore; the .bak copy still exists.
      }
      lines.push(`persistguard clean: rewrite failed for ${p.display}: ${(err as Error).message}`);
      lines.push(`  Restored from ${bakPath}.`);
      return {
        mode,
        files: results.concat([{ file: p.display, findings: p.publicFindings, tracked: p.tracked, changed: false, bak: bakPath }]),
        totals,
        types,
        exitCode: 2,
        lines,
        error: `rewrite failed for ${p.display}`,
      };
    }
    lines.push(`${p.display}: ${p.publicFindings.length} finding(s) redacted (backup: ${p.display}.bak)`);
    results.push({ file: p.display, findings: p.publicFindings, tracked: p.tracked, changed: true, bak: `${p.display}.bak` });
  }
  lines.unshift(`persistguard clean --write: ${totals.findings} finding(s) redacted in ${results.filter((r) => r.changed).length} file(s)`);
  lines.push(...rotationChecklist(types));
  return { mode, files: results, totals, types, exitCode: 0, lines };
}
