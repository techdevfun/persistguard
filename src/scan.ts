/**
 * Finding agent persistence files and scanning them.
 *
 * The walker only ever opens `.claude/settings*.json` files. It never
 * reads other files, so persistguard is not a general secret scanner:
 * for whole-repo scanning, use gitleaks or TruffleHog, which beat us
 * there. A test asserts this by planting secret-shaped values in
 * decoy files of other types.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve } from "node:path";
import { detectSecrets, redactText, type RawFinding } from "./detect.js";
import { parseRule } from "./rules.js";

export interface PublicFinding {
  file: string;
  list: string;
  ruleIndex: number;
  rule: string;
  detector: string;
  type: string;
  severity: "HIGH" | "MEDIUM";
  preview: string;
}

export interface FileScan {
  file: string;
  rulesScanned: number;
  findings: PublicFinding[];
  error?: string;
}

export interface ScanResult {
  files: FileScan[];
  /** `.bak` backups of settings files found in `.claude/` dirs. They
   * hold the original (pre-redaction) secrets in plaintext, so a scan
   * that finds one exits 1 until it is deleted (see findBakFiles). */
  bakFiles: string[];
  totals: { files: number; rulesScanned: number; findings: number; high: number; medium: number };
}

const SETTINGS_FILE = /^settings(\.local)?\.json$/;
// A `clean --write` backup: `<settings file>.bak`. It holds the full
// original secrets, so it must never be committed - and it must never
// be read for findings either (its contents are the pre-redaction
// file); it is only listed, never opened.
const BAK_FILE = /^settings(\.local)?\.json\.bak$/;
const SKIP_DIRS = new Set(["node_modules", ".git"]);

function walkFiles(dir: string, match: (fileName: string) => boolean): string[] {
  const found: string[] = [];
  const walk = (current: string): void => {
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full);
      } else if (entry.isFile()) {
        // Only files that live directly inside a `.claude` directory.
        const parent = current.split("/").pop();
        if (parent === ".claude" && match(entry.name)) {
          found.push(full);
        }
      }
    }
  };
  walk(resolve(dir));
  found.sort();
  return found;
}

export function findSettingsFiles(dir: string): string[] {
  return walkFiles(dir, (name) => SETTINGS_FILE.test(name));
}

/** `.bak` backups sitting next to settings files (listed, never read). */
export function findBakFiles(dir: string): string[] {
  return walkFiles(dir, (name) => BAK_FILE.test(name));
}

export function displayPath(dir: string, file: string): string {
  const rel = relative(resolve(dir), file);
  if (rel.startsWith("..")) return file;
  return rel;
}

export function toPublicFinding(file: string, list: string, ruleIndex: number, rule: string, f: RawFinding): PublicFinding {
  return {
    file,
    list,
    ruleIndex,
    rule: redactText(rule, [f]),
    detector: f.detector,
    type: f.type,
    severity: f.severity,
    preview: f.preview,
  };
}

export function scanFile(dir: string, file: string): FileScan {
  const display = displayPath(dir, file);
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    return { file: display, rulesScanned: 0, findings: [], error: `unreadable file: ${(err as Error).message}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    // Invalid JSON is reported per file, not fatal to the whole scan.
    return { file: display, rulesScanned: 0, findings: [], error: `invalid JSON: ${(err as Error).message}` };
  }
  const findings: PublicFinding[] = [];
  let rulesScanned = 0;
  const permissions =
    parsed !== null && typeof parsed === "object" && "permissions" in parsed
      ? (parsed as { permissions?: unknown }).permissions
      : undefined;
  if (permissions !== null && typeof permissions === "object") {
    for (const list of ["allow", "ask", "deny"]) {
      const rules = (permissions as Record<string, unknown>)[list];
      if (!Array.isArray(rules)) continue;
      rules.forEach((entry, ruleIndex) => {
        if (typeof entry !== "string") return;
        rulesScanned++;
        const parsedRule = parseRule(entry);
        if (!parsedRule || parsedRule.commandText === null) return;
        // Non-Bash rules are listed too, but only flagged when the
        // specifier itself carries a secret value.
        const hits = detectSecrets(parsedRule.commandText);
        // Detector spans are relative to the command text; shift them
        // to the full rule string before redacting the rule for output.
        const shift = entry.indexOf(parsedRule.commandText);
        for (const hit of hits) {
          findings.push(
            toPublicFinding(display, list, ruleIndex, entry, {
              ...hit,
              start: hit.start + shift,
              end: hit.end + shift,
            }),
          );
        }
      });
    }
  }
  return { file: display, rulesScanned, findings };
}

export function scanDir(dir: string, opts: { global?: boolean } = {}): ScanResult {
  const files = findSettingsFiles(dir);
  const bakFiles = findBakFiles(dir).map((f) => displayPath(dir, f));
  if (opts.global) {
    const globalFile = join(homedir(), ".claude", "settings.json");
    if (existsSync(globalFile) && !files.includes(globalFile)) {
      files.push(globalFile);
      files.sort();
    }
    const globalBak = `${globalFile}.bak`;
    if (existsSync(globalBak)) {
      const display = displayPath(dir, globalBak);
      if (!bakFiles.includes(display)) bakFiles.push(display);
      bakFiles.sort();
    }
  }
  const scanned = files.map((f) => scanFile(dir, f));
  const totals = {
    files: scanned.length,
    rulesScanned: scanned.reduce((n, f) => n + f.rulesScanned, 0),
    findings: scanned.reduce((n, f) => n + f.findings.length, 0),
    high: scanned.reduce((n, f) => n + f.findings.filter((x) => x.severity === "HIGH").length, 0),
    medium: scanned.reduce((n, f) => n + f.findings.filter((x) => x.severity === "MEDIUM").length, 0),
  };
  return { files: scanned, bakFiles, totals };
}

/** Run a git command in `dir`, returning stdout or null on failure. */
export function gitOutput(dir: string, args: string[]): string | null {
  try {
    return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    return null;
  }
}

export function isGitRepo(dir: string): boolean {
  return gitOutput(dir, ["rev-parse", "--git-dir"]) !== null;
}

/** True when the file at `absPath` is tracked by git in `dir`. */
export function isTracked(dir: string, absPath: string): boolean {
  const rel = relative(resolve(dir), absPath);
  if (rel.startsWith("..")) return false;
  const out = gitOutput(dir, ["ls-files", "--", rel]);
  return out !== null && out.trim().length > 0;
}

export function gitLogDates(dir: string, absPath: string): string[] {
  const rel = relative(resolve(dir), absPath);
  if (rel.startsWith("..")) return [];
  const out = gitOutput(dir, ["log", "--all", "--format=%ad", "--date=short", "--", rel]);
  if (out === null) return [];
  return out.split("\n").map((l) => l.trim()).filter(Boolean);
}
