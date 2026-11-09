#!/usr/bin/env node
/**
 * persistguard - guard the agent's persisted approvals.
 *
 * Commands:
 *   scan [dir] [--format json] [--global]
 *   history [dir] [--format json]
 *   clean [--write] [--force] [dir] [--format json]
 *   hook install [dir] [--force]
 *
 * Exit codes: 0 = clean / inside policy; 1 = findings or a leftover
 * .bak backup (scan), tracked-or-ever-committed (history), or hook
 * would block; 2 = usage or environment error.
 *
 * Never prints a secret value anywhere, including JSON output.
 * Previews show at most the first 4 + last 2 characters of a token,
 * or only the key name for a password assignment.
 */

import { homedir } from "node:os";
import { resolve } from "node:path";
import { cleanDir } from "./clean.js";
import { historyDir } from "./history.js";
import { installHook } from "./hook.js";
import { scanDir, type ScanResult } from "./scan.js";

const VERSION = "0.1.0";

const USAGE = `persistguard ${VERSION} - guard the agent's persisted approvals

Usage:
  persistguard scan [dir] [--format json] [--global]
  persistguard history [dir] [--format json]
  persistguard clean [--write] [--force] [dir] [--format json]
  persistguard hook install [dir] [--force]

Commands:
  scan     Find .claude/settings*.json files and flag secret-bearing allow rules.
           Also warns about .bak backups next to them - a .bak still holds the original secrets.
  history  Check whether a settings file is tracked or was ever committed.
  clean    Redact detected secrets from settings files (dry run by default).
  hook     Install a pre-commit gate plus the repo-level .gitignore fix.

Exit codes: 0 clean, 1 findings / tracked-or-ever-committed, 2 usage or environment error.
A secret value is never printed, including in JSON output.`;

function usageError(message: string): number {
  console.error(`persistguard: ${message}`);
  console.error(USAGE);
  return 2;
}

interface CommonOpts {
  dir: string;
  formatJson: boolean;
}

function parseCommon(args: string[]): { opts: CommonOpts } | null {
  let formatJson = false;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--format") {
      if (args[i + 1] === "json") {
        formatJson = true;
        i++;
      } else {
        return null;
      }
    } else if (arg === "--format=json") {
      formatJson = true;
    } else if (arg.startsWith("-")) {
      return null;
    } else {
      positional.push(arg);
    }
  }
  if (positional.length > 1) return null;
  return { opts: { dir: positional[0] ?? ".", formatJson } };
}

function printScanTable(result: ScanResult, dir: string): void {
  console.log(`persistguard scan: ${dir}`);
  if (result.files.length === 0) {
    console.log("No agent settings files found (.claude/settings*.json).");
    return;
  }
  for (const file of result.files) {
    console.log(`${file.file} (${file.rulesScanned} rule(s))`);
    if (file.error) {
      console.log(`  ERROR: ${file.error}`);
    }
    for (const f of file.findings) {
      console.log(`  [${f.severity}] ${f.type}  rule #${f.ruleIndex} (${f.list})  ${f.rule}  (preview: ${f.preview})`);
    }
  }
  const t = result.totals;
  console.log(
    `${t.files} file(s), ${t.rulesScanned} rule(s), ${t.findings} finding(s) (${t.high} HIGH, ${t.medium} MEDIUM)`,
  );
  if (result.bakFiles.length > 0) {
    // A .bak holds the ORIGINAL secrets in plaintext. Name the files
    // (never their contents) and fail the scan, so the pre-commit
    // hook blocks the commit until the backup is deleted.
    console.log(
      `WARNING: ${result.bakFiles.length} backup file(s) still hold the original (pre-redaction) secrets:`,
    );
    for (const b of result.bakFiles) {
      console.log(`  ${b}`);
    }
    console.log("Delete each .bak after rotating the credentials it contains - it is not protected by the scan.");
  }
}

function scanExitCode(result: ScanResult): number {
  if (result.totals.findings > 0 || result.bakFiles.length > 0) return 1;
  if (result.files.some((f) => f.error)) return 2;
  return 0;
}

function cmdScan(args: string[]): number {
  let global = false;
  const filtered: string[] = [];
  for (const arg of args) {
    if (arg === "--global") global = true;
    else filtered.push(arg);
  }
  const parsed = parseCommon(filtered);
  if (!parsed) return usageError("scan usage: persistguard scan [dir] [--format json] [--global]");
  const result = scanDir(resolve(parsed.opts.dir), { global });
  if (parsed.opts.formatJson) {
    console.log(JSON.stringify({ command: "scan", dir: parsed.opts.dir, ...result }, null, 2));
  } else {
    printScanTable(result, parsed.opts.dir);
    if (global) console.log(`(also read ${homedir()}/.claude/settings.json)`);
  }
  return scanExitCode(result);
}

function cmdHistory(args: string[]): number {
  const parsed = parseCommon(args);
  if (!parsed) return usageError("history usage: persistguard history [dir] [--format json]");
  const result = historyDir(resolve(parsed.opts.dir));
  if (parsed.opts.formatJson) {
    console.log(JSON.stringify({ command: "history", dir: parsed.opts.dir, ...result }, null, 2));
  } else {
    console.log(`persistguard history: ${parsed.opts.dir}`);
    if (!result.isRepo) {
      console.log("Not a git repository.");
      return 2;
    }
    if (result.entries.length === 0) {
      console.log("No agent settings files found (.claude/settings*.json).");
      return 0;
    }
    for (const e of result.entries) {
      const ever = e.everCommitted
        ? `yes (${e.commits} commit(s), oldest ${e.oldestCommit ?? "unknown"})`
        : "no";
      console.log(`${e.file}  tracked: ${e.tracked ? "yes" : "no"}  ever committed: ${ever}`);
    }
    if (result.anyExposed) {
      console.log(
        "A settings file is tracked or was ever committed - the secret lives in git history even after the file is deleted. Rotate the credentials and rewrite history with git filter-repo.",
      );
      return 1;
    }
    console.log("No settings file is tracked or was ever committed.");
    return 0;
  }
  if (!result.isRepo) return 2;
  return result.anyExposed ? 1 : 0;
}

function cmdClean(args: string[]): number {
  let write = false;
  let force = false;
  const filtered: string[] = [];
  for (const arg of args) {
    if (arg === "--write") write = true;
    else if (arg === "--force") force = true;
    else filtered.push(arg);
  }
  const parsed = parseCommon(filtered);
  if (!parsed) return usageError("clean usage: persistguard clean [--write] [--force] [dir] [--format json]");
  const result = cleanDir(resolve(parsed.opts.dir), { write, force });
  if (parsed.opts.formatJson) {
    const { lines: _lines, ...rest } = result;
    console.log(JSON.stringify({ command: "clean", dir: parsed.opts.dir, ...rest }, null, 2));
  } else {
    for (const line of result.lines) console.log(line);
  }
  return result.exitCode;
}

function cmdHook(args: string[]): number {
  if (args[0] !== "install") {
    return usageError("hook usage: persistguard hook install [dir] [--force]");
  }
  let force = false;
  const filtered: string[] = [];
  for (const arg of args.slice(1)) {
    if (arg === "--force") force = true;
    else if (arg.startsWith("-")) return usageError("hook usage: persistguard hook install [dir] [--force]");
    else filtered.push(arg);
  }
  if (filtered.length > 1) return usageError("hook usage: persistguard hook install [dir] [--force]");
  const result = installHook(resolve(filtered[0] ?? "."), { force });
  for (const line of result.lines) console.log(line);
  return result.exitCode;
}

export function main(argv: string[]): number {
  const [command, ...args] = argv;
  if (command === undefined || command === "--help" || command === "-h") {
    console.log(USAGE);
    return command === undefined ? 2 : 0;
  }
  if (command === "--version" || command === "-V") {
    console.log(`persistguard ${VERSION}`);
    return 0;
  }
  switch (command) {
    case "scan":
      return cmdScan(args);
    case "history":
      return cmdHistory(args);
    case "clean":
      return cmdClean(args);
    case "hook":
      return cmdHook(args);
    default:
      return usageError(`unknown command: ${command}`);
  }
}

process.exitCode = main(process.argv.slice(2));
