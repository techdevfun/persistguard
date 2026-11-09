/**
 * `persistguard hook install` - pre-commit gate + repo .gitignore fix.
 *
 * Installs `.git/hooks/pre-commit` (refuses to overwrite an existing
 * hook unless `--force`, in which case it chains: the old hook is saved
 * as `pre-commit.persistguard-old` and runs first). The hook runs
 * `persistguard scan` and blocks the commit on findings. It also
 * appends the two settings paths to the repo's `.gitignore` if absent
 * (repo-level, travels with the project - the exact fix for Claude
 * Code's global-excludes gap). Appending is idempotent.
 */

import { appendFileSync, chmodSync, copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

export const GITIGNORE_LINES = [".claude/settings.local.json", ".claude/settings.json"];

function hookScript(chained: boolean): string {
  const oldHook = chained
    ? [
        "# Run the hook this install replaced, first.",
        'OLD_HOOK="$(dirname "$0")/pre-commit.persistguard-old"',
        'if [ -x "$OLD_HOOK" ]; then',
        '  "$OLD_HOOK" "$@" || exit $?',
        "fi",
        "",
      ].join("\n")
    : "";
  return [
    "#!/bin/sh",
    "# persistguard pre-commit hook - blocks commits when agent settings",
    "# files hold secrets. Installed by `persistguard hook install`.",
    oldHook,
    "if command -v persistguard >/dev/null 2>&1; then",
    "  if ! persistguard scan .; then",
    '    echo "persistguard: commit blocked - fix the findings above (persistguard clean), then retry." >&2',
    "    exit 1",
    "  fi",
    "else",
    '  echo "persistguard: persistguard not found on PATH - skipping check." >&2',
    "fi",
    "",
  ].join("\n");
}

export interface HookResult {
  exitCode: number;
  lines: string[];
  error?: string;
}

export function installHook(dir: string, opts: { force?: boolean } = {}): HookResult {
  const resolved = resolve(dir);
  const gitDir = join(resolved, ".git");
  if (!existsSync(gitDir)) {
    return {
      exitCode: 2,
      lines: [`persistguard hook: not a git repository: ${resolved}`],
      error: "not a git repository",
    };
  }
  const hookPath = join(gitDir, "hooks", "pre-commit");
  const lines: string[] = [];
  let chained = false;
  if (existsSync(hookPath) && !opts.force) {
    return {
      exitCode: 2,
      lines: [
        "persistguard hook: a pre-commit hook already exists.",
        "Re-run with --force to chain it (the old hook is saved and runs first).",
      ],
      error: "hook already exists",
    };
  }
  if (existsSync(hookPath) && opts.force) {
    copyFileSync(hookPath, join(gitDir, "hooks", "pre-commit.persistguard-old"));
    chained = true;
  }
  writeFileSync(hookPath, hookScript(chained), "utf8");
  chmodSync(hookPath, 0o755);
  lines.push(`persistguard hook: installed .git/hooks/pre-commit${chained ? " (old hook chained first)" : ""}`);

  // Repo-level .gitignore fix, idempotent.
  const gitignorePath = join(resolved, ".gitignore");
  let existing = "";
  if (existsSync(gitignorePath)) {
    existing = readFileSync(gitignorePath, "utf8");
  }
  const present = new Set(existing.split("\n").map((l) => l.trim()));
  const added: string[] = [];
  for (const line of GITIGNORE_LINES) {
    if (!present.has(line)) {
      if (existing.length > 0 && !existing.endsWith("\n")) {
        appendFileSync(gitignorePath, "\n", "utf8");
        existing += "\n";
      }
      appendFileSync(gitignorePath, `${line}\n`, "utf8");
      existing += `${line}\n`;
      added.push(line);
    }
  }
  if (added.length > 0) {
    lines.push(`persistguard hook: added to .gitignore: ${added.join(", ")}`);
  } else {
    lines.push("persistguard hook: .gitignore already lists both settings paths");
  }
  return { exitCode: 0, lines };
}
