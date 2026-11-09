/**
 * `persistguard history` - was a settings file ever committed?
 *
 * Uses only local git commands (`git ls-files`, `git log --all`).
 * Nothing touches a remote. Exit 1 when any settings file is tracked
 * right now or was ever committed (the Apiiro scenario: the secret
 * lives in history even after the file is deleted), 0 otherwise,
 * 2 when the directory is not a git repository.
 */

import { relative, resolve } from "node:path";
import { findSettingsFiles, gitLogDates, gitOutput, isGitRepo } from "./scan.js";

export interface HistoryEntry {
  file: string;
  tracked: boolean;
  everCommitted: boolean;
  commits: number;
  oldestCommit: string | null;
}

export interface HistoryResult {
  isRepo: boolean;
  entries: HistoryEntry[];
  anyExposed: boolean;
}

function gitIsTracked(dir: string, absPath: string): boolean {
  const rel = relative(resolve(dir), absPath);
  if (rel.startsWith("..")) return false;
  const out = gitOutput(dir, ["ls-files", "--", rel]);
  return out !== null && out.trim().length > 0;
}

export function historyDir(dir: string): HistoryResult {
  const resolved = resolve(dir);
  if (!isGitRepo(resolved)) {
    return { isRepo: false, entries: [], anyExposed: false };
  }
  // Candidates: settings files on disk now, PLUS any settings path
  // that ever appears in git history - a file deleted after commit
  // still leaks through history, and must still be reported.
  const onDisk = findSettingsFiles(resolved).map((abs) => relative(resolved, abs));
  const ever = gitOutput(resolved, ["log", "--all", "--name-only", "--pretty=format:"]) ?? "";
  const historical = ever
    .split("\n")
    .map((l) => l.trim())
    .filter((p) => /(^|\/)\.claude\/settings(\.local)?\.json$/.test(p));
  const candidates = [...new Set([...onDisk, ...historical])].sort();
  const entries: HistoryEntry[] = candidates.map((rel) => {
    const abs = resolve(resolved, rel);
    const dates = gitLogDates(resolved, abs);
    return {
      file: rel,
      tracked: gitIsTracked(resolved, abs),
      everCommitted: dates.length > 0,
      commits: dates.length,
      oldestCommit: dates.length > 0 ? dates[dates.length - 1] : null,
    };
  });
  return {
    isRepo: true,
    entries,
    anyExposed: entries.some((e) => e.tracked || e.everCommitted),
  };
}
