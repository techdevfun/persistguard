#!/usr/bin/env node
/**
 * Rule 7 preflight - release gate script.
 *
 * Fails (exit 1) when any shipped text file contains:
 *  - any non-ASCII character (all public content is ASCII English only),
 *  - an internal name (team / lane / chat names that must never appear
 *    in a public repo),
 *  - an em dash (use a plain hyphen).
 *
 * Also fails when a fixture in examples/, test/ or demo/ contains a
 * secret-shaped value without the FAKE marker: every fixture secret
 * is synthetic and must be labelled FAKE.
 *
 * Scans text files under the repo root, excluding node_modules, .git,
 * dist, and binary files. The demo GIF is generated from
 * demo/transcript.txt, which is itself scanned here, so the GIF's text
 * is covered by construction.
 *
 * NOTE: the internal-name list below is written with \u escapes on
 * purpose - spelling the names out in plain text would make this very
 * file fail its own scan.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".work", "bin"]);
const TEXT_EXTS = new Set([
  ".md", ".ts", ".js", ".mjs", ".json", ".yml", ".yaml", ".sh", ".txt",
]);

const NON_ASCII = /[^\x00-\x7F]/;
const INTERNAL_NAMES = [
  "T\u1ED5ng qu\u1EA3n",
  "Tr\u1EE3 l\u00FD",
  "l\u00E0n B",
  "Lane\u0020B",
  "n\u1ED9i b\u1ED9",
  "b\u00ED m\u1EADt",
];

// Secret-shaped patterns; a line in examples/, test/ or demo/
// matching one must also contain FAKE. Short fragments such as a
// redacted preview (`sk-F...89`) do not match: the run after the
// prefix must be long enough to be a real secret shape.
const SECRET_PATTERNS = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{15,}/,
  /\bgithub_pat_[A-Za-z0-9_]{15,}/,
  /\bsk-proj-[A-Za-z0-9_-]{15,}/,
  /\bsk-[A-Za-z0-9_-]{15,}/,
  /\bAKIA[0-9A-Z]{10,}/,
  /\bxox[baprs]-[A-Za-z0-9-]{8,}/,
  /\bnpm_[A-Za-z0-9]{15,}/,
  /\bsq0at-[A-Za-z0-9_-]{8,}/,
  /\bsbp_[A-Za-z0-9]{15,}/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
  /\bPGPASSWORD=\S{5,}/,
  /\bMYSQL_PWD=\S{5,}/,
];
const FAKE_DIRS = new Set(["examples", "test", "demo"]);

const failures = [];
let scanned = 0;

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full);
    } else if (TEXT_EXTS.has(entry.slice(entry.lastIndexOf(".")))) {
      check(full);
    }
  }
}

function check(file) {
  const rel = relative(ROOT, file);
  const content = readFileSync(file, "utf8");
  scanned++;
  if (NON_ASCII.test(content)) {
    failures.push(`${rel}: non-ASCII character found (public content is ASCII English only)`);
  }
  for (const name of INTERNAL_NAMES) {
    if (content.includes(name)) {
      failures.push(`${rel}: internal name found`);
    }
  }
  if (/\u2014/.test(content)) {
    failures.push(`${rel}: em dash found (use a plain hyphen)`);
  }
  const topDir = rel.split("/")[0];
  if (FAKE_DIRS.has(topDir)) {
    for (const line of content.split("\n")) {
      // A ${VAR} reference holds no literal value - it is not a secret.
      if (line.includes("${")) continue;
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(line) && !line.includes("FAKE")) {
          failures.push(`${rel}: secret-shaped value without FAKE marker: ${line.trim().slice(0, 80)}`);
          break;
        }
      }
    }
  }
}

walk(ROOT);

if (failures.length > 0) {
  console.error("preflight FAILED:");
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`preflight OK: ${scanned} files, 0 non-ASCII characters, 0 internal names`);
