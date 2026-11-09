// CLI tests for `persistguard history` on a fixture git repo.
// Every fixture secret is synthetic and labelled FAKE.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const SK_TOKEN = "sk-FAKE0123456789abcdefghij0123456789";

function git(dir, ...args) {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });
}

function gitRepo() {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-history-"));
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "test@example.com");
  git(dir, "config", "user.name", "Test");
  mkdirSync(join(dir, ".claude"), { recursive: true });
  return dir;
}

function writeSettings(dir, obj, name = "settings.local.json") {
  writeFileSync(join(dir, ".claude", name), typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
}

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

const LEAKY = {
  permissions: { allow: [`Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com)`] },
};

test("history: tracked file exits 1 and reports tracked", () => {
  const dir = gitRepo();
  writeSettings(dir, LEAKY);
  git(dir, "add", ".");
  git(dir, "commit", "-qm", "add settings");
  const r = run(["history", dir]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /tracked: yes/);
  assert.match(r.stdout, /ever committed: yes/);
  assert.match(r.stdout, /oldest \d{4}-\d{2}-\d{2}/);
  assert.ok(!r.stdout.includes(SK_TOKEN), "history must never print a secret value");
});

test("history: ever-committed but no longer tracked exits 1", () => {
  const dir = gitRepo();
  writeSettings(dir, LEAKY);
  git(dir, "add", ".");
  git(dir, "commit", "-qm", "add settings");
  rmSync(join(dir, ".claude", "settings.local.json"));
  git(dir, "rm", "-q", ".claude/settings.local.json");
  const r = run(["history", dir]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /tracked: no/);
  assert.match(r.stdout, /ever committed: yes/);
});

test("history: never-committed file exits 0", () => {
  const dir = gitRepo();
  writeSettings(dir, LEAKY);
  writeFileSync(join(dir, "README.md"), "hello\n");
  git(dir, "add", "README.md");
  git(dir, "commit", "-qm", "readme");
  const r = run(["history", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /tracked: no/);
  assert.match(r.stdout, /ever committed: no/);
});

test("history: not a git repo exits 2", () => {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-nogit-"));
  mkdirSync(join(dir, ".claude"), { recursive: true });
  writeSettings(dir, LEAKY);
  const r = run(["history", dir]);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /Not a git repository/);
});

test("history --format json is structured and redacted", () => {
  const dir = gitRepo();
  writeSettings(dir, LEAKY);
  git(dir, "add", ".");
  git(dir, "commit", "-qm", "add settings");
  const r = run(["history", "--format", "json", dir]);
  assert.equal(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.equal(out.isRepo, true);
  assert.equal(out.anyExposed, true);
  assert.equal(out.entries[0].tracked, true);
  assert.equal(out.entries[0].everCommitted, true);
  assert.equal(out.entries[0].commits, 1);
  assert.ok(!r.stdout.includes(SK_TOKEN));
});
