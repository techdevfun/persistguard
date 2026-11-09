// CLI tests for `persistguard clean`: dry-run vs --write, .bak,
// shape preservation, and the tracked-file refusal.
// Every fixture secret is synthetic and labelled FAKE.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const SK_TOKEN = "sk-FAKE0123456789abcdefghij0123456789";
const DB_PASS = "FAKEdbpass987654321";
const PLACEHOLDER = "<REDACTED-BY-PERSISTGUARD>";

function tmpProject() {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-clean-"));
  mkdirSync(join(dir, ".claude"), { recursive: true });
  return dir;
}

function writeSettings(dir, obj) {
  writeFileSync(join(dir, ".claude", "settings.local.json"), JSON.stringify(obj, null, 2));
}

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

const LEAKY = {
  permissions: {
    allow: [
      "Bash(npm test *)",
      `Bash(psql postgres://app:${DB_PASS}@db.internal:5432/app -c "select 1")`,
      `Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com/health)`,
    ],
    ask: ["Bash(git push)"],
    deny: [],
  },
};

test("clean dry-run: prints the plan, writes nothing, exit 0", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  const before = readFileSync(join(dir, ".claude", "settings.local.json"), "utf8");
  const r = run(["clean", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /dry run/);
  assert.match(r.stdout, /Rotation checklist/);
  assert.ok(r.stdout.includes(PLACEHOLDER), "dry run shows the placeholder that would be written");
  assert.ok(!r.stdout.includes(DB_PASS));
  assert.ok(!r.stdout.includes(SK_TOKEN));
  assert.equal(readFileSync(join(dir, ".claude", "settings.local.json"), "utf8"), before, "dry run must not touch the file");
  assert.equal(existsSync(join(dir, ".claude", "settings.local.json.bak")), false);
});

test("clean --write: rewrites secrets, keeps shape, writes .bak, scan is clean once the .bak is deleted", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  const r = run(["clean", "--write", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /redacted/);
  assert.match(r.stdout, /Rotation checklist/);
  assert.match(r.stdout, /Delete the \.bak backup after rotating/);
  assert.match(r.stdout, /settings\.local\.json\.bak/);
  const bak = join(dir, ".claude", "settings.local.json.bak");
  assert.ok(existsSync(bak), ".bak copy must exist");
  assert.ok(readFileSync(bak, "utf8").includes(DB_PASS), ".bak keeps the original bytes");
  const after = JSON.parse(readFileSync(join(dir, ".claude", "settings.local.json"), "utf8"));
  // Shape preserved: same rules, same order, clean rule untouched.
  assert.deepEqual(after.permissions.ask, ["Bash(git push)"]);
  assert.equal(after.permissions.allow[0], "Bash(npm test *)");
  assert.equal(
    after.permissions.allow[1],
    `Bash(psql postgres://app:${PLACEHOLDER}@db.internal:5432/app -c "select 1")`,
  );
  assert.ok(after.permissions.allow[2].includes(PLACEHOLDER));
  assert.ok(!after.permissions.allow[2].includes(SK_TOKEN));
  assert.ok(!JSON.stringify(after).includes(DB_PASS));
  // The rewritten file is clean, but the .bak still holds the original
  // secrets, so scan fails until the backup is deleted (the documented
  // flow: rotate, then delete the .bak, then scan again).
  const blocked = run(["scan", dir]);
  assert.equal(blocked.status, 1, `scan must fail while the .bak exists: ${blocked.stdout}`);
  assert.match(blocked.stdout, /WARNING: 1 backup file/);
  assert.ok(!blocked.stdout.includes(DB_PASS));
  assert.ok(!blocked.stdout.includes(SK_TOKEN));
  unlinkSync(bak);
  const scan = run(["scan", dir]);
  assert.equal(scan.status, 0, `scan must be clean after the .bak is deleted: ${scan.stdout}`);
});

test("clean --write on a clean project exits 0 and writes nothing", () => {
  const dir = tmpProject();
  writeSettings(dir, { permissions: { allow: ["Bash(npm test *)"] } });
  const r = run(["clean", "--write", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /no findings/);
  assert.equal(existsSync(join(dir, ".claude", "settings.local.json.bak")), false);
});

test("clean --write refuses a tracked file without --force, changes nothing", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  execFileSync("git", ["-C", dir, "init", "-q"]);
  execFileSync("git", ["-C", dir, "config", "user.email", "test@example.com"]);
  execFileSync("git", ["-C", dir, "config", "user.name", "Test"]);
  execFileSync("git", ["-C", dir, "add", "."]);
  execFileSync("git", ["-C", dir, "commit", "-qm", "add settings"]);
  const before = readFileSync(join(dir, ".claude", "settings.local.json"), "utf8");
  const r = run(["clean", "--write", dir]);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /refused/);
  assert.match(r.stdout, /does not un-leak history/);
  assert.equal(readFileSync(join(dir, ".claude", "settings.local.json"), "utf8"), before);
  assert.equal(existsSync(join(dir, ".claude", "settings.local.json.bak")), false);
});

test("clean --write --force rewrites a tracked file and keeps the checklist", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  execFileSync("git", ["-C", dir, "init", "-q"]);
  execFileSync("git", ["-C", dir, "config", "user.email", "test@example.com"]);
  execFileSync("git", ["-C", dir, "config", "user.name", "Test"]);
  execFileSync("git", ["-C", dir, "add", "."]);
  execFileSync("git", ["-C", dir, "commit", "-qm", "add settings"]);
  const r = run(["clean", "--write", "--force", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Rotation checklist/);
  const after = readFileSync(join(dir, ".claude", "settings.local.json"), "utf8");
  assert.ok(!after.includes(DB_PASS));
  assert.ok(!after.includes(SK_TOKEN));
  assert.ok(after.includes(PLACEHOLDER));
});
