// CLI tests for `persistguard hook install`: fresh install, refusal
// on an existing hook, --force chaining, and .gitignore idempotence.
// Every fixture secret is synthetic and labelled FAKE.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const SK_TOKEN = "sk-FAKE0123456789abcdefghij0123456789";

function gitRepo() {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-hook-"));
  execFileSync("git", ["-C", dir, "init", "-q"]);
  execFileSync("git", ["-C", dir, "config", "user.email", "test@example.com"]);
  execFileSync("git", ["-C", dir, "config", "user.name", "Test"]);
  mkdirSync(join(dir, ".claude"), { recursive: true });
  return dir;
}

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...opts });
}

function hookPath(dir) {
  return join(dir, ".git", "hooks", "pre-commit");
}

test("hook install: fresh install writes an executable hook and the .gitignore fix", () => {
  const dir = gitRepo();
  const r = run(["hook", "install", dir]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(existsSync(hookPath(dir)));
  assert.match(readFileSync(hookPath(dir), "utf8"), /persistguard scan/);
  const gitignore = readFileSync(join(dir, ".gitignore"), "utf8");
  assert.ok(gitignore.includes(".claude/settings.local.json"));
  assert.ok(gitignore.includes(".claude/settings.json"));
  // The .bak backup holds the original secrets, so the .gitignore fix
  // must cover it too - otherwise `git add -A` would commit it.
  assert.ok(gitignore.includes(".claude/*.bak"));
});

test("hook install: refuses to overwrite an existing hook without --force", () => {
  const dir = gitRepo();
  const existing = "#!/bin/sh\necho old-hook-ran\n";
  writeFileSync(hookPath(dir), existing);
  const r = run(["hook", "install", dir]);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /already exists/);
  assert.equal(readFileSync(hookPath(dir), "utf8"), existing, "existing hook must be untouched");
});

test("hook install --force: chains the old hook and the gate blocks a leaky commit", () => {
  const dir = gitRepo();
  writeFileSync(hookPath(dir), "#!/bin/sh\necho old-hook-ran >> hook-log.txt\n");
  chmodSync(hookPath(dir), 0o755);
  writeFileSync(
    join(dir, ".claude", "settings.local.json"),
    JSON.stringify({ permissions: { allow: [`Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com)`] } }),
  );
  // A shim so the hook finds `persistguard` on PATH.
  const binDir = mkdtempSync(join(tmpdir(), "persistguard-bin-"));
  writeFileSync(join(binDir, "persistguard"), `#!/bin/sh\nexec node ${CLI} "$@"\n`);
  chmodSync(join(binDir, "persistguard"), 0o755);

  const r = run(["hook", "install", "--force", dir]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(existsSync(join(dir, ".git", "hooks", "pre-commit.persistguard-old")));
  assert.match(readFileSync(hookPath(dir), "utf8"), /pre-commit\.persistguard-old/);

  // The installed hook must block the commit AND run the old hook first.
  // (The settings file itself is gitignored by the install, so stage a
  // README: the hook scans the whole repo dir either way.)
  writeFileSync(join(dir, "README.md"), "hello\n");
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  const add = spawnSync("git", ["-C", dir, "add", "README.md"]);
  assert.equal(add.status, 0);
  const attempt = spawnSync("git", ["-C", dir, "commit", "-m", "leaky"], { encoding: "utf8", env });
  assert.notEqual(attempt.status, 0, "commit with a secret-bearing settings file must be blocked");
  assert.match(attempt.stderr + attempt.stdout, /commit blocked/);
  assert.ok(readFileSync(join(dir, "hook-log.txt"), "utf8").includes("old-hook-ran"), "old hook must run first");
  assert.ok(!attempt.stdout.includes(SK_TOKEN) && !attempt.stderr.includes(SK_TOKEN));

  // After cleaning, the commit is still blocked while the .bak exists:
  // the backup holds the original secrets, so scan fails until it is
  // deleted (rotate, then delete the .bak, then commit).
  const clean = run(["clean", "--write", "--force", dir]);
  assert.equal(clean.status, 0, clean.stdout + clean.stderr);
  const stillBlocked = spawnSync("git", ["-C", dir, "commit", "-m", "still blocked"], { encoding: "utf8", env });
  assert.notEqual(stillBlocked.status, 0, "commit must stay blocked while the .bak exists");
  assert.match(stillBlocked.stderr + stillBlocked.stdout, /commit blocked/);
  unlinkSync(join(dir, ".claude", "settings.local.json.bak"));
  const ok = spawnSync("git", ["-C", dir, "commit", "-m", "clean"], { encoding: "utf8", env });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
});

test("hook install: a .bak cannot be committed after hook install", () => {
  const dir = gitRepo();
  const r = run(["hook", "install", dir]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  // A leftover backup from `clean --write`, next to a clean settings file.
  writeFileSync(
    join(dir, ".claude", "settings.local.json"),
    JSON.stringify({ permissions: { allow: ["Bash(npm test *)"] } }),
  );
  writeFileSync(
    join(dir, ".claude", "settings.local.json.bak"),
    JSON.stringify({ permissions: { allow: [`Bash(curl ${SK_TOKEN})`] } }),
  );
  writeFileSync(join(dir, "README.md"), "hello\n");
  // (1) `git add -A` must not stage the .bak: the .gitignore fix covers it.
  const addAll = spawnSync("git", ["-C", dir, "add", "-A"], { encoding: "utf8" });
  assert.equal(addAll.status, 0);
  const status = execFileSync("git", ["-C", dir, "status", "--porcelain"], { encoding: "utf8" });
  assert.ok(!status.includes("settings.local.json.bak"), "the .bak must not be staged by git add -A");
  // (2) Even force-adding it, the hook blocks the commit: scan fails
  // while a .bak exists, and the .bak contents are never printed.
  const binDir = mkdtempSync(join(tmpdir(), "persistguard-bin-"));
  writeFileSync(join(binDir, "persistguard"), `#!/bin/sh\nexec node ${CLI} "$@"\n`);
  chmodSync(join(binDir, "persistguard"), 0o755);
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  execFileSync("git", ["-C", dir, "add", "-f", ".claude/settings.local.json.bak"]);
  const attempt = spawnSync("git", ["-C", dir, "commit", "-m", "bak"], { encoding: "utf8", env });
  assert.notEqual(attempt.status, 0, "committing a .bak must be blocked");
  assert.match(attempt.stderr + attempt.stdout, /commit blocked/);
  assert.ok(!attempt.stdout.includes(SK_TOKEN) && !attempt.stderr.includes(SK_TOKEN));
  const commits = execFileSync("git", ["-C", dir, "rev-list", "--all", "--count"], { encoding: "utf8" });
  assert.equal(commits.trim(), "0", "no commit holding the .bak must exist");
});

test("hook install is idempotent on .gitignore", () => {
  const dir = gitRepo();
  assert.equal(run(["hook", "install", dir]).status, 0);
  assert.equal(run(["hook", "install", "--force", dir]).status, 0);
  const gitignore = readFileSync(join(dir, ".gitignore"), "utf8");
  const localCount = gitignore.split("\n").filter((l) => l === ".claude/settings.local.json").length;
  const sharedCount = gitignore.split("\n").filter((l) => l === ".claude/settings.json").length;
  const bakCount = gitignore.split("\n").filter((l) => l === ".claude/*.bak").length;
  assert.equal(localCount, 1);
  assert.equal(sharedCount, 1);
  assert.equal(bakCount, 1);
});

test("hook install outside a git repo exits 2", () => {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-nogit-"));
  const r = run(["hook", "install", dir]);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /Not a git repository|not a git repository/);
});
