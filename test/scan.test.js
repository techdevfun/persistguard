// CLI tests for `persistguard scan` (table + JSON), the walker scope,
// redaction in output, and invalid JSON handling.
// Every fixture secret is synthetic and labelled FAKE.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, unlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const GH_TOKEN = "ghp_FAKE0123456789abcdefghij0123456789";
const SK_TOKEN = "sk-FAKE0123456789abcdefghij0123456789";
const DB_PASS = "FAKEdbpass987654321";

function tmpProject() {
  const dir = mkdtempSync(join(tmpdir(), "persistguard-scan-"));
  mkdirSync(join(dir, ".claude"), { recursive: true });
  return dir;
}

function writeSettings(dir, obj, name = "settings.local.json") {
  writeFileSync(join(dir, ".claude", name), typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
}

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...opts });
}

const LEAKY = {
  permissions: {
    allow: [
      "Bash(npm test *)",
      `Bash(psql postgres://app:${DB_PASS}@db.internal:5432/app -c "select 1")`,
      `Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com/health)`,
    ],
    ask: ["Bash(git push)"],
    deny: ["Bash(rm -rf /)"],
  },
};

const REDACTED_PLACEHOLDER = "<REDACTED-BY-PERSISTGUARD>";

test("scan: table output finds 2 secrets, exit 1, no secret value printed", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  const r = run(["scan", dir]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /2 finding\(s\)/);
  assert.match(r.stdout, /HIGH/);
  assert.ok(!r.stdout.includes(DB_PASS), "table output must not contain the DB password");
  assert.ok(!r.stdout.includes(SK_TOKEN), "table output must not contain the token");
  assert.ok(r.stdout.includes("****"), "previews must mask values");
  assert.ok(r.stdout.includes(REDACTED_PLACEHOLDER) || r.stdout.includes("sk-F"), "preview shows first chars only");
});

test("scan --format json: findings are redacted and structured", () => {
  const dir = tmpProject();
  writeSettings(dir, LEAKY);
  const r = run(["scan", "--format", "json", dir]);
  assert.equal(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.equal(out.totals.findings, 2);
  assert.equal(out.totals.high, 2);
  assert.equal(out.totals.rulesScanned, 5);
  assert.ok(!r.stdout.includes(DB_PASS));
  assert.ok(!r.stdout.includes(SK_TOKEN));
  const types = out.files[0].findings.map((f) => f.type).sort();
  assert.deepEqual(types, ["credential-url", "openai-key"]);
  // The redacted rule keeps the command shape.
  const urlFinding = out.files[0].findings.find((f) => f.type === "credential-url");
  assert.ok(urlFinding.rule.includes("postgres://app:"));
  assert.ok(urlFinding.rule.includes("@db.internal:5432/app"));
});

test("scan: clean project exits 0", () => {
  const dir = tmpProject();
  writeSettings(dir, { permissions: { allow: ["Bash(npm test *)", "Bash(git log --oneline)"], deny: [] } });
  const r = run(["scan", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /0 finding\(s\)/);
});

test("scan: no settings files exits 0 with a message", () => {
  const dir = tmpProject();
  const r = run(["scan", dir]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No agent settings files found/);
});

test("scan: invalid JSON is reported per file, scan continues, exit 2", () => {
  const dir = tmpProject();
  writeSettings(dir, "{ not json", "settings.local.json");
  writeSettings(dir, LEAKY, "settings.json");
  const r = run(["scan", dir]);
  // Findings exist, so exit 1; the bad file is still reported.
  assert.equal(r.status, 1);
  assert.match(r.stdout, /invalid JSON/);

  const dir2 = tmpProject();
  writeSettings(dir2, "{ not json", "settings.local.json");
  const r2 = run(["scan", dir2]);
  assert.equal(r2.status, 2);
  assert.match(r2.stdout, /invalid JSON/);
});

test("walker only ever opens .claude/settings*.json (no general scanning)", () => {
  const dir = tmpProject();
  writeSettings(dir, { permissions: { allow: ["Bash(npm test *)"] } });
  // Decoys full of secret-shaped values in files the walker must never open.
  writeFileSync(join(dir, "README.md"), `token ${GH_TOKEN}\n`);
  writeFileSync(join(dir, ".claude", "notes.txt"), `token ${GH_TOKEN}\n`);
  writeFileSync(join(dir, ".claude", "other.json"), JSON.stringify({ token: GH_TOKEN }));
  mkdirSync(join(dir, "sub"), { recursive: true });
  writeFileSync(join(dir, "sub", "leak.txt"), GH_TOKEN);
  const r = run(["scan", dir]);
  assert.equal(r.status, 0, `decoy files must not be scanned: ${r.stdout}`);
  assert.match(r.stdout, /0 finding\(s\)/);
});

test("scan: a .bak next to a settings file warns and exits 1, without ever reading it", () => {
  const dir = tmpProject();
  writeSettings(dir, { permissions: { allow: ["Bash(npm test *)"] } });
  // The .bak holds a secret-shaped value, but scan must only LIST it:
  // its contents are the pre-redaction file and must never be opened.
  writeFileSync(
    join(dir, ".claude", "settings.local.json.bak"),
    JSON.stringify({ permissions: { allow: [`Bash(curl ${GH_TOKEN})`] } }),
  );
  const r = run(["scan", dir]);
  assert.equal(r.status, 1, `scan must fail while a .bak exists: ${r.stdout}`);
  assert.match(r.stdout, /0 finding\(s\)/);
  assert.match(r.stdout, /WARNING: 1 backup file/);
  assert.match(r.stdout, /settings\.local\.json\.bak/);
  assert.match(r.stdout, /Delete each \.bak/);
  assert.ok(!r.stdout.includes(GH_TOKEN), "scan must never print the .bak contents");
  const json = run(["scan", "--format", "json", dir]);
  assert.equal(json.status, 1);
  const out = JSON.parse(json.stdout);
  assert.deepEqual(out.bakFiles, [".claude/settings.local.json.bak"]);
  assert.ok(!json.stdout.includes(GH_TOKEN));
  // Deleting the .bak clears the scan.
  unlinkSync(join(dir, ".claude", "settings.local.json.bak"));
  const clean = run(["scan", dir]);
  assert.equal(clean.status, 0, `scan must be clean once the .bak is gone: ${clean.stdout}`);
});

test("walker finds settings files in nested .claude dirs", () => {
  const dir = tmpProject();
  mkdirSync(join(dir, "packages", "web", ".claude"), { recursive: true });
  writeFileSync(
    join(dir, "packages", "web", ".claude", "settings.local.json"),
    JSON.stringify({ permissions: { allow: [`Bash(curl ${GH_TOKEN})`] } }),
  );
  const r = run(["scan", dir]);
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes(GH_TOKEN));
});

test("scan --global reads ~/.claude/settings.json", () => {
  const dir = tmpProject();
  const home = mkdtempSync(join(tmpdir(), "persistguard-home-"));
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(
    join(home, ".claude", "settings.json"),
    JSON.stringify({ permissions: { allow: [`Bash(curl ${GH_TOKEN})`] } }),
  );
  const r = run(["scan", "--global", dir], { env: { ...process.env, HOME: home } });
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes(GH_TOKEN));
  assert.match(r.stdout, /settings\.json/);
});

test("scan: non-Bash rules are listed but only flagged with a secret value", () => {
  const dir = tmpProject();
  writeSettings(dir, {
    permissions: {
      allow: ["Read(file.txt)", `WebFetch(https://api.example.com/?token=${GH_TOKEN})`, "Bash(npm test)"],
    },
  });
  const r = run(["scan", "--format", "json", dir]);
  assert.equal(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.equal(out.totals.rulesScanned, 3);
  assert.equal(out.totals.findings, 1);
  assert.equal(out.files[0].findings[0].type, "github-token");
});

test("scan honours the :* wildcard suffix", () => {
  const dir = tmpProject();
  writeSettings(dir, {
    permissions: { allow: [`Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com:*)`] },
  });
  const r = run(["scan", dir]);
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes(SK_TOKEN));
});

test("build entry point exists and is executable", () => {
  assert.ok(existsSync(CLI));
  const r = run(["--version"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /persistguard 0\.1\.0/);
});
