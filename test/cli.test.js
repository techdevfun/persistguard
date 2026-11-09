// CLI tests for exit codes, usage errors, and --help/--version.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("exit codes: unknown command and bad flags are usage errors (2)", () => {
  assert.equal(run(["frobnicate"]).status, 2);
  assert.equal(run(["scan", "--nope"]).status, 2);
  assert.equal(run(["scan", "a", "b"]).status, 2);
  assert.equal(run(["clean", "--format", "xml"]).status, 2);
  assert.equal(run(["hook"]).status, 2);
  assert.equal(run(["hook", "remove"]).status, 2);
});

test("exit codes: no arguments prints usage and exits 2", () => {
  const r = run([]);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /Usage:/);
});

test("--help exits 0, --version prints the version", () => {
  assert.equal(run(["--help"]).status, 0);
  assert.match(run(["--help"]).stdout, /persistguard 0\.1\.0/);
  assert.match(run(["--help"]).stdout, /never printed/);
  assert.equal(run(["--version"]).status, 0);
  assert.match(run(["--version"]).stdout, /persistguard 0\.1\.0/);
});
