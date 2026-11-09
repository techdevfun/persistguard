// Unit tests for detectors and allow-rule parsing.
// Every fixture secret is synthetic and labelled FAKE - never a real credential.
import test from "node:test";
import assert from "node:assert/strict";
import { detectSecrets, redactText, REDACTED } from "../dist/detect.js";
import { parseRule, rebuildRule } from "../dist/rules.js";

// --- fixture secrets (all FAKE) ---
const GH_TOKEN = "ghp_FAKE0123456789abcdefghij0123456789";
const GH_PAT = "github_pat_FAKE0123456789abcdefghij0123456789";
const SK_TOKEN = "sk-FAKE0123456789abcdefghij0123456789";
const SK_PROJ = "sk-proj-FAKE0123456789abcdefghij0123456789";
const AWS_KEY = "AKIAFAKE0123456789AB";
const SLACK_TOKEN = "xoxb-FAKE0123456789-0123456789-AbCdEfGhIjKlMnOp";
const NPM_TOKEN = "npm_FAKE0123456789abcdefghij";
const SQUARE_TOKEN = "sq0at-FAKE0123456789abcdefghij";
const SBP_KEY = "sbp_FAKE0123456789abcdefghij";
const JWT = "eyJFAKEheader.eyJFAKEpayload.eyJFAKEsignature1234567890";
const DB_PASS = "FAKEdbpass987654321";
const MYSQL_PASS = "FAKEmysqlpass123";
const BASIC_PASS = "FAKEbasicauth99";
const ENTROPY_TOKEN = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW";

function types(cmd) {
  return detectSecrets(cmd).map((f) => f.type);
}

test("known-prefix tokens: each detector fires on its own shape", () => {
  assert.deepEqual(types(`curl https://api.example.com -H "Authorization: Bearer ${GH_TOKEN}"`), ["github-token"]);
  assert.deepEqual(types(`export X=${GH_PAT}`), ["github-pat"]);
  assert.deepEqual(types(`curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com`), ["openai-key"]);
  assert.deepEqual(types(`curl -H "Authorization: Bearer ${SK_PROJ}" https://api.example.com`), ["openai-key"]);
  assert.deepEqual(types(`aws s3 ls --access-key ${AWS_KEY}`), ["aws-access-key"]);
  assert.deepEqual(types(`curl -H "Authorization: Bearer ${SLACK_TOKEN}" https://slack.com/api/auth.test`), ["slack-token"]);
  assert.deepEqual(types(`npm publish --//registry.npmjs.org/:_authToken=${NPM_TOKEN}`), ["npm-token"]);
  assert.deepEqual(types(`curl -H "Authorization: Bearer ${SQUARE_TOKEN}" https://connect.squareup.com/v2/orders`), ["square-token"]);
  assert.deepEqual(types(`curl -H "apikey: ${SBP_KEY}" https://xyz.supabase.co/rest/v1/x`), ["supabase-key"]);
  assert.deepEqual(types(`curl -H "Authorization: Bearer ${JWT}" https://api.example.com`), ["jwt"]);
});

test("215-shape: password inside a command, no key format", () => {
  // The shape Apiiro showed both big scanners miss: a database
  // password typed inside an approved command string.
  const url = detectSecrets(`psql postgres://app:${DB_PASS}@db.internal:5432/app -c "select 1"`);
  assert.equal(url.length, 1);
  assert.equal(url[0].type, "credential-url");
  assert.equal(url[0].severity, "HIGH");
  assert.equal(url[0].value, DB_PASS);

  const mysql = detectSecrets(`mysql -u root -p${MYSQL_PASS} -h db.internal app`);
  assert.equal(mysql.length, 1);
  assert.equal(mysql[0].type, "password-assignment");
  assert.equal(mysql[0].value, MYSQL_PASS);

  const basic = detectSecrets(`curl -u deploy:${BASIC_PASS} https://api.internal.example.com/health`);
  assert.equal(basic.length, 1);
  assert.equal(basic[0].type, "basic-auth-password");
  assert.equal(basic[0].value, BASIC_PASS);
});

test("password assignments: --password, env vars, password:, sshpass", () => {
  assert.equal(types(`deploy --password=${DB_PASS}`)[0], "password-assignment");
  assert.equal(types(`deploy --password ${DB_PASS}`)[0], "password-assignment");
  assert.equal(types(`PGPASSWORD=${DB_PASS} psql -h db.internal -U app`)[0], "password-assignment");
  assert.equal(types(`MYSQL_PWD=${MYSQL_PASS} mysql -h db.internal`)[0], "password-assignment");
  assert.equal(types(`login password:${DB_PASS}`)[0], "password-assignment");
  assert.equal(types(`sshpass -p ${MYSQL_PASS} ssh user@db.internal`)[0], "password-assignment");
  assert.equal(types(`sshpass -p${MYSQL_PASS} ssh user@db.internal`)[0], "password-assignment");
});

test("Authorization header detector", () => {
  const found = detectSecrets(`curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com`);
  // Known-prefix wins the dedupe over the header detector (same span).
  assert.equal(found.length, 1);
  assert.equal(found[0].value, SK_TOKEN);
  const basic = detectSecrets('curl -H "Authorization: Basic dXNlcjpwYXNz" https://api.example.com');
  assert.equal(basic.length, 1);
  assert.equal(basic[0].type, "authorization-header");
});

test("high-entropy token next to a host or known command", () => {
  const found = detectSecrets(`curl https://api.example.com/data?token=${ENTROPY_TOKEN}`);
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "high-entropy-token");
  assert.equal(found[0].severity, "MEDIUM");
  assert.equal(found[0].value, ENTROPY_TOKEN);
});

test("detectors stay quiet on clean commands", () => {
  for (const cmd of [
    "npm test",
    "npm test *",
    "git log --oneline",
    "curl https://api.example.com/health",
    "echo hello world",
    "ssh user@host.example.com",
    "psql -h db.internal -U app -c \"select 1\"",
    "mysql -u root -h db.internal app",
    "grep -p pattern file.txt",
  ]) {
    assert.deepEqual(detectSecrets(cmd), [], `expected no findings for: ${cmd}`);
  }
});

test("redaction: preview never contains the secret, placeholder replaces it", () => {
  const cmd = `psql postgres://app:${DB_PASS}@db.internal:5432/app`;
  const found = detectSecrets(cmd);
  assert.equal(found.length, 1);
  assert.ok(!found[0].preview.includes(DB_PASS), "preview must not contain the secret");
  assert.ok(found[0].preview.includes("****"), "preview must mask the value");
  const redacted = redactText(cmd, found);
  assert.ok(!redacted.includes(DB_PASS), "redacted text must not contain the secret");
  assert.ok(redacted.includes(REDACTED), "redacted text must hold the placeholder");
  assert.ok(redacted.includes("postgres://app:"), "command shape must survive");
  assert.ok(redacted.includes("@db.internal:5432/app"), "host must survive");

  const tokenCmd = `curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com`;
  const tokenFound = detectSecrets(tokenCmd);
  assert.equal(tokenFound.length, 1);
  assert.ok(!tokenFound[0].preview.includes(SK_TOKEN));
  assert.ok(tokenFound[0].preview.startsWith("sk-F"), "token preview shows first 4 chars only");
  assert.ok(!redactText(tokenCmd, tokenFound).includes(SK_TOKEN));
});

test("allow-rule parsing: Bash(...), :* suffix, bare tools, non-Bash", () => {
  const withSuffix = parseRule(`Bash(curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com:*)`);
  assert.ok(withSuffix);
  assert.equal(withSuffix.tool, "Bash");
  assert.equal(withSuffix.wildcardSuffix, true);
  assert.equal(withSuffix.commandText, `curl -H "Authorization: Bearer ${SK_TOKEN}" https://api.example.com`);
  assert.equal(detectSecrets(withSuffix.commandText).length, 1);

  const clean = parseRule("Bash(npm test:*)");
  assert.ok(clean);
  assert.equal(clean.commandText, "npm test");
  assert.deepEqual(detectSecrets(clean.commandText), []);

  const bare = parseRule("Bash");
  assert.ok(bare);
  assert.equal(bare.tool, "Bash");
  assert.equal(bare.specifier, null);
  assert.equal(bare.commandText, null);

  const read = parseRule("Read(file.txt)");
  assert.ok(read);
  assert.equal(read.tool, "Read");
  assert.equal(read.commandText, "file.txt");

  assert.equal(parseRule(""), null);
  assert.equal(parseRule("   "), null);

  // Rebuild preserves the :* suffix after a rewrite.
  assert.equal(rebuildRule(withSuffix, "curl https://api.example.com"), "Bash(curl https://api.example.com:*)");
  assert.equal(rebuildRule(clean, "npm test"), "Bash(npm test:*)");
});
