# persistguard

One click in your AI coding agent can persist a password forever.
persistguard finds it, proves whether it ever reached git, redacts
it, and stops the next one at commit time.

It parses Claude Code's persisted approval files
(`.claude/settings.local.json` and `.claude/settings.json`) as JSON,
walks the `permissions.allow` list rule by rule, and detects secrets
typed *inside approved commands* - the exact shape both big generic
scanners miss. Then it closes the loop: `history` checks git,
`clean` rewrites the secret values out, and `hook` installs a
pre-commit gate plus the repo-level `.gitignore` entries that Claude
Code's own protection never writes - for the settings files and for
their `.bak` backups, which still hold the original secrets after
a rewrite.

![demo](demo/demo.gif)

## Why this exists

Picking "Yes, and don't ask again" on a Bash command saves that exact
command - password included - as an `allow` rule in the project's
`.claude/settings.local.json`, in plaintext. Apiiro's research
(published 2026-11-05; files collected 2026-11-01 to 2026-11-03)
scanned 104,185 public copies of that file and classified 1,122
(1.1%) as containing real secrets - 1,379 distinct values. Counting
git history, shared settings and agent transcripts, the total is
2,539 secrets across 1,994 repositories and 63 organisations,
including 379 database passwords, 122 Supabase service-role keys,
43 SSH logins, 42 GitHub/GitLab/npm tokens and 23 AWS keys.
Credentials were not tested; one notified company confirmed its key
was still live. The 2,539 total rests partly on an LLM reviewer's
judgement - it is Apiiro's number, not ours.

The same research ran the two big generic scanners over those 1,122
files: gitleaks flagged 564, TruffleHog flagged 643, and **215 were
flagged by neither** - usually because the secret is a password typed
inside a command, not a key in a recognizable format. That is the
blind spot persistguard is built for.

Claude Code's own protection adds the file to the user's *global* git
excludes on that one machine. It never lands in the repo's
`.gitignore`, so clones, other laptops and already-committed copies
stay exposed - and it cannot protect a file that is already tracked.

## Install

npm is not published yet. Install from source:

```sh
git clone https://github.com/techdevfun/persistguard.git
cd persistguard
npm ci
npm run build
npm link
```

Requires Node 20 or later. Zero runtime dependencies.

## Usage

```sh
# Find secret-bearing allow rules (exit 1 on findings, 0 when clean)
persistguard scan .

# Was a settings file ever committed? (exit 1 if tracked or ever committed)
persistguard history .

# Dry run: print what would change. Nothing is written.
persistguard clean .

# Rewrite the secrets out (backup .bak first; refuses tracked files
# without --force - rewriting a tracked file does not un-leak history).
# After rotating, delete the .bak backup: it still holds the original
# secrets, and scan keeps failing until it is gone.
persistguard clean --write .

# Install the pre-commit gate + repo .gitignore fix (settings files
# and their .claude/*.bak backups)
persistguard hook install .
```

A secret value is never printed anywhere - not in the table, not in
`--format json` output, not in logs. Previews show at most the first
4 and last 2 characters of a token, or only the key name for a
password assignment.

## Worked example

A fixture project ships in `examples/demo-project/` (every credential
there is synthetic and labelled `FAKE`):

```sh
$ persistguard scan examples/demo-project
persistguard scan: examples/demo-project
.claude/settings.local.json (5 rule(s))
  [HIGH] credential-url  rule #1 (allow)  Bash(psql postgres://app:<REDACTED-BY-PERSISTGUARD>@db.internal:5432/app -c "select 1")  (preview: postgres://app:****@db.internal:5432)
  [HIGH] openai-key  rule #2 (allow)  Bash(curl -H "Authorization: Bearer <REDACTED-BY-PERSISTGUARD>" https://api.example.com/health)  (preview: sk-F...89)
1 file(s), 5 rule(s), 2 finding(s) (2 HIGH, 0 MEDIUM)
```

The fixture is tracked by git in this repo, so a plain `clean --write`
refuses it (rewriting a tracked file does not un-leak history).
`--force` is safe here because every credential in the fixture is
synthetic and labelled `FAKE` - on a file that held a real secret,
rotate the credential first, and never `--force` a file you have not
rotated yet.

```sh
$ persistguard clean --write --force examples/demo-project
persistguard clean --write: 2 finding(s) redacted in 1 file(s)
.claude/settings.local.json: 2 finding(s) redacted (backup: .claude/settings.local.json.bak)
Rotation checklist - redaction does not un-leak history:
  - credential-url: rotate/revoke this credential
  - openai-key: rotate/revoke this credential
  Rotate or revoke every credential listed above. If the file was
  ever committed, the secret lives in git history: rotate it and
  rewrite history with git filter-repo (this tool does not do that).
  Delete the .bak backup after rotating - it still holds the original secrets:
    .claude/settings.local.json.bak

$ rm examples/demo-project/.claude/settings.local.json.bak
$ persistguard scan examples/demo-project
1 file(s), 5 rule(s), 0 finding(s) (0 HIGH, 0 MEDIUM)
```

The `rm` step is part of the flow, not cleanup: the `.bak` backup
holds the original secrets in plaintext, so `scan` keeps failing
(and the pre-commit hook keeps blocking) until it is deleted. The
hook's `.gitignore` fix also covers `.claude/*.bak`, so a backup can
never be committed by accident - but only deleting it removes the
secret from the disk. Restore the fixture afterwards with
`git checkout -- examples/demo-project`.

## What it detects

| Detector | Severity | Example |
| --- | --- | --- |
| Known-prefix token | HIGH | `ghp_`, `github_pat_`, `sk-`, `sk-proj-`, `AKIA`, `xox[baprs]-`, `npm_`, `sq0at-`, `sbp_`, JWT-shaped `eyJ...` |
| Credential URL | HIGH | `postgres://user:password@host` |
| Basic auth | HIGH | `curl -u user:password https://...` |
| Authorization header | HIGH | `Authorization: Bearer <token>` |
| Password assignment | MEDIUM | `--password=`, `PGPASSWORD=`, `MYSQL_PWD=`, `password:`, `mysql -p...`, `sshpass -p ...` |
| High-entropy token | MEDIUM | 20+ mixed-class characters next to a public host or a known command (`curl`, `psql`, `mysql`, `sshpass`) |

Findings are graded by detector confidence. HIGH blocks the hook;
MEDIUM is reported as REVIEW and also blocks the hook - the hook's
job is to stop the commit until a human looks.

False-positive rate, measured on the fixture set shipped with this
repo: 0 false positives and 0 false negatives. The set is
`examples/demo-project` (3 allow rules: 2 planted secrets, 1 clean
rule correctly unflagged) plus the unit-test fixtures (every planted
secret flagged, none of the 9 clean commands flagged). Fixtures are
synthetic by construction, so this measures the detectors against
their own design, not against real-world traffic.

## What this is not

- **Not a general secret scanner.** The walker only ever opens
  `.claude/settings*.json` files. It never scans other files. For
  whole-repo scanning, use gitleaks or TruffleHog - they beat us
  there, and they caught 564 and 643 of the 1,122 files
  respectively. persistguard exists for the 215 they both missed.
- **Not a history rewriter.** `clean` rewrites the file on disk
  only. If the file was ever committed, the secret is in git
  history: rotate the credential and rewrite history with
  `git filter-repo`. This tool does not do that, and it refuses to
  rewrite a tracked file without an explicit `--force`.
- **Not a guarantee.** Detectors are heuristic. A password that
  looks like an ordinary word next to no host will be missed (false
  negative), and a high-entropy string that is not a secret can be
  flagged (false positive). Never claim "finds all secrets" - and
  this tool never does.

## Where rivals beat us

gitleaks and TruffleHog scan every file in a repo and its full
history, with hundreds of detectors and verified-secret checks;
persistguard only looks at agent persistence files and only detects
secret-shaped values inside allow rules. GitGuardian remediates at
push time across an org; persistguard is local-only, one machine,
one repo. Claude Code's global-excludes protection is automatic and
needs no install; persistguard needs the user to run it (or install
the hook). What persistguard does that none of them do: parse the
allow list as a structure, catch the password-inside-a-command
shape, rewrite the persisted rule, and write the repo-level
`.gitignore` fix.

## Roadmap

- Cursor / Codex settings formats (same persisted-approval shape,
  different files).
- Pre-push hook mode for teams that commit from shared machines.
- A review flow for shared `.claude/settings.json` (committed on
  purpose) that separates intentional rules from leaked ones.

## License

MIT. See [LICENSE](LICENSE).
