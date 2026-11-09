# demo-project

A fixture project for the persistguard demo. Every credential in
`.claude/settings.local.json` is synthetic and labelled `FAKE` - there
is no real secret in this directory.

It holds three persisted allow rules:

- `Bash(npm test *)` - clean.
- `Bash(psql postgres://app:FAKE...@db.internal ...)` - a database
  password inside an approved command (the shape generic scanners
  miss: 215 of the 1,122 secret-bearing settings files Apiiro found
  were flagged by neither gitleaks nor TruffleHog).
- `Bash(curl -H "Authorization: Bearer sk-FAKE..." ...)` - a token
  inside an approved command.

Run the demo from the repo root:

```sh
node dist/cli.js scan examples/demo-project
node dist/cli.js clean --write examples/demo-project
node dist/cli.js scan examples/demo-project
```

Note: `clean --write` rewrites the fixture file in place. Restore it
with `git checkout -- examples/demo-project` (in a checkout) or copy
it back from the demo transcript setup in `scripts/record-demo.sh`,
which works on a throwaway copy and never touches this file.
