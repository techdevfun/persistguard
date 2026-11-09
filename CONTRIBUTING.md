# Contributing

Small, focused tool - keep contributions small and focused too.

- Run `npm run build`, `npm test` and `node scripts/preflight.js`
  before opening a pull request. All three must be green.
- Tests are plain JavaScript under `test/`, run with `node --test`
  and an explicit file list in `package.json`. Add a test for every
  new detector, command, or edge case.
- Every fixture secret must be synthetic and labelled `FAKE`. The
  preflight script fails the build if a fixture in `examples/`,
  `test/` or `demo/` contains a secret-shaped value without the
  `FAKE` marker. Never put a real credential anywhere in this repo.
- All public content is ASCII English only. No Vietnamese diacritics,
  no internal names. The preflight script checks this.
- Detectors are heuristic: grade new findings HIGH only when the
  shape is unambiguous (known prefix, credential URL, Authorization
  header). Everything else is MEDIUM.
- Never print a secret value - in output, logs, JSON, or tests. The
  test suite asserts this by scanning CLI output for fixture secrets.
