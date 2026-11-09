#!/usr/bin/env bash
# Record the persistguard demo transcript from REAL runs.
# Usage: bash scripts/record-demo.sh
# Writes demo/transcript.txt - the source of truth for scripts/make-gif.py.
# Each screen in the transcript starts with "$ " (the typed command);
# following lines are that command's real output (stdout + stderr).
# Title/end cards start with "### ".
#
# Provenance: the demo works on a throwaway copy of
# examples/demo-project under demo/.work. That copy is git-initialised
# and its settings file is committed, so `history` shows the tracked
# case for real. The copy (including the .bak written by clean) is
# deleted at the end of this script; the fixture in examples/ is
# never touched. Every credential in the fixture is synthetic and
# labelled FAKE.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
npm run build

# Short `persistguard` shim so the transcript shows clean commands, not a path.
mkdir -p "$ROOT/demo/bin"
ln -sf "$ROOT/dist/cli.js" "$ROOT/demo/bin/persistguard"
chmod +x "$ROOT/dist/cli.js"
export PATH="$ROOT/demo/bin:$PATH"
BIN="persistguard"
OUT="$ROOT/demo/transcript.txt"
: > "$OUT"

# Demo workdir: a throwaway copy of the fixture, committed to git.
WORK="$ROOT/demo/.work"
rm -rf "$WORK"
mkdir -p "$WORK"
cp -r "$ROOT/examples/demo-project" "$WORK/demo-project"
cd "$WORK/demo-project"
git init -q
git config user.email "demo@example.com"
git config user.name "Demo"
git add .
git commit -qm "add fixture settings"
cd "$ROOT"

run_screen() {
  # $1 = command line to print and run (evaluated by bash)
  echo "\$ $1" >> "$OUT"
  eval "$1" >> "$OUT" 2>&1
  echo "[exit code: $?]" >> "$OUT"
  echo "" >> "$OUT"
}

{
  echo "### TITLE: persistguard - the secret your agent persisted"
  echo ""
} >> "$OUT"

run_screen "$BIN scan demo/.work/demo-project"
run_screen "$BIN history demo/.work/demo-project"
run_screen "$BIN clean --write demo/.work/demo-project"
run_screen "$BIN clean --write --force demo/.work/demo-project"
run_screen "$BIN scan demo/.work/demo-project"

{
  echo "### END: persistguard 0.1.0 - MIT - github.com/techdevfun/persistguard"
  echo ""
} >> "$OUT"

# Clean up the throwaway copy; the transcript keeps the output.
rm -rf "$WORK"

echo "transcript written to $OUT"
wc -l "$OUT"
