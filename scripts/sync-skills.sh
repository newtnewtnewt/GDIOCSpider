#!/usr/bin/env sh
# Sync the portable skill into the Claude Code skill folder.
#
# .agents/skills/gdiocspider is the source of truth (the agentskills.io layout
# that Cursor/Codex/Copilot read). .claude/skills/gdiocspider is a generated
# mirror so Claude Code gets the skill on clone without a manual link step.
# Edit the .agents copy only; run this script (or just commit) to update the
# mirror.
set -eu

# Resolve repo root so the script works from any directory.
ROOT="$(git rev-parse --show-toplevel)"
CANON="$ROOT/.agents/skills/gdiocspider"
MIRROR="$ROOT/.claude/skills/gdiocspider"

if [ ! -d "$CANON" ]; then
    echo "sync-skills: source of truth not found: $CANON" >&2
    exit 1
fi

if diff -r -q "$CANON" "$MIRROR" >/dev/null 2>&1; then
    exit 0  # already in sync
fi

rm -rf "$MIRROR"
mkdir -p "$(dirname "$MIRROR")"
cp -r "$CANON" "$MIRROR"
git add "$MIRROR"
echo "sync-skills: synced .agents/skills/gdiocspider -> .claude/skills/gdiocspider"
