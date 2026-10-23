#!/usr/bin/env bash
# Install the Synsema skill (the open Agent Skills format: SKILL.md + one file per topic).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
#       → ~/.claude/skills/synsema            (Claude Code)
#   ... | bash -s -- --agents
#       → ~/.agents/skills/synsema            (Codex, opencode and other clients of ~/.agents/skills)
#   ... | bash -s -- --dir <skills folder>
#       → <skills folder>/synsema             (any other agent)
#   ... | bash -s -- --ref v0.6.46            (the skill of one release; default: main)
#   # or, from a checkout of the repo:
#   bash install-skill.sh [--agents | --dir <folder>]
#
# With Node, `npx skills add kitecosmic/synsema -g -y` installs it once per machine for every agent it detects.
# opencode reads both ~/.claude/skills and ~/.agents/skills: with a copy in each, update both.
# Re-running replaces the installed copy, so it is also how you update it.

set -euo pipefail

REPO="kitecosmic/synsema"
REF="main"
ROOT="$HOME/.claude/skills"

while [ $# -gt 0 ]; do
    case "$1" in
        --claude) ROOT="$HOME/.claude/skills" ;;
        --agents) ROOT="$HOME/.agents/skills" ;;
        --dir)    [ $# -ge 2 ] || { echo "--dir needs a folder" >&2; exit 2; }; ROOT="$2"; shift ;;
        --ref)    [ $# -ge 2 ] || { echo "--ref needs a branch or tag" >&2; exit 2; }; REF="$2"; shift ;;
        -h|--help) sed -n '2,17p' "$0" 2>/dev/null || true; exit 0 ;;
        *) echo "unknown option: $1 (use --claude, --agents, --dir <folder> or --ref <tag>)" >&2; exit 2 ;;
    esac
    shift
done

DEST="$ROOT/synsema"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$script_dir" ] && [ -f "$script_dir/skills/synsema/SKILL.md" ] && [ "$REF" = "main" ]; then
    SRC="$script_dir/skills/synsema"                                  # local checkout
else
    case "$REF" in
        v[0-9]*) url="https://codeload.github.com/$REPO/tar.gz/refs/tags/$REF" ;;
        *)       url="https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF" ;;
    esac
    curl -fsSL "$url" | tar -xz -C "$tmp"
    # releases up to v0.6.46 kept the skill in .synsema-skill/
    SRC=""
    for d in "$tmp"/*/skills/synsema "$tmp"/*/.synsema-skill; do
        if [ -f "$d/SKILL.md" ]; then SRC="$d"; break; fi
    done
    [ -n "$SRC" ] || { echo "skills/synsema/SKILL.md not found in $REPO@$REF" >&2; exit 1; }
fi

mkdir -p "$ROOT"
rm -rf "$DEST"
cp -R "$SRC" "$DEST"

echo "Synsema skill installed at: $DEST ($(ls "$DEST" | wc -l | tr -d ' ') files)"
echo "Restart your agent if the skill does not show up."
