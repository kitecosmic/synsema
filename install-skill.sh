#!/bin/bash
# Install the Synsema skill for Claude Code.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
#   # or, from a checkout:
#   cd synsema && bash install-skill.sh

set -euo pipefail

SKILL_DIR="$HOME/.claude/skills/synsema"
REPO_URL="https://raw.githubusercontent.com/kitecosmic/synsema/main/.synsema-skill"

# SKILL.md (with YAML frontmatter) MUST be first — it is the entry point that
# makes Claude Code auto-detect the skill. The rest are reference files that the
# skill loads on demand. Keep this list in sync with .synsema-skill/*.md.
SKILL_FILES="
SKILL.md
INDEX.md
why-synsema.md
syntax.md
builtins.md
types.md
modules.md
testing.md
stdlib.md
concurrency.md
frontend.md
serve.md
capabilities.md
secrets.md
agents.md
llm.md
human.md
observability.md
memory.md
patterns.md
structure.md
deploy.md
pitfalls.md
"

echo "Installing the Synsema skill for Claude Code..."
mkdir -p "$SKILL_DIR"

for file in $SKILL_FILES; do
    if [ -f ".synsema-skill/$file" ]; then
        cp ".synsema-skill/$file" "$SKILL_DIR/$file"        # local checkout
    else
        curl -fsSL "$REPO_URL/$file" -o "$SKILL_DIR/$file"  # remote
    fi
    echo "  + $file"
done

echo ""
echo "Synsema skill installed at: $SKILL_DIR"
echo ""
echo "Claude Code auto-detects it via SKILL.md — no CLAUDE.md edits needed."
echo "Just start working on .syn / .fsyn files, or type /synsema."
echo ""
echo "Done!"
