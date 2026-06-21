#!/bin/bash
# Install Synsema skill for Claude Code
#
# Usage:
#   curl -s https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
#   OR
#   cd synsema && bash install-skill.sh

set -e

SKILL_DIR="$HOME/.claude/skills/synsema"
REPO_URL="https://raw.githubusercontent.com/kitecosmic/synsema/main"

echo "Installing Synsema skill for Claude Code..."

mkdir -p "$SKILL_DIR"

# Download skill files
SKILL_FILES="INDEX.md syntax.md builtins.md types.md capabilities.md agents.md llm.md human.md observability.md memory.md patterns.md structure.md"

for file in $SKILL_FILES; do
    if [ -f ".synsema-skill/$file" ]; then
        # Local install
        cp ".synsema-skill/$file" "$SKILL_DIR/$file"
    else
        # Remote install
        curl -sL "$REPO_URL/.synsema-skill/$file" -o "$SKILL_DIR/$file"
    fi
    echo "  Installed $file"
done

echo ""
echo "Synsema skill installed at: $SKILL_DIR"
echo ""
echo "To use in Claude Code, tell Claude:"
echo "  'Read the Synsema skill index at ~/.claude/skills/synsema/INDEX.md'"
echo ""
echo "Or add to your CLAUDE.md:"
echo "  'For Synsema development, read ~/.claude/skills/synsema/INDEX.md'"
echo ""
echo "Done!"
