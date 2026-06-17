#!/bin/bash
# Install Syntecnia skill for Claude Code
#
# Usage:
#   curl -s https://raw.githubusercontent.com/kitecosmic/Syntecnia/main/install-skill.sh | bash
#   OR
#   cd Syntecnia && bash install-skill.sh

set -e

SKILL_DIR="$HOME/.claude/skills/syntecnia"
REPO_URL="https://raw.githubusercontent.com/kitecosmic/Syntecnia/main"

echo "Installing Syntecnia skill for Claude Code..."

mkdir -p "$SKILL_DIR"

# Download skill files
SKILL_FILES="INDEX.md syntax.md builtins.md types.md capabilities.md agents.md llm.md human.md observability.md memory.md patterns.md structure.md"

for file in $SKILL_FILES; do
    if [ -f ".syntecnia-skill/$file" ]; then
        # Local install
        cp ".syntecnia-skill/$file" "$SKILL_DIR/$file"
    else
        # Remote install
        curl -sL "$REPO_URL/.syntecnia-skill/$file" -o "$SKILL_DIR/$file"
    fi
    echo "  Installed $file"
done

echo ""
echo "Syntecnia skill installed at: $SKILL_DIR"
echo ""
echo "To use in Claude Code, tell Claude:"
echo "  'Read the Syntecnia skill index at ~/.claude/skills/syntecnia/INDEX.md'"
echo ""
echo "Or add to your CLAUDE.md:"
echo "  'For Syntecnia development, read ~/.claude/skills/syntecnia/INDEX.md'"
echo ""
echo "Done!"
