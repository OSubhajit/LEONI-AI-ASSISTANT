#!/usr/bin/env bash
set -e
echo ""
echo "  LEONI v6.0 - Linux/macOS Setup"
echo "  ================================"
echo ""
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found."
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  macOS:         brew install python"
    exit 1
fi
echo "  [1/3] Python: $(python3 --version)"
echo "  [2/3] Installing dependencies..."
pip3 install -r backend/requirements.txt
echo ""
echo "  [3/3] Groq API Key (FREE at console.groq.com)"
read -r -p "  Paste Groq key (or Enter to skip): " GROQ_KEY
if [ -n "$GROQ_KEY" ]; then
    SHELL_RC="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
    grep -v "GROQ_API_KEY" "$SHELL_RC" > /tmp/_leoni_rc && mv /tmp/_leoni_rc "$SHELL_RC"
    echo "export GROQ_API_KEY=\"$GROQ_KEY\"" >> "$SHELL_RC"
    export GROQ_API_KEY="$GROQ_KEY"
    echo "  Groq key saved to $SHELL_RC"
else
    echo "  Skipped. Set later in LEONI Settings."
fi
echo ""
echo "  SETUP COMPLETE! Run: bash start_leoni.sh"
echo ""
