#!/usr/bin/env sh
# Aegis-2B One-Line Global Installer (No git clone required)
# Usage: curl -fsSL https://raw.githubusercontent.com/Mhdomer/aegis-2b/main/install.sh | sh

set -e

REPO_URL="git+https://github.com/Mhdomer/aegis-2b.git"

printf "\033[1;36m==> Installing Aegis-2B (Autonomous Cloud Safety Circuit Breaker)...\033[0m\n"

if command -v uv >/dev/null 2>&1; then
    printf "  • Found 'uv' — installing global CLI tool via 'uv tool install'...\n"
    uv tool install --force "$REPO_URL"
elif command -v pipx >/dev/null 2>&1; then
    printf "  • Found 'pipx' — installing global CLI tool via 'pipx install'...\n"
    pipx install --force "$REPO_URL"
elif command -v pip3 >/dev/null 2>&1; then
    printf "  • Installing via 'pip3 install --user'...\n"
    pip3 install --user --upgrade "$REPO_URL"
else
    printf "\033[1;31mError: None of 'uv', 'pipx', or 'pip3' were found. Install uv first: curl -LsSf https://astral.sh/uv/install.sh | sh\033[0m\n"
    exit 1
fi

printf "\n\033[1;32m✔ Aegis-2B installed successfully!\033[0m\n"
printf "  • Run \033[1;36maegis test-aws\033[0m to verify live Botocore circuit breaking on your AWS account\n"
printf "  • Run \033[1;36maegis ui\033[0m to open the web dashboard at http://127.0.0.1:8765\n"
printf "  • Run \033[1;36maegis audit\033[0m to run the 8-vector security & fail-closed self-audit\n"
