#!/usr/bin/env bash
# Idempotent installer for claude-fail2ban.
# Run as root on the target host: ./install.sh
#
# What this does:
#   1. Builds/refreshes a Python venv at /opt/claude-fail2ban/.venv
#   2. Installs/upgrades requirements
#   3. Installs systemd units to /etc/systemd/system
#   4. systemctl daemon-reload
#
# It deliberately does NOT:
#   - Create /etc/claude-fail2ban/.env (you stage secrets out-of-band)
#   - Enable/start timers (deploy first, decide later)
#   - Touch state under /var/lib/claude-fail2ban/

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR=/opt/claude-fail2ban
VENV_DIR="$INSTALL_DIR/.venv"
ETC_DIR=/etc/claude-fail2ban
VAR_DIR=/var/lib/claude-fail2ban

install -d -m 0755 "$INSTALL_DIR" "$VAR_DIR"
install -d -m 0700 "$ETC_DIR"

# Sync the package tree to the install dir. rsync if available, otherwise cp -a.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude='.venv/' --exclude='__pycache__/' --exclude='*.pyc' \
        --exclude='.git/' --exclude='.gitignore' --exclude='examples/' \
        --exclude='systemd/' --exclude='install.sh' \
        --exclude='README.md' --exclude='CLAUDE.md' --exclude='requirements.txt' \
        "$REPO_DIR/" "$INSTALL_DIR/"
    cp "$REPO_DIR/requirements.txt" "$INSTALL_DIR/"
else
    rm -rf "$INSTALL_DIR/claude_fail2ban"
    cp -a "$REPO_DIR/claude_fail2ban" "$INSTALL_DIR/"
    cp "$REPO_DIR/requirements.txt" "$INSTALL_DIR/"
fi

# Build venv (if missing) and install requirements.
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade-strategy only-if-needed \
    -r "$INSTALL_DIR/requirements.txt"

# Install systemd units.
install -m 0644 "$REPO_DIR/systemd/claude-fail2ban.service" /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/claude-fail2ban.timer" /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/claude-fail2ban-digest.service" /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/claude-fail2ban-digest.timer" /etc/systemd/system/

systemctl daemon-reload

if [[ ! -f "$ETC_DIR/config.toml" ]]; then
    echo
    echo "NOTE: $ETC_DIR/config.toml is missing. Copy a template from"
    echo "      $REPO_DIR/examples/ and adjust per host."
fi
if [[ ! -f "$ETC_DIR/.env" ]]; then
    echo "NOTE: $ETC_DIR/.env is missing. Stage secrets per host:"
    echo "      ANTHROPIC_API_KEY=..."
    echo "      HEALTHCHECK_URL=..."
    echo "      QWEN_URL=https://10.8.0.1:8442"
    echo "      QWEN_TOKEN=..."
    echo "      MAILCOW_API_URL=...   # mailcow hosts only"
    echo "      MAILCOW_API_KEY=...   # mailcow hosts only"
    echo "      Then chmod 600 $ETC_DIR/.env"
fi
echo
echo "Installed. Enable timers when ready:"
echo "  systemctl enable --now claude-fail2ban.timer claude-fail2ban-digest.timer"
