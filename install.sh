#!/usr/bin/env bash
# =============================================================================
# VerdictMail Installation Script
# https://github.com/ascarola/verdictmail
#
# Usage:
#   sudo bash install.sh
#
# Tested on Ubuntu 22.04 LTS and 24.04 LTS.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colours
# -----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fatal()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# -----------------------------------------------------------------------------
# 0. Preflight checks
# -----------------------------------------------------------------------------
header "Preflight checks"

[[ $EUID -eq 0 ]] || fatal "This script must be run as root. Try: sudo bash install.sh"

# OS check
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "This script is tested on Ubuntu. Detected: ${PRETTY_NAME:-unknown}. Proceeding anyway."
    else
        info "OS: $PRETTY_NAME"
    fi
fi

# Python check
PYTHON=$(command -v python3 || true)
[[ -n "$PYTHON" ]] || fatal "python3 not found. Install it with: apt-get install python3"
PY_VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
[[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -ge 11 ]] || fatal "Python 3.11+ required. Found: $PY_VER"
info "Python: $PY_VER"

# git check
command -v git >/dev/null 2>&1 || fatal "git not found. Install it with: apt-get install git"
info "git: $(git --version)"

# systemd check
command -v systemctl >/dev/null 2>&1 || fatal "systemctl not found — systemd is required."
info "systemd: present"

success "Preflight checks passed."

# -----------------------------------------------------------------------------
# 1. System dependencies
# -----------------------------------------------------------------------------
header "Installing system dependencies"

apt-get update -qq
apt-get install -y -qq \
    git python3 python3-venv python3-dev python3-pip \
    build-essential libssl-dev sqlite3

success "System dependencies installed."

# -----------------------------------------------------------------------------
# 2. Service user and directories
# -----------------------------------------------------------------------------
header "Creating service user and directories"

if id verdictmail &>/dev/null; then
    info "User 'verdictmail' already exists — skipping."
else
    useradd -r -s /bin/false -M -d /opt/verdictmail verdictmail
    success "Created user 'verdictmail'."
fi

mkdir -p /opt/verdictmail /var/log/verdictmail
chown verdictmail:verdictmail /opt/verdictmail /var/log/verdictmail
success "Directories ready."

# -----------------------------------------------------------------------------
# 3. Clone the repository
# -----------------------------------------------------------------------------
header "Cloning repository"

if [[ -d /opt/verdictmail/.git ]]; then
    info "Repository already cloned — pulling latest changes."
    git -C /opt/verdictmail pull --ff-only
elif [[ -d /opt/verdictmail ]] && [[ -n "$(ls -A /opt/verdictmail 2>/dev/null)" ]]; then
    fatal "/opt/verdictmail exists and is not empty but has no .git directory. " \
          "Remove or empty it manually and re-run."
else
    git clone https://github.com/ascarola/verdictmail.git /opt/verdictmail
fi
chown -R verdictmail:verdictmail /opt/verdictmail
success "Repository ready at /opt/verdictmail"

# -----------------------------------------------------------------------------
# 4. Virtual environment and dependencies
# -----------------------------------------------------------------------------
header "Setting up Python virtual environment"

if [[ ! -d /opt/verdictmail/venv ]]; then
    python3 -m venv /opt/verdictmail/venv
fi
/opt/verdictmail/venv/bin/pip install --upgrade pip -q
/opt/verdictmail/venv/bin/pip install -r /opt/verdictmail/requirements.txt -q
chown -R verdictmail:verdictmail /opt/verdictmail/venv
success "Virtual environment ready."

# -----------------------------------------------------------------------------
# 5. Credentials (.env)
# -----------------------------------------------------------------------------
header "Configuring credentials"

if [[ -f /opt/verdictmail/.env ]]; then
    warn ".env already exists — skipping credential prompts. Edit /opt/verdictmail/.env manually if needed."
else
    echo
    echo -e "${BOLD}Enter your Gmail credentials.${RESET}"
    echo -e "You need a Gmail App Password (not your regular password)."
    echo -e "Generate one at: Google Account → Security → 2-Step Verification → App passwords\n"

    read -rp "  Gmail address: " GMAIL_USER
    read -rsp "  Gmail App Password: " GMAIL_PASS
    echo

    echo
    echo -e "${BOLD}Enter your AI provider API key.${RESET}"
    echo -e "Leave blank any providers you are not using.\n"

    read -rsp "  OpenAI API key (sk-...): " OPENAI_KEY
    echo
    read -rsp "  Anthropic API key (sk-ant-...): " ANTHROPIC_KEY
    echo
    read -rsp "  Ollama API key (leave blank if not required): " OLLAMA_KEY
    echo

    echo
    echo -e "${BOLD}URLhaus threat intelligence (optional).${RESET}"
    echo -e "Get a free key at https://abuse.ch/ — leave blank to skip.\n"
    read -rsp "  URLhaus API key: " URLHAUS_KEY
    echo

    cat > /opt/verdictmail/.env <<EOF
# VerdictMail — environment variables
# Never commit this file to version control.

# Gmail credentials
GMAIL_USERNAME=${GMAIL_USER}
GMAIL_APP_PASSWORD=${GMAIL_PASS}

# AI provider API keys — only the key for your chosen provider is required
OPENAI_API_KEY=${OPENAI_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
OLLAMA_API_KEY=${OLLAMA_KEY}

# URLhaus threat intelligence — optional but recommended
# Free API key from https://abuse.ch/
URLHAUS_API_KEY=${URLHAUS_KEY}
EOF

    chown verdictmail:verdictmail /opt/verdictmail/.env
    chmod 600 /opt/verdictmail/.env
    success ".env written."
fi

# -----------------------------------------------------------------------------
# 6. Application config (verdictmail.yaml)
# -----------------------------------------------------------------------------
header "Configuring application"

if [[ -f /opt/verdictmail/config/verdictmail.yaml ]]; then
    warn "verdictmail.yaml already exists — skipping. Edit it manually if needed."
else
    cp /opt/verdictmail/config/verdictmail.yaml.example \
       /opt/verdictmail/config/verdictmail.yaml
    chown verdictmail:verdictmail /opt/verdictmail/config/verdictmail.yaml

    echo
    echo -e "${BOLD}AI provider configuration.${RESET}\n"

    PS3="  Select AI provider [1-3]: "
    AI_PROVIDER=""
    select AI_PROVIDER in "openai" "anthropic" "ollama"; do
        [[ -n "$AI_PROVIDER" ]] && break
        warn "Invalid selection — enter 1, 2, or 3."
    done
    [[ -n "$AI_PROVIDER" ]] || fatal "No AI provider selected."

    case "$AI_PROVIDER" in
        openai)    DEFAULT_MODEL="gpt-4o-mini" ;;
        anthropic) DEFAULT_MODEL="claude-haiku-4-5-20251001" ;;
        ollama)    DEFAULT_MODEL="qwen2.5-coder:14b" ;;
    esac

    read -rp "  Model name [${DEFAULT_MODEL}]: " AI_MODEL
    AI_MODEL="${AI_MODEL:-$DEFAULT_MODEL}"

    # Patch provider and model into yaml using python (avoids sed fragility)
    /opt/verdictmail/venv/bin/python3 - <<PYEOF
import yaml, pathlib
p = pathlib.Path("/opt/verdictmail/config/verdictmail.yaml")
cfg = yaml.safe_load(p.read_text())
cfg.setdefault("ai", {})["provider"] = "${AI_PROVIDER}"
cfg["ai"]["model"] = "${AI_MODEL}"
p.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True))
PYEOF

    # Timezone
    echo
    read -rp "  Timezone (IANA name, e.g. America/New_York) [UTC]: " TZ_NAME
    TZ_NAME="${TZ_NAME:-UTC}"

    /opt/verdictmail/venv/bin/python3 - <<PYEOF
import yaml, pathlib
p = pathlib.Path("/opt/verdictmail/config/verdictmail.yaml")
cfg = yaml.safe_load(p.read_text())
cfg["timezone"] = "${TZ_NAME}"
p.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True))
PYEOF

    success "verdictmail.yaml configured (provider=${AI_PROVIDER}, model=${AI_MODEL}, timezone=${TZ_NAME})."
fi

# -----------------------------------------------------------------------------
# 7. systemd units
# -----------------------------------------------------------------------------
header "Installing systemd service units"

cp /opt/verdictmail/systemd/verdictmail.service     /etc/systemd/system/
cp /opt/verdictmail/systemd/verdictmail-web.service /etc/systemd/system/
systemctl daemon-reload
success "Service units installed."

# -----------------------------------------------------------------------------
# 8. sudoers rule
# -----------------------------------------------------------------------------
header "Installing sudoers rule"

cp /opt/verdictmail/systemd/verdictmail-sudoers /etc/sudoers.d/verdictmail
chmod 440 /etc/sudoers.d/verdictmail
success "sudoers rule installed."

# -----------------------------------------------------------------------------
# 9. Enable and start services
# -----------------------------------------------------------------------------
header "Starting services"

systemctl enable --now verdictmail verdictmail-web
sleep 3

DAEMON_STATUS=$(systemctl is-active verdictmail 2>/dev/null || true)
WEB_STATUS=$(systemctl is-active verdictmail-web 2>/dev/null || true)

if [[ "$DAEMON_STATUS" == "active" && "$WEB_STATUS" == "active" ]]; then
    success "Both services are running."
else
    warn "One or more services may not have started cleanly."
    warn "  verdictmail:     $DAEMON_STATUS"
    warn "  verdictmail-web: $WEB_STATUS"
    warn "Run: journalctl -u verdictmail -n 30"
fi

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo -e "${GREEN}${BOLD}============================================${RESET}"
echo -e "${GREEN}${BOLD}  VerdictMail installation complete!${RESET}"
echo -e "${GREEN}${BOLD}============================================${RESET}"
echo
echo -e "  Open your browser and go to:"
echo -e "  ${BOLD}http://${SERVER_IP}${RESET}"
echo
echo -e "  On first visit you will be prompted to set a web UI password."
echo
echo -e "  If you need to make changes:"
echo -e "    Credentials : /opt/verdictmail/.env"
echo -e "    Config      : /opt/verdictmail/config/verdictmail.yaml"
echo -e "    Logs        : journalctl -u verdictmail -f"
echo
