#!/usr/bin/env bash
# ============================================================================
# Digital Footprint Audit
# A unified OSINT workflow script for macOS
#
# Orchestrates: Sherlock, Maigret, theHarvester, PhoneInfoga,
#               SpiderFoot, Recon-ng
#
# Usage:  ./digital-footprint-audit.sh [--tor] [--full-scan]
# Output: ~/digital-footprint-reports/<timestamp>/
# ============================================================================

set -uo pipefail  # NOTE: no -e; we handle errors manually per-tool

# ── Configuration ──────────────────────────────────────────────────────────
REPORT_BASE="$HOME/digital-footprint-reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_DIR="$REPORT_BASE/$TIMESTAMP"
USE_TOR=false
TIMEOUT=60
HIBP_API_KEY=""

# ── Ensure common pip/Python bin dirs are in PATH ──────────────────────────
# pip installs CLI tools here on macOS and they're often missing from PATH
export PATH="$HOME/.local/bin:$HOME/Library/Python/3.11/bin:$HOME/Library/Python/3.12/bin:$HOME/Library/Python/3.13/bin:$(python3 -c 'import site; print(site.USER_BASE)' 2>/dev/null)/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helper Functions ───────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $1"; }
header()  { echo -e "\n${BOLD}═══ $1 ═══${NC}\n"; }

# Locate a command by checking multiple possible names and common brew paths.
# Returns 0 and prints the path if found, returns 1 if not found.
BREW_PREFIX=$(brew --prefix 2>/dev/null || echo "/opt/homebrew")

find_cmd() {
    for cmd_name in "$@"; do
        local found

        # 1. Standard PATH lookup
        found=$(command -v "$cmd_name" 2>/dev/null) && { echo "$found"; return 0; }

        # 2. Direct check in common bin dirs
        for dir in "$BREW_PREFIX/bin" "$BREW_PREFIX/sbin" "$HOME/.local/bin" "$HOME/go/bin"; do
            [[ -x "$dir/$cmd_name" ]] && { echo "$dir/$cmd_name"; return 0; }
        done

        # 3. Brute-force search in brew prefix (catches libexec/bin, Cellar/*/bin, etc.)
        #    Uses find with -maxdepth to keep it fast
        found=$(find "$BREW_PREFIX" -maxdepth 6 -name "$cmd_name" -type f -perm +111 2>/dev/null | head -1)
        [[ -n "$found" && -x "$found" ]] && { echo "$found"; return 0; }

        # 4. Also search pipx binary dir
        [[ -x "$HOME/.local/pipx/venvs/$cmd_name/bin/$cmd_name" ]] && {
            echo "$HOME/.local/pipx/venvs/$cmd_name/bin/$cmd_name"; return 0;
        }
    done
    return 1
}

# Common email providers — skip domain recon against these
COMMON_EMAIL_DOMAINS="gmail.com|yahoo.com|hotmail.com|outlook.com|aol.com|icloud.com|me.com|mac.com|protonmail.com|proton.me|live.com|msn.com|ymail.com|fastmail.com|zoho.com|mail.com"

is_common_email_provider() {
    local domain="$1"
    echo "$domain" | grep -qEi "^($COMMON_EMAIL_DOMAINS)$"
}

# ── Parse CLI Flags ────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --tor)           USE_TOR=true ;;
        --timeout=*)     TIMEOUT="${arg#*=}" ;;
        --hibp-key=*)    HIBP_API_KEY="${arg#*=}" ;;
        --help|-h)
            echo "Usage: $0 [--tor] [--timeout=SECONDS] [--hibp-key=KEY]"
            echo ""
            echo "Options:"
            echo "  --tor              Route tool requests through Tor (requires Tor)"
            echo "  --timeout=SECONDS  Per-request timeout (default: 60)"
            echo "  --hibp-key=KEY     Have I Been Pwned API key (get one at https://haveibeenpwned.com/API/Key)"
            echo "                     Without a key, HIBP runs in limited mode (breach names only)."
            echo "  --help, -h         Show this help message"
            exit 0
            ;;
        *)
            warn "Unknown flag: $arg (ignoring)"
            ;;
    esac
done

# ── Dependency Management ──────────────────────────────────────────────────

# Detect PEP 668 (externally-managed Python) and set pip flags accordingly
PIP_EXTRA_FLAGS=""
if python3 -c "import sysconfig; p=sysconfig.get_path('stdlib'); exit(0 if __import__('os').path.exists(p+'/../EXTERNALLY-MANAGED') else 1)" 2>/dev/null; then
    PIP_EXTRA_FLAGS="--break-system-packages"
    info "Detected externally-managed Python (PEP 668). Using --break-system-packages."
fi

# Check if pipx is available (preferred for Python CLI tools on PEP 668 systems)
HAS_PIPX=false
if command -v pipx &>/dev/null; then
    HAS_PIPX=true
elif [[ -n "$PIP_EXTRA_FLAGS" ]]; then
    # PEP 668 detected but no pipx — install it (essential for Python CLI tools)
    info "PEP 668 system without pipx detected. Installing pipx (needed for Python CLI tools)..."
    brew install pipx 2>&1 | tail -3 || true
    pipx ensurepath 2>/dev/null || true
    export PATH="$HOME/.local/bin:$PATH"
    hash -r 2>/dev/null
    if command -v pipx &>/dev/null; then
        HAS_PIPX=true
        success "pipx installed"
    else
        warn "Could not install pipx. Some Python tools may fail to install."
    fi
fi

# Run an install command, capturing its exit code independently of pipefail.
# Shows last 5 lines of output for diagnostics.
run_install() {
    local install_cmd="$1"
    local log_file
    log_file=$(mktemp)
    info "  Trying: $install_cmd"

    # Run in a subshell with pipefail disabled to get the TRUE exit code
    local rc=0
    ( set +o pipefail; eval "$install_cmd" > "$log_file" 2>&1 ) || rc=$?

    # Show last 5 lines for diagnostics
    tail -5 "$log_file" 2>/dev/null
    rm -f "$log_file"

    hash -r 2>/dev/null  # refresh command cache after any install attempt
    return $rc
}

# Try multiple install methods in order. Returns 0 if any succeeds.
try_install() {
    local tool_name="$1"
    shift
    for install_cmd in "$@"; do
        if run_install "$install_cmd"; then
            success "  Install command completed for $tool_name"
            return 0
        fi
        warn "  Method failed, trying next..."
    done
    return 1
}

# After all install attempts, do a final find_cmd check as a safety net.
# This catches cases where an install method "failed" by exit code but
# actually put the binary in place (common with brew cleanup warnings).
resolve_tool() {
    local var_has="$1"   # e.g., HAS_SHERLOCK
    local var_cmd="$2"   # e.g., CMD_SHERLOCK
    local label="$3"     # e.g., "Sherlock"
    shift 3
    # remaining args: command names to search for

    local found_path
    if found_path=$(find_cmd "$@"); then
        eval "$var_has=true"
        eval "$var_cmd='$found_path'"
        success "$label found at $found_path"
        return 0
    fi
    return 1
}

header "Checking Dependencies"

# Track which tools are available + their resolved command paths
HAS_SHERLOCK=false;    CMD_SHERLOCK=""
HAS_MAIGRET=false;     CMD_MAIGRET=""
HAS_HARVESTER=false;   CMD_HARVESTER=""
HAS_PHONEINFOGA=false; CMD_PHONEINFOGA=""
HAS_SPIDERFOOT=false;  CMD_SPIDERFOOT=""
HAS_RECONNG=false;     CMD_RECONNG=""

# Ensure Homebrew is available
if ! command -v brew &>/dev/null; then
    fail "Homebrew is required but not installed."
    echo "  Install it from https://brew.sh"
    exit 1
fi

# Ensure pip3 is available
if ! command -v pip3 &>/dev/null; then
    fail "pip3 is required but not installed."
    echo "  Install Python 3: brew install python"
    exit 1
fi

info "Python user bin: $(python3 -c 'import site; print(site.USER_BASE)' 2>/dev/null)/bin"
info "pipx available: $HAS_PIPX"
info "pip extra flags: ${PIP_EXTRA_FLAGS:-<none>}"
echo ""

# ── Sherlock ───────────────────────────────────────────────────────────────
info "Checking Sherlock..."
if ! resolve_tool HAS_SHERLOCK CMD_SHERLOCK "Sherlock" sherlock; then
    warn "Sherlock not found. Installing..."
    # Try brew first (most reliable on macOS), then pipx, then pip
    try_install "Sherlock" \
        "brew install sherlock" \
        ${HAS_PIPX:+"pipx install sherlock-project"} \
        "pip3 install --user $PIP_EXTRA_FLAGS sherlock-project" \
        "pip3 install $PIP_EXTRA_FLAGS sherlock-project" \
        || true

    # Brew sometimes installs but doesn't link — force link
    brew link --overwrite sherlock 2>/dev/null || true
    hash -r 2>/dev/null

    # Safety net: check again regardless of try_install exit code
    if ! resolve_tool HAS_SHERLOCK CMD_SHERLOCK "Sherlock" sherlock; then
        fail "Sherlock — could not install or find command in PATH."
        fail "  Manual fix: brew link sherlock  OR  pipx install sherlock-project"
    fi
fi

# ── Maigret ────────────────────────────────────────────────────────────────
info "Checking Maigret..."
if ! resolve_tool HAS_MAIGRET CMD_MAIGRET "Maigret" maigret; then
    warn "Maigret not found. Installing..."
    try_install "Maigret" \
        ${HAS_PIPX:+"pipx install maigret"} \
        "pip3 install --user $PIP_EXTRA_FLAGS maigret" \
        "pip3 install $PIP_EXTRA_FLAGS maigret" \
        || true

    hash -r 2>/dev/null
    if ! resolve_tool HAS_MAIGRET CMD_MAIGRET "Maigret" maigret; then
        fail "Maigret — could not install or find command in PATH."
        fail "  Manual fix: pipx install maigret"
    fi
fi

# ── theHarvester ───────────────────────────────────────────────────────────
# The command name varies: theHarvester, theharvester, theHarvester.py
info "Checking theHarvester..."
if ! resolve_tool HAS_HARVESTER CMD_HARVESTER "theHarvester" theHarvester theharvester theHarvester.py; then
    warn "theHarvester not found. Installing..."
    try_install "theHarvester" \
        "brew install theharvester" \
        ${HAS_PIPX:+"pipx install theHarvester"} \
        "pip3 install --user $PIP_EXTRA_FLAGS theHarvester" \
        "pip3 install $PIP_EXTRA_FLAGS theHarvester" \
        || true

    hash -r 2>/dev/null
    # Also check brew's libexec path where some brew formulas put Python scripts
    BREW_PREFIX=$(brew --prefix 2>/dev/null || echo "/opt/homebrew")
    export PATH="$BREW_PREFIX/opt/theharvester/libexec/bin:$PATH"

    # Brew sometimes installs but doesn't link
    brew link --overwrite theharvester 2>/dev/null || true
    hash -r 2>/dev/null

    if ! resolve_tool HAS_HARVESTER CMD_HARVESTER "theHarvester" theHarvester theharvester theHarvester.py; then
        fail "theHarvester — could not install or find command in PATH."
        fail "  Manual fix: brew link theharvester  OR  pipx install theHarvester"
    fi
fi

# ── PhoneInfoga ────────────────────────────────────────────────────────────
info "Checking PhoneInfoga..."
if ! resolve_tool HAS_PHONEINFOGA CMD_PHONEINFOGA "PhoneInfoga" phoneinfoga; then
    warn "PhoneInfoga not found. Installing..."
    try_install "PhoneInfoga" \
        "brew install phoneinfoga" \
        "go install github.com/sundowndev/phoneinfoga/v2@latest" \
        || true

    hash -r 2>/dev/null
    export PATH="$HOME/go/bin:$PATH"

    if ! resolve_tool HAS_PHONEINFOGA CMD_PHONEINFOGA "PhoneInfoga" phoneinfoga; then
        fail "PhoneInfoga — could not install or find command in PATH."
        fail "  Manual fix: brew install phoneinfoga"
    fi
fi

# ── SpiderFoot ─────────────────────────────────────────────────────────────
info "Checking SpiderFoot..."
SPIDERFOOT_DIR="$HOME/spiderfoot"
if resolve_tool HAS_SPIDERFOOT CMD_SPIDERFOOT "SpiderFoot" spiderfoot sfcli.py; then
    : # found in PATH
elif [[ -f "$SPIDERFOOT_DIR/sf.py" ]]; then
    CMD_SPIDERFOOT="python3 $SPIDERFOOT_DIR/sf.py"
    HAS_SPIDERFOOT=true
    success "SpiderFoot found at $SPIDERFOOT_DIR/sf.py"
elif [[ -f "$SPIDERFOOT_DIR/sfcli.py" ]]; then
    CMD_SPIDERFOOT="python3 $SPIDERFOOT_DIR/sfcli.py"
    HAS_SPIDERFOOT=true
    success "SpiderFoot CLI found at $SPIDERFOOT_DIR/sfcli.py"
else
    warn "SpiderFoot not found. Cloning to ~/spiderfoot..."
    if git clone https://github.com/smicallef/spiderfoot.git "$SPIDERFOOT_DIR" 2>&1 | tail -3; then
        info "Installing SpiderFoot dependencies..."
        pip3 install --user $PIP_EXTRA_FLAGS -r "$SPIDERFOOT_DIR/requirements.txt" 2>&1 | tail -5 || true
        if [[ -f "$SPIDERFOOT_DIR/sfcli.py" ]]; then
            CMD_SPIDERFOOT="python3 $SPIDERFOOT_DIR/sfcli.py"
            HAS_SPIDERFOOT=true
            success "SpiderFoot installed at $SPIDERFOOT_DIR"
        elif [[ -f "$SPIDERFOOT_DIR/sf.py" ]]; then
            CMD_SPIDERFOOT="python3 $SPIDERFOOT_DIR/sf.py"
            HAS_SPIDERFOOT=true
            success "SpiderFoot installed at $SPIDERFOOT_DIR"
        else
            fail "SpiderFoot cloned but no entry point found."
        fi
    else
        fail "Could not clone SpiderFoot. Skipping."
    fi
fi

# ── Recon-ng ───────────────────────────────────────────────────────────────
info "Checking Recon-ng..."
RECONNG_DIR="$HOME/recon-ng"
if resolve_tool HAS_RECONNG CMD_RECONNG "Recon-ng" recon-ng; then
    : # found in PATH
elif [[ -f "$RECONNG_DIR/recon-ng" ]]; then
    CMD_RECONNG="$RECONNG_DIR/recon-ng"
    HAS_RECONNG=true
    success "Recon-ng found at $RECONNG_DIR"
else
    warn "Recon-ng not found. Installing..."
    try_install "Recon-ng" \
        "brew install recon-ng" \
        "pip3 install --user $PIP_EXTRA_FLAGS recon-ng" \
        || true

    hash -r 2>/dev/null

    if ! resolve_tool HAS_RECONNG CMD_RECONNG "Recon-ng" recon-ng; then
        # Try clone as last resort
        warn "Command not in PATH. Trying git clone..."
        if git clone https://github.com/lanmaster53/recon-ng.git "$RECONNG_DIR" 2>&1 | tail -3; then
            pip3 install --user $PIP_EXTRA_FLAGS -r "$RECONNG_DIR/REQUIREMENTS" 2>&1 | tail -3 || true
            if [[ -f "$RECONNG_DIR/recon-ng" ]]; then
                CMD_RECONNG="$RECONNG_DIR/recon-ng"
                HAS_RECONNG=true
                success "Recon-ng cloned to $RECONNG_DIR"
            fi
        fi
        $HAS_RECONNG || fail "Recon-ng — could not install. Skipping."
    fi
fi

# ── Dependency Summary ────────────────────────────────────────────────────
echo ""
header "Dependency Summary"
for pair in "Sherlock:$HAS_SHERLOCK" "Maigret:$HAS_MAIGRET" "theHarvester:$HAS_HARVESTER" \
            "PhoneInfoga:$HAS_PHONEINFOGA" "SpiderFoot:$HAS_SPIDERFOOT" "Recon-ng:$HAS_RECONNG"; do
    name="${pair%%:*}"
    avail="${pair#*:}"
    if $avail; then
        success "$name — ready"
    else
        fail "$name — unavailable"
    fi
done
echo ""

# Count available tools and warn if too few
TOOLS_AVAILABLE=0
$HAS_SHERLOCK    && ((TOOLS_AVAILABLE++)) || true
$HAS_MAIGRET     && ((TOOLS_AVAILABLE++)) || true
$HAS_HARVESTER   && ((TOOLS_AVAILABLE++)) || true
$HAS_PHONEINFOGA && ((TOOLS_AVAILABLE++)) || true
$HAS_SPIDERFOOT  && ((TOOLS_AVAILABLE++)) || true
$HAS_RECONNG     && ((TOOLS_AVAILABLE++)) || true

if [[ $TOOLS_AVAILABLE -eq 0 ]]; then
    fail "No tools are available. Cannot proceed."
    echo "  Try installing tools manually first, then re-run the script."
    exit 1
elif [[ $TOOLS_AVAILABLE -lt 3 ]]; then
    warn "Only $TOOLS_AVAILABLE/6 tools available. Results will be limited."
    read -rp "$(echo -e "${YELLOW}Continue anyway? [Y/n]:${NC} ")" cont
    [[ "$cont" =~ ^[Nn]$ ]] && { echo "Exiting."; exit 0; }
fi

# Tor (optional)
if $USE_TOR; then
    if ! command -v tor &>/dev/null; then
        warn "Tor not found. Installing via Homebrew..."
        brew install tor 2>/dev/null || { fail "Could not install Tor. Running without it."; USE_TOR=false; }
    fi
    if $USE_TOR; then
        info "Starting Tor in background..."
        tor &>/dev/null &
        TOR_PID=$!
        sleep 5
        success "Tor started (PID: $TOR_PID)"
    fi
fi

# ── Gather Target Information ──────────────────────────────────────────────
header "Target Information"
echo "Enter the details for the person to audit."
echo "Press Enter to skip any field."
echo ""

read -rp "$(echo -e "${CYAN}Username:${NC}     ")" TARGET_USERNAME
read -rp "$(echo -e "${CYAN}Email:${NC}        ")" TARGET_EMAIL
read -rp "$(echo -e "${CYAN}Phone:${NC}        ")" TARGET_PHONE
read -rp "$(echo -e "${CYAN}Domain:${NC}       ")" TARGET_DOMAIN

# Validate at least one input was provided
if [[ -z "$TARGET_USERNAME" && -z "$TARGET_EMAIL" && -z "$TARGET_PHONE" && -z "$TARGET_DOMAIN" ]]; then
    fail "No target information provided. Exiting."
    exit 1
fi

# Phone format reminder
if [[ -n "$TARGET_PHONE" && ! "$TARGET_PHONE" =~ ^\+ ]]; then
    warn "Phone number should include country code (e.g., +14155551234)"
    read -rp "$(echo -e "${YELLOW}Continue anyway? [y/N]:${NC} ")" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { read -rp "$(echo -e "${CYAN}Re-enter phone:${NC} ")" TARGET_PHONE; }
fi

# ── Create Report Directory ────────────────────────────────────────────────
header "Setting Up Report Directory"
mkdir -p "$REPORT_DIR"/{sherlock,maigret,theharvester,phoneinfoga,spiderfoot,recon-ng,hibp}
success "Report directory: $REPORT_DIR"

# Write metadata file
cat > "$REPORT_DIR/audit-metadata.json" <<EOF
{
    "audit_timestamp": "$TIMESTAMP",
    "target": {
        "username": "${TARGET_USERNAME:-null}",
        "email": "${TARGET_EMAIL:-null}",
        "phone": "${TARGET_PHONE:-null}",
        "domain": "${TARGET_DOMAIN:-null}"
    },
    "options": {
        "tor_enabled": $USE_TOR,
        "timeout": $TIMEOUT
    },
    "tools": {
        "sherlock": $HAS_SHERLOCK,
        "maigret": $HAS_MAIGRET,
        "theharvester": $HAS_HARVESTER,
        "phoneinfoga": $HAS_PHONEINFOGA,
        "spiderfoot": $HAS_SPIDERFOOT,
        "recon_ng": $HAS_RECONNG
    }
}
EOF

# Build TOR flags for tools that support it
TOR_FLAG_SHERLOCK=""
TOR_FLAG_MAIGRET=""
if $USE_TOR; then
    TOR_FLAG_SHERLOCK="--tor"
    TOR_FLAG_MAIGRET="--tor"
fi

# ── Tool Execution Functions ───────────────────────────────────────────────

run_hibp() {
    if [[ -z "$TARGET_EMAIL" ]]; then
        info "HIBP: No email provided, skipping."
        return 0
    fi

    header "Have I Been Pwned — Breach Check"
    local outdir="$REPORT_DIR/hibp"
    local encoded_email
    encoded_email=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TARGET_EMAIL'))")

    if [[ -n "$HIBP_API_KEY" ]]; then
        # ── Full API mode (paid key) ──────────────────────────────────────
        info "Checking breaches for '$TARGET_EMAIL' (API key provided)..."

        # 1. Breached accounts
        local breaches_response
        breaches_response=$(curl -s -w "\n%{http_code}" \
            -H "hibp-api-key: $HIBP_API_KEY" \
            -H "user-agent: DigitalFootprintAudit" \
            "https://haveibeenpwned.com/api/v3/breachedaccount/$encoded_email?truncateResponse=false" \
            2>/dev/null) || true

        local breaches_http_code breaches_body
        breaches_http_code=$(echo "$breaches_response" | tail -1)
        breaches_body=$(echo "$breaches_response" | sed '$d')

        if [[ "$breaches_http_code" == "200" ]]; then
            echo "$breaches_body" > "$outdir/breaches.json"
            local breach_count
            breach_count=$(python3 -c "import json; print(len(json.loads('''$breaches_body''')))" 2>/dev/null || echo "?")
            warn "Found in $breach_count breach(es)!"
        elif [[ "$breaches_http_code" == "404" ]]; then
            echo "[]" > "$outdir/breaches.json"
            success "No breaches found for this email."
        else
            warn "HIBP breaches API returned HTTP $breaches_http_code"
            echo "{\"error\": \"HTTP $breaches_http_code\", \"body\": $(echo "$breaches_body" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')}" > "$outdir/breaches.json"
        fi

        # Brief pause to respect rate limiting (1.5s between requests)
        sleep 2

        # 2. Pastes
        info "Checking pastes..."
        local pastes_response
        pastes_response=$(curl -s -w "\n%{http_code}" \
            -H "hibp-api-key: $HIBP_API_KEY" \
            -H "user-agent: DigitalFootprintAudit" \
            "https://haveibeenpwned.com/api/v3/pasteaccount/$encoded_email" \
            2>/dev/null) || true

        local pastes_http_code pastes_body
        pastes_http_code=$(echo "$pastes_response" | tail -1)
        pastes_body=$(echo "$pastes_response" | sed '$d')

        if [[ "$pastes_http_code" == "200" ]]; then
            echo "$pastes_body" > "$outdir/pastes.json"
            local paste_count
            paste_count=$(python3 -c "import json; print(len(json.loads('''$pastes_body''')))" 2>/dev/null || echo "?")
            warn "Found in $paste_count paste(s)!"
        elif [[ "$pastes_http_code" == "404" ]]; then
            echo "[]" > "$outdir/pastes.json"
            success "No pastes found for this email."
        else
            warn "HIBP pastes API returned HTTP $pastes_http_code"
        fi

    else
        # ── Free mode (no API key) ────────────────────────────────────────
        # Uses the breach catalog API (free, no key needed) plus password check
        info "Checking breaches for '$TARGET_EMAIL' (no API key — limited mode)..."
        info "Tip: Get a full API key at https://haveibeenpwned.com/API/Key"

        # The v3 breachedaccount endpoint requires a key, but we can check
        # against the full breach list and do a password hash check
        local breaches_response
        breaches_response=$(curl -s -w "\n%{http_code}" \
            -H "user-agent: DigitalFootprintAudit" \
            "https://haveibeenpwned.com/api/v3/breachedaccount/$encoded_email?truncateResponse=true" \
            2>/dev/null) || true

        local breaches_http_code breaches_body
        breaches_http_code=$(echo "$breaches_response" | tail -1)
        breaches_body=$(echo "$breaches_response" | sed '$d')

        if [[ "$breaches_http_code" == "200" ]]; then
            echo "$breaches_body" > "$outdir/breaches.json"
            warn "Email appears in breaches (limited details without API key)."
        elif [[ "$breaches_http_code" == "404" ]]; then
            echo "[]" > "$outdir/breaches.json"
            success "No breaches found for this email."
        elif [[ "$breaches_http_code" == "401" ]]; then
            info "HIBP API requires a key for detailed breach data."
            info "Falling back to breach catalog lookup..."

            # Fetch the full breach catalog (free, no key needed)
            curl -s -H "user-agent: DigitalFootprintAudit" \
                "https://haveibeenpwned.com/api/v3/breaches" \
                > "$outdir/all_breaches_catalog.json" 2>/dev/null || true

            # Also generate manual check URLs
            python3 -c "
import json

data = {
    'email': '$TARGET_EMAIL',
    'note': 'Full breach check requires an API key. Use the links below to check manually.',
    'manual_check_urls': {
        'haveibeenpwned': 'https://haveibeenpwned.com/account/$encoded_email',
        'dehashed': 'https://www.dehashed.com/search?query=$TARGET_EMAIL',
        'intelx': 'https://intelx.io/?s=$TARGET_EMAIL',
        'leakcheck': 'https://leakcheck.io/'
    },
    'api_key_url': 'https://haveibeenpwned.com/API/Key'
}

with open('$outdir/breaches.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f\"Manual check links generated.\")
for name, url in data['manual_check_urls'].items():
    print(f\"  {name}: {url}\")
" 2>/dev/null || true
        else
            warn "HIBP API returned HTTP $breaches_http_code"
        fi
    fi

    # 3. Password hash check (always free — k-anonymity model)
    # This checks if common passwords for this account appear in breaches
    # We don't have the user's password, but we can note this capability
    python3 -c "
import json, os

outdir = '$outdir'
breaches_file = os.path.join(outdir, 'breaches.json')
pastes_file = os.path.join(outdir, 'pastes.json')

summary = {
    'email': '$TARGET_EMAIL',
    'has_api_key': $([ -n "$HIBP_API_KEY" ] && echo 'True' || echo 'False'),
    'breaches': None,
    'pastes': None,
    'breach_count': 0,
    'paste_count': 0
}

if os.path.exists(breaches_file):
    try:
        with open(breaches_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            summary['breaches'] = data
            summary['breach_count'] = len(data)
        else:
            summary['breaches'] = data
    except:
        pass

if os.path.exists(pastes_file):
    try:
        with open(pastes_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            summary['pastes'] = data
            summary['paste_count'] = len(data)
    except:
        pass

with open(os.path.join(outdir, 'hibp_summary.json'), 'w') as f:
    json.dump(summary, f, indent=2)
" 2>/dev/null || true

    success "HIBP results saved to $outdir/"
}

run_sherlock() {
    if ! $HAS_SHERLOCK || [[ -z "$TARGET_USERNAME" ]]; then return 0; fi
    header "Sherlock — Username Enumeration"
    info "Searching for '$TARGET_USERNAME' across 400+ sites..."
    info "Using: $CMD_SHERLOCK"
    local outdir="$REPORT_DIR/sherlock"

    $CMD_SHERLOCK "$TARGET_USERNAME" \
        --print-found \
        --json "$outdir/${TARGET_USERNAME}.json" \
        --csv \
        --output "$outdir/${TARGET_USERNAME}.txt" \
        --timeout "$TIMEOUT" \
        $TOR_FLAG_SHERLOCK \
        2>&1 | tee "$outdir/sherlock.log" || warn "Sherlock encountered errors (see log)"

    # Move CSV if generated in current directory
    [[ -f "${TARGET_USERNAME}.csv" ]] && mv "${TARGET_USERNAME}.csv" "$outdir/" 2>/dev/null || true

    success "Sherlock results saved to $outdir/"
}

run_maigret() {
    if ! $HAS_MAIGRET || [[ -z "$TARGET_USERNAME" ]]; then return 0; fi
    header "Maigret — Advanced Username Enumeration"
    info "Searching for '$TARGET_USERNAME' across 1000+ sites..."
    info "Using: $CMD_MAIGRET"
    local outdir="$REPORT_DIR/maigret"

    $CMD_MAIGRET "$TARGET_USERNAME" \
        --json "$outdir/${TARGET_USERNAME}.json" \
        --html \
        --timeout "$TIMEOUT" \
        $TOR_FLAG_MAIGRET \
        2>&1 | tee "$outdir/maigret.log" || warn "Maigret encountered errors (see log)"

    # Maigret may output HTML in the current directory — move it
    for f in report_*.html; do
        [[ -f "$f" ]] && mv "$f" "$outdir/" 2>/dev/null || true
    done 2>/dev/null

    success "Maigret results saved to $outdir/"
}

run_theharvester() {
    if ! $HAS_HARVESTER; then return 0; fi
    local outdir="$REPORT_DIR/theharvester"

    # Run against email's domain or explicit domain
    local search_domain=""
    if [[ -n "$TARGET_DOMAIN" ]]; then
        search_domain="$TARGET_DOMAIN"
    elif [[ -n "$TARGET_EMAIL" && "$TARGET_EMAIL" == *@* ]]; then
        local email_domain="${TARGET_EMAIL#*@}"
        if is_common_email_provider "$email_domain"; then
            info "theHarvester: Email domain '$email_domain' is a common provider. Skipping domain recon."
            return 0
        fi
        search_domain="$email_domain"
    fi

    if [[ -z "$search_domain" ]]; then
        info "theHarvester: No domain or email provided, skipping."
        return 0
    fi

    header "theHarvester — Email & Domain Reconnaissance"
    info "Searching public sources for '$search_domain'..."

    info "Using: $CMD_HARVESTER"
    $CMD_HARVESTER \
        -d "$search_domain" \
        -b google,bing,duckduckgo,yahoo,crtsh,dnsdumpster \
        -l 200 \
        -f "$outdir/harvester_report" \
        2>&1 | tee "$outdir/theharvester.log" || warn "theHarvester encountered errors (see log)"

    # theHarvester generates .xml and .html with the -f flag
    # Convert to JSON if XML exists
    if [[ -f "$outdir/harvester_report.xml" ]]; then
        python3 -c "
import xml.etree.ElementTree as ET
import json, sys

tree = ET.parse('$outdir/harvester_report.xml')
root = tree.getroot()

data = {'emails': [], 'hosts': [], 'ips': []}
for elem in root.iter():
    if elem.tag == 'email' and elem.text:
        data['emails'].append(elem.text.strip())
    elif elem.tag == 'host' and elem.text:
        data['hosts'].append(elem.text.strip())
    elif elem.tag == 'ip' and elem.text:
        data['ips'].append(elem.text.strip())

with open('$outdir/harvester_results.json', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null || info "Could not convert XML to JSON (raw XML still available)"
    fi

    success "theHarvester results saved to $outdir/"
}

run_phoneinfoga() {
    if ! $HAS_PHONEINFOGA || [[ -z "$TARGET_PHONE" ]]; then return 0; fi
    header "PhoneInfoga — Phone Number OSINT"
    info "Scanning '$TARGET_PHONE'..."
    local outdir="$REPORT_DIR/phoneinfoga"

    info "Using: $CMD_PHONEINFOGA"
    $CMD_PHONEINFOGA scan -n "$TARGET_PHONE" \
        2>&1 | tee "$outdir/phoneinfoga.log" || warn "PhoneInfoga encountered errors (see log)"

    # Try JSON output if supported
    $CMD_PHONEINFOGA scan -n "$TARGET_PHONE" -o json \
        > "$outdir/phone_results.json" 2>/dev/null || true

    # If JSON output is empty or failed, create one from log
    if [[ ! -s "$outdir/phone_results.json" ]]; then
        python3 -c "
import json, re

with open('$outdir/phoneinfoga.log') as f:
    log = f.read()

data = {
    'phone_number': '${TARGET_PHONE}',
    'raw_output': log,
    'parsed': {}
}

# Basic parsing of common fields
for line in log.splitlines():
    if ':' in line:
        key, _, val = line.partition(':')
        key = key.strip().lower().replace(' ', '_')
        val = val.strip()
        if key and val:
            data['parsed'][key] = val

with open('$outdir/phone_results.json', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null || true
    fi

    success "PhoneInfoga results saved to $outdir/"
}

run_spiderfoot() {
    if ! $HAS_SPIDERFOOT; then return 0; fi
    local outdir="$REPORT_DIR/spiderfoot"

    header "SpiderFoot — Multi-Source Aggregator"
    info "Using: $CMD_SPIDERFOOT"

    # SpiderFoot's sf.py is primarily a web server. For CLI scanning, we:
    #   1. Start the web server in the background on a random port
    #   2. Run scans via the REST API
    #   3. Collect results and shut down
    # If sfcli.py exists, we can try that directly first.

    local SF_PORT=5099
    local SF_URL="http://127.0.0.1:$SF_PORT"
    local SF_PID=""

    # Try to detect if we have sfcli.py (standalone CLI mode)
    local sf_cli_path=""
    local sf_dir
    sf_dir=$(dirname "$(echo "$CMD_SPIDERFOOT" | awk '{print $NF}')")
    if [[ -f "$sf_dir/sfcli.py" ]]; then
        sf_cli_path="python3 $sf_dir/sfcli.py"
    elif [[ -f "$HOME/spiderfoot/sfcli.py" ]]; then
        sf_cli_path="python3 $HOME/spiderfoot/sfcli.py"
    fi

    if [[ -n "$sf_cli_path" ]]; then
        # ── sfcli.py mode (direct CLI) ────────────────────────────────
        info "Using SpiderFoot CLI: $sf_cli_path"

        local module_list="sfp_dnsresolve,sfp_emailformat,sfp_haveibeenpwned,sfp_social_general"

        if [[ -n "$TARGET_EMAIL" ]]; then
            info "SpiderFoot: Scanning email '$TARGET_EMAIL'..."
            eval $sf_cli_path -s "$TARGET_EMAIL" -t EMAILADDR -m "$module_list" -o json -q \
                > "$outdir/sf_email.json" 2>"$outdir/sf_email.log" \
                || warn "SpiderFoot email scan had errors (see sf_email.log)"
        fi

        if [[ -n "$TARGET_USERNAME" ]]; then
            info "SpiderFoot: Scanning username '$TARGET_USERNAME'..."
            eval $sf_cli_path -s "$TARGET_USERNAME" -t USERNAME -m "$module_list" -o json -q \
                > "$outdir/sf_username.json" 2>"$outdir/sf_username.log" \
                || warn "SpiderFoot username scan had errors (see sf_username.log)"
        fi
    else
        # ── Web server + REST API mode ────────────────────────────────
        info "No sfcli.py found. Starting SpiderFoot web server for API scanning..."
        eval $CMD_SPIDERFOOT -l "127.0.0.1:$SF_PORT" > "$outdir/sf_server.log" 2>&1 &
        SF_PID=$!

        # Wait for server to start (max 15 seconds)
        local waited=0
        while ! curl -s "$SF_URL" > /dev/null 2>&1; do
            sleep 1
            ((waited++))
            if [[ $waited -ge 15 ]]; then
                warn "SpiderFoot server did not start within 15 seconds."
                kill "$SF_PID" 2>/dev/null || true
                fail "SpiderFoot: Could not start web server. Skipping."
                return 0
            fi
        done
        success "SpiderFoot server running on port $SF_PORT"

        # Run scans via REST API
        for target_pair in \
            "email:$TARGET_EMAIL:EMAILADDR" \
            "username:$TARGET_USERNAME:USERNAME" \
            "phone:$TARGET_PHONE:PHONE_NUMBER" \
            "domain:$TARGET_DOMAIN:DOMAIN_NAME"; do

            IFS=: read -r label target_val target_type <<< "$target_pair"
            [[ -z "$target_val" ]] && continue

            info "SpiderFoot: Scanning $label '$target_val'..."

            # Start a scan
            local scan_id
            scan_id=$(curl -s "$SF_URL/startscan" \
                -d "scanname=audit_${label}_${TIMESTAMP}" \
                -d "scantarget=$target_val" \
                -d "usecase=all" \
                2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('scanId',''))" 2>/dev/null) || true

            if [[ -n "$scan_id" ]]; then
                info "  Scan started (ID: $scan_id). Waiting for completion..."
                # Poll for completion (max 120 seconds)
                local poll=0
                while [[ $poll -lt 120 ]]; do
                    local status
                    status=$(curl -s "$SF_URL/scanstatus/$scan_id" 2>/dev/null \
                        | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null) || true
                    [[ "$status" == "FINISHED" || "$status" == "ABORTED" || "$status" == "ERROR-FAILED" ]] && break
                    sleep 3
                    ((poll+=3))
                done

                # Fetch results
                curl -s "$SF_URL/scaneventresultsexport/$scan_id?type=json" \
                    > "$outdir/sf_${label}.json" 2>/dev/null || true
            else
                warn "  Could not start scan for $label."
            fi
        done

        # Shut down the server
        kill "$SF_PID" 2>/dev/null || true
        wait "$SF_PID" 2>/dev/null || true
        info "SpiderFoot server stopped."
    fi

    # Remove empty JSON files
    find "$outdir" -name "sf_*.json" -empty -delete 2>/dev/null || true

    success "SpiderFoot results saved to $outdir/"
}

run_reconng() {
    if ! $HAS_RECONNG; then return 0; fi
    local outdir="$REPORT_DIR/recon-ng"

    # We need at least a domain to make recon-ng useful
    local search_domain=""
    if [[ -n "$TARGET_DOMAIN" ]]; then
        search_domain="$TARGET_DOMAIN"
    elif [[ -n "$TARGET_EMAIL" && "$TARGET_EMAIL" == *@* ]]; then
        local email_domain="${TARGET_EMAIL#*@}"
        # Skip common email providers — their infrastructure isn't useful for personal OSINT
        if is_common_email_provider "$email_domain"; then
            info "Recon-ng: Email domain '$email_domain' is a common provider (not a personal/org domain). Skipping."
            return 0
        fi
        search_domain="$email_domain"
    fi

    if [[ -z "$search_domain" ]]; then
        info "Recon-ng: No domain or email provided, skipping."
        return 0
    fi

    header "Recon-ng — Modular Reconnaissance"
    info "Running automated recon on '$search_domain'..."

    local workspace="audit_${TIMESTAMP//[-:]/_}"
    local rc_file="$outdir/reconng_commands.rc"

    # Build a recon-ng resource file for non-interactive execution
    # NOTE: recon-ng does NOT support # comments — every line is a command
    cat > "$rc_file" <<RCEOF
workspaces create $workspace
marketplace install recon/domains-hosts/hackertarget
marketplace install recon/domains-contacts/whois_pocs
marketplace install recon/hosts-hosts/resolve
marketplace install recon/contacts-contacts/mailtester
marketplace install reporting/json
modules load recon/domains-hosts/hackertarget
options set SOURCE $search_domain
run
modules load recon/domains-contacts/whois_pocs
options set SOURCE $search_domain
run
modules load recon/hosts-hosts/resolve
run
modules load reporting/json
options set FILENAME $outdir/reconng_results.json
run
exit
RCEOF

    info "Using: $CMD_RECONNG"
    $CMD_RECONNG -r "$rc_file" \
        2>&1 | tee "$outdir/reconng.log" || warn "Recon-ng encountered errors (see log)"

    success "Recon-ng results saved to $outdir/"
}

# ── Run All Tools ──────────────────────────────────────────────────────────
header "Starting Digital Footprint Audit"
echo -e "  Target username: ${BOLD}${TARGET_USERNAME:-<not provided>}${NC}"
echo -e "  Target email:    ${BOLD}${TARGET_EMAIL:-<not provided>}${NC}"
echo -e "  Target phone:    ${BOLD}${TARGET_PHONE:-<not provided>}${NC}"
echo -e "  Target domain:   ${BOLD}${TARGET_DOMAIN:-<not provided>}${NC}"
echo -e "  Tor enabled:     ${BOLD}${USE_TOR}${NC}"
echo -e "  Report dir:      ${BOLD}${REPORT_DIR}${NC}"
echo ""

AUDIT_START=$(date +%s)

run_hibp
run_sherlock
run_maigret
run_theharvester
run_phoneinfoga
run_spiderfoot
run_reconng

AUDIT_END=$(date +%s)
AUDIT_DURATION=$((AUDIT_END - AUDIT_START))

# ── Generate HTML Summary Report ──────────────────────────────────────────
header "Generating HTML Summary Report"

generate_html_report() {
    local report_file="$REPORT_DIR/index.html"

    python3 <<'PYEOF'
import json
import os
import glob
from datetime import datetime
from pathlib import Path

report_dir = os.environ.get("REPORT_DIR", "")
timestamp  = os.environ.get("TIMESTAMP", "")
username   = os.environ.get("TARGET_USERNAME", "")
email      = os.environ.get("TARGET_EMAIL", "")
phone      = os.environ.get("TARGET_PHONE", "")
domain     = os.environ.get("TARGET_DOMAIN", "")
duration   = os.environ.get("AUDIT_DURATION", "0")
use_tor    = os.environ.get("USE_TOR", "false")

def load_json_safe(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

def count_files(directory):
    if not os.path.isdir(directory):
        return 0
    return len([f for f in os.listdir(directory) if not f.startswith('.')])

def file_size_human(path):
    if not os.path.isfile(path):
        return "N/A"
    size = os.path.getsize(path)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"

# ── Gather results per tool ──

tool_summaries = []

# HIBP
hibp_dir = os.path.join(report_dir, "hibp")
hibp_summary_path = os.path.join(hibp_dir, "hibp_summary.json")
hibp_data = load_json_safe(hibp_summary_path)
hibp_breaches = 0
hibp_pastes = 0
hibp_found_str = "N/A"
if hibp_data:
    hibp_breaches = hibp_data.get("breach_count", 0)
    hibp_pastes = hibp_data.get("paste_count", 0)
    if hibp_data.get("has_api_key"):
        hibp_found_str = f"{hibp_breaches} breaches, {hibp_pastes} pastes"
    elif isinstance(hibp_data.get("breaches"), list):
        hibp_found_str = f"{hibp_breaches} breaches"
    else:
        hibp_found_str = "Limited (no API key)"
tool_summaries.append({
    "name": "Have I Been Pwned",
    "category": "Breach & Paste Check",
    "dir": "hibp",
    "found": hibp_found_str,
    "files": count_files(hibp_dir),
    "has_data": hibp_data is not None
})

# Sherlock
sherlock_dir = os.path.join(report_dir, "sherlock")
sherlock_json = glob.glob(os.path.join(sherlock_dir, "*.json"))
sherlock_data = None
sherlock_count = 0
if sherlock_json:
    sherlock_data = load_json_safe(sherlock_json[0])
    if isinstance(sherlock_data, dict):
        sherlock_count = sum(1 for v in sherlock_data.values()
                          if isinstance(v, dict) and v.get("status", "").lower() == "claimed")
    elif isinstance(sherlock_data, list):
        sherlock_count = len(sherlock_data)
tool_summaries.append({
    "name": "Sherlock",
    "category": "Username Enumeration",
    "dir": "sherlock",
    "found": sherlock_count if sherlock_data else "N/A",
    "files": count_files(sherlock_dir),
    "has_data": sherlock_data is not None
})

# Maigret
maigret_dir = os.path.join(report_dir, "maigret")
maigret_json = glob.glob(os.path.join(maigret_dir, "*.json"))
maigret_data = None
maigret_count = 0
if maigret_json:
    maigret_data = load_json_safe(maigret_json[0])
    if isinstance(maigret_data, dict):
        maigret_count = len(maigret_data.get("sites", maigret_data))
tool_summaries.append({
    "name": "Maigret",
    "category": "Advanced Username Enumeration",
    "dir": "maigret",
    "found": maigret_count if maigret_data else "N/A",
    "files": count_files(maigret_dir),
    "has_data": maigret_data is not None
})

# theHarvester
harvester_dir = os.path.join(report_dir, "theharvester")
harvester_json_path = os.path.join(harvester_dir, "harvester_results.json")
harvester_data = load_json_safe(harvester_json_path)
harvester_emails = 0
harvester_hosts = 0
if harvester_data:
    harvester_emails = len(harvester_data.get("emails", []))
    harvester_hosts = len(harvester_data.get("hosts", []))
tool_summaries.append({
    "name": "theHarvester",
    "category": "Email & Domain Recon",
    "dir": "theharvester",
    "found": f"{harvester_emails} emails, {harvester_hosts} hosts" if harvester_data else "N/A",
    "files": count_files(harvester_dir),
    "has_data": harvester_data is not None
})

# PhoneInfoga
phone_dir = os.path.join(report_dir, "phoneinfoga")
phone_json_path = os.path.join(phone_dir, "phone_results.json")
phone_data = load_json_safe(phone_json_path)
tool_summaries.append({
    "name": "PhoneInfoga",
    "category": "Phone OSINT",
    "dir": "phoneinfoga",
    "found": "See report" if phone_data else "N/A",
    "files": count_files(phone_dir),
    "has_data": phone_data is not None
})

# SpiderFoot
sf_dir = os.path.join(report_dir, "spiderfoot")
sf_jsons = glob.glob(os.path.join(sf_dir, "sf_*.json"))
sf_total = 0
for jf in sf_jsons:
    d = load_json_safe(jf)
    if isinstance(d, list):
        sf_total += len(d)
tool_summaries.append({
    "name": "SpiderFoot",
    "category": "Multi-Source Aggregator",
    "dir": "spiderfoot",
    "found": f"{sf_total} data points" if sf_jsons else "N/A",
    "files": count_files(sf_dir),
    "has_data": len(sf_jsons) > 0
})

# Recon-ng
reconng_dir = os.path.join(report_dir, "recon-ng")
reconng_json_path = os.path.join(reconng_dir, "reconng_results.json")
reconng_data = load_json_safe(reconng_json_path)
tool_summaries.append({
    "name": "Recon-ng",
    "category": "Modular Recon Framework",
    "dir": "recon-ng",
    "found": f"{len(reconng_data)} records" if isinstance(reconng_data, list) else ("See report" if reconng_data else "N/A"),
    "files": count_files(reconng_dir),
    "has_data": reconng_data is not None
})

# ── Build HTML ──
tools_ran = sum(1 for t in tool_summaries if t["has_data"])
tools_total = len(tool_summaries)

tool_cards_html = ""
for t in tool_summaries:
    badge_classes = "bg-primary/20 text-primary font-medium" if t["has_data"] else "bg-neutral-dark/50 text-neutral-text"
    status_label = "Completed" if t["has_data"] else "Skipped / No Data"
    card_opacity = "" if t["has_data"] else " opacity-60"
    tool_cards_html += f"""
        <div class="bg-neutral-dark/40 rounded-xl p-6 border border-neutral-dark/50 hover:border-primary/50 transition-colors{card_opacity}">
            <div class="flex justify-between items-center mb-2">
                <h3 class="text-white font-bold text-lg">{t['name']}</h3>
                <span class="text-xs font-semibold uppercase px-3 py-1 rounded-full {badge_classes}">{status_label}</span>
            </div>
            <p class="text-neutral-text text-sm mb-4">{t['category']}</p>
            <div class="flex gap-6 mb-4">
                <div>
                    <span class="block text-xs text-neutral-text uppercase tracking-wide">Results</span>
                    <span class="text-white font-semibold">{t['found']}</span>
                </div>
                <div>
                    <span class="block text-xs text-neutral-text uppercase tracking-wide">Files</span>
                    <span class="text-white font-semibold">{t['files']}</span>
                </div>
            </div>
            <a href="{t['dir']}/" class="text-primary hover:text-primary/80 font-medium text-sm transition-colors">View raw output &rarr;</a>
        </div>
    """

duration_min = int(duration) // 60
duration_sec = int(duration) % 60
dur_str = f"{duration_min}m {duration_sec}s" if duration_min > 0 else f"{duration_sec}s"

html = f"""<!DOCTYPE html>
<html class="dark" lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Digital Footprint Audit — {timestamp}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght@100..700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;900&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            darkMode: "class",
            theme: {{
                extend: {{
                    colors: {{
                        "primary": "#f49e0b",
                        "background-light": "#f8f7f5",
                        "background-dark": "#221b10",
                        "neutral-dark": "#393328",
                        "neutral-text": "#baaf9c"
                    }},
                    fontFamily: {{ "display": ["Inter", "sans-serif"] }},
                    borderRadius: {{ "DEFAULT": "0.5rem", "lg": "1rem", "xl": "1.5rem", "full": "9999px" }},
                    boxShadow: {{ "glow": "0 0 20px -5px rgba(244, 158, 11, 0.3)" }}
                }}
            }}
        }}
    </script>
</head>
<body class="bg-background-dark min-h-screen text-slate-100 font-display flex flex-col">
<header class="flex items-center gap-3 border-b border-neutral-dark/50 bg-background-dark px-10 py-4 sticky top-0 z-50">
    <div class="size-8 text-primary">
        <span class="material-symbols-outlined text-[32px]">shield_lock</span>
    </div>
    <h2 class="text-white text-xl font-bold tracking-tight">PrivacyGuard</h2>
</header>
<main class="flex-1 w-full max-w-[1280px] mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <h1 class="text-white text-2xl font-bold mb-1">Digital Footprint Audit Report</h1>
    <p class="text-neutral-text mb-8">Generated {timestamp} &middot; Duration: {dur_str} &middot; Tor: {"Enabled" if use_tor == "true" else "Disabled"}</p>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div class="bg-neutral-dark/40 rounded-xl p-4 border border-neutral-dark/50">
            <div class="text-neutral-text text-xs uppercase tracking-wide">Username</div>
            <div class="text-white font-semibold mt-1 break-all">{username or '—'}</div>
        </div>
        <div class="bg-neutral-dark/40 rounded-xl p-4 border border-neutral-dark/50">
            <div class="text-neutral-text text-xs uppercase tracking-wide">Email</div>
            <div class="text-white font-semibold mt-1 break-all">{email or '—'}</div>
        </div>
        <div class="bg-neutral-dark/40 rounded-xl p-4 border border-neutral-dark/50">
            <div class="text-neutral-text text-xs uppercase tracking-wide">Phone</div>
            <div class="text-white font-semibold mt-1 break-all">{phone or '—'}</div>
        </div>
        <div class="bg-neutral-dark/40 rounded-xl p-4 border border-neutral-dark/50">
            <div class="text-neutral-text text-xs uppercase tracking-wide">Domain</div>
            <div class="text-white font-semibold mt-1 break-all">{domain or '—'}</div>
        </div>
    </div>

    <div class="flex gap-8 mb-8 bg-neutral-dark/40 rounded-xl p-6 border border-neutral-dark/50">
        <div class="text-center">
            <div class="text-3xl font-bold text-primary">{tools_ran}</div>
            <div class="text-neutral-text text-sm">Tools Ran</div>
        </div>
        <div class="text-center">
            <div class="text-3xl font-bold text-primary">{tools_total - tools_ran}</div>
            <div class="text-neutral-text text-sm">Skipped</div>
        </div>
        <div class="text-center">
            <div class="text-3xl font-bold text-primary">{dur_str}</div>
            <div class="text-neutral-text text-sm">Duration</div>
        </div>
    </div>

    <h2 class="text-white text-lg font-bold mb-4 pb-2 border-b border-neutral-dark/50">Tool Results</h2>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {tool_cards_html}
    </div>
</main>
<footer class="mt-12 pt-4 border-t border-neutral-dark/50 text-neutral-text text-sm text-center">
    Digital Footprint Audit Toolkit &middot; For personal use only &middot; Respect all applicable laws and platform terms of service
</footer>
</body>
</html>
"""

output_path = os.path.join(report_dir, "index.html")
with open(output_path, "w") as f:
    f.write(html)

print(f"HTML report generated: {output_path}")
PYEOF
}

# Export environment variables for the Python script
export REPORT_DIR TIMESTAMP TARGET_USERNAME TARGET_EMAIL TARGET_PHONE TARGET_DOMAIN AUDIT_DURATION USE_TOR

generate_html_report

# ── Cleanup ────────────────────────────────────────────────────────────────
if $USE_TOR && [[ -n "${TOR_PID:-}" ]]; then
    kill "$TOR_PID" 2>/dev/null && info "Tor process stopped."
fi

# ── Final Summary ──────────────────────────────────────────────────────────
header "Audit Complete"
echo -e "  Duration:    ${BOLD}${AUDIT_DURATION}s${NC}"
echo -e "  Report dir:  ${BOLD}${REPORT_DIR}${NC}"
echo -e "  HTML report: ${BOLD}${REPORT_DIR}/index.html${NC}"
echo ""
success "Digital footprint audit finished."

info "Opening report in browser..."
open "${REPORT_DIR}/index.html"
