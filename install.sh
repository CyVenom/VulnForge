#!/usr/bin/env bash
# =============================================================================
# VulnForge Installer
# Supports: Ubuntu, Debian, Kali Linux, Windows WSL
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

PYTHON_MIN="3.10"
VENV_DIR=".venv"
REQUIREMENTS="requirements.txt"

echo -e "${BOLD}${RED}"
cat << 'BANNER'
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
BANNER
echo -e "${NC}"
echo -e "${BOLD}VulnForge Installer — Authorized Security Testing Framework${NC}"
echo ""

# --------------------------------------------------------------------------
# Detect environment
# --------------------------------------------------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif uname -r | grep -qi microsoft; then
        echo "wsl"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
IS_WSL=false
if uname -r 2>/dev/null | grep -qi microsoft; then
    IS_WSL=true
    info "Windows Subsystem for Linux (WSL) detected."
fi

info "Detected OS: ${OS}"

# --------------------------------------------------------------------------
# System package installation
# --------------------------------------------------------------------------
install_system_deps() {
    case "$OS" in
        ubuntu|debian|kali)
            info "Updating package lists..."
            sudo apt-get update -qq

            info "Installing system dependencies..."
            sudo apt-get install -y -qq \
                nmap \
                masscan \
                python3 \
                python3-pip \
                python3-venv \
                python3-dev \
                libssl-dev \
                libffi-dev \
                build-essential \
                libxml2-dev \
                libxslt1-dev \
                libcairo2 \
                libpango-1.0-0 \
                libpangocairo-1.0-0 \
                libgdk-pixbuf2.0-0 \
                libffi-dev \
                git \
                curl \
                2>/dev/null || warn "Some packages failed — continuing."
            ;;
        fedora|rhel|centos)
            sudo dnf install -y nmap masscan python3 python3-pip python3-devel \
                openssl-devel libffi-devel gcc 2>/dev/null || warn "Some packages failed."
            ;;
        arch)
            sudo pacman -Sy --noconfirm nmap masscan python python-pip 2>/dev/null || true
            ;;
        *)
            warn "Unknown OS '${OS}' — skipping apt/dnf install. Ensure nmap is in PATH."
            ;;
    esac
}

# --------------------------------------------------------------------------
# Python version check
# --------------------------------------------------------------------------
check_python() {
    local python_cmd
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local version
            version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            local major minor
            IFS='.' read -r major minor <<< "$version"
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    error "Python ${PYTHON_MIN}+ not found. Please install it first."
}

# --------------------------------------------------------------------------
# Virtual environment setup
# --------------------------------------------------------------------------
setup_venv() {
    local python_cmd="$1"
    if [ -d "$VENV_DIR" ]; then
        warn "Virtual environment ${VENV_DIR} already exists — reusing."
    else
        info "Creating virtual environment in ${VENV_DIR}..."
        "$python_cmd" -m venv "$VENV_DIR"
        success "Virtual environment created."
    fi

    # Activate
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate" 2>/dev/null \
        || source "${VENV_DIR}/Scripts/activate" 2>/dev/null \
        || error "Could not activate venv — try: source ${VENV_DIR}/bin/activate"

    info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel -q
}

# --------------------------------------------------------------------------
# Python dependencies
# --------------------------------------------------------------------------
install_python_deps() {
    if [ ! -f "$REQUIREMENTS" ]; then
        error "${REQUIREMENTS} not found. Run this script from the VulnForge directory."
    fi

    info "Installing Python dependencies..."
    pip install -r "$REQUIREMENTS" -q --no-warn-script-location
    success "Python dependencies installed."
}

# --------------------------------------------------------------------------
# Directory structure
# --------------------------------------------------------------------------
create_dirs() {
    info "Creating directory structure..."
    mkdir -p reports logs plugins
    success "Directories ready: reports/ logs/ plugins/"
}

# --------------------------------------------------------------------------
# Verify nmap
# --------------------------------------------------------------------------
verify_nmap() {
    if command -v nmap &>/dev/null; then
        local ver
        ver=$(nmap --version | head -1)
        success "nmap found: ${ver}"
    else
        warn "nmap not found in PATH. Port scanning will fall back to basic TCP scan."
        warn "Install nmap: sudo apt install nmap  OR  https://nmap.org/download.html"
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    # Ensure we're in the VulnForge directory
    if [ ! -f "vulnforge.py" ]; then
        error "vulnforge.py not found. Please run this script from the VulnForge directory."
    fi

    install_system_deps
    local PYTHON_CMD
    PYTHON_CMD=$(check_python)
    success "Using Python: ${PYTHON_CMD} ($(${PYTHON_CMD} --version))"

    setup_venv "$PYTHON_CMD"
    install_python_deps
    create_dirs
    verify_nmap

    echo ""
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    echo -e "${GREEN}${BOLD}  VulnForge installation complete!${NC}"
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    echo ""
    echo -e "  ${CYAN}Activate venv:${NC}  source ${VENV_DIR}/bin/activate"
    echo -e "  ${CYAN}Run a scan:${NC}     python vulnforge.py scanme.nmap.org"
    echo -e "  ${CYAN}Help:${NC}           python vulnforge.py --help"
    echo ""
}

main "$@"
