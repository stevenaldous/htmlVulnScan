#!/usr/bin/env bash
# =============================================================================
#  install.sh — One-time setup for nmap_vuln_scan.sh
#
#  Creates:
#    /scripts/nmap_vuln_scan.sh  — the scanner (executable by all users via sudo)
#    /scans/                     — world-readable report storage
#
#  Usage:
#    sudo bash install.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Please run as root: sudo bash install.sh"

SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nmap_vuln_scan.sh"
SCRIPT_DEST="/scripts/nmap_vuln_scan.sh"
SCANS_DIR="/scans"

# ── /scripts ──────────────────────────────────────────────────────────────────
info "Creating /scripts directory…"
mkdir -p /scripts
# Owned by root, readable+executable by everyone, writable only by root
chmod 755 /scripts
chown root:root /scripts

# Copy (or overwrite) the scanner script
[[ -f "$SCRIPT_SRC" ]] || die "nmap_vuln_scan.sh not found next to install.sh (expected: $SCRIPT_SRC)"
cp "$SCRIPT_SRC" "$SCRIPT_DEST"
chmod 755 "$SCRIPT_DEST"   # rwxr-xr-x — all users can read/execute
chown root:root "$SCRIPT_DEST"
success "Installed $SCRIPT_DEST"

# ── /scans ────────────────────────────────────────────────────────────────────
info "Creating /scans directory…"
mkdir -p "$SCANS_DIR"
# rwxrwxr-x — root owns it; members of group 'scans' can write;
# everyone else can read and browse in a file manager
groupadd -f scans
chown root:scans "$SCANS_DIR"
chmod 775 "$SCANS_DIR"     # group-writable so sudoed scans land here
# Sticky bit prevents users from deleting each other's scan folders
chmod +t "$SCANS_DIR"
success "Created $SCANS_DIR  (mode: $(stat -c '%A' "$SCANS_DIR"))"

# ── Optional: add current SUDO_USER to the scans group ────────────────────────
if [[ -n "${SUDO_USER:-}" ]]; then
  usermod -aG scans "$SUDO_USER"
  success "Added '$SUDO_USER' to the 'scans' group (re-login to take effect)"
fi

# ── Dependency check ──────────────────────────────────────────────────────────
echo ""
info "Checking dependencies…"
if command -v nmap &>/dev/null; then
  success "nmap found: $(nmap --version | head -1)"
else
  echo -e "${RED}[MISSING]${RESET} nmap is not installed."
  echo "         Install with: apt install nmap"
fi

if command -v python3 &>/dev/null; then
  success "python3 found: $(python3 --version)"
else
  echo -e "${RED}[MISSING]${RESET} python3 is not installed."
  echo "         Install with: apt install python3"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
success "Installation complete!"
echo ""
echo -e "  Run a scan:   ${CYAN}sudo /scripts/nmap_vuln_scan.sh <target>${RESET}"
echo -e "  View reports: ${CYAN}file:///scans${RESET}  (browse in any file manager)"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
