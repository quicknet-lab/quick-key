#!/bin/sh
# Installs `qk`, the Quick-Key management tool, on macOS or Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/quicknet-lab/quick-key/main/install.sh | sh
#
# It puts qk and its Python libraries into their own environment
# (~/.local/share/quick-key) and links the `qk` command into ~/.local/bin.
# On Linux it also installs the smart card service (pcscd) and a udev rule so
# that the key works without root; that part asks for sudo.
#
# Running it again updates qk to the latest release. Options (environment):
#   QK_VERSION=1.0.0   install that release instead of the latest
#   QK_SOURCE=<dir>    install from a local checkout (development)
set -eu

REPO="quicknet-lab/quick-key"
HOME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/quick-key"
BIN_DIR="$HOME/.local/bin"

say() { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

OS=$(uname -s)
case "$OS" in
  Darwin|Linux) ;;
  *) fail "unsupported system $OS: Quick-Key installs on macOS and Linux" ;;
esac

as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# Linux: the smart card service, the libraries pyscard is built against,
# and access to the key for the logged-in user.
if [ "$OS" = Linux ]; then
  say "Installing the smart card service (pcscd) and build tools (sudo)..."
  if command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update -qq
    as_root apt-get install -y -qq pcscd libpcsclite-dev swig gcc python3-dev python3-venv curl
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y -q pcsc-lite pcsc-lite-devel swig gcc python3-devel curl
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -S --needed --noconfirm pcsclite ccid swig gcc python curl
  elif command -v zypper >/dev/null 2>&1; then
    as_root zypper --non-interactive install pcsc-lite pcsc-lite-devel swig gcc python3-devel curl
  else
    say "Unknown package manager: install pcscd, the pcsc-lite headers, swig, gcc and python3-venv yourself."
  fi
  if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl enable --now pcscd.socket >/dev/null 2>&1 || true
  fi
  # FIDO (hidraw) and the ROM download port for `qk flash` (ESP32-S3 USB).
  as_root sh -c 'cat > /etc/udev/rules.d/70-quick-key.rules' <<'RULES'
# Quick-Key: FIDO interface for the logged-in user
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="0001", TAG+="uaccess"
# ESP32-S3 ROM download mode (qk flash)
SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", TAG+="uaccess"
RULES
  as_root udevadm control --reload-rules >/dev/null 2>&1 || true
  as_root udevadm trigger >/dev/null 2>&1 || true
fi

command -v python3 >/dev/null 2>&1 || fail "python3 not found: install Python 3.9 or newer first"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || fail "Python 3.9 or newer is needed (found $(python3 -V 2>&1))"
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || fail "Python's venv module is missing (Debian/Ubuntu: sudo apt install python3-venv)"

# What to install: a local checkout, or a release archive from GitHub.
if [ -n "${QK_SOURCE:-}" ]; then
  SRC=$(cd "$QK_SOURCE" && pwd)
  LABEL="local checkout $SRC"
else
  if [ -n "${QK_VERSION:-}" ]; then
    TAG="v${QK_VERSION#v}"
  else
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])') \
      || fail "cannot find the latest release of $REPO"
  fi
  SRC="https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"
  LABEL="release $TAG"
fi

say "Installing qk ($LABEL) into $HOME_DIR..."
rm -rf "$HOME_DIR/venv"
python3 -m venv "$HOME_DIR/venv"
"$HOME_DIR/venv/bin/python" -m pip install --quiet --upgrade pip
"$HOME_DIR/venv/bin/python" -m pip install --quiet "$SRC"

mkdir -p "$BIN_DIR"
ln -sf "$HOME_DIR/venv/bin/qk" "$BIN_DIR/qk"

say ""
say "Installed: $("$BIN_DIR/qk" --version)"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) RC="~/.zshrc" ;;
      */bash) RC="~/.bashrc" ;;
      *) RC="your shell's startup file" ;;
    esac
    say ""
    say "$BIN_DIR is not on your PATH. Add this line to $RC and open a new terminal:"
    say "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac
say ""
say "Next:"
say "  qk flash      first flash of a new key (hold BOOT while plugging it in)"
say "  qk info       check a key that already runs Quick-Key"
say "  qk tui        terminal UI for everything"
