#!/bin/sh
# DepSec installer — downloads the correct binary for your platform
set -e

REPO="chocksy/depsec"
INSTALL_DIR="${DEPSEC_INSTALL_DIR:-$HOME/.local/bin}"

# Parse args
VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    *) echo "Unknown option: $1"; exit 1;;
  esac
done

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux) OS="unknown-linux-musl" ;;
  darwin) OS="apple-darwin" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARGET="${ARCH}-${OS}"

# Get latest version if not specified
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')
  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version"
    exit 1
  fi
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/depsec-${TARGET}.tar.gz"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

echo "Installing depsec ${VERSION} for ${TARGET}..."

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download binary
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/depsec.tar.gz"
curl -fsSL "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt"

# Verify checksum
cd "$TMP_DIR"
EXPECTED=$(grep "depsec-${TARGET}.tar.gz" checksums.txt | awk '{print $1}')
if [ -n "$EXPECTED" ]; then
  if command -v sha256sum > /dev/null 2>&1; then
    ACTUAL=$(sha256sum depsec.tar.gz | awk '{print $1}')
  elif command -v shasum > /dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 depsec.tar.gz | awk '{print $1}')
  else
    echo "Warning: no sha256sum or shasum found — skipping checksum verification"
    ACTUAL="$EXPECTED"
  fi

  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Actual:   $ACTUAL"
    exit 1
  fi
  echo "Checksum verified."
else
  echo "Warning: could not find checksum for ${TARGET}"
fi

# Extract and install
tar xzf depsec.tar.gz
mv depsec "$INSTALL_DIR/depsec"
chmod +x "$INSTALL_DIR/depsec"

echo "Installed depsec to $INSTALL_DIR/depsec"

# Check if install dir is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -q "^${INSTALL_DIR}$"; then
  echo ""
  echo "Add $INSTALL_DIR to your PATH:"
  echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo "Run 'depsec scan .' to get started."
