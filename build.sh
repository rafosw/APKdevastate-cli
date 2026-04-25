#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# build.sh – Configure & build APKdevastate CLI
#
# Usage:
#

#   chmod +x build.sh
#   ./build.sh --release    # Release (optimised)
#   ./build.sh --clean      # Clean build directory first
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
BUILD_TYPE="Debug"
CLEAN=0

for arg in "$@"; do
    case "$arg" in
        --release) BUILD_TYPE="Release" ;;
        --clean)   CLEAN=1 ;;
        --help|-h)
            echo "Usage: $0 [--release] [--clean]"
            exit 0
            ;;
    esac
done

echo -e "\033[96m[*]\033[0m Checking dependencies…"
MISSING=()
for tool in cmake pkg-config g++ openssl; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
pkg-config --exists libzip 2>/dev/null || MISSING+=("libzip-dev")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo -e "\033[91m[-]\033[0m Missing dependencies: ${MISSING[*]}"
    echo ""
    echo "Install on Debian/Kali:"
    echo "  sudo apt install cmake g++ pkg-config libssl-dev libzip-dev"
    echo ""
    echo "Install on Arch:"
    echo "  sudo pacman -S cmake gcc pkgconf openssl libzip"
    echo ""
    echo "Install on Fedora:"
    echo "  sudo dnf install cmake gcc-c++ pkgconf-pkg-config openssl-devel libzip-devel"
    exit 1
fi
echo -e "\033[92m[+]\033[0m All dependencies present"

NLOHMANN_HEADER="${SCRIPT_DIR}/include/nlohmann/json.hpp"
if ! pkg-config --exists nlohmann_json 2>/dev/null && [ ! -f "$NLOHMANN_HEADER" ]; then
    echo -e "\033[93m[!]\033[0m nlohmann/json not found – downloading single-header…"
    mkdir -p "$(dirname "$NLOHMANN_HEADER")"
    curl -fsSL \
        "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp" \
        -o "$NLOHMANN_HEADER"
    echo -e "\033[92m[+]\033[0m Downloaded to include/nlohmann/json.hpp"
fi

if [[ $CLEAN -eq 1 ]] && [[ -d "$BUILD_DIR" ]]; then
    echo -e "\033[96m[*]\033[0m Cleaning build directory…"
    rm -rf "$BUILD_DIR"
fi

echo -e "\033[96m[*]\033[0m Configuring (${BUILD_TYPE})…"
cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" \
      -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      2>&1 | grep -E 'error|warning|APKdevastate|OpenSSL|libzip' || true

JOBS=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
echo -e "\033[96m[*]\033[0m Building with ${JOBS} parallel jobs…"
cmake --build "$BUILD_DIR" --parallel "$JOBS"

BINARY="${SCRIPT_DIR}/apkdevastate"
if [[ -f "$BINARY" ]]; then
    echo ""
    echo -e "\033[92m[+]\033[0m Build successful!"
    echo -e "\033[92m[+]\033[0m Binary: \033[1m${BINARY}\033[0m"
    echo ""
    echo "Run:  ./apkdevastate <file.apk>"
    echo "      ./apkdevastate --help"
else
    echo -e "\033[91m[-]\033[0m Build failed – binary not found"
    exit 1
fi
