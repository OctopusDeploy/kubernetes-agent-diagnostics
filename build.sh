#!/usr/bin/env bash
#
# Build a single-file executable of octopus-agent-diag using PyInstaller.
#
# Usage:
#   ./build.sh
#
# The output binary lands in ./dist/ and is named for the current platform.
# It will only work on the platform it was built on — you can't cross-compile
# with PyInstaller. For cross-platform releases, use the GitHub Actions
# workflow in .github/workflows/release.yml.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$(uname -s)" in
  Linux*)   PLATFORM="linux" ;;
  Darwin*)  PLATFORM="macos" ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
  *)        PLATFORM="unknown" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$(uname -m)" ;;
esac

NAME="octopus-agent-diag-${PLATFORM}-${ARCH}"
[ "$PLATFORM" = "windows" ] && NAME="${NAME}.exe"

echo "Building for: ${PLATFORM}-${ARCH}"
echo "Output name:  ${NAME}"
echo ""

if [ "${PYINSTALLER_NO_VENV:-0}" != "1" ]; then
  if [ ! -d .build-venv ]; then
    echo "Creating build virtualenv..."
    python3 -m venv .build-venv
  fi
  source .build-venv/bin/activate 2>/dev/null || source .build-venv/Scripts/activate
fi

echo "Installing PyInstaller..."
python3 -m pip install --upgrade pip "pyinstaller==6.19.0" "pyinstaller-hooks-contrib>=2025.1" >/dev/null

echo "Running tests first..."
python3 test_octopus_agent_diag.py

echo ""
echo "Building binary..."
pyinstaller \
  --onefile \
  --name "$NAME" \
  --console \
  --noupx \
  --distpath ./dist \
  --workpath ./build \
  --specpath ./build \
  octopus-agent-diag.py

echo ""
echo "Smoke test: running binary with --help..."
./dist/"$NAME" --help

echo ""
echo "Done. Binary is at: ./dist/${NAME}"
echo ""
echo "Size:"
ls -lh "./dist/${NAME}" | awk '{print "  " $5}'