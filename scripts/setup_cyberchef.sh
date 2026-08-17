#!/usr/bin/env bash
# Installs the CyberChef node bridge used by the cyberchef MCP tools.
#
#   1. Ensures the CyberChef submodule is checked out at the pinned tag
#   2. Installs CyberChef npm dependencies
#   3. Patches `assert {type: "json"}` -> `with {type: "json"}` for Node 22+
#   4. Regenerates the operation index/config for the node API
#   5. Verifies the bridge responds to a ping
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRIDGE_DIR="$ROOT/vendor/cyberchef-bridge"
CHEF_DIR="$ROOT/vendor/cyberchef"
BRIDGE="$BRIDGE_DIR/bridge.mjs"

if ! command -v node >/dev/null 2>&1; then
    echo "error: node is required (https://nodejs.org)" >&2
    exit 1
fi

echo "[1/6] Ensuring CyberChef submodule (v10.24.0)..."
git -C "$ROOT" submodule update --init --recursive
git -C "$CHEF_DIR" checkout v10.24.0

echo "[2/6] Installing CyberChef dependencies..."
npm ci --prefix "$CHEF_DIR"

echo "[3/6] Patching assert {type: \"json\"} -> with {type: \"json\"} (Node 22+)..."
for file in \
    src/core/lib/Magic.mjs \
    src/core/Recipe.mjs \
    src/node/api.mjs \
    src/core/ChefWorker.js \
    src/web/index.js; do
    target="$CHEF_DIR/$file"
    if grep -q 'assert {type: "json"}' "$target"; then
        sed -i 's/assert {type: "json"}/with {type: "json"}/g' "$target"
        echo "  patched $file"
    fi
done

echo "[4/6] Regenerating operation index and config..."
node --no-warnings --no-deprecation "$CHEF_DIR/src/core/config/scripts/generateOpsIndex.mjs"
node --no-warnings --no-deprecation "$CHEF_DIR/src/core/config/scripts/generateConfig.mjs"
node --no-warnings --no-deprecation "$CHEF_DIR/src/node/config/scripts/generateNodeIndex.mjs"

echo "[5/6] Verifying bridge..."
if printf '%s\n' '{"id":1,"method":"ping"}' | node "$BRIDGE" | grep -q '"ok":true'; then
    echo "  bridge responds OK"
else
    echo "error: bridge ping failed" >&2
    exit 1
fi

echo "[6/6] CyberChef bridge ready. Run: .venv/bin/python -m pytest tests/"
