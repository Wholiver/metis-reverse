#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p dist

# 1. Create unminified clean bundle
cat src/crypto_util.js src/session_manager.js src/index.js > dist/bundle.clean.js

# 2. Obfuscate aggressively with terser (mangled toplevel, mangled properties, 3 compression passes, no sourcemap)
npx terser dist/bundle.clean.js \
  --compress passes=3 \
  --mangle toplevel=true \
  --mangle-props regex=/^_/ \
  -o dist/bundle.min.js

echo "Successfully built dist/bundle.clean.js and dist/bundle.min.js"
