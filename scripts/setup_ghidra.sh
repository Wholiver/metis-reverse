#!/usr/bin/env bash
set -e

METIS_ENV="$HOME/.local/share/metis_env"
ZIP_FILE="$METIS_ENV/ghidra_11.3.1.zip"
TARGET_DIR="$METIS_ENV/ghidra_11.3.1_PUBLIC"

export JAVA_HOME="$METIS_ENV/jdk-21/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

if [ -d "$TARGET_DIR" ] && [ -f "$TARGET_DIR/support/analyzeHeadless" ]; then
    echo "Ghidra already extracted at $TARGET_DIR"
    "$TARGET_DIR/support/analyzeHeadless" 2>&1 | head -n 3 || true
    exit 0
fi

if [ -f "$ZIP_FILE" ]; then
    echo "Extracting Ghidra 11.3.1..."
    unzip -q -o "$ZIP_FILE" -d "$METIS_ENV"
    echo "Extraction complete."
    "$TARGET_DIR/support/analyzeHeadless" 2>&1 | head -n 3 || true
else
    echo "Ghidra zip not found at $ZIP_FILE yet."
fi
