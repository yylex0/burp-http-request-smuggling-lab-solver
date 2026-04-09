#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT/src/main/java"
BUILD_DIR="$ROOT/build"
CLASSES_DIR="$BUILD_DIR/classes"
JAR_PATH="${1:-/usr/share/burpsuite/burpsuite.jar}"
OUT_JAR="$BUILD_DIR/http2-tunnel-solver.jar"

rm -rf "$CLASSES_DIR"
mkdir -p "$CLASSES_DIR"

javac -cp "$JAR_PATH" -d "$CLASSES_DIR" $(find "$SRC_DIR" -name '*.java')
jar --create --file "$OUT_JAR" -C "$CLASSES_DIR" .

printf 'Built %s\n' "$OUT_JAR"
