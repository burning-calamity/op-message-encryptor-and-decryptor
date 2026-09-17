#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENBOARD_DIR="$ROOT_DIR/openboard-encrypting"
RUN_ANDROID_BUILD=false

if [[ "${1:-}" == "--android" ]]; then
    RUN_ANDROID_BUILD=true
elif [[ $# -ne 0 ]]; then
    echo "usage: $0 [--android]" >&2
    exit 2
fi

if [[ ! -f "$OPENBOARD_DIR/gradlew" ]]; then
    echo "OpenBoard submodule is missing; run: git submodule update --init --recursive" >&2
    exit 1
fi

echo "== Python syntax and tests =="
python -m compileall -q \
    "$ROOT_DIR/encripter.py" \
    "$ROOT_DIR/ars_occultandarum_litterarum" \
    "$ROOT_DIR/apk/v1/encripter.py" \
    "$ROOT_DIR/tests"
(cd "$ROOT_DIR" && python -m pytest -q)

echo "== OpenBoard script syntax =="
bash -n "$OPENBOARD_DIR/gradlew" "$OPENBOARD_DIR/app/src/main/jni/run-tests.sh"

echo "== OpenBoard cipher compilation =="
classes_dir="$(mktemp -d)"
trap 'rm -rf "$classes_dir"' EXIT
javac -Xlint:all -d "$classes_dir" \
    "$OPENBOARD_DIR"/app/src/main/java/org/dslul/openboard/inputmethod/latin/ciphers/*.java

if [[ "$RUN_ANDROID_BUILD" == true ]]; then
    echo "== OpenBoard Android build and lint =="
    (cd "$OPENBOARD_DIR" && ./gradlew --no-daemon assembleDebug lint)
else
    echo "Skipping the Android SDK build; pass --android to enable it."
fi
