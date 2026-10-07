#!/bin/bash

# Run clang-tidy on source files
# Requires a compile_commands.json in the build directory

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${ROOT_DIR}/build"

# Find clang-tidy
CLANG_TIDY=""
for name in clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15; do
    if command -v "$name" &> /dev/null; then
        CLANG_TIDY="$name"
        break
    fi
done

# Check Homebrew LLVM paths on macOS
if [ -z "$CLANG_TIDY" ]; then
    for path in /opt/homebrew/opt/llvm/bin/clang-tidy /usr/local/opt/llvm/bin/clang-tidy; do
        if [ -x "$path" ]; then
            CLANG_TIDY="$path"
            break
        fi
    done
fi

if [ -z "$CLANG_TIDY" ]; then
    echo "Error: clang-tidy not found"
    exit 1
fi

# Ensure compile_commands.json exists
if [ ! -f "${BUILD_DIR}/compile_commands.json" ]; then
    echo "Generating compile_commands.json..."
    cmake -B "$BUILD_DIR" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$ROOT_DIR"
fi

# Find all source files, excluding build/ and src/esp/ directories
SOURCES=$(find "$ROOT_DIR/src" \
    -path '*/build' -prune -o \
    -path '*/src/esp' -prune -o \
    \( -name '*.cpp' -o -name '*.c' \) -print 2>/dev/null || true)

if [ -z "$SOURCES" ]; then
    echo "No source files found"
    exit 0
fi

# Parse arguments
FIX_FLAG=""
if [ "$1" = "--fix" ]; then
    FIX_FLAG="--fix"
fi

# A non-Apple clang-tidy (e.g. Homebrew LLVM) does not know where the macOS SDK keeps the
# standard library headers, so point it there. If xcrun cannot report an SDK path, clang-tidy
# runs without a sysroot
EXTRA_ARGS=()
if [ "$(uname)" = "Darwin" ] && command -v xcrun &> /dev/null; then
    SDK_PATH="$(xcrun --show-sdk-path 2>/dev/null || true)"
    if [ -n "$SDK_PATH" ]; then
        EXTRA_ARGS=(--extra-arg=-isysroot "--extra-arg=$SDK_PATH")
    else
        echo "Note: no macOS SDK found (xcrun --show-sdk-path failed), running clang-tidy without a sysroot" >&2
    fi
fi

echo "Running clang-tidy..."
if [ -n "$FIX_FLAG" ]; then
    # Serial, so two files that include the same header cannot apply conflicting fixes to it
    $CLANG_TIDY -p "$BUILD_DIR" $FIX_FLAG "${EXTRA_ARGS[@]}" $SOURCES
else
    # One process per file across every core; xargs exits non-zero if any file fails
    JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
    printf '%s\n' $SOURCES | xargs -P "$JOBS" -n 1 "$CLANG_TIDY" -p "$BUILD_DIR" "${EXTRA_ARGS[@]}"
fi
