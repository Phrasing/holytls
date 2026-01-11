#!/bin/bash

# HolyTLS Linux Build Script
# Requires: CMake, Ninja, Go (for BoringSSL), GCC/Clang

set -e

BUILD_DIR="build"
BUILD_TYPE="Release"
GENERATOR="Ninja"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

show_help() {
    echo ""
    echo "HolyTLS Linux Build Script"
    echo ""
    echo "Usage: ./build.sh [options]"
    echo ""
    echo "Options:"
    echo "  release    Build Release configuration (default)"
    echo "  debug      Build Debug configuration"
    echo "  clean      Remove build directory"
    echo "  rebuild    Clean and rebuild"
    echo "  --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./build.sh              Build Release"
    echo "  ./build.sh debug        Build Debug"
    echo "  ./build.sh clean        Clean build directory"
    echo "  ./build.sh rebuild      Clean and rebuild Release"
    echo ""
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        release)
            BUILD_TYPE="Release"
            shift
            ;;
        clean)
            echo "Cleaning build directory..."
            rm -rf "$BUILD_DIR"
            echo "Done."
            exit 0
            ;;
        rebuild)
            echo "Cleaning build directory..."
            rm -rf "$BUILD_DIR"
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}ERROR: $1 not found${NC}"
        echo "$2"
        exit 1
    fi
}

check_tool "cmake" "Please install CMake: sudo apt install cmake"
check_tool "ninja" "Please install Ninja: sudo apt install ninja-build"
check_tool "go" "Go is required for BoringSSL: https://go.dev/dl/"

# Create build directory
mkdir -p "$BUILD_DIR"

# Configure
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Configuring HolyTLS ($BUILD_TYPE)${NC}"
echo -e "${GREEN}Generator: $GENERATOR${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

cmake -B "$BUILD_DIR" -G "$GENERATOR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

# Build
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Building HolyTLS ($BUILD_TYPE)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

cmake --build "$BUILD_DIR" --parallel "$(nproc)"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Binaries are in: $BUILD_DIR/"
echo ""
echo "Examples:"
echo "  $BUILD_DIR/fingerprint_check"
echo "  $BUILD_DIR/async_example"
echo ""
echo "Tests:"
echo "  $BUILD_DIR/tests/test_fingerprint"
echo "  $BUILD_DIR/tests/stress/stress_test"
echo ""
