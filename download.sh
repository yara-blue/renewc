#!/usr/bin/env sh

set -e

ARCH=$(uname -m)
OS=$(uname)

case $OS in
    Linux)
        case $ARCH in
            # arm*) TARGET="arm-linux-gnueabihf" ;;
            # armv7*) TARGET="armv7-linux-gnueabihf" ;;
            aarch64) TARGET="aarch64" ;;
            x86_64) TARGET="x64" ;;
            *) echo "Error: Unsupported architecture: $ARCH, please open an issue"; exit 1 ;;
        esac
    ;;
    *)
        echo "Error: We currently only supports Linux."
        exit 1
    ;;
esac

echo "Detected architecture: $TARGET"

REPO="https://github.com/dvdsk/renewc"
LATEST_RELEASE_URL="$REPO/releases/latest/download/renewc_$TARGET"

echo "Downloading..."
curl -sL "$LATEST_RELEASE_URL" -o "renewc"
chmod +x renewc

echo ""
echo "Finished!"
echo "You can now run renewc from this directory, use: ./renewc help" 
echo ""
echo "[Note]: if you want to use renewc from anywhere try moving it to"
echo "~.local/bin it is usually in PATH"
