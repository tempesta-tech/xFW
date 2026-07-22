#!/bin/bash

set -euo pipefail

PACKAGE_DIR="./PACKAGE"
DEBIAN_SOURCE="./pkg"

rm -rf "$PACKAGE_DIR"
mkdir -p $PACKAGE_DIR
cp -R "${DEBIAN_SOURCE}/." "${PACKAGE_DIR}"
cd "$PACKAGE_DIR" && dpkg-buildpackage -us -uc -b
