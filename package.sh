#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="AppLock"
./build.sh

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)"
STAGE="build/dmg"
DMG="dist/${APP_NAME}-${VERSION}.dmg"

rm -rf "$STAGE" "$DMG"
mkdir -p "$STAGE"
cp -R "dist/$APP_NAME.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

hdiutil create -volname "程序锁" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

echo "安装包: $(pwd)/$DMG"
