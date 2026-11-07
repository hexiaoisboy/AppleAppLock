#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="AppLock"
rm -rf build "dist/$APP_NAME.app"
mkdir -p build "dist/$APP_NAME.app/Contents/MacOS" "dist/$APP_NAME.app/Contents/Resources"

COMMON_FLAGS=(
  -O -swift-version 5 -parse-as-library
  -framework AppKit -framework SwiftUI -framework Combine
  -framework CryptoKit -framework Security -framework UniformTypeIdentifiers
)

swiftc "${COMMON_FLAGS[@]}" -target arm64-apple-macos15.0 \
  -o "build/$APP_NAME-arm64" AppLock.swift
swiftc "${COMMON_FLAGS[@]}" -target x86_64-apple-macos15.0 \
  -o "build/$APP_NAME-x86_64" AppLock.swift
lipo -create "build/$APP_NAME-arm64" "build/$APP_NAME-x86_64" -output "build/$APP_NAME"

cp "build/$APP_NAME" "dist/$APP_NAME.app/Contents/MacOS/$APP_NAME"
cp Info.plist "dist/$APP_NAME.app/Contents/Info.plist"

ICON_SRC="AppIcon-1024.png"
if [ -f "$ICON_SRC" ]; then
  rm -rf build/AppIcon.iconset
  mkdir -p build/AppIcon.iconset
  for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$ICON_SRC" \
      --out "build/AppIcon.iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$ICON_SRC" \
      --out "build/AppIcon.iconset/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns build/AppIcon.iconset -o build/AppIcon.icns
  cp build/AppIcon.icns "dist/$APP_NAME.app/Contents/Resources/AppIcon.icns"
fi

codesign --force --sign - "dist/$APP_NAME.app"

echo "构建完成: $(pwd)/dist/$APP_NAME.app"
