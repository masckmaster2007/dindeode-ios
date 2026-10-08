#!/bin/bash

set -e

BASE_URL="https://github.com/revolut-mobile/openssl-binary/releases/download/3.3.3001"
THEOS_LIB="$THEOS/lib"

echo "Downloading OpenSSL frameworks..."

rm -rf OpenSSL.xcframework OpenSSL_arm64e
rm -f OpenSSL.xcframework.zip OpenSSL_with_arm64e.xcframework.zip

curl -sL "$BASE_URL/OpenSSL.xcframework.zip" \
    -o OpenSSL.xcframework.zip

curl -sL "$BASE_URL/OpenSSL_with_arm64e.xcframework.zip" \
    -o OpenSSL_with_arm64e.xcframework.zip

unzip -oq OpenSSL.xcframework.zip

mkdir -p OpenSSL_arm64e
unzip -oq OpenSSL_with_arm64e.xcframework.zip -d OpenSSL_arm64e

mkdir -p "$THEOS_LIB"

rm -rf "$THEOS_LIB/OpenSSL.framework"
rm -rf "$THEOS_LIB/OpenSSL_arm64e.framework"

cp -R \
    "OpenSSL.xcframework/ios-arm64/OpenSSL.framework" \
    "$THEOS_LIB/OpenSSL.framework"

cp -R \
    "OpenSSL_arm64e/OpenSSL.xcframework/ios-arm64_arm64e/OpenSSL.framework" \
    "$THEOS_LIB/OpenSSL_arm64e.framework"

rm -f OpenSSL.xcframework.zip OpenSSL_with_arm64e.xcframework.zip
rm -rf OpenSSL.xcframework OpenSSL_arm64e

mkdir -p "./Resources/Frameworks"

rm -rf "./Resources/Frameworks/OpenSSL.framework"
rm -rf "./Resources/Frameworks/OpenSSL_arm64e.framework"

rsync -a \
    --exclude 'Headers' \
    "$THEOS_LIB/OpenSSL.framework/" \
    "./Resources/Frameworks/OpenSSL.framework/"

rsync -a \
    --exclude 'Headers' \
    "$THEOS_LIB/OpenSSL_arm64e.framework/" \
    "./Resources/Frameworks/OpenSSL_arm64e.framework/"

echo "OpenSSL frameworks installed successfully."
