#!/bin/bash

set -e

BASE_URL="https://github.com/revolut-mobile/openssl-binary/releases/download/3.3.3001"
THEOS_LIB="$THEOS/lib"

if [ -d "$THEOS_LIB/OpenSSL.framework" ] && [ -d "$THEOS_LIB/OpenSSL_arm64e.framework" ]; then
    echo "OpenSSL frameworks already exist in $THEOS_LIB"
else
    echo "Downloading OpenSSL frameworks..."

    rm -rf OpenSSL.xcframework OpenSSL_with_arm64e.xcframework
    rm -f OpenSSL.xcframework.zip OpenSSL_with_arm64e.xcframework.zip

    curl -L "$BASE_URL/OpenSSL.xcframework.zip" \
        -o OpenSSL.xcframework.zip

    curl -L "$BASE_URL/OpenSSL_with_arm64e.xcframework.zip" \
        -o OpenSSL_with_arm64e.xcframework.zip

    unzip -q OpenSSL.xcframework.zip
    unzip -q OpenSSL_with_arm64e.xcframework.zip

    mkdir -p "$THEOS_LIB"

    rm -rf "$THEOS_LIB/OpenSSL.framework"
    rm -rf "$THEOS_LIB/OpenSSL_arm64e.framework"

    cp -R \
        "OpenSSL.xcframework/ios-arm64/OpenSSL.framework" \
        "$THEOS_LIB/OpenSSL.framework"

    cp -R \
        "OpenSSL_with_arm64e.xcframework/ios-arm64_arm64e/OpenSSL.framework" \
        "$THEOS_LIB/OpenSSL_arm64e.framework"

    rm -f OpenSSL.xcframework.zip OpenSSL_with_arm64e.xcframework.zip
    rm -rf OpenSSL.xcframework OpenSSL_with_arm64e.xcframework

    echo "OpenSSL frameworks installed to $THEOS_LIB"
fi

if [ ! -d "./Resources/Frameworks/OpenSSL.framework" ]; then
    rsync -av \
        --exclude 'Headers' \
        "$THEOS_LIB/OpenSSL.framework" \
        "./Resources/Frameworks"
fi

if [ ! -d "./Resources/Frameworks/OpenSSL_arm64e.framework" ]; then
    rsync -av \
        --exclude 'Headers' \
        "$THEOS_LIB/OpenSSL_arm64e.framework" \
        "./Resources/Frameworks"
fi

echo
echo "arm64:"
lipo -info "$THEOS_LIB/OpenSSL.framework/OpenSSL"

echo
echo "arm64e:"
lipo -info "$THEOS_LIB/OpenSSL_arm64e.framework/OpenSSL"
