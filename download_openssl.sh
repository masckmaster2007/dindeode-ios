#!/bin/bash
if [ -d "$THEOS/lib/OpenSSL.framework" ]; then
	echo "OpenSSL.framework already exists in $THEOS/lib"
else
	echo "OpenSSL.framework not found. Downloading..."

	curl -L "https://github.com/revolut-mobile/openssl-binary/releases/download/3.3.3001/OpenSSL_with_arm64e.xcframework.zip" -o "OpenSSL.xcframework.zip"

	unzip -q "OpenSSL.xcframework.zip" -d .

	mkdir -p "$THEOS/lib"
	mv "OpenSSL.xcframework/ios-arm64_arm64e/OpenSSL.framework" "$THEOS/lib"

	rm -f "OpenSSL.xcframework.zip"
	rm -rf "OpenSSL.xcframework"

	echo "OpenSSL.framework has been installed to $THEOS/lib"
fi

if [ ! -d "./Resources/Frameworks/OpenSSL.framework" ]; then
    rsync -av --exclude 'Headers' "$THEOS/lib/OpenSSL.framework" "./Resources/Frameworks"
fi
