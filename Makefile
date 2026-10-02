export ARCHS := arm64
PACKAGE_FORMAT = ipa
TARGET := iphone:clang:latest:14.0:13.5
#TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = Geode

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = Geode

ifeq ($(TROLLSTORE),1)
Geode_CODESIGN_FLAGS = -Sts-entitlements.xml
THEOS_PACKAGE_NAME=trollstore
else
Geode_CODESIGN_FLAGS = -Sentitlements.xml
endif

Geode_FILES = $(wildcard src/*.m) \
    $(wildcard src/*.mm) \
    $(wildcard src/views/*.m) \
    $(wildcard src/components/*.m) \
    $(wildcard src/LCUtils/*.m) \
    $(wildcard src/components/clearsword/*.c) \
    $(wildcard src/components/clearsword/*.m) \
    $(wildcard src/components/clearsword/taskrop/*.m) \
    fishhook/fishhook.c \
    $(wildcard MSColorPicker/MSColorPicker/*.m) \
    $(wildcard GCDWebServer/GCDWebServer/*/*.m)

Geode_FRAMEWORKS = UIKit CoreGraphics Security IOSurface

Geode_CFLAGS = -fobjc-arc \
    -Iinclude \
    -IGCDWebServer/GCDWebServer/Core \
    -IGCDWebServer/GCDWebServer/Requests \
    -IGCDWebServer/GCDWebServer/Responses \
    -Wno-error=deprecated-declarations \
    -Wno-unused-variable \
    -Wno-unused-function

Geode_CXXFLAGS = -std=c++17 -I./include
Geode_LIBRARIES = archive

$(APPLICATION_NAME)_LDFLAGS = -e _GeodeMain -rpath @loader_path/Frameworks

include $(THEOS_MAKE_PATH)/application.mk
SUBPROJECTS += ZSign TweakLoader WebServerLib PlatformConsole TestJITLess EnterpriseLoader CAHighFPS
include $(THEOS_MAKE_PATH)/aggregate.mk

after-package::
ifeq ($(TROLLSTORE),1)
	@mv "$(THEOS_PACKAGE_DIR)/trollstore_$(THEOS_PACKAGE_BASE_VERSION).ipa" "$(THEOS_PACKAGE_DIR)/be.dimisaio.dindem_$(THEOS_PACKAGE_BASE_VERSION).tipa"
endif

before-all::
	@sh ./download_openssl.sh