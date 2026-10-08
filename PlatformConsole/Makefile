ARCHS := arm64 arm64e
TARGET := iphone:clang:16.5:14.0
PACKAGE_FORMAT = ipa
INSTALL_TARGET_PROCESSES = Geode
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = PlatformConsole

PlatformConsole_FILES = Window.m ../fishhook/fishhook.c
PlatformConsole_CFLAGS = -fobjc-arc
PlatformConsole_INSTALL_PATH = /Applications/Geode.app/Frameworks

include $(THEOS_MAKE_PATH)/library.mk
