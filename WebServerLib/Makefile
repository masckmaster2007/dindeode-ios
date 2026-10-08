ARCHS := arm64 arm64e
TARGET := iphone:clang:16.5:14.0
PACKAGE_FORMAT = ipa
INSTALL_TARGET_PROCESSES = Geode
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = WebServer

WebServer_FILES = WebServer.m
WebServer_CFLAGS = -fobjc-arc
WebServer_INSTALL_PATH = /Applications/Geode.app/Frameworks

include $(THEOS_MAKE_PATH)/library.mk
