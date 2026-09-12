TARGET := iphone:clang:latest:16.0
INSTALL_TARGET_PROCESSES :=

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := DetectionMonitor
DetectionMonitor_FILES := Tweak.xm
DetectionMonitor_CFLAGS := -fobjc-arc -Wall -Wextra
DetectionMonitor_FRAMEWORKS := Foundation
DetectionMonitor_LIBRARIES := substrate
DetectionMonitor_CXXFLAGS := -std=c++17

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "sbreload"
