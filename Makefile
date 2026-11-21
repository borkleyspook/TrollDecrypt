export TARGET := iphone:clang:16.5:14.0
export INSTALL_TARGET_PROCESSES = TrollDecrypt
export THEOS_PACKAGE_SCHEME = rootless
# Dopamine ships an arm64-only libkrw. Building an arm64e slice makes dyld pick
# it on arm64e devices and fail to load libkrw.0.dylib, crashing at launch.
ARCHS = arm64

# FoulDecrypt's kerninfra backend uses libkrw for kernel read/write.
export USE_LIBKRW = 1

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += deps/SSZipArchive
include $(THEOS_MAKE_PATH)/aggregate.mk

APPLICATION_NAME = TrollDecrypt

# App sources (exclude vendored dirs; include ObjC++ for FoulDecrypt.mm).
TrollDecrypt_FILES = $(shell find . -path "*/.theos/*" -prune -o -path "./theos/*" -prune -o -path "./deps/SSZipArchive/*" -prune -o -path "./kerninfra/*" -prune -o \( -name "*.m" -o -name "*.mm" -o -name "*.c" -o -name "*.cpp" \) -print)
# Compile kerninfra directly into the app (static subproject linking was not
# resolving its symbols at app link time). Only the libkrw provider files.
TrollDecrypt_FILES += kerninfra/patchfinder/libdimentio.c \
                     kerninfra/rw_wrap/rw_wrap.cpp \
                     kerninfra/kern_func.cpp \
                     kerninfra/kerninfra.mm \
                     kerninfra/rw_prov/rw_prov_libkrw/rw_prov_libkrw.c

TrollDecrypt_FRAMEWORKS = UIKit CoreGraphics MobileCoreServices Security IOKit
TrollDecrypt_PRIVATE_FRAMEWORKS = AppServerSupport RunningBoardServices
# iOS 14 deployment target + newer libc++ (<format>) + Clang modules makes the
# whole `std` module fail to build. FoulDecrypt does not use std::format.
TrollDecrypt_CFLAGS = -fobjc-arc -fno-modules -D_LIBCPP_DISABLE_AVAILABILITY -DUSE_LIBKRW -I./include -I./deps -I./kerninfra -I./kerninfra/includes
# kerninfra requires C++20; .mm files are built with CCFLAGS as well.
TrollDecrypt_CCFLAGS = -std=c++2a -fno-modules -D_LIBCPP_DISABLE_AVAILABILITY -Wno-deprecated-literal-operator -fobjc-arc -Wno-unused-variable -DUSE_LIBKRW -I./include -I./deps -I./kerninfra -I./kerninfra/includes

# libdimentio needs libcompression. libkrw is now dlopen()ed at runtime
# (see rw_prov_libkrw.c), so there is NO link-time/libkrw load command —
# the .tipa can launch on stock iOS / TrollStore without a jailbreak dylib.
TrollDecrypt_LDFLAGS += -lcompression
TrollDecrypt_LDFLAGS += -F$(THEOS_OBJ_DIR)
TrollDecrypt_LDFLAGS += -Wl,-rpath,@executable_path/Frameworks
TrollDecrypt_EXTRA_FRAMEWORKS += SSZipArchive

TrollDecrypt_OBJCFLAGS = -include shared.h
# The .tipa is installed by TrollStore, which re-signs it and rejects the extra
# FoulDecrypt/debug entitlements at AMFI bootstrap (pid -1, "Launch failed").
# TrollStore apps cannot use kernel R/W on stock iOS anyway, so the .tipa uses
# the original upstream entitlement set; the .deb builds keep the full set.
ifeq ($(PACKAGE_TIPA),1)
TrollDecrypt_CODESIGN_FLAGS = -STrollDecrypt.tipa.entitlements
else
TrollDecrypt_CODESIGN_FLAGS = -STrollDecrypt.entitlements
endif

internal-stage::
	echo "Moving SSZipArchive.framework into app bundle"
	mkdir -p $(THEOS_STAGING_DIR)/Applications/TrollDecrypt.app/Frameworks
	cp -R $(THEOS_STAGING_DIR)/Library/Frameworks/SSZipArchive.framework \
	      $(THEOS_STAGING_DIR)/Applications/TrollDecrypt.app/Frameworks
	rm -rf $(THEOS_STAGING_DIR)/Library

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	echo "compiling Assets.car..."
	$(ECHO_NOTHING)mkdir -p $(THEOS_PROJECT_DIR)/_assetbuild$(ECHO_END)
	$(ECHO_NOTHING)xcrun actool Resources/Assets.xcassets \
		--output-format human-readable-text \
		--notices --warnings \
		--platform iphoneos \
		--minimum-deployment-target 14.0 \
		--app-icon AppIcon \
		--include-all-app-icons \
		--output-partial-info-plist "$(THEOS_PROJECT_DIR)/_assetbuild/assetcatalog.plist" \
		--compile "$(THEOS_STAGING_DIR)/Applications/TrollDecrypt.app"$(ECHO_END)
	$(ECHO_NOTHING)rm -rf "$(THEOS_STAGING_DIR)/Applications/TrollDecrypt.app/Assets.xcassets"$(ECHO_END)

ifeq ($(PACKAGE_TIPA),1)
	echo "Building .tipa"
	$(ECHO_NOTHING)rm -rf Payload$(ECHO_END)
	$(ECHO_NOTHING)rm -f TrollDecrypt.tipa$(ECHO_END)
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Payload$(ECHO_END)
	$(ECHO_NOTHING)cp -a $(THEOS_STAGING_DIR)/Applications/* $(THEOS_STAGING_DIR)/Payload$(ECHO_END)
	$(ECHO_NOTHING)mv $(THEOS_STAGING_DIR)/Payload .$(ECHO_END)
	$(ECHO_NOTHING)zip -q -r TrollDecrypt.tipa Payload$(ECHO_END)
	$(ECHO_NOTHING)rm -rf Payload$(ECHO_END)
endif
