#
# Copyright (C) 2018-2019 The LineageOS Project
#
# SPDX-License-Identifier: Apache-2.0
#
$(call inherit-product, $(SRC_TARGET_DIR)/product/base.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)

LOCAL_PATH := device/oneplus/guacamole
PRODUCT_PLATFORM := msmnile
PRODUCT_SHIPPING_API_LEVEL := 28

# Physical A/B recovery support without importing the full sm8150 ROM product.
AB_OTA_UPDATER := true
AB_OTA_PARTITIONS += \
    boot \
    dtbo \
    odm \
    system \
    vendor \
    vbmeta

PRODUCT_PACKAGES += \
    android.hardware.boot@1.0-impl:64 \
    android.hardware.boot@1.0-impl.recovery \
    bootctrl.$(PRODUCT_PLATFORM).recovery \
    fastbootd \
    resetprop \
    update_engine \
    update_engine_sideload \
    update_verifier

# Soong namespaces
PRODUCT_SOONG_NAMESPACES += \
    $(LOCAL_PATH)

PRODUCT_SOONG_NAMESPACES += \
    vendor/qcom/opensource/commonsys-intf/display

PRODUCT_PACKAGES += \
    qcom_decrypt \
    qcom_decrypt_fbe

PRODUCT_BUILD_RECOVERY_IMAGE := true

# Crypto
TW_INCLUDE_CRYPTO := true
TW_INCLUDE_CRYPTO_FBE := true
TW_INCLUDE_FBE_METADATA_DECRYPT := true
PLATFORM_SECURITY_PATCH := 2099-12-31
VENDOR_SECURITY_PATCH := 2099-12-31
PLATFORM_VERSION := 99.87.36
PLATFORM_VERSION_LAST_STABLE := $(PLATFORM_VERSION)
BOARD_USES_QCOM_FBE_DECRYPTION := true
TW_USE_FSCRYPT_POLICY := 1

TARGET_RECOVERY_DEVICE_MODULES += libion vendor.display.config@1.0 vendor.display.config@2.0 libdisplayconfig.qti device_manifest.xml system_manifest.xml

# TWRP specific build flags
TW_THEME := portrait_hdpi
RECOVERY_SDCARD_ON_DATA := true
TARGET_RECOVERY_QCOM_RTC_FIX := true
TW_EXCLUDE_DEFAULT_USB_INIT := true
TW_EXTRA_LANGUAGES := true
TW_INCLUDE_NTFS_3G := true
TW_USE_TOOLBOX := true
TW_INCLUDE_RESETPROP := true
TW_INCLUDE_REPACKTOOLS := true
TW_INPUT_BLACKLIST := "hbtp_vm"
TW_BRIGHTNESS_PATH := "/sys/class/backlight/panel0-backlight/brightness"
TW_MAX_BRIGHTNESS := 1023
TW_DEFAULT_BRIGHTNESS := 200
TW_Y_OFFSET := 80
TW_H_OFFSET := -80
TWRP_INCLUDE_LOGCAT := true
TARGET_USES_LOGD := true
TARGET_USES_MKE2FS := true
TW_NO_SCREEN_BLANK := true
TW_USE_LEDS_HAPTICS := true
TW_HAS_EDL_MODE := true
TW_EXCLUDE_PYTHON := true
TW_EXCLUDE_NANO := true
TW_EXCLUDE_BASH := true
TW_FRAMERATE := 60

#Properties
TW_OVERRIDE_SYSTEM_PROPS := \
    "ro.build.fingerprint=ro.system.build.fingerprint;ro.build.version.incremental"

RECOVERY_LIBRARY_SOURCE_FILES += \
    $(TARGET_OUT_SHARED_LIBRARIES)/libion.so \
    $(TARGET_OUT_SYSTEM_EXT_SHARED_LIBRARIES)/vendor.display.config@1.0.so \
    $(TARGET_OUT_SYSTEM_EXT_SHARED_LIBRARIES)/vendor.display.config@2.0.so \
    $(TARGET_OUT_SYSTEM_EXT_SHARED_LIBRARIES)/libdisplayconfig.qti.so

PRODUCT_COPY_FILES += \
    $(OUT_DIR)/target/product/guacamole/system/etc/vintf/manifest.xml:$(TARGET_COPY_OUT_RECOVERY)/root/system/etc/vintf/manifest.xml \
    $(OUT_DIR)/target/product/guacamole/vendor/etc/vintf/manifest.xml:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/etc/vintf/manifest.xml
