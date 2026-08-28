#
# Copyright (C) 2019 The LineageOS Project
#
# SPDX-License-Identifier: Apache-2.0
#

PRODUCT_RELEASE_NAME := guacamole

$(call inherit-product, vendor/twrp/config/common.mk)
$(call inherit-product, device/oneplus/guacamole/device.mk)

PRODUCT_NAME := twrp_guacamole
PRODUCT_DEVICE := guacamole
PRODUCT_BRAND := OnePlus
PRODUCT_MODEL := GM1917
PRODUCT_MANUFACTURER := OnePlus

PRODUCT_SYSTEM_NAME := OnePlus7Pro
PRODUCT_SYSTEM_DEVICE := OnePlus7Pro

PRODUCT_AAPT_CONFIG := xxxhdpi
PRODUCT_AAPT_PREF_CONFIG := xxxhdpi
PRODUCT_CHARACTERISTICS := nosdcard

PRODUCT_BUILD_PROP_OVERRIDES += \
    TARGET_DEVICE=OnePlus7Pro \
    TARGET_NAME=OnePlus7Pro
