#
# Copyright (C) 2018-2019 The LineageOS Project
#
# SPDX-License-Identifier: Apache-2.0
#

-include device/oneplus/sm8150-common/BoardConfigCommon.mk

BOARD_VENDOR := oneplus
DEVICE_PATH := device/oneplus/guacamole

# The final recovery-as-boot image is rebuilt from the exact H.40 components.
TARGET_COMPILE_WITH_MSM_KERNEL :=
TARGET_FORCE_PREBUILT_KERNEL := true
TARGET_NO_KERNEL := false
TARGET_KERNEL_SOURCE :=
BOARD_KERNEL_IMAGE_NAME := Image
TARGET_PREBUILT_KERNEL := $(DEVICE_PATH)/prebuilt/h40/kernel
TARGET_PREBUILT_DTB := $(DEVICE_PATH)/prebuilt/h40/dtb.img
BOARD_PREBUILT_DTBOIMAGE := $(DEVICE_PATH)/prebuilt/h40/recovery-dtbo.img
BOARD_INCLUDE_RECOVERY_DTBO := true
BOARD_BOOT_HEADER_VERSION := 2
BOARD_KERNEL_PAGESIZE := 4096
BOARD_KERNEL_BASE := 0x00000000
BOARD_KERNEL_OFFSET := 0x00008000
BOARD_RAMDISK_OFFSET := 0x01000000
BOARD_KERNEL_SECOND_OFFSET := 0x00000000
BOARD_KERNEL_TAGS_OFFSET := 0x00000100
BOARD_DTB_OFFSET := 0x01f00000
BOARD_KERNEL_CMDLINE := console=ttyMSM0,115200n8 earlycon=msm_geni_serial,0xa90000 androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 video=vfb:640x400,bpp=32,memsize=3072000 msm_rtb.filter=0x237 service_locator.enable=1 swiotlb=2048 loop.max_part=7 androidboot.usbcontroller=a600000.dwc3 buildvariant=user
BOARD_MKBOOTIMG_ARGS += --base $(BOARD_KERNEL_BASE)
BOARD_MKBOOTIMG_ARGS += --pagesize $(BOARD_KERNEL_PAGESIZE)
BOARD_MKBOOTIMG_ARGS += --ramdisk_offset $(BOARD_RAMDISK_OFFSET)
BOARD_MKBOOTIMG_ARGS += --tags_offset $(BOARD_KERNEL_TAGS_OFFSET)
BOARD_MKBOOTIMG_ARGS += --kernel_offset $(BOARD_KERNEL_OFFSET)
BOARD_MKBOOTIMG_ARGS += --second_offset $(BOARD_KERNEL_SECOND_OFFSET)
BOARD_MKBOOTIMG_ARGS += --dtb_offset $(BOARD_DTB_OFFSET)
BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)
BOARD_MKBOOTIMG_ARGS += --dtb $(TARGET_PREBUILT_DTB)

# Guacamole has physical A/B partitions and runs recovery from boot.
BOARD_BUILD_SYSTEM_ROOT_IMAGE := true
BOARD_BOOTIMAGE_PARTITION_SIZE := 100663296
BOARD_DTBOIMG_PARTITION_SIZE := 25165824
BOARD_USES_RECOVERY_AS_BOOT := true
TARGET_NO_RECOVERY := true
TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery/root/system/etc/recovery.fstab
BOARD_HAS_NO_REAL_SDCARD := true

TARGET_USE_QCOM_BIONIC_OPTIMIZATION := true
TARGET_SCREEN_DENSITY := 560
TARGET_SYSTEM_PROP += $(DEVICE_PATH)/system.prop

# Required values for the sensor Soong namespace inherited from
# sm8150-common. These are Guacamole's panel-space ALS coordinates.
SOONG_CONFIG_ONEPLUS_MSMNILE_SENSORS_ALS_POS_X := 1000
SOONG_CONFIG_ONEPLUS_MSMNILE_SENSORS_ALS_POS_Y := 260

# The full-ROM common tree sets this for SystemUI; recovery does not build it.
TARGET_SURFACEFLINGER_UDFPS_LIB :=

# Compile the reviewed universal H.40 ColorOS decryption adapter.
TW_INCLUDE_OPLUS_H40_DECRYPT := true
