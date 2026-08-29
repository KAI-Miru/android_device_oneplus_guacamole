# TWRP for the OnePlus 7 Pro family

This is an unofficial ColorOS-focused TWRP device tree for the OnePlus 7 Pro
family (`guacamole`, `guacamoleb`, and `guacamolec`). It builds TWRP
3.7.1_12-0 from the latest pinned Android 12.1 snapshot used by this project.

The current target is the static A/B, recovery-as-boot layout used by the
OnePlus 7 series. It is not a unified tree for the OnePlus 7T series, which
uses dynamic partitions and a separate recovery partition.

## ColorOS support

The recovery keeps the ColorOS H.40 boot ramdisk and layers TWRP onto it. The
H.40 compatibility patch set provides:

- ColorOS 12.1 H.40 and H.40-based port decryption;
- direct Keymaster 4.x metadata-key handling;
- isolated OEM credential verification;
- parent-process Android 12.1 synthetic-password and CE-key installation;
- a private Keystore2 runtime compatible with the retained SDK30 service
  manager; and
- explicit fail-closed handling for malformed `pKMblob` values and unsupported
  key origins.

The supported decryption scope is intentionally limited to Android user 0,
the device owner. Owner decryption was physically validated on an H.40-based
ColorOS 14 port. Secondary Android users, work profiles, System Cloner data,
and other non-owner credential domains are unsupported; recovery deliberately
does not attempt to mutate their keys. Other device variants and ROM bases
still require device testing.

## Repository layout

- `.github/workflows/build-recovery.yml` is the only supported build entry.
- `build/h40/patches/` contains four final patches against pinned upstream
  repositories.
- `build/h40/stock-first/` contains the deterministic CPIO, boot-v2, AVB, and
  independent verification tools.
- `build/h40/package-keystore2-runtime.py` produces the private runtime used by
  the stock-first ramdisk.
- `build/h40/verify-recovery-elf.sh` validates the compiled recovery adapter.
- `prebuilt/h40/` contains the exact H.40 boot components and the small,
  hash-pinned RC2 overlay payloads.
- `recovery/root/` contains only current recovery configuration and TWRP
  resources; stock init, services, and proprietary runtime come from H.40.

The experiment-by-experiment Python transform chain was removed. Its history
remains available in Git, while the maintained branch contains only the final
reproducible state. See [`build/h40/README.md`](build/h40/README.md) for the
pinned commits, patch provenance, and invariants.

## Building

Run the **Guacamole H.40 stock-first TWRP boot** workflow manually, or push a
relevant change to `android-12.1-latest-snapshot`. It compiles the current
adapter, rebuilds the tested stock-first ramdisk, preserves the exact H.40
kernel/DTB/recovery-DTBO, adds and verifies the `boot` AVB footer, and publishes
a complete 96 MiB `boot.img`. The compiled-payload artifact is a diagnostic
failsafe; the stock-first device-test artifact is the testable result.

Use `fastboot boot` for the first test of every new build. Do not flash an
unreviewed image or assume temporary boot is supported by every ColorOS base.

## Status

- Decryption: working for the owner (Android user 0) on the tested H.40-based
  port; non-owner credential domains are formally out of scope.
- ext4, F2FS, and EROFS kernel filesystem support: present on the tested device.
- ADB: working in ordinary recovery use.
- MTP: host enumeration is physically validated. The stock kernel's enforcing
  file-descriptor denial is repaired by one early, hash-pinned live-policy
  rule; an end-to-end transfer on the resulting image remains a release test.
  ADB sideload USB transitions have been exercised; a complete sideload
  transfer remains a release test.
- Haptics, timezone data, cgroup configuration, exact Guacamole CommonDCS, and
  the stock QSEE plugin closure are installed from one checked, manifest-backed
  overlay.
- Stock-init cleanup keeps QSEE explicit-start-only for decryption and disables
  unavailable recovery Wi-Fi, IRSC, and vendor service-manager processes.

This project is unofficial and is not affiliated with TeamWin or OnePlus.
