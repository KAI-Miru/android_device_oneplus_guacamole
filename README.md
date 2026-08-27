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

User 0 decryption was physically validated on an H.40-based ColorOS 14 port.
Other device variants and ROM bases still require device testing.

## Repository layout

- `.github/workflows/build-recovery.yml` is the only supported build entry.
- `build/h40/patches/` contains four final patches against pinned upstream
  repositories.
- `build/h40/package-keystore2-runtime.py` produces the private runtime used by
  the hybrid ramdisk.
- `build/h40/verify-recovery-elf.sh` validates the compiled recovery adapter.
- `recovery/root/` contains device ramdisk files and TWRP resources.

The experiment-by-experiment Python transform chain was removed. Its history
remains available in Git, while the maintained branch contains only the final
reproducible state. See [`build/h40/README.md`](build/h40/README.md) for the
pinned commits, patch provenance, and invariants.

## Building

Run the **Guacamole TWRP 12.1 ColorOS** workflow manually, or push a relevant
change to `android-12.1-latest-snapshot`. The workflow always uploads compiled
binaries immediately after a successful link, before later packaging checks.

The produced recovery binary is intended for the established hybrid-ramdisk
repack process. Do not flash an unreviewed image or assume temporary boot is
supported by ColorOS.

## Status

- Decryption: working for user 0 on the tested H.40-based port.
- ext4, F2FS, and EROFS kernel filesystem support: present on the tested device.
- ADB: working in ordinary recovery use.
- MTP and ADB sideload: known USB gadget integration issue; not yet fixed.

This project is unofficial and is not affiliated with TeamWin or OnePlus.

