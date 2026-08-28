# H.40 compatibility patch set

This directory is the complete source-side compatibility layer for the
ColorOS H.40 hybrid recovery. It replaces the former chronological V4.x/V5.x
transform stack.

## Pinned upstream inputs

| Repository | Commit | Patch |
| --- | --- | --- |
| `TeamWin/android_bootable_recovery` | `5c3d206a5eeb3d446bcda8248a405a4b278bab5c` | `patches/recovery.patch` |
| `TeamWin/android_system_vold` | `a164ba05c5fef288059774a776b2e6e1119957cf` | `patches/vold.patch` |
| `TeamWin/android_system_security` | `14737db1429b8eebc15568bc748b2cd79ccad5c2` | `patches/security.patch` |
| `AOSP/frameworks/native` | `89c808424fbce9e40c0d4e0d1920b3c64a191b7f` | `patches/binder.patch` |

Patch SHA-256 values:

```text
c196b8bd497039ae9ec7587212d47e0fe105867982b4ee06a02bbe30507b464e  recovery.patch
a79e9a761ded5640f4413c48191fee3bc511e7eb15f316cbac8aa0f6b264298d  recovery-no-credential.patch
034b64defe6e7ff10b91e8948e0f2ac19da3a7f434bb03e9e6351fba283f2cda  vold.patch
ee2472e7bb81f320d2fd473cedadc3db2f475fd15551beb3c4948d73522e7199  vold-no-credential.patch
0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523  security.patch
bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895  binder.patch
```

The original patch set was exported by successful GitHub Actions run
[`33031812198`](https://github.com/KAI-Miru/android_device_oneplus_guacamole/actions/runs/33031812198).
The recovery patch was subsequently regenerated from the same pinned commit to
support both an already-mounted dynamic system and the static by-name system
layout. All six patches apply cleanly in their documented order with
`git apply --check --whitespace=error-all` to their pinned commits.

## Responsibilities

- `recovery.patch` plus `recovery-no-credential.patch` add the H.40 adapter,
  isolated credential helper, user-0 dispatch, parent-process credentialed and
  no-credential handoffs, and universal installed-system identity discovery
  for static and dynamic partition layouts. The supplement avoids the stock
  `fscrypt_init_user0_ce()` crash and requires a parent-process CE proof.
- `vold.patch` plus `vold-no-credential.patch` are shared byte-for-byte with
  Hotdog. They implement HIDL
  Keymaster compatibility, constructor-safe state, fail-closed `pKMblob`
  handling, explicit fscrypt key mode, guarded direct-AES credentialed CE, and
  a read-only Keymaster-backed no-credential CE installer.
- `security.patch` grants only the recovery-domain Keystore2 operations needed
  for locksettings namespace 103.
- `binder.patch` bridges SDK30 raw stability values on kernel Binder while
  preserving Android 12.1's packed representation for Binder RPC.
- `package-keystore2-runtime.py` copies the exact private dependency closure,
  changes only Keystore2's interpreter, and emits merge-only context shims.
- `apply-recovery-fixes.py` removes conflicting stock-init USB ownership and
  stale waits, replaces the stock mount tables with the audited Guacamole
  tables, suppresses unavailable stock services, then installs the MTP,
  cgroup, timezone, haptics, and QSEE payloads required by the hybrid ramdisk.
- `stock-first/build_full_boot.sh` starts from the checked H.40 ramdisk, builds
  the exact private TWRP dependency closure, applies the tested RC2 fixes and
  Keystore2 runtime, restores the H.40 boot-v2 framing, and verifies the final
  AVB-padded `boot.img` independently.
- `prebuilt/h40/manifest.json` pins every stock component and deliberate binary
  overlay. The 75,024-byte CommonDCS library is the tested H.40 `system_ext`
  copy (`e9ea4b62...`), not the different H.40 ODM/Hotdog copy.

## Release support policy

- Decryption support is owner-only: Android user 0 is supported and physically
  validated. Secondary users, work profiles, System Cloner data, and other
  non-owner credential domains are intentionally unsupported.
- The current-only CE installer accepts exactly two read-only schemas:
  `encrypted_key` plus `version`, or those files plus a literal `none`
  stretching marker and a nonzero 16 KiB `secdiscardable`. Unknown, mixed,
  linked, malformed, or changing schemas fail closed without mutation.
- `qseecomd` remains disabled by default and is started only by the accepted
  credential flow. Its proprietary binary hard-codes the listener table, so
  the matching stock `libspl.so` and `libops.so` plugins are retained instead
  of binary-patching the security daemon. They are mirrored into
  `/system/lib64` because mounting the real `/vendor` hides recovery's embedded
  `/vendor/lib64` before `qseecomd` starts.
- The recovery-fix transformer removes the premature health-service start and
  legacy cpuacct/cpuset commands. It also makes `gatekeeperd` explicit-start
  only and disables unavailable `vndservicemanager`, `irsc_util`, and recovery
  Wi-Fi services.
- `aw8697_rtp.bin` is the 72,000-byte Guacamole vendor firmware blob (SHA-256
  `36438cefa7206dac9ef150b613418d5912c3eb69ed4e0084798602985b43470d`).
- `80ms_RTP_170Hz.bin` is the 1,979-byte OnePlus AW8697 170 Hz firmware blob
  (SHA-256
  `98fb90d52ddf8ce2e5825d057c67be0237d78e6c6df439c2d8fbceff136ab4ff`).
  It is embedded with the other AW8697 firmware so touch vibration does not
  depend on mounting the installed ROM's `/vendor`.
- `op2` is the device's real 256 MiB ext4 cache partition and is intentionally
  mounted only as `/cache`. The nonexistent `special_preload`, `opporeserve`,
  and external-SD entries are omitted; USB OTG is exposed once as
  `/usbstorage`.
- System has one canonical fstab entry. TWRP probes its current filesystem, so
  both ext4 and EROFS installations remain mountable without duplicate System
  rows in the Mount page.
- Ramdisk configuration is UTF-8/LF only. `.gitattributes` normalizes supported
  text formats and CI rejects any remaining carriage-return bytes.

## Maintenance rules

1. Never edit a patch without updating its SHA-256 here and in the workflow.
2. Never move an upstream commit without regenerating and reviewing all patches.
3. Preserve the stock ColorOS policy, stock recovery, kernel, DTB, recovery
   DTBO, and `/system/lib64/libbinder.so`.
4. Keep the Keystore2 service disabled; the adapter starts it only during an
   accepted credential flow.
5. Preserve both exact-H.40 OEM hash gates and fail closed on ambiguity:
   decryption blobs come from the stock ramdisk and CommonDCS comes from the
   pinned H.40 `system_ext` overlay.
6. A successful compile must upload its binaries before optional packaging or
   diagnostics can fail.
7. Do not expand decryption beyond Android user 0 without separate physical
   validation and an explicit support-policy change.
8. Treat the compiled Android boot output as an intermediate only. Release and
   device-test artifacts must pass the complete stock-first verification.

Version numbers belong in Git history and release notes, not filenames. Future
fixes should update the appropriate final patch instead of adding another
transform layer.
