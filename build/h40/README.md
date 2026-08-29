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
ccd7231d66b3599203c8fde236ec4f9ca90bab3118239d67f5547f3c0032dbe5  recovery.patch
491f78e08921259749cc1333191ba12c0a73d86bf504822f1f445056870a24f5  recovery-no-credential.patch
91033f9fb2238c54bd88e0cb50f8d684e8ffcd3c3491ca9dba635d0688931b0f  recovery-password-probe.patch
214fb48a0372dfef489235ab693024a1a15dac7d676398883a51dfc781d53192  recovery-setup-de-ce-guard.patch
b1664fe7e29b500310e4e4fb6a3f108ddcbe399d50ce66497d58c3fc627b07dd  vold.patch
18df63112bac56871e54b6d37e6e185eb5ec8bee179ba39c2ed9bfbe66fd256f  vold-no-credential.patch
0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523  security.patch
bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895  binder.patch
```

The original patch set was exported by successful GitHub Actions run
[`33031812198`](https://github.com/KAI-Miru/android_device_oneplus_guacamole/actions/runs/33031812198).
The recovery patch was subsequently regenerated from the same pinned commit to
support both an already-mounted dynamic system and the static by-name system
layout. All eight patches apply cleanly in their documented order with
`git apply --check --whitespace=error-all` to their pinned commits.

## Responsibilities

- `recovery.patch`, `recovery-no-credential.patch`,
  `recovery-password-probe.patch`, and `recovery-setup-de-ce-guard.patch` add
  the H.40 adapter,
  isolated credential helper, user-0 dispatch, parent-process credentialed and
  no-credential handoffs, and universal installed-system identity discovery
  for static and dynamic partition layouts. The supplement avoids the stock
  `fscrypt_init_user0_ce()` crash, bypasses the stock password-type ABI when no
  `.pwd` protector exists, and requires a parent-process CE proof.
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
  the exact private TWRP dependency closure and complete Bash/Nano/ZIP feature
  bundles, restores generated `/file_contexts`, shell configuration, `/bin`,
  and the fixed `mke2fs` configuration path, applies the tested RC2 fixes and
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
  Wi-Fi services. The stock Phoenix recovery start and service are removed
  because their executable is not present in the ramdisk.
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
