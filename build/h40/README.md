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
bf99fa1bcd3c9c73fd94d0a554898df9711332b2dea87e8566a01f6f740be394  vold.patch
0cd8269b20fa83fcfff42eee02a6a0be8a0d8a74bb2ee9baba8449dc26441523  security.patch
bc1398b4901403a33d7ad80a171ba95974ba2c938558bc10b69ff350e8850895  binder.patch
```

The original patch set was exported by successful GitHub Actions run
[`33031812198`](https://github.com/KAI-Miru/android_device_oneplus_guacamole/actions/runs/33031812198).
The recovery patch was subsequently regenerated from the same pinned commit to
support both an already-mounted dynamic system and the static by-name system
layout. All four patches apply cleanly with
`git apply --check --whitespace=error-all` to their pinned commits.

## Responsibilities

- `recovery.patch` adds the H.40 adapter, isolated credential helper, user-0
  dispatch, parent-process modern decryption handoff, and universal installed
  system identity discovery for static and dynamic partition layouts.
- `vold.patch` implements HIDL Keymaster compatibility, constructor-safe state,
  fail-closed `pKMblob` handling, explicit fscrypt key mode, and the guarded CE
  key installation path.
- `security.patch` grants only the recovery-domain Keystore2 operations needed
  for locksettings namespace 103.
- `binder.patch` bridges SDK30 raw stability values on kernel Binder while
  preserving Android 12.1's packed representation for Binder RPC.
- `package-keystore2-runtime.py` copies the exact private dependency closure,
  changes only Keystore2's interpreter, and emits merge-only context shims.
- `apply-recovery-fixes.py` removes conflicting stock-init USB ownership and
  stale mounts/waits, then installs the MTP, cgroup, haptics, and QSEE payloads
  required by the hybrid ramdisk.

## Maintenance rules

1. Never edit a patch without updating its SHA-256 here and in the workflow.
2. Never move an upstream commit without regenerating and reviewing all patches.
3. Preserve the stock ColorOS policy and `/system/lib64/libbinder.so`.
4. Keep the Keystore2 service disabled; the adapter starts it only during an
   accepted credential flow.
5. Preserve the exact-H.40 OEM library hash gate and fail closed on ambiguity.
6. A successful compile must upload its binaries before optional packaging or
   diagnostics can fail.

Version numbers belong in Git history and release notes, not filenames. Future
fixes should update the appropriate final patch instead of adding another
transform layer.
