#!/usr/bin/env python3
"""Bridge Android 12.1 libbinder to the retained H.40 SDK30 servicemanager.

ColorOS H.40 keeps Android 11's raw Binder stability values on kernel Binder
(0, 3, 12, and 63).  Android 12.1 normally serializes a packed Category whose
low byte is wire version 1, so the stock servicemanager rejects registrations
such as SYSTEM (0x0c000001), while the private runtime rejects stock replies as
wire version 0.

Keep Android 12.1's Category representation inside libbinder and for Binder
RPC.  Translate only at the kernel-Binder Parcel boundary:

* flatten writes the raw SDK30 level;
* unflatten recognizes only the four complete raw values and converts them to
  the current packed Category before the existing full validation runs; and
* every other input is passed through unchanged, preserving version-1 input
  compatibility and avoiding truncation of malformed 32-bit values.

This is intentionally an ABI-neutral, one-file source transform.  It does not
change BBinder/BpBinder object layout or replace the stock servicemanager.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PINNED_FRAMEWORKS_NATIVE_COMMIT = "89c808424fbce9e40c0d4e0d1920b3c64a191b7f"
PINNED_PARCEL_GIT_BLOB = "617708f3d44bf8253c27d29283208a0b119ae062"
TARGET = Path("libs/binder/Parcel.cpp")
MARKER = "H40_RECOVERY_BINDER_STABILITY_V0_V52"


FLATTEN_OLD = """status_t Parcel::finishFlattenBinder(const sp<IBinder>& binder)
{
    internal::Stability::tryMarkCompilationUnit(binder.get());
    auto category = internal::Stability::getCategory(binder.get());
    return writeInt32(category.repr());
}
"""

FLATTEN_NEW = """status_t Parcel::finishFlattenBinder(const sp<IBinder>& binder)
{
    internal::Stability::tryMarkCompilationUnit(binder.get());
    auto category = internal::Stability::getCategory(binder.get());
    return writeInt32(isForRpc() ? category.repr()
                                 : static_cast<int32_t>(category.level));
}
"""

UNFLATTEN_OLD = """status_t Parcel::finishUnflattenBinder(
    const sp<IBinder>& binder, sp<IBinder>* out) const
{
    int32_t stability;
    status_t status = readInt32(&stability);
    if (status != OK) return status;

    status = internal::Stability::setRepr(binder.get(), stability, true /*log*/);
    if (status != OK) return status;

    *out = binder;
    return OK;
}
"""

UNFLATTEN_NEW = f"""namespace {{

constexpr char kH40BinderStabilityV0Marker[] = "{MARKER}";
constexpr uint8_t kH40BinderWireFormatVersion = 1;

bool IsH40LegacyKernelBinderStability(int32_t stability) {{
    // These are Android 11's complete raw stability values.  Keep the exact
    // int32 comparison outside the enum cast so malformed high bits cannot be
    // truncated into a valid private Stability::Level.
    switch (stability) {{
        case 0:   // UNDECLARED
        case 3:   // VENDOR
        case 12:  // SYSTEM
        case 63:  // VINTF
            return true;
        default:
            return false;
    }}
}}

}}  // namespace

status_t Parcel::finishUnflattenBinder(
    const sp<IBinder>& binder, sp<IBinder>* out) const
{{
    int32_t stability;
    status_t status = readInt32(&stability);
    if (status != OK) return status;

    if (!isForRpc() && IsH40LegacyKernelBinderStability(stability)) {{
        static std::atomic<bool> bridge_logged(false);
        if (!bridge_logged.exchange(true, std::memory_order_relaxed)) {{
            ALOGI("%s: translating SDK30 kernel-Binder stability values",
                  kH40BinderStabilityV0Marker);
        }}
        // Reproduce Category::currentFromLevel() locally.  That helper is
        // declared inline in Stability.h but defined only in Stability.cpp,
        // so calling it from Parcel.cpp triggers -Wundefined-inline.
        const internal::Stability::Category category{{
                .version = kH40BinderWireFormatVersion,
                .reserved = {{0}},
                .level = static_cast<internal::Stability::Level>(stability),
        }};
        stability = category.repr();
    }}

    status = internal::Stability::setRepr(binder.get(), stability, true /*log*/);
    if (status != OK) return status;

    *out = binder;
    return OK;
}}
"""


class TransformError(RuntimeError):
    """The pinned source or a V5.2 invariant did not match."""


def git_blob(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise TransformError(f"{label}: expected one exact source anchor, found {count}")
    return text.replace(old, new, 1)


def validate(text: str) -> None:
    required = (
        MARKER,
        "return writeInt32(isForRpc() ? category.repr()",
        ": static_cast<int32_t>(category.level));",
        "if (!isForRpc() && IsH40LegacyKernelBinderStability(stability))",
        "case 0:   // UNDECLARED",
        "case 3:   // VENDOR",
        "case 12:  // SYSTEM",
        "case 63:  // VINTF",
        "constexpr uint8_t kH40BinderWireFormatVersion = 1;",
        ".version = kH40BinderWireFormatVersion",
        ".reserved = {0}",
        "static_cast<internal::Stability::Level>(stability)",
        "internal::Stability::setRepr(binder.get(), stability, true /*log*/)",
    )
    for token in required:
        if token not in text:
            raise TransformError(f"missing V5.2 invariant: {token}")

    if text.count(MARKER) != 1:
        raise TransformError("V5.2 marker must occur exactly once")
    if "return writeInt32(category.repr());" in text:
        raise TransformError("unconditional packed Category serialization survived")
    if "Stability::Category::currentFromLevel(" in text:
        raise TransformError("undefined-inline Category helper call survived")
    if text.count("IsH40LegacyKernelBinderStability") != 2:
        raise TransformError("legacy stability predicate must have one definition and one call")

    # The exact-value switch must precede the enum cast.  This prevents a
    # malformed high-bit int32 from truncating into a valid uint8_t Level.
    switch_pos = text.index("switch (stability)")
    cast_pos = text.index("static_cast<internal::Stability::Level>(stability)")
    if switch_pos >= cast_pos:
        raise TransformError("raw stability must be validated before enum conversion")

    # Binder RPC must retain the Android 12.1 packed representation in both
    # directions; only kernel Binder gets the H.40 translation.
    flatten_start = text.index("status_t Parcel::finishFlattenBinder")
    flatten_end = text.index("status_t Parcel::finishUnflattenBinder", flatten_start)
    flatten = text[flatten_start:flatten_end]
    if "isForRpc() ? category.repr()" not in flatten:
        raise TransformError("Binder RPC packed flatten path is missing")
    unflatten_start = flatten_end
    unflatten_end = text.index("static constexpr inline int schedPolicyMask", unflatten_start)
    unflatten = text[unflatten_start:unflatten_end]
    if "!isForRpc()" not in unflatten:
        raise TransformError("Binder RPC unflatten guard is missing")


def transform(native_root: Path) -> Path:
    target = native_root / TARGET
    if not target.is_file():
        raise TransformError(f"missing pinned target: {target}")

    original = target.read_bytes()
    text = original.decode("utf-8")
    if MARKER in text:
        validate(text)
        print(f"V5.2 Binder bridge already present: {target}")
        return target

    actual_blob = git_blob(original)
    if actual_blob != PINNED_PARCEL_GIT_BLOB:
        raise TransformError(
            f"unexpected Parcel.cpp git blob {actual_blob}; "
            f"expected {PINNED_PARCEL_GIT_BLOB} from {PINNED_FRAMEWORKS_NATIVE_COMMIT}"
        )

    updated = replace_once(text, FLATTEN_OLD, FLATTEN_NEW, "flatten bridge")
    updated = replace_once(updated, UNFLATTEN_OLD, UNFLATTEN_NEW, "unflatten bridge")
    validate(updated)
    target.write_text(updated, encoding="utf-8", newline="\n")

    print(f"patched {target}")
    print(f"base_git_blob={actual_blob}")
    print(f"result_sha256={hashlib.sha256(updated.encode()).hexdigest()}")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("frameworks_native", type=Path)
    args = parser.parse_args()
    transform(args.frameworks_native.resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TransformError as error:
        raise SystemExit(f"V5.2 Binder transform failed: {error}") from error
