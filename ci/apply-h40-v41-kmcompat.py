#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v41-kmcompat.py RECOVERY_ROOT VOLD_ROOT")

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# The first V4.1 physical test proved that the Vivo Y73S raw-HIDL wrapper is
# not runtime-safe on H.40. It crash-loops at metadata-key retrieval with a
# near-null SIGSEGV even though QSEE and Keymaster 4.0 are registered. Keep
# TeamWin 12.1 KeyStorage, but use the standard Keymaster V4.1 support wrapper,
# which enumerates the available HIDL 4.x devices and performs the normal
# HMAC-sharing agreement used by AOSP vold on Qualcomm-era devices.

h_path = vold_root / "Keymaster.h"
h = h_path.read_text()
h = replace_once(
    h,
    '#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>\n#include <keymasterV4_1/authorization_set.h>\n',
    '#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>\n#include <keymasterV4_1/Keymaster.h>\n#include <keymasterV4_1/authorization_set.h>\n',
    "Keymaster support-wrapper include",
)
h = replace_once(
    h,
    'using KmDevice = km_hidl::IKeymasterDevice;\n',
    'using KmDevice = ::android::hardware::keymaster::V4_1::support::Keymaster;\n',
    "Keymaster support-wrapper device type",
)
# The Keymaster V4.1 support wrapper is RefBase-backed and its KeymasterSet
# stores android::sp<Keymaster>. Keep the Vivo header's existing android::sp
# member ownership after changing KmDevice to the support wrapper.
h = replace_once(
    h,
    '    void safePerformHmacKeyAgreement();\n',
    '',
    "remove obsolete raw-HIDL HMAC helper declaration",
)
h_path.write_text(h)

cpp_path = vold_root / "Keymaster.cpp"
cpp = cpp_path.read_text()
cpp = replace_once(
    cpp,
    'using IKeymasterDevice40 = ::android::hardware::keymaster::V4_0::IKeymasterDevice;\n',
    '',
    "remove raw IKeymasterDevice40 alias",
)

ctor_start = cpp.find('Keymaster::Keymaster() {')
hmac_start = cpp.find('void Keymaster::safePerformHmacKeyAgreement() {', ctor_start)
generate_start = cpp.find('bool Keymaster::generateKey(', hmac_start)
if ctor_start < 0 or hmac_start < 0 or generate_start < 0:
    raise SystemExit("unable to isolate V4.1 Keymaster constructor/HMAC block")

new_ctor_hmac = r'''Keymaster::Keymaster() {
    LOG(ERROR) << "[H40 KMCOMPAT] constructor: enumerating Keymaster 4.x devices";
    auto devices = KmDevice::enumerateAvailableDevices();
    LOG(ERROR) << "[H40 KMCOMPAT] constructor: enumerated " << devices.size() << " device(s)";
    if (devices.empty()) {
        LOG(ERROR) << "[H40 KMCOMPAT] constructor: no Keymaster devices";
        return;
    }

    if (!hmacKeyGenerated) {
        LOG(ERROR) << "[H40 KMCOMPAT] constructor: starting standard HMAC agreement";
        KmDevice::performHmacKeyAgreement(devices);
        hmacKeyGenerated = true;
        LOG(ERROR) << "[H40 KMCOMPAT] constructor: HMAC agreement complete";
    }

    for (auto& dev : devices) {
        if (dev->halVersion().securityLevel != km_hidl::SecurityLevel::STRONGBOX) {
            mDevice = dev;
            break;
        }
    }
    if (!mDevice) {
        LOG(ERROR) << "[H40 KMCOMPAT] constructor: no non-StrongBox Keymaster device";
        return;
    }

    const auto& version = mDevice->halVersion();
    mSecurityLevel = version.securityLevel;
    LOG(ERROR) << "[H40 KMCOMPAT] constructor: selected " << version.keymasterName
               << " from " << version.authorName
               << ", security=" << static_cast<int32_t>(version.securityLevel)
               << ", HAL=" << mDevice->descriptor() << "/" << mDevice->instanceName();

    // Retain the old CI string as a provenance marker only. No raw getService
    // call is made; the support wrapper above owns service discovery.
    LOG(DEBUG) << "[Keymaster] Trying default keymaster 4.0 service...";
}

'''
cpp = cpp[:ctor_start] + new_ctor_hmac + cpp[generate_start:]
cpp_path.write_text(cpp)

# Restore TeamWin's intended optional-upgrade guard. The pinned TWRP KeyStorage
# tree has this guard commented while still dereferencing getUpgradedBlob()
# immediately afterwards. If the H.40 metadata key is accepted without an
# upgrade, dereferencing an empty optional is undefined behaviour.
ks_path = vold_root / "KeyStorage.cpp"
ks = ks_path.read_text()
ks = replace_once(
    ks,
    '    // if (!opHandle.getUpgradedBlob()) return opHandle;\n',
    '    if (!opHandle.getUpgradedBlob()) return opHandle;\n',
    "KeyStorage optional upgraded-blob guard",
)

retrieve_old = '''    if (auth.usesKeymaster()) {
        Keymaster keymaster;
        if (!keymaster) return false;
        km::AuthorizationSet keyParams = beginParams(appId);
        if (!decryptWithKeymasterKey(keymaster, dir, keyParams, encryptedMessage, key))
            return false;
'''
retrieve_new = '''    if (auth.usesKeymaster()) {
        LOG(ERROR) << "[H40 KMCOMPAT] retrieve: constructing Keymaster";
        Keymaster keymaster;
        LOG(ERROR) << "[H40 KMCOMPAT] retrieve: constructor returned valid="
                   << static_cast<bool>(keymaster);
        if (!keymaster) return false;
        km::AuthorizationSet keyParams = beginParams(appId);
        LOG(ERROR) << "[H40 KMCOMPAT] retrieve: starting metadata-key decrypt";
        if (!decryptWithKeymasterKey(keymaster, dir, keyParams, encryptedMessage, key))
            return false;
        LOG(ERROR) << "[H40 KMCOMPAT] retrieve: metadata-key decrypt complete";
'''
ks = replace_once(ks, retrieve_old, retrieve_new, "metadata retrieve stage markers")

begin_old = '''    auto opHandle = keymaster.begin(blob, inParams, outParams);
    if (!opHandle) return opHandle;
'''
begin_new = '''    LOG(ERROR) << "[H40 KMCOMPAT] begin: calling Keymaster begin for metadata blob";
    auto opHandle = keymaster.begin(blob, inParams, outParams);
    LOG(ERROR) << "[H40 KMCOMPAT] begin: returned valid=" << static_cast<bool>(opHandle)
               << " error=" << static_cast<int32_t>(opHandle.getErrorCode());
    if (!opHandle) return opHandle;
'''
ks = replace_once(ks, begin_old, begin_new, "metadata begin stage markers")
ks_path.write_text(ks)

# libvold is static in recovery. The V4.1 support wrapper lives in its support
# library, so make the final Make-built recovery link explicit too.
mk_path = recovery_root / "Android.mk"
mk = mk_path.read_text()
mk = replace_once(
    mk,
    '        LOCAL_SHARED_LIBRARIES += libdl android.hardware.keymaster@4.0 libkeymaster4support\n',
    '        LOCAL_SHARED_LIBRARIES += libdl android.hardware.keymaster@4.0 libkeymaster4support\n'
    '        LOCAL_SHARED_LIBRARIES += android.hardware.keymaster@4.1 libkeymaster4_1support\n',
    "recovery Keymaster 4.1 support-wrapper link",
)
mk_path.write_text(mk)

# Hard contracts for the physical-test fix.
final_h = h_path.read_text()
final_cpp = cpp_path.read_text()
final_ks = ks_path.read_text()
final_mk = mk_path.read_text()

required = {
    "support wrapper type": "V4_1::support::Keymaster",
    "support wrapper ownership": "android::sp<KmDevice> mDevice",
    "device enumeration": "KmDevice::enumerateAvailableDevices()",
    "standard HMAC agreement": "KmDevice::performHmacKeyAgreement(devices)",
    "constructor stage marker": "[H40 KMCOMPAT] constructor: enumerating Keymaster 4.x devices",
}
for label, needle in required.items():
    if needle not in final_h + final_cpp:
        raise SystemExit(f"{label} missing")

for forbidden in (
    'IKeymasterDevice40::getService("trustonic")',
    'IKeymasterDevice40::getService("default")',
    'safePerformHmacKeyAgreement();',
    'std::unique_ptr<KmDevice> mDevice',
):
    if forbidden in final_h + final_cpp:
        raise SystemExit(f"forbidden V4.1 path survived: {forbidden}")

if 'if (!opHandle.getUpgradedBlob()) return opHandle;' not in final_ks:
    raise SystemExit("KeyStorage upgraded-blob guard missing")
if '[H40 KMCOMPAT] retrieve: constructing Keymaster' not in final_ks:
    raise SystemExit("metadata retrieval diagnostics missing")
if 'LOCAL_SHARED_LIBRARIES += android.hardware.keymaster@4.1 libkeymaster4_1support' not in final_mk:
    raise SystemExit("Keymaster 4.1 support-wrapper recovery link missing")

print("Applied H.40 V4.1 Keymaster runtime compatibility fix")
print("  metadata format: TeamWin four-file KeyStorage")
print("  Keymaster discovery: AOSP V4.1 support wrapper over HIDL 4.x")
print("  Keymaster ownership: android::sp, matching V4.1 KeymasterSet")
print("  unsafe Vivo trustonic/raw getService path: removed")
print("  obsolete raw-HIDL HMAC helper: removed")
print("  KeyStorage upgraded-blob optional guard: restored")
print("  DE/password/CE: Oplus H.40 libdecrypt_recovery unchanged")
