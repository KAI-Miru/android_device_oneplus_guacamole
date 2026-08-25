#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v42-blobprobe.py RECOVERY_ROOT VOLD_ROOT")

recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# H.40 V4.2 physical result:
#   - QSEE/RPMB, Gatekeeper, Keymaster registration, Keymaster enumeration and
#     HMAC agreement all succeed.
#   - getKeyCharacteristics() on the metadata key returns -33 INVALID_KEY_BLOB
#     before begin() operation parameters can matter.
#   - the stored metadata keymaster_key_blob is 463 bytes and APPLICATION_ID is
#     the expected 64-byte SHA-512-derived value.
#
# Android 12 Keystore2's legacy Keymaster compatibility layer prefixes blobs it
# receives from a real Keymaster 4.x HAL with eight bytes before returning a
# Domain::BLOB key to clients: seven-byte magic "pKMblob" followed by an origin
# byte (0 = real hardware Keymaster, 1 = software KeyMint).  Before calling a
# legacy HIDL Keymaster operation, Keystore2 removes that prefix.  The V4.1/V4.2
# direct-HIDL bridge bypassed Keystore2 but passed the on-disk blob unchanged,
# so QTI saw the compatibility prefix as part of its native blob and rejected it.
#
# V4.3 keeps the V4.2 PURPOSE filtering and read-only characteristics probe, but
# mirrors Keystore2's prefix contract at the legacy-HIDL boundary.  Legacy
# unprefixed blobs remain accepted.  A software-KeyMint prefix fails closed,
# because this recovery path intentionally targets the QTI TEE Keymaster.

cpp_path = vold_root / "Keymaster.cpp"
cpp = cpp_path.read_text()

cpp = replace_once(
    cpp,
    '#include <android-base/logging.h>\n',
    '#include <android-base/logging.h>\n#include <cstring>\n',
    "V4.3 key-blob prefix memcmp include",
)

blob_helpers = r'''namespace {

static constexpr size_t kKs2KeyBlobPrefixSize = 8;
static constexpr uint8_t kKs2KeyBlobMagic[7] = {'p', 'K', 'M', 'b', 'l', 'o', 'b'};

struct Ks2KeyBlobView {
    std::string raw;
    bool prefixPresent;
    bool softKeyMint;
    bool malformedPrefix;
};

static Ks2KeyBlobView UnwrapKs2KeyBlob(const std::string& stored) {
    Ks2KeyBlobView result{stored, false, false, false};
    if (stored.size() < sizeof(kKs2KeyBlobMagic) ||
        std::memcmp(stored.data(), kKs2KeyBlobMagic, sizeof(kKs2KeyBlobMagic)) != 0) {
        return result;  // Genuine legacy/unprefixed blob.
    }

    result.prefixPresent = true;
    if (stored.size() < kKs2KeyBlobPrefixSize) {
        result.raw.clear();
        result.malformedPrefix = true;
        return result;
    }

    const uint8_t origin = static_cast<uint8_t>(stored[kKs2KeyBlobPrefixSize - 1]);
    if (origin != 0 && origin != 1) {
        result.raw.clear();
        result.malformedPrefix = true;
        return result;
    }

    result.softKeyMint = origin == 1;
    result.raw.assign(stored.data() + kKs2KeyBlobPrefixSize,
                      stored.size() - kKs2KeyBlobPrefixSize);
    if (result.raw.empty()) result.malformedPrefix = true;
    return result;
}

static bool IsUsableHidlKeyBlob(const Ks2KeyBlobView& view, const char* operation) {
    if (view.malformedPrefix) {
        LOG(ERROR) << "[H40 BLOBPREFIX] " << operation << ": malformed pKMblob prefix";
        return false;
    }
    if (view.softKeyMint) {
        LOG(ERROR) << "[H40 BLOBPREFIX] " << operation
                   << ": software-KeyMint blob unsupported on QTI HIDL";
        return false;
    }
    if (view.raw.empty()) {
        LOG(ERROR) << "[H40 BLOBPREFIX] " << operation << ": empty HIDL key blob";
        return false;
    }
    return true;
}

static std::string WrapKs2HardwareKeyBlob(const std::string& raw) {
    std::string stored;
    stored.reserve(kKs2KeyBlobPrefixSize + raw.size());
    stored.append(reinterpret_cast<const char*>(kKs2KeyBlobMagic),
                  sizeof(kKs2KeyBlobMagic));
    stored.push_back('\0');
    stored.append(raw);
    return stored;
}

}  // namespace

'''
cpp = replace_once(
    cpp,
    'namespace android {\nnamespace vold {\n\n',
    'namespace android {\nnamespace vold {\n\n' + blob_helpers,
    "V4.3 Keystore2 key-blob compatibility helpers",
)

# Preserve Keystore2's representation when a legacy HIDL upgrade is returned.
# The raw QTI blob goes to the HAL; the upgraded blob returned to KeyStorage is
# wrapped back into the Android-12 Domain::BLOB format.
cpp = replace_once(
    cpp,
    '''    auto oldKeyBlob = km_hidl::support::blob2hidlVec(oldKey);
    auto hidlParams = convertToHidl(inParams);
''',
    '''    auto oldBlobView = UnwrapKs2KeyBlob(oldKey);
    LOG(ERROR) << "[H40 BLOBPREFIX] upgrade: storedLen=" << oldKey.size()
               << " prefixPresent=" << oldBlobView.prefixPresent
               << " softKeyMint=" << oldBlobView.softKeyMint
               << " hidlLen=" << oldBlobView.raw.size();
    if (!IsUsableHidlKeyBlob(oldBlobView, "upgrade")) return false;
    auto oldKeyBlob = km_hidl::support::blob2hidlVec(oldBlobView.raw);
    auto hidlParams = convertToHidl(inParams);
''',
    "V4.3 upgrade input blob unwrapping",
)
cpp = replace_once(
    cpp,
    '''        if (newKey && upgradedKeyBlob.size() > 0)
            newKey->assign(reinterpret_cast<const char*>(&upgradedKeyBlob[0]), upgradedKeyBlob.size());
''',
    '''        if (newKey && upgradedKeyBlob.size() > 0) {
            std::string rawUpgraded(
                    reinterpret_cast<const char*>(&upgradedKeyBlob[0]), upgradedKeyBlob.size());
            *newKey = WrapKs2HardwareKeyBlob(rawUpgraded);
            LOG(ERROR) << "[H40 BLOBPREFIX] upgrade: rawUpgradedLen=" << rawUpgraded.size()
                       << " returnedStoredLen=" << newKey->size();
        }
''',
    "V4.3 upgrade output blob wrapping",
)

# Keep destructive/diagnostic HIDL helpers consistent with the same representation
# rule.  These paths are not needed for the read-only metadata probe itself, but
# leaving them raw would make the wrapper internally inconsistent after V4.3.
cpp = replace_once(
    cpp,
    '''bool Keymaster::deleteKey(const std::string& key) {
    LOG(INFO) << "[Keymaster] deleteKey";
    if (!mDevice) return false;
    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto error = mDevice->deleteKey(keyBlob);
''',
    '''bool Keymaster::deleteKey(const std::string& key) {
    LOG(INFO) << "[Keymaster] deleteKey";
    if (!mDevice) return false;
    auto blobView = UnwrapKs2KeyBlob(key);
    if (!IsUsableHidlKeyBlob(blobView, "delete")) return false;
    auto keyBlob = km_hidl::support::blob2hidlVec(blobView.raw);
    auto error = mDevice->deleteKey(keyBlob);
''',
    "V4.3 delete blob unwrapping",
)
cpp = replace_once(
    cpp,
    '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    hidl_vec<uint8_t> clientId, appData;  // empty for most keys
''',
    '''    auto blobView = UnwrapKs2KeyBlob(key);
    if (!IsUsableHidlKeyBlob(blobView, "characteristics")) return false;
    auto keyBlob = km_hidl::support::blob2hidlVec(blobView.raw);
    hidl_vec<uint8_t> clientId, appData;  // empty for most keys
''',
    "V4.3 public characteristics blob unwrapping",
)

first_begin_old = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);
    printf("[Keymaster] begin: hidlParams count=%zu\\n", hidlParams.size());

    uint64_t mOpHandle = 0;
'''
first_begin_new = '''    auto blobView = UnwrapKs2KeyBlob(key);
    LOG(ERROR) << "[H40 BLOBPREFIX] begin: storedLen=" << key.size()
               << " prefixPresent=" << blobView.prefixPresent
               << " softKeyMint=" << blobView.softKeyMint
               << " hidlLen=" << blobView.raw.size();
    if (!IsUsableHidlKeyBlob(blobView, "begin")) {
        return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
    }

    auto keyBlob = km_hidl::support::blob2hidlVec(blobView.raw);
    auto hidlParams = convertToHidl(inParams);

    km_hidl::AuthorizationSet beginHidlParams;
    hidl_vec<uint8_t> clientId;
    size_t purposeParamCount = 0;
    size_t appIdParamCount = 0;
    size_t nonceParamCount = 0;
    size_t nonceLen = 0;
    uint32_t macLengthBits = 0;
    bool sawMacLength = false;

    for (const auto& param : hidlParams) {
        if (param.tag == km_hidl::Tag::PURPOSE) {
            ++purposeParamCount;
            continue;
        }
        if (param.tag == km_hidl::Tag::APPLICATION_ID) {
            ++appIdParamCount;
            clientId.resize(param.blob.size());
            for (size_t i = 0; i < param.blob.size(); ++i) clientId[i] = param.blob[i];
        } else if (param.tag == km_hidl::Tag::NONCE) {
            ++nonceParamCount;
            nonceLen = param.blob.size();
        } else if (param.tag == km_hidl::Tag::MAC_LENGTH) {
            sawMacLength = true;
            macLengthBits = param.f.integer;
        }
        beginHidlParams.push_back(param);
    }

    LOG(ERROR) << "[H40 BLOBPROBE] begin bridge: purpose="
               << static_cast<int32_t>(purpose)
               << " storedBlobLen=" << key.size()
               << " hidlBlobLen=" << blobView.raw.size()
               << " keymintParams=" << inParams.size()
               << " hidlParams=" << hidlParams.size()
               << " filteredParams=" << beginHidlParams.size()
               << " removedPurpose=" << purposeParamCount
               << " appIdCount=" << appIdParamCount
               << " appIdLen=" << clientId.size()
               << " nonceCount=" << nonceParamCount
               << " nonceLen=" << nonceLen
               << " macLengthPresent=" << sawMacLength
               << " macLengthBits=" << macLengthBits;

    km_hidl::ErrorCode characteristicsError = km_hidl::ErrorCode::UNKNOWN_ERROR;
    size_t characteristicsHwCount = 0;
    size_t characteristicsSwCount = 0;
    auto characteristicsTransport = mDevice->getKeyCharacteristics(
            keyBlob, clientId, hidl_vec<uint8_t>(),
            [&](km_hidl::ErrorCode ret, const km_hidl::KeyCharacteristics& chars) {
                characteristicsError = ret;
                if (ret == km_hidl::ErrorCode::OK) {
                    characteristicsHwCount = chars.hardwareEnforced.size();
                    characteristicsSwCount = chars.softwareEnforced.size();
                }
            });
    LOG(ERROR) << "[H40 BLOBPROBE] characteristics: transportOk="
               << characteristicsTransport.isOk()
               << " error=" << static_cast<int32_t>(characteristicsError)
               << " hwParams=" << characteristicsHwCount
               << " swParams=" << characteristicsSwCount;

    uint64_t mOpHandle = 0;
'''
cpp = replace_once(cpp, first_begin_old, first_begin_new, "primary begin bridge/probe/prefix")

cpp = replace_once(
    cpp,
    '''    auto error = mDevice->begin(purpose, keyBlob, hidlParams.hidl_data(),
                                km_hidl::HardwareAuthToken(), hidlCb);
''',
    '''    auto error = mDevice->begin(purpose, keyBlob, beginHidlParams.hidl_data(),
                                km_hidl::HardwareAuthToken(), hidlCb);
''',
    "primary begin filtered parameters",
)
cpp = replace_once(
    cpp,
    '''            error = mDevice->begin(purpose, upgradedKeyBlob, hidlParams.hidl_data(),
                                   km_hidl::HardwareAuthToken(), hidlCb);
''',
    '''            error = mDevice->begin(purpose, upgradedKeyBlob, beginHidlParams.hidl_data(),
                                   km_hidl::HardwareAuthToken(), hidlCb);
''',
    "upgraded primary begin filtered parameters",
)

# Apply the same prefix unwrapping and PURPOSE filtering to the authenticated
# begin overload used by later credential-encrypted paths.
auth_begin_old = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);

    uint64_t mOpHandle = 0;
'''
auth_begin_new = '''    auto blobView = UnwrapKs2KeyBlob(key);
    LOG(ERROR) << "[H40 BLOBPREFIX] auth begin: storedLen=" << key.size()
               << " prefixPresent=" << blobView.prefixPresent
               << " softKeyMint=" << blobView.softKeyMint
               << " hidlLen=" << blobView.raw.size();
    if (!IsUsableHidlKeyBlob(blobView, "auth begin")) {
        return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
    }

    auto keyBlob = km_hidl::support::blob2hidlVec(blobView.raw);
    auto hidlParams = convertToHidl(inParams);
    km_hidl::AuthorizationSet beginHidlParams;
    size_t purposeParamCount = 0;
    for (const auto& param : hidlParams) {
        if (param.tag == km_hidl::Tag::PURPOSE) {
            ++purposeParamCount;
            continue;
        }
        beginHidlParams.push_back(param);
    }
    LOG(ERROR) << "[H40 BLOBPROBE] auth begin bridge: purpose="
               << static_cast<int32_t>(purpose)
               << " storedBlobLen=" << key.size()
               << " hidlBlobLen=" << blobView.raw.size()
               << " hidlParams=" << hidlParams.size()
               << " filteredParams=" << beginHidlParams.size()
               << " removedPurpose=" << purposeParamCount;

    uint64_t mOpHandle = 0;
'''
cpp = replace_once(cpp, auth_begin_old, auth_begin_new, "authenticated begin prefix/PURPOSE filter")
cpp = replace_once(
    cpp,
    '    auto error = mDevice->begin(purpose, keyBlob, hidlParams.hidl_data(), authToken, hidlCb);\n',
    '    auto error = mDevice->begin(purpose, keyBlob, beginHidlParams.hidl_data(), authToken, hidlCb);\n',
    "authenticated begin filtered parameters",
)
cpp = replace_once(
    cpp,
    '            error = mDevice->begin(purpose, upgradedKeyBlob, hidlParams.hidl_data(), authToken, hidlCb);\n',
    '            error = mDevice->begin(purpose, upgradedKeyBlob, beginHidlParams.hidl_data(), authToken, hidlCb);\n',
    "upgraded authenticated begin filtered parameters",
)

# upgradeKey() now returns an Android-12-prefixed representation.  Strip that
# representation again for the immediate retry that still calls the legacy HAL.
upgraded_blob_old = '            auto upgradedKeyBlob = km_hidl::support::blob2hidlVec(upgradedKey);\n'
upgraded_blob_new = '''            auto upgradedBlobView = UnwrapKs2KeyBlob(upgradedKey);
            if (!IsUsableHidlKeyBlob(upgradedBlobView, "retry")) {
                return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
            }
            auto upgradedKeyBlob = km_hidl::support::blob2hidlVec(upgradedBlobView.raw);
'''
if cpp.count(upgraded_blob_old) != 2:
    raise SystemExit(
        f"V4.3 expected exactly two upgraded begin blob call sites, found {cpp.count(upgraded_blob_old)}"
    )
cpp = cpp.replace(upgraded_blob_old, upgraded_blob_new)

cpp_path.write_text(cpp)

final_cpp = cpp_path.read_text()
required = (
    '[H40 BLOBPREFIX] begin:',
    '[H40 BLOBPREFIX] upgrade:',
    '[H40 BLOBPROBE] begin bridge:',
    '[H40 BLOBPROBE] characteristics:',
    '[H40 BLOBPROBE] auth begin bridge:',
    'kKs2KeyBlobPrefixSize = 8',
    "{'p', 'K', 'M', 'b', 'l', 'o', 'b'}",
    'UnwrapKs2KeyBlob(',
    'IsUsableHidlKeyBlob(',
    'malformedPrefix',
    'malformed pKMblob prefix',
    'WrapKs2HardwareKeyBlob(',
    'mDevice->getKeyCharacteristics(',
    'param.tag == km_hidl::Tag::APPLICATION_ID',
    'param.tag == km_hidl::Tag::PURPOSE',
    'beginHidlParams.hidl_data()',
)
for needle in required:
    if needle not in final_cpp:
        raise SystemExit(f"V4.3 blob-prefix contract missing: {needle}")

if final_cpp.count('beginHidlParams.hidl_data()') != 4:
    raise SystemExit("V4.3 expected exactly four filtered HIDL begin call sites")
if final_cpp.count('auto upgradedBlobView = UnwrapKs2KeyBlob(upgradedKey);') != 2:
    raise SystemExit("V4.3 expected exactly two upgraded-key retry unwraps")
if final_cpp.count('IsUsableHidlKeyBlob(') != 8:
    raise SystemExit("V4.3 expected helper plus seven fail-closed HIDL consumers")
for forbidden_guard in (
    "if (oldBlobView.softKeyMint)",
    "if (blobView.softKeyMint)",
    "if (upgradedBlobView.softKeyMint)",
):
    if forbidden_guard in final_cpp:
        raise SystemExit(f"V4.3 softKeyMint-only guard survived: {forbidden_guard}")

# Do not allow diagnostics to expose APPLICATION_ID or key-blob bytes.
for forbidden in (
    'clientId.data()',
    'clientId.c_str()',
    'appId.data()',
    'appId.c_str()',
    'blobView.raw.data()',
    'blobView.raw.c_str()',
):
    if forbidden in final_cpp:
        raise SystemExit(f"V4.3 secret-bearing diagnostic survived: {forbidden}")

print("Applied H.40 V4.3 Keystore2 blob-prefix compatibility")
print("  stored Domain::BLOB prefix: pKMblob + origin byte")
print("  hardware Keymaster prefix: stripped before legacy HIDL")
print("  legacy unprefixed blobs: accepted unchanged")
print("  malformed/software-KeyMint-prefixed blobs: fail closed")
print("  upgraded hardware blobs: re-prefixed before returning to KeyStorage")
print("  HIDL begin PURPOSE: passed only as dedicated argument")
print("  metadata blob probe: getKeyCharacteristics with exact APPLICATION_ID")
print("  secret bytes logged: no")
