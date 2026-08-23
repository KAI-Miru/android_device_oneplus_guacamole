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


# H.40 V4.1 physical result:
#   - QSEE/RPMB, Gatekeeper, Keymaster registration, Keymaster enumeration and
#     HMAC agreement all succeed.
#   - metadata retrieval reaches the QTI Keymaster TA, but begin() returns -33.
#
# The TeamWin Android-12 KeyStorage API embeds PURPOSE in its KeyMint operation
# parameter set because Keystore2 consumes it there.  The Android-11 HIDL vold
# API instead passes purpose as the dedicated IKeymasterDevice::begin() argument
# and does not include TAG_PURPOSE in the operation parameters.  The Vivo-derived
# compatibility bridge was doing both.  Filter only TAG_PURPOSE at the HIDL
# begin boundary, leaving it intact for key-generation authorization sets.
#
# Also issue a read-only getKeyCharacteristics() probe with the exact
# APPLICATION_ID already derived by KeyStorage.  This distinguishes a blob/appId
# rejection from an operation-parameter rejection without upgrading, deleting,
# rewriting, or otherwise mutating the on-device metadata key.

cpp_path = vold_root / "Keymaster.cpp"
cpp = cpp_path.read_text()

first_begin_old = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);
    printf("[Keymaster] begin: hidlParams count=%zu\\n", hidlParams.size());

    uint64_t mOpHandle = 0;
'''
first_begin_new = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
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
               << " keyBlobLen=" << key.size()
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
cpp = replace_once(cpp, first_begin_old, first_begin_new, "primary begin bridge/probe")

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

# Apply the same canonical HIDL PURPOSE filtering to the authenticated begin
# overload used later by credential-encrypted key handling.  The metadata probe
# above is intentionally only on the first, no-auth-token path so this build
# remains focused and does not add redundant secure-world traffic.
auth_begin_old = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);

    uint64_t mOpHandle = 0;
'''
auth_begin_new = '''    auto keyBlob = km_hidl::support::blob2hidlVec(key);
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
               << " hidlParams=" << hidlParams.size()
               << " filteredParams=" << beginHidlParams.size()
               << " removedPurpose=" << purposeParamCount;

    uint64_t mOpHandle = 0;
'''
cpp = replace_once(cpp, auth_begin_old, auth_begin_new, "authenticated begin PURPOSE filter")
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

cpp_path.write_text(cpp)

final_cpp = cpp_path.read_text()
required = (
    '[H40 BLOBPROBE] begin bridge:',
    '[H40 BLOBPROBE] characteristics:',
    '[H40 BLOBPROBE] auth begin bridge:',
    'mDevice->getKeyCharacteristics(',
    'param.tag == km_hidl::Tag::APPLICATION_ID',
    'param.tag == km_hidl::Tag::PURPOSE',
    'beginHidlParams.hidl_data()',
)
for needle in required:
    if needle not in final_cpp:
        raise SystemExit(f"V4.2 blob probe contract missing: {needle}")

if final_cpp.count('beginHidlParams.hidl_data()') != 4:
    raise SystemExit("V4.2 expected exactly four filtered HIDL begin call sites")

# Do not allow the diagnostic to expose the derived APPLICATION_ID bytes.
for forbidden in (
    'clientId.data()',
    'clientId.c_str()',
    'appId.data()',
    'appId.c_str()',
):
    if forbidden in final_cpp:
        raise SystemExit(f"V4.2 secret-bearing diagnostic survived: {forbidden}")

print("Applied H.40 V4.2 Keymaster blob probe")
print("  HIDL begin PURPOSE: passed only as dedicated argument")
print("  KeyMint TAG_PURPOSE: filtered from HIDL operation params")
print("  metadata blob probe: getKeyCharacteristics with exact APPLICATION_ID")
print("  probe mutates key material: no")
print("  secret bytes logged: no")
