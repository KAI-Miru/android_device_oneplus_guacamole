#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v42-blobprobe.py RECOVERY_ROOT VOLD_ROOT")

repo_root = Path(__file__).resolve().parents[1]
base_transform = repo_root / "ci" / "apply-h40-v43-blobprefix-base.py"
if not base_transform.is_file():
    raise SystemExit(f"V4.4 base transform missing: {base_transform}")

# Apply the physically tested V4.3 transform first.  V4.4 is intentionally a
# narrow delta on top of that exact source state.
subprocess.run(
    [sys.executable, str(base_transform), sys.argv[1], sys.argv[2]],
    check=True,
)

cpp_path = Path(sys.argv[2]) / "Keymaster.cpp"
cpp = cpp_path.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# V4.3 physical result:
#   storedLen=463 prefixPresent=1 softKeyMint=0 hidlLen=455
#   getKeyCharacteristics(raw 455-byte blob + exact 64-byte APPLICATION_ID)
#       -> -62 KEY_REQUIRES_UPGRADE
#   begin(raw blob + purpose-filtered operation params)
#       -> -62 KEY_REQUIRES_UPGRADE
#   upgradeKey(raw blob + EMPTY params)
#       -> -33 INVALID_KEY_BLOB
#
# Android 12 Keystore2 does not use an empty upgrade parameter set here.  Its
# create_operation() removes PURPOSE, then upgrade_keyblob_if_required_with()
# passes that same purpose-filtered operation parameter set to upgradeKey().
# This is especially important for keys bound to APPLICATION_ID/APPLICATION_DATA.
# Mirror that contract exactly instead of relying on the Vivo-derived bridge's
# old "empty params" shortcut.

primary_old = '''        std::string upgradedKey;
        // upgradeKey needs empty params - keymaster will use current OS_VERSION/OS_PATCHLEVEL
        km::AuthorizationSet emptyParams;
        if (upgradeKey(key, emptyParams, &upgradedKey)) {
'''
primary_new = '''        std::string upgradedKey;
        km::AuthorizationSet upgradeParams;
        size_t upgradePurposeCount = 0;
        for (const auto& param : inParams) {
            if (param.tag == km::Tag::PURPOSE) {
                ++upgradePurposeCount;
                continue;
            }
            upgradeParams.push_back(param);
        }
        LOG(ERROR) << "[H40 UPGRADEPARAMS] begin: keymintParams=" << inParams.size()
                   << " filteredParams=" << upgradeParams.size()
                   << " removedPurpose=" << upgradePurposeCount;
        if (upgradeKey(key, upgradeParams, &upgradedKey)) {
'''
cpp = replace_once(cpp, primary_old, primary_new, "V4.4 primary upgrade parameter forwarding")

auth_old = '''        std::string upgradedKey;
        km::AuthorizationSet emptyParams;
        if (upgradeKey(key, emptyParams, &upgradedKey)) {
'''
auth_new = '''        std::string upgradedKey;
        km::AuthorizationSet upgradeParams;
        size_t upgradePurposeCount = 0;
        for (const auto& param : inParams) {
            if (param.tag == km::Tag::PURPOSE) {
                ++upgradePurposeCount;
                continue;
            }
            upgradeParams.push_back(param);
        }
        LOG(ERROR) << "[H40 UPGRADEPARAMS] auth begin: keymintParams=" << inParams.size()
                   << " filteredParams=" << upgradeParams.size()
                   << " removedPurpose=" << upgradePurposeCount;
        if (upgradeKey(key, upgradeParams, &upgradedKey)) {
'''
cpp = replace_once(cpp, auth_old, auth_new, "V4.4 authenticated upgrade parameter forwarding")

upgrade_probe_old = '''    auto oldKeyBlob = km_hidl::support::blob2hidlVec(oldBlobView.raw);
    auto hidlParams = convertToHidl(inParams);
'''
upgrade_probe_new = '''    auto oldKeyBlob = km_hidl::support::blob2hidlVec(oldBlobView.raw);
    auto hidlParams = convertToHidl(inParams);
    size_t upgradeAppIdCount = 0;
    size_t upgradeAppIdLen = 0;
    size_t upgradeAppDataCount = 0;
    size_t upgradePurposeCount = 0;
    size_t upgradeNonceCount = 0;
    size_t upgradeMacLengthCount = 0;
    for (const auto& param : hidlParams) {
        if (param.tag == km_hidl::Tag::APPLICATION_ID) {
            ++upgradeAppIdCount;
            upgradeAppIdLen = param.blob.size();
        } else if (param.tag == km_hidl::Tag::APPLICATION_DATA) {
            ++upgradeAppDataCount;
        } else if (param.tag == km_hidl::Tag::PURPOSE) {
            ++upgradePurposeCount;
        } else if (param.tag == km_hidl::Tag::NONCE) {
            ++upgradeNonceCount;
        } else if (param.tag == km_hidl::Tag::MAC_LENGTH) {
            ++upgradeMacLengthCount;
        }
    }
    LOG(ERROR) << "[H40 UPGRADEPARAMS] upgrade: keymintParams=" << inParams.size()
               << " hidlParams=" << hidlParams.size()
               << " purposeCount=" << upgradePurposeCount
               << " appIdCount=" << upgradeAppIdCount
               << " appIdLen=" << upgradeAppIdLen
               << " appDataCount=" << upgradeAppDataCount
               << " nonceCount=" << upgradeNonceCount
               << " macLengthCount=" << upgradeMacLengthCount;
'''
cpp = replace_once(cpp, upgrade_probe_old, upgrade_probe_new, "V4.4 upgrade parameter diagnostic")

cpp_path.write_text(cpp)

final_cpp = cpp_path.read_text()
for needle in (
    '[H40 BLOBPREFIX] begin:',
    '[H40 BLOBPROBE] characteristics:',
    '[H40 UPGRADEPARAMS] begin:',
    '[H40 UPGRADEPARAMS] auth begin:',
    '[H40 UPGRADEPARAMS] upgrade:',
    'upgradeKey(key, upgradeParams, &upgradedKey)',
    'param.tag == km::Tag::PURPOSE',
    'param.tag == km_hidl::Tag::APPLICATION_ID',
):
    if needle not in final_cpp:
        raise SystemExit(f"V4.4 upgrade-parameter contract missing: {needle}")

if final_cpp.count('upgradeKey(key, upgradeParams, &upgradedKey)') != 2:
    raise SystemExit("V4.4 expected exactly two Keystore2-compatible upgrade call sites")
if 'km::AuthorizationSet emptyParams;' in final_cpp:
    raise SystemExit("V4.4 legacy empty upgrade parameter set survived")
if final_cpp.count('[H40 UPGRADEPARAMS] upgrade:') != 1:
    raise SystemExit("V4.4 expected exactly one upgrade parameter diagnostic")

# Never log APPLICATION_ID, key-blob, or upgraded-key contents.
for forbidden in (
    'upgradeParams.data()',
    'upgradeParams.c_str()',
    'oldBlobView.raw.data()',
    'oldBlobView.raw.c_str()',
    'upgradedKey.data()',
    'upgradedKey.c_str()',
):
    if forbidden in final_cpp:
        raise SystemExit(f"V4.4 secret-bearing diagnostic survived: {forbidden}")

print("Applied H.40 V4.4 Keystore2-compatible upgrade parameters")
print("  V4.3 pKMblob handling: retained")
print("  begin PURPOSE filtering: retained")
print("  upgradeKey params: same purpose-filtered operation params as Keystore2")
print("  upgrade APPLICATION_ID bytes logged: no")
