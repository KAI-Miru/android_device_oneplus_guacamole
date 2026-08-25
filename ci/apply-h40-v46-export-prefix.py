#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v46-export-prefix.py RECOVERY_ROOT VOLD_ROOT")

cpp_path = Path(sys.argv[2]) / "Keymaster.cpp"
cpp = cpp_path.read_text()

start = cpp.find("bool Keymaster::exportKey(const KeyBuffer& kmKey, std::string* key) {")
end = cpp.find("\nbool Keymaster::deleteKey(", start)
if start < 0 or end < 0:
    raise SystemExit("V4.6 unable to isolate Keymaster::exportKey")

old = cpp[start:end]
if "Using key directly" not in old:
    raise SystemExit("V4.6 expected unsafe Vivo export fallback was not found")
if "mDevice->exportKey" not in old:
    raise SystemExit("V4.6 expected HIDL export call was not found")

new = r'''bool Keymaster::exportKey(const KeyBuffer& kmKey, std::string* key) {
    if (!mDevice) {
        LOG(ERROR) << "[H40 BLOBPREFIX] export: no Keymaster device";
        return false;
    }

    const std::string storedBlob(kmKey.begin(), kmKey.end());
    const auto blobView = UnwrapKs2KeyBlob(storedBlob);
    LOG(INFO) << "[H40 BLOBPREFIX] export: storedLen=" << storedBlob.size()
              << " prefixPresent=" << blobView.prefixPresent
              << " softKeyMint=" << blobView.softKeyMint
              << " hidlLen=" << blobView.raw.size();

    if (blobView.softKeyMint) {
        LOG(ERROR) << "[H40 BLOBPREFIX] export: software-KeyMint pKMblob is unsupported "
                      "on the QTI-HIDL recovery path";
        return false;
    }
    if (blobView.raw.empty()) {
        LOG(ERROR) << "[H40 BLOBPREFIX] export: empty raw HIDL key blob";
        return false;
    }

    auto keyBlob = blob2hidlVec(reinterpret_cast<const uint8_t*>(blobView.raw.data()),
                                blobView.raw.size());
    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    std::string exportedKey;
    auto hidlCb = [&km_error, &exportedKey](km_hidl::ErrorCode ret,
                                            const hidl_vec<uint8_t>& exportedData) {
        km_error = ret;
        if (ret == km_hidl::ErrorCode::OK) {
            exportedKey.assign(reinterpret_cast<const char*>(exportedData.data()),
                               exportedData.size());
        }
    };

    auto error = mDevice->exportKey(km_hidl::KeyFormat::RAW, keyBlob, hidl_vec<uint8_t>(),
                                    hidl_vec<uint8_t>(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "[H40 BLOBPREFIX] export result: transport failure";
        return false;
    }

    LOG(INFO) << "[H40 BLOBPREFIX] export result: error=" << static_cast<int32_t>(km_error)
              << " exportedLen=" << exportedKey.size();
    if (km_error != km_hidl::ErrorCode::OK || exportedKey.empty()) return false;

    if (key) *key = exportedKey;
    return true;
}
'''
cpp = cpp[:start] + new + cpp[end:]
cpp_path.write_text(cpp)

final = cpp_path.read_text()
export_start = final.find("bool Keymaster::exportKey(const KeyBuffer& kmKey, std::string* key) {")
export_end = final.find("\nbool Keymaster::deleteKey(", export_start)
body = final[export_start:export_end]

for required in (
    "UnwrapKs2KeyBlob(storedBlob)",
    "[H40 BLOBPREFIX] export:",
    "prefixPresent=",
    "softKeyMint=",
    "hidlLen=",
    "[H40 BLOBPREFIX] export result:",
    "mDevice->exportKey(km_hidl::KeyFormat::RAW",
):
    if required not in body:
        raise SystemExit(f"V4.6 pKMblob export contract missing: {required}")
for forbidden in (
    "Using key directly",
    "key->assign(kmKey.begin(), kmKey.end())",
    "kmKey.data()",
):
    if forbidden in body:
        raise SystemExit(f"V4.6 unsafe/direct export path survived: {forbidden}")

print("Applied H.40 V4.6 pKMblob-aware wrapped-storage-key export")
print("  hardware pKMblob origin: unwrap to raw QTI HIDL blob")
print("  software KeyMint origin: fail closed")
print("  QTI export failure: fail closed")
print("  raw key-blob-as-storage-key fallback: removed")
