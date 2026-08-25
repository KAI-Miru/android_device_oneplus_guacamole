#!/usr/bin/env python3
from pathlib import Path
import re
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v46-fscrypt-lazy.py RECOVERY_ROOT VOLD_ROOT")

vold = Path(sys.argv[2])

def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)

fs_path = vold / "FsCrypt.cpp"
fs = fs_path.read_text()

old_globals = '''namespace {

const std::string device_key_dir = std::string() + DATA_MNT_POINT + fscrypt_unencrypted_folder;
const std::string device_key_path = device_key_dir + "/key";
const std::string device_key_temp = device_key_dir + "/temp";

const std::string user_key_dir = std::string() + DATA_MNT_POINT + "/misc/vold/user_keys";
const std::string user_key_temp = user_key_dir + "/temp";
const std::string prepare_subdirs_path = "/system/bin/vold_prepare_subdirs";

const std::string systemwide_volume_key_dir =
    std::string() + DATA_MNT_POINT + "/misc/vold/volume_keys";

// Some users are ephemeral, don't try to wipe their keys from disk
std::set<userid_t> s_ephemeral_users;

}  // namespace

// Map user ids to encryption policies
std::map<userid_t, EncryptionPolicy> s_de_policies;
std::map<userid_t, EncryptionPolicy> s_ce_policies;
std::string de_key_raw_ref;
bool retry = true;
'''
new_globals = '''namespace {

const std::string& GetDeviceKeyDir() {
    static auto* value =
            new std::string(std::string() + DATA_MNT_POINT + fscrypt_unencrypted_folder);
    return *value;
}

const std::string& GetDeviceKeyPath() {
    static auto* value = new std::string(GetDeviceKeyDir() + "/key");
    return *value;
}

const std::string& GetDeviceKeyTemp() {
    static auto* value = new std::string(GetDeviceKeyDir() + "/temp");
    return *value;
}

const std::string& GetUserKeyDir() {
    static auto* value = new std::string(std::string() + DATA_MNT_POINT + "/misc/vold/user_keys");
    return *value;
}

const std::string& GetUserKeyTemp() {
    static auto* value = new std::string(GetUserKeyDir() + "/temp");
    return *value;
}

const std::string& GetPrepareSubdirsPath() {
    static auto* value = new std::string("/system/bin/vold_prepare_subdirs");
    return *value;
}

const std::string& GetSystemwideVolumeKeyDir() {
    static auto* value =
            new std::string(std::string() + DATA_MNT_POINT + "/misc/vold/volume_keys");
    return *value;
}

std::set<userid_t>& GetEphemeralUsers() {
    static auto* users = new std::set<userid_t>();
    return *users;
}

}  // namespace

std::map<userid_t, EncryptionPolicy>& GetDePolicies() {
    static auto* policies = new std::map<userid_t, EncryptionPolicy>();
    return *policies;
}

std::map<userid_t, EncryptionPolicy>& GetCePolicies() {
    static auto* policies = new std::map<userid_t, EncryptionPolicy>();
    return *policies;
}

std::string& GetDeKeyRawRef() {
    static auto* raw_ref = new std::string();
    return *raw_ref;
}

bool retry = true;
'''
fs = replace_once(fs, old_globals, new_globals, "FsCrypt non-trivial namespace globals")

replacements = {
    "device_key_dir": "GetDeviceKeyDir()",
    "device_key_path": "GetDeviceKeyPath()",
    "device_key_temp": "GetDeviceKeyTemp()",
    "user_key_dir": "GetUserKeyDir()",
    "user_key_temp": "GetUserKeyTemp()",
    "prepare_subdirs_path": "GetPrepareSubdirsPath()",
    "systemwide_volume_key_dir": "GetSystemwideVolumeKeyDir()",
    "s_ephemeral_users": "GetEphemeralUsers()",
    "s_de_policies": "GetDePolicies()",
    "s_ce_policies": "GetCePolicies()",
    "de_key_raw_ref": "GetDeKeyRawRef()",
}
for old_name, new_name in replacements.items():
    fs = re.sub(rf"\b{re.escape(old_name)}\b", new_name, fs)

fs = fs.replace("using android::vold::kEmptyAuthentication;",
                "using android::vold::GetEmptyAuthentication;")
fs = re.sub(r"\bkEmptyAuthentication\b", "GetEmptyAuthentication()", fs)

old_insert = '''        auto ret = GetDePolicies().insert({user_id, de_policy});
        if (!ret.second && ret.first->second != de_policy) {
'''
new_insert = '''        auto& de_policies = GetDePolicies();
        LOG(INFO) << "[H40 FSCRYPTLAZY] DE policies ready: user=" << user_id
                  << " size=" << de_policies.size();
        auto ret = de_policies.insert({user_id, de_policy});
        LOG(INFO) << "[H40 FSCRYPTLAZY] DE policy insertion complete: user=" << user_id
                  << " inserted=" << ret.second << " size=" << de_policies.size();
        if (!ret.second && ret.first->second != de_policy) {
'''
fs = replace_once(fs, old_insert, new_insert, "V4.6 DE-policy crash-boundary diagnostics")
fs_path.write_text(fs)

common_path = vold / "fscrypt-common.h"
common = common_path.read_text()
common = replace_once(
    common,
    '''// Store main DE/CE policy
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_de_policies;
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_ce_policies;
extern std::string de_key_raw_ref;
''',
    '''// Recovery-safe first-use storage for main DE/CE policy state.
std::map<userid_t, android::fscrypt::EncryptionPolicy>& GetDePolicies();
std::map<userid_t, android::fscrypt::EncryptionPolicy>& GetCePolicies();
std::string& GetDeKeyRawRef();
''',
    "fscrypt-common lazy policy declarations",
)
common_path.write_text(common)

decrypt_path = vold / "Decrypt.cpp"
decrypt = decrypt_path.read_text()
for old_name, new_name in (
    ("s_de_policies", "GetDePolicies()"),
    ("s_ce_policies", "GetCePolicies()"),
    ("de_key_raw_ref", "GetDeKeyRawRef()"),
):
    decrypt = re.sub(rf"\b{old_name}\b", new_name, decrypt)
decrypt_path.write_text(decrypt)

kh_path = vold / "KeyStorage.h"
kh = kh_path.read_text()
kh = replace_once(
    kh,
    "extern const KeyAuthentication kEmptyAuthentication;\n",
    "const KeyAuthentication& GetEmptyAuthentication();\n",
    "KeyStorage empty-auth declaration",
)
kh_path.write_text(kh)

ks_path = vold / "KeyStorage.cpp"
ks = ks_path.read_text()
ks = replace_once(
    ks,
    'const KeyAuthentication kEmptyAuthentication{""};\n',
    '''const KeyAuthentication& GetEmptyAuthentication() {
    static auto* auth = new KeyAuthentication("");
    return *auth;
}
''',
    "KeyStorage lazy empty-auth object",
)
ks = re.sub(r"\bkEmptyAuthentication\b", "GetEmptyAuthentication()", ks)
ks = replace_once(
    ks,
    "static std::mutex key_upgrade_lock;\n",
    '''static std::mutex& GetKeyUpgradeLock() {
    static auto* lock = new std::mutex();
    return *lock;
}
''',
    "KeyStorage lazy upgrade lock",
)
ks = replace_once(
    ks,
    "static std::vector<std::string> key_dirs_to_commit;\n",
    '''static std::vector<std::string>& GetKeyDirsToCommit() {
    static auto* dirs = new std::vector<std::string>();
    return *dirs;
}
''',
    "KeyStorage lazy deferred-upgrade directories",
)
ks = re.sub(r"\bkey_upgrade_lock\b", "GetKeyUpgradeLock()", ks)
ks = re.sub(r"\bkey_dirs_to_commit\b", "GetKeyDirsToCommit()", ks)
ks_path.write_text(ks)

metadata_path = vold / "MetadataCrypt.cpp"
metadata = metadata_path.read_text()
metadata = re.sub(r"\bkEmptyAuthentication\b", "GetEmptyAuthentication()", metadata)
metadata = replace_once(
    metadata,
    'static const std::string kDmNameUserdata = "userdata";\n',
    '''static const std::string& GetDmNameUserdata() {
    static auto* value = new std::string("userdata");
    return *value;
}
''',
    "MetadataCrypt lazy userdata dm-name",
)
metadata = re.sub(r"\bkDmNameUserdata\b", "GetDmNameUserdata()", metadata)
metadata_path.write_text(metadata)

# The actual V4.5 recovery ELF contains Utils.cpp.  Its namespace-scope mutex is
# therefore part of the same recovery constructor boundary even though it is not
# DE-policy state.  Keep the lock process-lifetime and initialize it at first use.
utils_path = vold / "Utils.cpp"
utils = utils_path.read_text()
utils = replace_once(
    utils,
    "static std::mutex kSecurityLock;\n",
    '''static std::mutex& GetSecurityLock() {
    static auto* lock = new std::mutex();
    return *lock;
}
''',
    "Utils recovery security lock",
)
utils = re.sub(r"\bkSecurityLock\b", "GetSecurityLock()", utils)
utils_path.write_text(utils)

vh_path = vold / "VoldUtil.h"
vh = vh_path.read_text()
vh = replace_once(
    vh,
    "extern android::fs_mgr::Fstab fstab_default;\n",
    "android::fs_mgr::Fstab& GetFstabDefault();\n",
    "VoldUtil lazy Fstab declaration",
)
vh_path.write_text(vh)

vcpp_path = vold / "VoldUtil.cpp"
vcpp = vcpp_path.read_text()
vcpp = replace_once(
    vcpp,
    "android::fs_mgr::Fstab fstab_default;\n",
    '''android::fs_mgr::Fstab& GetFstabDefault() {
    static auto* fstab = new android::fs_mgr::Fstab();
    return *fstab;
}
''',
    "VoldUtil lazy Fstab storage",
)
vcpp_path.write_text(vcpp)

fstab_users = []
for path in vold.rglob("*"):
    if not path.is_file() or path.suffix not in (".cpp", ".h", ".cc"):
        continue
    if path in (vh_path, vcpp_path):
        continue
    text = path.read_text(errors="ignore")
    if "fstab_default" not in text:
        continue
    text = re.sub(r"\bfstab_default\b", "GetFstabDefault()", text)
    path.write_text(text)
    fstab_users.append(str(path.relative_to(vold)))

if not fstab_users:
    raise SystemExit("V4.6 Fstab audit unexpectedly found no consumers")

final_fs = fs_path.read_text()
for forbidden in (
    "std::map<userid_t, EncryptionPolicy> s_de_policies;",
    "std::map<userid_t, EncryptionPolicy> s_ce_policies;",
    "std::set<userid_t> s_ephemeral_users;",
    "std::string de_key_raw_ref;",
    "const std::string device_key_dir",
    "const std::string user_key_dir",
):
    if forbidden in final_fs:
        raise SystemExit(f"V4.6 unsafe FsCrypt namespace object survived: {forbidden}")

for required in (
    "std::map<userid_t, EncryptionPolicy>& GetDePolicies()",
    "std::map<userid_t, EncryptionPolicy>& GetCePolicies()",
    "std::set<userid_t>& GetEphemeralUsers()",
    "std::string& GetDeKeyRawRef()",
    "[H40 FSCRYPTLAZY] DE policies ready:",
    "[H40 FSCRYPTLAZY] DE policy insertion complete:",
):
    if required not in final_fs:
        raise SystemExit(f"V4.6 lazy FsCrypt contract missing: {required}")

final_ks = ks_path.read_text()
for forbidden in (
    'const KeyAuthentication kEmptyAuthentication{""};',
    "static std::mutex key_upgrade_lock;",
    "static std::vector<std::string> key_dirs_to_commit;",
):
    if forbidden in final_ks:
        raise SystemExit(f"unsafe KeyStorage namespace object survived: {forbidden}")
for required in (
    "static std::mutex& GetKeyUpgradeLock()",
    "static auto* lock = new std::mutex();",
    "static std::vector<std::string>& GetKeyDirsToCommit()",
    "static auto* dirs = new std::vector<std::string>();",
    "std::lock_guard<std::mutex> lock(GetKeyUpgradeLock())",
):
    if required not in final_ks:
        raise SystemExit(f"lazy KeyStorage contract missing: {required}")
if "android::fs_mgr::Fstab fstab_default;" in vcpp_path.read_text():
    raise SystemExit("namespace-scope Fstab survived")
if "static const std::string kDmNameUserdata" in metadata_path.read_text():
    raise SystemExit("namespace-scope MetadataCrypt std::string survived")
if "static std::mutex kSecurityLock;" in utils_path.read_text():
    raise SystemExit("namespace-scope Utils security mutex survived")
if "GetSecurityLock()" not in utils_path.read_text():
    raise SystemExit("lazy Utils security mutex missing")

leftovers = []
for path in vold.rglob("*"):
    if path.is_file() and path.suffix in (".cpp", ".h", ".cc"):
        text = path.read_text(errors="ignore")
        if "fstab_default" in text:
            leftovers.append(str(path.relative_to(vold)))
if leftovers:
    raise SystemExit(f"V4.6 fstab_default consumers survived: {leftovers}")

print("Applied H.40 V4.6 recovery-safe lazy FsCrypt/key globals")
print("  FsCrypt maps/set/strings: first-use leaked storage")
print("  KeyStorage empty authentication/upgrade state: first-use")
print("  MetadataCrypt userdata dm-name: first-use")
print("  Utils security mutex: first-use")
print("  vold default Fstab: first-use")
print("  rewritten Fstab consumers: " + ", ".join(sorted(fstab_users)))
