#!/usr/bin/env python3
from pathlib import Path
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: apply-h40-v48-secondary-user.py RECOVERY_ROOT VOLD_ROOT"
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"V4.8 {label}: expected one source match, found {count}")
    return text.replace(old, new, 1)


recovery_root = Path(sys.argv[1])
vold_root = Path(sys.argv[2])
adapter_path = recovery_root / "oplus_h40_decrypt.cpp"
manager_path = recovery_root / "partitionmanager.cpp"
fscrypt_path = vold_root / "FsCrypt.cpp"

adapter = adapter_path.read_text()
manager = manager_path.read_text()
fscrypt = fscrypt_path.read_text()

if "[H40 USERMAP]" in adapter:
    raise SystemExit("V4.8 transform already applied: [H40 USERMAP]")
for marker, source in (
    ("[H40 FSCRYPTKEYRING]", adapter),
    ("[H40 FSCRYPTMODE]", fscrypt),
):
    if marker not in source:
        raise SystemExit(f"V4.8 requires the post-V4.7 source marker: {marker}")

old_guard = '''        if (user_id != 0) {
            LOGERR("Oplus H.40 user0-only mode refusing secondary/unsupported user id %d from %s/%s\\n",
                   user_id, path, entry->d_name);
            valid = false;
            break;
        }
        found_user0 = true;
'''
new_guard = '''        if (user_id == INT_MAX) {
            LOGERR("Oplus H.40 user0-only mode refusing malformed user entry %s/%s\\n",
                   path, entry->d_name);
            valid = false;
            break;
        }
        if (user_id != 0) {
            LOGINFO("[H40 USERMAP] ignoring secondary user id %d from %s/%s; "
                    "user0-only decrypt remains enforced\\n",
                    user_id, path, entry->d_name);
            errno = 0;
            continue;
        }
        found_user0 = true;
'''
adapter = replace_once(
    adapter,
    old_guard,
    new_guard,
    "secondary-user layout guard",
)

scan_start = adapter.index("bool ScanSingleUserDirectory(")
scan_end = adapter.index("\nbool ValidateSingleUser0DeLayout()", scan_start)
scan_body = adapter[scan_start:scan_end]
for required in (
    "if (user_id == INT_MAX)",
    "Oplus H.40 user0-only mode refusing malformed user entry %s/%s",
    "if (user_id != 0)",
    "[H40 USERMAP] ignoring secondary user id %d from %s/%s; ",
    "user0-only decrypt remains enforced",
    "continue;",
    "found_user0 = true;",
):
    if required not in scan_body:
        raise SystemExit(f"V4.8 scan contract missing after transform: {required}")
secondary_start = scan_body.index("if (user_id != 0)")
secondary_end = scan_body.index("\n        }", secondary_start)
secondary_body = scan_body[secondary_start:secondary_end]
if "errno = 0;" not in secondary_body or \
        secondary_body.index("errno = 0;") > secondary_body.index("continue;"):
    raise SystemExit("V4.8 secondary-user branch does not clear errno before continue")
if "refusing secondary/unsupported user id" in adapter:
    raise SystemExit("V4.8 obsolete all-secondary fatal guard survived")
if adapter.count("*user_id = INT_MAX;") != 2:
    raise SystemExit("V4.8 canonical parser no longer rejects both overflow and aliases")

layout_start = adapter.index("bool ValidateSingleUser0DeLayout()")
layout_end = adapter.index("\nbool CheckFscryptKeyPresent(", layout_start)
layout_body = adapter[layout_start:layout_end]
for required in (
    'CheckReadableFile("/data/unencrypted/key/version")',
    'CheckReadableDirectory("/data/system_de/0")',
    'CheckReadableFile("/data/system/users/0.xml")',
    'ScanSingleUserDirectory("/data/system_de", "", true)',
    'ScanSingleUserDirectory("/data/system/users", "", false)',
    'ScanSingleUserDirectory("/data/system/users", ".xml", true)',
):
    if required not in layout_body:
        raise SystemExit(f"V4.8 user0 layout contract missing: {required}")

credential_start = adapter.index("Result DecryptUser(")
credential_body = adapter[credential_start:]
if 'if (user_id != 0)' not in credential_body or \
        'refusing credential for user %d' not in credential_body:
    raise SystemExit("V4.8 adapter nonzero-user credential refusal was weakened")

for required in (
    "if (oplus_active && user_id != 0)",
    'user0.userId = "0";',
    "user_list->clear();",
    "user_list->push_back(user0);",
    "Oplus H.40 user 0 decrypted; secondary-user sweep disabled",
):
    if required not in manager:
        raise SystemExit(f"V4.8 partition-manager user0-only contract missing: {required}")
synth_start = manager.index("std::vector<users_struct>* user_list = Get_Users_List()")
synth_end = manager.index("Check_Users_Decryption_Status();", synth_start)
synth_body = manager[synth_start:synth_end]
if synth_body.count("user_list->push_back(") != 1:
    raise SystemExit("V4.8 synthesized TWRP user map is no longer exactly user0-only")

with adapter_path.open("w", newline="\n") as stream:
    stream.write(adapter)

print("Applied H.40 V4.8 canonical secondary-user coexistence fix")
print("  layout: canonical secondary profiles are ignored during user0 discovery")
print("  malformed: overflow and noncanonical numeric aliases remain fail-closed")
print("  decrypt: adapter and TWRP continue to authorize only user 0")
