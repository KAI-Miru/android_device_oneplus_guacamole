#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
pm_path = root / 'partitionmanager.cpp'
pm = pm_path.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one match, found {count}')
    return text.replace(old, new, 1)

# Once PrepareMetadataRuntime() succeeded, every later handoff result is
# authoritative.  kUnavailable is not a legal route back into TeamWin DE after
# the Oplus process state has been activated.
old_handoff = '''\t\t\t\t\t\tif (oplus_handoff == twrp::oplus_h40::Result::kSuccess) {
\t\t\t\t\t\t\toplus_metadata_used = true;
\t\t\t\t\t\t} else if (oplus_handoff == twrp::oplus_h40::Result::kFailure) {
\t\t\t\t\t\t\tDecrypt_Data->Is_Decrypted = false;
\t\t\t\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t\t\t\t\tLOGERR("Oplus H.40 v4 DE handoff failed after TWRP metadata mount\\n");
\t\t\t\t\t\t\treturn;
\t\t\t\t\t\t}
'''
new_handoff = '''\t\t\t\t\t\tif (oplus_handoff == twrp::oplus_h40::Result::kSuccess) {
\t\t\t\t\t\t\toplus_metadata_used = true;
\t\t\t\t\t\t} else {
\t\t\t\t\t\t\tDecrypt_Data->Is_Decrypted = false;
\t\t\t\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t\t\t\t\tLOGERR("Oplus H.40 v4 DE handoff failed after TWRP metadata mount (result=%d)\\n",
\t\t\t\t\t\t\t\tstatic_cast<int>(oplus_handoff));
\t\t\t\t\t\t\treturn;
\t\t\t\t\t\t}
'''
pm = replace_once(pm, old_handoff, new_handoff, 'post-metadata handoff fail-closed')

# Likewise, if the TeamWin four-file metadata reader fails after the Oplus
# runtime has been deliberately activated, do not continue into legacy FDE.
old_metadata_failure = '''\t\t\t} else {
\t\t\t\tLOGINFO("Unable to decrypt metadata encryption\\n");
\t\t\t}
#else
'''
new_metadata_failure = '''\t\t\t} else {
#ifdef TW_INCLUDE_OPLUS_H40_DECRYPT
\t\t\t\tif (oplus_runtime_ready) {
\t\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t\t\tLOGERR("Oplus H.40 v4 TWRP metadata mapping failed after runtime activation; refusing FDE fallback\\n");
\t\t\t\t\treturn;
\t\t\t\t}
#endif
\t\t\t\tLOGINFO("Unable to decrypt metadata encryption\\n");
\t\t\t}
#else
'''
pm = replace_once(pm, old_metadata_failure, new_metadata_failure, 'metadata failure fail-closed')

pm_path.write_text(pm)
print('Applied H.40 V4 fail-closed hardening')
