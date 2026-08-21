#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
CPP = ROOT / 'oplus_h40_decrypt.cpp'
HPP = ROOT / 'oplus_h40_decrypt.hpp'
PM = ROOT / 'partitionmanager.cpp'


def must_replace(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one match, found {count}')
    return text.replace(old, new, 1)


cpp = CPP.read_text()
hpp = HPP.read_text()
pm = PM.read_text()

# Public pre-metadata gate. V4 deliberately starts the H.40 crypto runtime and
# the TWRP keystore2 runtime before TeamWin's own MetadataCrypt reader runs.
hpp = must_replace(
    hpp,
    'bool IsActive();\nResult MountMetadataAndPrepareDe(const std::string& mount_point, User0State* user0_state);\n',
    'bool IsActive();\nResult PrepareMetadataRuntime();\nResult MountMetadataAndPrepareDe(const std::string& mount_point, User0State* user0_state);\n',
    'hpp API insertion',
)

cpp = cpp.replace('Oplus H.40 v3 adapter entered process-lifetime fatal state:',
                  'Oplus H.40 v4 hybrid adapter entered process-lifetime fatal state:')
cpp = cpp.replace('Oplus H.40 v3 ICryptoeng/default binderized get+ping ready',
                  'Oplus H.40 v4 ICryptoeng/default binderized get+ping ready')

anchor = '''bool IsActive() {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    return GetRuntimeState().phase != Phase::kIdle;
}

'''
insert = '''Result PrepareMetadataRuntime() {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    const Api& api = GetApi();
    if (api.handle == nullptr) return Result::kUnavailable;

    RuntimeState& state = GetRuntimeState();
    if (state.phase == Phase::kFatal) return Result::kFailure;
    if (state.phase == Phase::kActive || state.phase == Phase::kPreparedLocked ||
        state.phase == Phase::kPreparedNoLock || state.phase == Phase::kUnlocked) {
        return Result::kSuccess;
    }
    if (state.phase != Phase::kIdle) {
        return FailActive("unexpected phase before TWRP metadata runtime preparation");
    }

    state.phase = Phase::kActive;
    LOGINFO("Oplus H.40 v4 hybrid activated; TWRP owns metadata mapping, OEM owns DE/CE\\n");

    if (!PrepareMetadataServices()) {
        return FailActive("metadata crypto services unavailable");
    }

    // TeamWin android_system_vold 12.1 retrieves the four-file metadata key
    // through keystore2. The H.40 ramdisk does not ship that service, so the
    // hybrid image supplies the matching TWRP keystore2 runtime under /system/tw.
    if (!SetProperty("ctl.start", "keystore2-v4") ||
        !WaitForPropertyValue("init.svc.keystore2-v4", "running",
                              "TWRP keystore2 runtime")) {
        return FailActive("TWRP keystore2 runtime unavailable");
    }
    return Result::kSuccess;
}

bool IsActive() {
    std::lock_guard<std::mutex> lock(GetRuntimeMutex());
    return GetRuntimeState().phase != Phase::kIdle;
}

'''
cpp = must_replace(cpp, anchor, insert, 'PrepareMetadataRuntime insertion')

old_mount = '''    const Api& api = GetApi();
    if (api.handle == nullptr) return Result::kUnavailable;

    RuntimeState& state = GetRuntimeState();
    if (state.phase == Phase::kFatal) return Result::kFailure;
    if (state.phase == Phase::kPreparedLocked || state.phase == Phase::kPreparedNoLock) {
        *user0_state = state.user0;
        return Result::kSuccess;
    }
    if (state.phase == Phase::kUnlocked) {
        return FailActive("metadata preparation requested after CE unlock");
    }
    if (state.phase != Phase::kIdle) {
        return FailActive("reentrant metadata preparation");
    }

    state.phase = Phase::kActive;
    LOGINFO("Oplus H.40 v3 adapter activated; generic keystore2 fallback is now forbidden\\n");

    if (!PrepareMetadataServices()) return FailActive("metadata crypto services unavailable");

    LOGINFO("Oplus H.40 invoking metadata mount for %s\\n", mount_point.c_str());
    const bool mounted = api.mount_metadata(mount_point);
    LOGINFO("Oplus H.40 metadata mount for %s returned %d\\n", mount_point.c_str(), mounted);
    if (!mounted) return FailActive("OEM metadata mount failed");

    if (!ValidateMapper(&state.user0)) return FailActive("metadata mapper validation failed");
'''
new_mount = '''    const Api& api = GetApi();
    if (api.handle == nullptr) return Result::kUnavailable;

    RuntimeState& state = GetRuntimeState();
    if (state.phase == Phase::kFatal) return Result::kFailure;
    if (state.phase == Phase::kPreparedLocked || state.phase == Phase::kPreparedNoLock) {
        *user0_state = state.user0;
        return Result::kSuccess;
    }
    if (state.phase == Phase::kUnlocked) {
        return FailActive("metadata preparation requested after CE unlock");
    }
    if (state.phase != Phase::kActive) {
        return FailActive("TWRP metadata handoff requested before runtime preparation");
    }

    LOGINFO("Oplus H.40 v4 hybrid adopting TWRP metadata mapping for %s\\n",
            mount_point.c_str());
    if (!ValidateMapper(&state.user0)) return FailActive("TWRP metadata mapper validation failed");
'''
cpp = must_replace(cpp, old_mount, new_mount, 'replace OEM metadata mount')

# V4 always gives the metadata key and dm-default-key mapping to TeamWin vold.
# OEM activation is a precondition only for the later DE/CE handoff.
pre_pattern = re.compile(
    r'#ifdef TW_INCLUDE_OPLUS_H40_DECRYPT\n'
    r'\t\t\tbool metadata_mounted = false;\n'
    r'\t\t\tbool oplus_metadata_used = false;\n'
    r'\t\t\ttwrp::oplus_h40::User0State oplus_user0;\n'
    r'\t\t\tconst twrp::oplus_h40::Result oplus_metadata =\n'
    r'\t\t\t\ttwrp::oplus_h40::MountMetadataAndPrepareDe\(Decrypt_Data->Mount_Point,\n'
    r'\t\t\t\t\t&oplus_user0\);\n'
    r'\t\t\tif \(oplus_metadata == twrp::oplus_h40::Result::kSuccess\) \{\n'
    r'\t\t\t\tmetadata_mounted = true;\n'
    r'\t\t\t\toplus_metadata_used = true;\n'
    r'\t\t\t\} else if \(oplus_metadata == twrp::oplus_h40::Result::kUnavailable\) \{\n'
    r'\t\t\t\tmetadata_mounted = android::vold::fscrypt_mount_metadata_encrypted\((.*?)\);\n'
    r'\t\t\t\} else \{\n'
    r'\t\t\t\tg_oplus_h40_decrypt_blocked = true;\n'
    r'\t\t\t\tLOGERR\("Oplus H\.40 metadata setup failed; refusing generic metadata/FDE fallback\\n"\);\n'
    r'\t\t\t\treturn;\n'
    r'\t\t\t\}\n'
    r'\t\t\tif \(metadata_mounted\) \{\n'
    r'#else\n'
    r'\t\t\tif \(android::vold::fscrypt_mount_metadata_encrypted\((.*?)\)\) \{\n'
    r'#endif',
    re.S,
)
match = pre_pattern.search(pm)
if not match:
    raise SystemExit('partitionmanager pre-metadata V3 block not found')
if match.group(1) != match.group(2):
    raise SystemExit('generic metadata call differs between V3 and baseline branches')
generic_args = match.group(1)
pre_repl = f'''#ifdef TW_INCLUDE_OPLUS_H40_DECRYPT
\t\t\tbool oplus_metadata_used = false;
\t\t\tbool oplus_runtime_ready = false;
\t\t\ttwrp::oplus_h40::User0State oplus_user0;
\t\t\tconst twrp::oplus_h40::Result oplus_runtime =
\t\t\t\ttwrp::oplus_h40::PrepareMetadataRuntime();
\t\t\tif (oplus_runtime == twrp::oplus_h40::Result::kSuccess) {{
\t\t\t\toplus_runtime_ready = true;
\t\t\t}} else if (oplus_runtime == twrp::oplus_h40::Result::kFailure) {{
\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t\tLOGERR("Oplus H.40 v4 runtime preparation failed; refusing metadata/FDE fallback\\n");
\t\t\t\treturn;
\t\t\t}}
\t\t\tif (android::vold::fscrypt_mount_metadata_encrypted({generic_args})) {{
#else
\t\t\tif (android::vold::fscrypt_mount_metadata_encrypted({generic_args})) {{
#endif'''
pm = pm[:match.start()] + pre_repl + pm[match.end():]

mount_anchor = '''\t\t\t\tif (Decrypt_Data->Mount(false)) {
#ifdef TW_INCLUDE_OPLUS_H40_DECRYPT
\t\t\t\t\tif (oplus_metadata_used) {
'''
mount_insert = '''\t\t\t\tif (Decrypt_Data->Mount(false)) {
#ifdef TW_INCLUDE_OPLUS_H40_DECRYPT
\t\t\t\t\tif (oplus_runtime_ready) {
\t\t\t\t\t\tconst twrp::oplus_h40::Result oplus_handoff =
\t\t\t\t\t\t\ttwrp::oplus_h40::MountMetadataAndPrepareDe(
\t\t\t\t\t\t\t\tDecrypt_Data->Mount_Point, &oplus_user0);
\t\t\t\t\t\tif (oplus_handoff == twrp::oplus_h40::Result::kSuccess) {
\t\t\t\t\t\t\toplus_metadata_used = true;
\t\t\t\t\t\t} else if (oplus_handoff == twrp::oplus_h40::Result::kFailure) {
\t\t\t\t\t\t\tDecrypt_Data->Is_Decrypted = false;
\t\t\t\t\t\t\tg_oplus_h40_decrypt_blocked = true;
\t\t\t\t\t\t\tLOGERR("Oplus H.40 v4 DE handoff failed after TWRP metadata mount\\n");
\t\t\t\t\t\t\treturn;
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tif (oplus_metadata_used) {
'''
pm = must_replace(pm, mount_anchor, mount_insert, 'post-mount Oplus handoff')

pm = pm.replace('Oplus H.40 v3 bypassing generic TWRP keystore2 DE/user discovery',
                'Oplus H.40 v4 preserving TWRP metadata mapping and bypassing generic DE/user discovery')
pm = pm.replace('Oplus H.40 v3 synthesized TWRP user 0 state:',
                'Oplus H.40 v4 synthesized TWRP user 0 state:')

CPP.write_text(cpp)
HPP.write_text(hpp)
PM.write_text(pm)

print('Applied H.40 V4 hybrid source transform')
print('  metadata mapper: TeamWin android_system_vold')
print('  DE/password/CE:  Oplus H.40 libdecrypt_recovery')
print('  runtime:         H.40 qsee/keymaster/cryptoeng + TWRP keystore2-v4')
