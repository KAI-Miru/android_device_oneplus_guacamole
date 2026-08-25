#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-h40-v46-portidentity.py RECOVERY_ROOT VOLD_ROOT")

recovery_cpp_path = Path(sys.argv[1]) / "oplus_h40_decrypt.cpp"
cpp = recovery_cpp_path.read_text()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


cpp = replace_once(
    cpp,
    '#include <sys/stat.h>\n#include <sys/wait.h>\n#include <unistd.h>\n',
    '#include <sys/mount.h>\n#include <sys/stat.h>\n#include <sys/wait.h>\n#include <unistd.h>\n'
    '#include <fstream>\n#include <vector>\n',
    "V4.6 installed-system identity includes",
)

# Isolate the whole V4.5 function, not the first nested block.  The V4.5 body
# contains an early multi-line if() whose closing brace is followed by a blank
# line, so delimiter-based matching is unsafe.  Brace depth is exact for this
# known function and leaves the surrounding recovery source untouched.
start = cpp.find('bool PrepareKeymasterBuildIdentity() {')
if start < 0:
    raise SystemExit("V4.6 unable to find V4.5 PrepareKeymasterBuildIdentity")
brace = cpp.find('{', start)
depth = 0
end = -1
for pos in range(brace, len(cpp)):
    if cpp[pos] == '{':
        depth += 1
    elif cpp[pos] == '}':
        depth -= 1
        if depth == 0:
            end = pos + 1
            break
if end < 0:
    raise SystemExit("V4.6 unable to isolate complete V4.5 PrepareKeymasterBuildIdentity")
while end < len(cpp) and cpp[end] == '\n':
    end += 1

new = r'''bool IsValidAndroidRelease(const std::string& value) {
    if (value.empty() || value.size() > 16) return false;
    bool last_was_dot = true;
    for (char c : value) {
        if (c == '.') {
            if (last_was_dot) return false;
            last_was_dot = true;
        } else if (c >= '0' && c <= '9') {
            last_was_dot = false;
        } else {
            return false;
        }
    }
    return !last_was_dot;
}

bool IsLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

bool IsValidSecurityPatch(const std::string& value) {
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 4 || i == 7) continue;
        if (value[i] < '0' || value[i] > '9') return false;
    }
    const int year = std::stoi(value.substr(0, 4));
    const int month = std::stoi(value.substr(5, 2));
    const int day = std::stoi(value.substr(8, 2));
    if (year < 2000 || month < 1 || month > 12 || day < 1) return false;
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int max_day = days[month - 1];
    if (month == 2 && IsLeapYear(year)) max_day = 29;
    return day <= max_day;
}

bool ReadBuildPropValue(const std::string& path, const std::vector<std::string>& keys,
                        std::string* value, std::string* matched_key) {
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '#') continue;
        const size_t eq = line.find('=', first);
        if (eq == std::string::npos) continue;

        std::string name = line.substr(first, eq - first);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
        for (const auto& key : keys) {
            if (name != key) continue;
            std::string parsed = line.substr(eq + 1);
            const size_t value_first = parsed.find_first_not_of(" \t");
            if (value_first == std::string::npos) parsed.clear();
            else parsed.erase(0, value_first);
            while (!parsed.empty() && (parsed.back() == ' ' || parsed.back() == '\t')) {
                parsed.pop_back();
            }
            *value = parsed;
            if (matched_key) *matched_key = key;
            return true;
        }
    }
    return false;
}

bool ReadIdentityPair(const std::string& path, const std::vector<std::string>& release_keys,
                      const std::vector<std::string>& patch_keys, std::string* release,
                      std::string* patch) {
    std::string release_key;
    std::string patch_key;
    if (!ReadBuildPropValue(path, release_keys, release, &release_key)) return false;
    if (!ReadBuildPropValue(path, patch_keys, patch, &patch_key)) return false;
    if (!IsValidAndroidRelease(*release) || !IsValidSecurityPatch(*patch)) {
        LOGERR("[H40 PORTIDENTITY] invalid identity in %s\n", path.c_str());
        return false;
    }
    LOGINFO("[H40 PORTIDENTITY] property source: path=%s releaseKey=%s patchKey=%s\n",
            path.c_str(), release_key.c_str(), patch_key.c_str());
    return true;
}

bool DiscoverInstalledSystemIdentity(std::string* release, std::string* patch) {
    std::string slot_suffix = ReadProperty("ro.boot.slot_suffix");
    if (slot_suffix.empty()) {
        const std::string slot = ReadProperty("ro.boot.slot");
        if (slot == "a" || slot == "b") slot_suffix = "_" + slot;
    }
    if (slot_suffix != "_a" && slot_suffix != "_b") {
        LOGERR("[H40 PORTIDENTITY] unable to determine active system slot: suffix=%s\n",
               slot_suffix.c_str());
        return false;
    }

    const std::string block = "/dev/block/bootdevice/by-name/system" + slot_suffix;
    constexpr char kMountPoint[] = "/tmp/h40-installed-system";
    if (mkdir(kMountPoint, 0700) != 0 && errno != EEXIST) {
        LOGERR("[H40 PORTIDENTITY] mkdir failed: %s\n", strerror(errno));
        return false;
    }

    constexpr unsigned long kReadOnlyFlags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;
    const char* mounted_type = nullptr;
    if (mount(block.c_str(), kMountPoint, "ext4", kReadOnlyFlags, "") == 0) {
        mounted_type = "ext4";
    } else if (mount(block.c_str(), kMountPoint, "erofs", kReadOnlyFlags, "") == 0) {
        mounted_type = "erofs";
    }
    if (!mounted_type) {
        LOGERR("[H40 PORTIDENTITY] read-only system mount failed for slot %s: %s\n",
               slot_suffix.c_str(), strerror(errno));
        rmdir(kMountPoint);
        return false;
    }

    LOGINFO("[H40 PORTIDENTITY] installed system mounted read-only: slot=%s fs=%s\n",
            slot_suffix.c_str(), mounted_type);

    struct Candidate {
        const char* relative_path;
        std::vector<std::string> release_keys;
        std::vector<std::string> patch_keys;
    };
    const std::vector<Candidate> candidates = {
        {"/system/build.prop",
         {"ro.system.build.version.release", "ro.build.version.release"},
         {"ro.system.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/build.prop",
         {"ro.system.build.version.release", "ro.build.version.release"},
         {"ro.system.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/system/system/build.prop",
         {"ro.system.build.version.release", "ro.build.version.release"},
         {"ro.system.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/product/build.prop",
         {"ro.product.build.version.release", "ro.build.version.release"},
         {"ro.product.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/system_ext/build.prop",
         {"ro.system_ext.build.version.release", "ro.build.version.release"},
         {"ro.system_ext.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/system/product/build.prop",
         {"ro.product.build.version.release", "ro.build.version.release"},
         {"ro.product.build.version.security_patch", "ro.build.version.security_patch"}},
        {"/system/system_ext/build.prop",
         {"ro.system_ext.build.version.release", "ro.build.version.release"},
         {"ro.system_ext.build.version.security_patch", "ro.build.version.security_patch"}},
    };

    bool found = false;
    for (const auto& candidate : candidates) {
        const std::string path = std::string(kMountPoint) + candidate.relative_path;
        std::string candidate_release;
        std::string candidate_patch;
        if (ReadIdentityPair(path, candidate.release_keys, candidate.patch_keys,
                             &candidate_release, &candidate_patch)) {
            *release = candidate_release;
            *patch = candidate_patch;
            found = true;
            break;
        }
    }

    if (umount(kMountPoint) != 0) {
        LOGERR("[H40 PORTIDENTITY] failed to unmount installed system: %s\n", strerror(errno));
        return false;
    }
    rmdir(kMountPoint);

    if (!found) {
        LOGERR("[H40 PORTIDENTITY] no reliable release/SPL pair found in installed system\n");
        return false;
    }
    return true;
}

bool PrepareKeymasterBuildIdentity() {
    const std::string keymaster_state = ReadProperty("init.svc.keymaster-4-0");
    if (keymaster_state == "running" || keymaster_state == "restarting") {
        LOGERR("[H40 PORTIDENTITY] refusing late identity change: keymaster-4-0=%s\n",
               keymaster_state.c_str());
        return false;
    }

    std::string system_release;
    std::string system_patch;
    if (!DiscoverInstalledSystemIdentity(&system_release, &system_patch)) return false;

    const std::string vendor_patch = ReadProperty("ro.vendor.build.security_patch");
    if (!IsValidSecurityPatch(vendor_patch)) {
        LOGERR("[H40 PORTIDENTITY] recovery vendor patch missing/invalid\n");
        return false;
    }

    LOGINFO("[H40 PORTIDENTITY] source: release=%s systemPatch=%s vendorPatch=%s\n",
            system_release.c_str(), system_patch.c_str(), vendor_patch.c_str());

    if (!RunResetprop("ro.build.version.release", system_release.c_str())) return false;
    if (!RunResetprop("ro.build.version.security_patch", system_patch.c_str())) return false;

    const std::string after_release = ReadProperty("ro.build.version.release");
    const std::string after_patch = ReadProperty("ro.build.version.security_patch");
    const std::string after_vendor_patch = ReadProperty("ro.vendor.build.security_patch");
    if (after_release != system_release || after_patch != system_patch) {
        LOGERR("[H40 PORTIDENTITY] final identity verification failed\n");
        return false;
    }
    if (after_vendor_patch != vendor_patch) {
        LOGERR("[H40 PORTIDENTITY] vendor patch changed unexpectedly: before=%s after=%s\n",
               vendor_patch.c_str(), after_vendor_patch.c_str());
        return false;
    }

    LOGINFO("[H40 PORTIDENTITY] applied: release=%s systemPatch=%s\n",
            after_release.c_str(), after_patch.c_str());
    return true;
}

'''
cpp = cpp[:start] + new + cpp[end:]
recovery_cpp_path.write_text(cpp)

final = recovery_cpp_path.read_text()
for forbidden in (
    'constexpr char kSystemRelease[] = "14";',
    'constexpr char kSystemSecurityPatch[] = "2025-03-01";',
    '[H40 PORTIDENTITY] before:',
    '[H40 PORTIDENTITY] after:',
):
    if forbidden in final:
        raise SystemExit(f"V4.6 hardcoded/obsolete identity path survived: {forbidden}")
for required in (
    'bool DiscoverInstalledSystemIdentity(std::string* release, std::string* patch)',
    'MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC',
    '"/dev/block/bootdevice/by-name/system" + slot_suffix',
    '"ro.system.build.version.release"',
    '"ro.system.build.version.security_patch"',
    '[H40 PORTIDENTITY] source:',
    '[H40 PORTIDENTITY] applied:',
):
    if required not in final:
        raise SystemExit(f"V4.6 dynamic identity contract missing: {required}")
if final.count('RunResetprop("') != 2:
    raise SystemExit("V4.6 must override exactly two read-only build properties")
if 'RunResetprop("ro.vendor.build.security_patch"' in final:
    raise SystemExit("V4.6 must not override H.40 vendor patch level")
identity_call = final.find('if (!PrepareKeymasterBuildIdentity()) return false;')
qsee_trigger = final.find('if (!SetProperty("enable.qseecomd.service", "1")) return false;')
if identity_call < 0 or qsee_trigger < 0 or identity_call >= qsee_trigger:
    raise SystemExit("V4.6 identity discovery must finish before QSEE/Keymaster trigger")

print("Applied H.40 V4.6 dynamic installed-system Keymaster identity")
print("  system source: active slotted system partition, read-only")
print("  release/SPL: parsed and validated from installed build.prop")
print("  recovery ro.build identity: exactly two resetprop overrides")
print("  H.40 vendor SPL: preserved")
print("  failure mode: closed")
