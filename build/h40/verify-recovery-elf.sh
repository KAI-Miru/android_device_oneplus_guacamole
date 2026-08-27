#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 RECOVERY_ELF REPORT_DIRECTORY" >&2
  exit 2
fi

recovery_elf="$1"
report_dir="$2"

test -f "$recovery_elf"
mkdir -p "$report_dir"
command -v readelf >/dev/null
command -v strings >/dev/null

readelf --file-header --wide "$recovery_elf" \
  | tee "$report_dir/recovery-elf-header.txt"
readelf --dynamic --wide "$recovery_elf" \
  | tee "$report_dir/recovery-dynamic-section.txt"

awk '
  /\(NEEDED\)/ {
    line = $0
    sub(/^.*Shared library: \[/, "", line)
    sub(/\].*$/, "", line)
    print line
  }
' "$report_dir/recovery-dynamic-section.txt" \
  | tee "$report_dir/recovery-dt-needed.txt"

if ! grep -Fqx 'libdl.so' "$report_dir/recovery-dt-needed.txt"; then
  echo "recovery does not have a direct DT_NEEDED entry for libdl.so" >&2
  exit 1
fi

if grep -Fqx 'libdecrypt_recovery.so' "$report_dir/recovery-dt-needed.txt"; then
  echo "recovery has a forbidden hard DT_NEEDED on libdecrypt_recovery.so" >&2
  exit 1
fi

string_report="$report_dir/recovery-adapter-strings.txt"
: > "$string_report"
all_strings="$(mktemp)"
trap 'rm -f -- "$all_strings"' EXIT
strings -a "$recovery_elf" > "$all_strings"

check_string() {
  local label="$1"
  local value="$2"
  if ! grep -Fqx -- "$value" "$all_strings"; then
    echo "missing $label string: $value" >&2
    exit 1
  fi
  printf 'present\t%s\t%s\n' "$label" "$value" >> "$string_report"
}

reject_string() {
  local label="$1"
  local value="$2"
  if grep -Fqx -- "$value" "$all_strings"; then
    echo "forbidden $label string survived: $value" >&2
    exit 1
  fi
  printf 'absent\t%s\t%s\n' "$label" "$value" >> "$string_report"
}

check_string dlopen_library 'libdecrypt_recovery.so'
check_string dlsym_verify \
  '_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi'
check_string dlsym_setup_de_ce '_Z11setup_de_cei'
check_string dlsym_get_password_type '_Z17get_password_typei'
check_string dlsym_init_user0_ce '_Z21fscrypt_init_user0_cev'
check_string dlsym_mount_metadata \
  '_Z32fscrypt_mount_metadata_encryptedRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE'

check_string runtime_cryptoeng_fqname \
  'vendor.oplus.hardware.cryptoeng@1.0::ICryptoeng'
check_string runtime_system_ce_path '/data/system_ce/0'
check_string runtime_media_ce_path '/data/media/0'
check_string log_marker_abi 'I:Oplus H.40 decrypt ABI loaded'

adapter_version=v3
if grep -Fqx -- \
  'I:Oplus H.40 v4 hybrid activated; TWRP owns metadata mapping, OEM owns DE/CE' \
  "$all_strings"
then
  adapter_version=v4-hybrid
  check_string log_marker_activation \
    'I:Oplus H.40 v4 hybrid activated; TWRP owns metadata mapping, OEM owns DE/CE'
  check_string log_marker_cryptoeng_ready \
    'I:Oplus H.40 v4 ICryptoeng/default binderized get+ping ready after %d stable samples'
  check_string log_marker_metadata_adopt \
    'I:Oplus H.40 v4 hybrid adopting TWRP metadata mapping for %s'
  check_string log_marker_de_bypass \
    'I:Oplus H.40 v4 preserving TWRP metadata mapping and bypassing generic DE/user discovery'
  check_string log_marker_fatal \
    'E:Oplus H.40 v4 hybrid adapter entered process-lifetime fatal state: %s'
  check_string log_marker_metadata_failclosed \
    'E:Oplus H.40 v4 TWRP metadata mapping failed after runtime activation; refusing FDE fallback'
  check_string log_marker_handoff_failclosed \
    'E:Oplus H.40 v4 DE handoff failed after TWRP metadata mount (result=%d)'
  reject_string old_oem_metadata_invocation \
    'I:Oplus H.40 invoking metadata mount for %s'
else
  check_string log_marker_activation \
    'I:Oplus H.40 v3 adapter activated; generic keystore2 fallback is now forbidden'
  check_string log_marker_cryptoeng_ready \
    'I:Oplus H.40 v3 ICryptoeng/default binderized get+ping ready after %d stable samples'
  check_string log_marker_de_bypass \
    'I:Oplus H.40 v3 bypassing generic TWRP keystore2 DE/user discovery'
  check_string log_marker_fatal \
    'E:Oplus H.40 v3 adapter entered process-lifetime fatal state: %s'
fi

# These postcondition strings are shared with the reviewed V3 state machine.
check_string log_marker_policy \
  'I:Oplus H.40 v3 FS_IOC_GET_ENCRYPTION_POLICY_EX version=%u for %s'
check_string log_marker_key_present \
  'I:Oplus H.40 v3 FS_IOC_GET_ENCRYPTION_KEY_STATUS PRESENT for %s: status=%u'
check_string log_marker_key_not_present \
  'E:Oplus H.40 v3 FS_IOC_GET_ENCRYPTION_KEY_STATUS not PRESENT for %s: status=%u'
check_string log_marker_active_unavailable \
  'E:Oplus H.40 active adapter returned unavailable; refusing generic credential fallback'
check_string log_marker_no_lock_success \
  'I:Oplus H.40 v3 no-lock user 0 CE postcondition satisfied'
check_string log_marker_credential_success \
  'I:Oplus H.40 v3 user 0 CE postcondition satisfied'

sha256sum "$recovery_elf" > "$report_dir/recovery-elf.sha256"
{
  stat --printf='size_bytes=%s\n' "$recovery_elf"
  echo "elf_path=$recovery_elf"
} > "$report_dir/recovery-elf-metadata.txt"

{
  echo "result=pass"
  echo "adapter_version=$adapter_version"
  echo "required_dlsym_strings=5"
  echo "required_runtime_strings=3"
  echo "dlopen_library_string=present"
  echo "dt_needed_libdl=present"
  echo "dt_needed_libdecrypt_recovery=absent"
  echo "binary_uploaded=false"
} | tee "$report_dir/adapter-verification.txt"

