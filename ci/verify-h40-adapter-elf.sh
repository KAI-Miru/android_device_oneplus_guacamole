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

check_string dlopen_library 'libdecrypt_recovery.so'
check_string dlsym_verify \
  '_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi'
check_string dlsym_setup_de_ce '_Z11setup_de_cei'
check_string dlsym_get_password_type '_Z17get_password_typei'
check_string dlsym_init_user0_ce '_Z21fscrypt_init_user0_cev'
check_string dlsym_mount_metadata \
  '_Z32fscrypt_mount_metadata_encryptedRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE'
check_string log_marker_abi 'I:Oplus H.40 decrypt ABI loaded'
check_string log_marker_metadata_stop \
  'E:Oplus H.40 metadata setup failed; refusing FDE fallback'
check_string log_marker_setup_stop \
  'E:Oplus H.40 metadata or DE/user discovery previously failed; refusing another setup attempt'
check_string log_marker_credential_stop \
  'E:Oplus H.40 metadata or DE/user discovery previously failed; refusing credential handling'
check_string log_marker_no_lock_recheck \
  'I:Oplus H.40 rechecking no-credential user 0 CE postcondition'

sha256sum "$recovery_elf" > "$report_dir/recovery-elf.sha256"
{
  stat --printf='size_bytes=%s\n' "$recovery_elf"
  echo "elf_path=$recovery_elf"
} > "$report_dir/recovery-elf-metadata.txt"

{
  echo "result=pass"
  echo "required_dlsym_strings=5"
  echo "required_log_markers=5"
  echo "dlopen_library_string=present"
  echo "dt_needed_libdl=present"
  echo "dt_needed_libdecrypt_recovery=absent"
  echo "binary_uploaded=false"
} | tee "$report_dir/adapter-verification.txt"
