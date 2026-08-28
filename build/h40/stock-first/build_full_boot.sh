#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --twrp-cpio FILE --twrp-tree DIR --recovery-root DIR --work-dir DIR --output FILE" >&2
  exit 2
}

twrp_cpio=
twrp_tree=
recovery_root=
work_dir=
output=
while (($#)); do
  case "$1" in
    --twrp-cpio) twrp_cpio="$2"; shift 2 ;;
    --twrp-tree) twrp_tree="$2"; shift 2 ;;
    --recovery-root) recovery_root="$2"; shift 2 ;;
    --work-dir) work_dir="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$twrp_cpio" && -n "$twrp_tree" && -n "$recovery_root" && -n "$work_dir" && -n "$output" ]] || usage
[[ -f "$twrp_cpio" && -d "$twrp_tree" && -d "$recovery_root" ]] || usage
[[ ! -e "$output" ]] || { echo "output already exists: $output" >&2; exit 1; }
[[ ! -e "$work_dir" ]] || { echo "work directory already exists: $work_dir" >&2; exit 1; }

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"
prebuilt="$repo_root/prebuilt/h40"
manifest="$prebuilt/manifest.json"
mkdir -p "$work_dir"

python3 "$script_dir/verify_prebuilts.py" \
  --prebuilt-dir "$prebuilt" \
  --manifest "$manifest" \
  --report "$work_dir/prebuilt-verification.json"

python3 "$script_dir/assemble_stock_boot_v2.py" \
  --prebuilt-dir "$prebuilt" \
  --manifest "$manifest" \
  --output "$work_dir/stock-boot-payload.img" \
  --report "$work_dir/stock-assemble.json"
python3 "$script_dir/extract_boot_ramdisk.py" \
  --image "$work_dir/stock-boot-payload.img" \
  --raw-cpio "$work_dir/stock.cpio" \
  --report "$work_dir/stock-extract.json"
python3 "$script_dir/extract_newc_regulars.py" \
  --cpio "$work_dir/stock.cpio" \
  --output "$work_dir/stock-tree"

python3 "$script_dir/make_private_twrp_overlay.py" \
  --twrp-tree "$twrp_tree" \
  --twrp-cpio "$twrp_cpio" \
  --stock-cpio "$work_dir/stock.cpio" \
  --stock-tree "$work_dir/stock-tree" \
  --dlopen-root-manifest "$script_dir/h40-proprietary-manifest.json" \
  --elf-audit-dir "$script_dir" \
  --output "$work_dir/private-overlay.cpio" \
  --manifest "$work_dir/private-overlay.json" \
  --required-helper system/bin/magiskboot
python3 "$script_dir/make_stock_patch_overlay.py" \
  --stock-tree "$work_dir/stock-tree" \
  --stock-cpio "$work_dir/stock.cpio" \
  --output "$work_dir/stock-patch-overlay.cpio" \
  --manifest "$work_dir/stock-patch-overlay.json" \
  --enable-adb
python3 "$script_dir/h40_cryptoeng_dependency.py" \
  --stock-cpio "$work_dir/stock.cpio" \
  --source "$prebuilt/overlay/system/lib64/vendor.oplus.hardware.commondcs@1.0.so" \
  --elf-audit-dir "$script_dir" \
  --output "$work_dir/cryptoeng-overlay.cpio" \
  --manifest "$work_dir/cryptoeng-overlay.json"

python3 "$script_dir/merge_newc.py" \
  --base "$work_dir/stock.cpio" \
  --overlay "$work_dir/private-overlay.cpio" \
  --overlay "$work_dir/stock-patch-overlay.cpio" \
  --overlay "$work_dir/cryptoeng-overlay.cpio" \
  --output "$work_dir/hybrid-base.cpio" \
  --report "$work_dir/hybrid-base-merge.json"
python3 "$script_dir/gzip_deterministic.py" \
  "$work_dir/hybrid-base.cpio" "$work_dir/hybrid-base.cpio.gz"
python3 "$script_dir/verify_hybrid.py" \
  --stock-cpio "$work_dir/stock.cpio" \
  --twrp-cpio "$twrp_cpio" \
  --raw-cpio "$work_dir/hybrid-base.cpio" \
  --gzip-cpio "$work_dir/hybrid-base.cpio.gz" \
  --private-manifest "$work_dir/private-overlay.json" \
  --stock-patch-manifest "$work_dir/stock-patch-overlay.json" \
  --dlopen-root-manifest "$script_dir/h40-proprietary-manifest.json" \
  --h40-cryptoeng-overlay "$work_dir/cryptoeng-overlay.cpio" \
  --h40-cryptoeng-manifest "$work_dir/cryptoeng-overlay.json" \
  --elf-audit-dir "$script_dir" \
  --report "$work_dir/hybrid-base-verification.json"

python3 "$script_dir/apply_recovery_fixes_cpio.py" \
  --input "$work_dir/hybrid-base.cpio" \
  --fixer "$repo_root/build/h40/apply-recovery-fixes.py" \
  --work-dir "$work_dir/recovery-fixes" \
  --output "$work_dir/hybrid-fixed.cpio" \
  --report "$work_dir/recovery-fixes-cpio.json"
python3 "$repo_root/build/h40/package-keystore2-runtime.py" \
  --recovery-root "$recovery_root" \
  --output "$work_dir/keystore2-runtime" \
  --source-date-epoch 0
python3 "$script_dir/apply_rc2_runtime_cpio.py" \
  --input "$work_dir/hybrid-fixed.cpio" \
  --recovery-root "$recovery_root" \
  --runtime "$work_dir/keystore2-runtime" \
  --output "$work_dir/final-ramdisk.cpio" \
  --report "$work_dir/runtime-cpio.json"
python3 "$script_dir/gzip_deterministic.py" \
  "$work_dir/final-ramdisk.cpio" "$work_dir/final-ramdisk.cpio.gz"
final_ramdisk_bytes="$(wc -c < "$work_dir/final-ramdisk.cpio.gz")"
if ((final_ramdisk_bytes > 42000000)); then
  echo "final ramdisk is too large for the 96 MiB boot partition: $final_ramdisk_bytes" >&2
  exit 1
fi

python3 "$script_dir/repack_boot_v2.py" \
  --stock-boot "$work_dir/stock-boot-payload.img" \
  --ramdisk "$work_dir/final-ramdisk.cpio.gz" \
  --output "$work_dir/boot-preavb.img" \
  --report "$work_dir/boot-repack.json"
cp "$work_dir/boot-preavb.img" "$work_dir/boot.img"
python3 "$script_dir/avbtool_android-12.1.0_r4.py" add_hash_footer \
  --image "$work_dir/boot.img" \
  --partition_name boot \
  --partition_size 100663296 \
  --algorithm NONE \
  --salt 30b78a2f2a2db01f1b142deeb9933256b2b8f1f4802c8bdfdcc1730da819405e \
  --prop 'com.android.build.boot.fingerprint:qti/msmnile/msmnile:12/SKQ1.210216.001/1679565591292:user/release-keys' \
  --prop 'com.android.build.boot.os_version:12' \
  --prop 'com.android.build.boot.security_patch:2022-12-05' \
  --prop 'com.android.build.boot.security_patch:2022-12-05'
mkdir -p "$work_dir/verify-avb"
cp "$work_dir/boot.img" "$work_dir/verify-avb/boot.img"
python3 "$script_dir/avbtool_android-12.1.0_r4.py" verify_image \
  --image "$work_dir/verify-avb/boot.img" | tee "$work_dir/avb-verify.txt"
python3 "$script_dir/avbtool_android-12.1.0_r4.py" info_image \
  --image "$work_dir/boot.img" | tee "$work_dir/avb-info.txt"

python3 "$script_dir/verify_h40_stock_first.py" \
  --stock-boot "$work_dir/stock-boot-payload.img" \
  --final-boot "$work_dir/boot.img" \
  --stock-cpio "$work_dir/stock.cpio" \
  --raw-cpio "$work_dir/final-ramdisk.cpio" \
  --gzip-cpio "$work_dir/final-ramdisk.cpio.gz" \
  --prebuilt-dir "$prebuilt" \
  --manifest "$manifest" \
  --recovery-root "$recovery_root" \
  --stock-patch-report "$work_dir/stock-patch-overlay.json" \
  --private-manifest "$work_dir/private-overlay.json" \
  --fix-report "$work_dir/recovery-fixes-cpio.json" \
  --runtime-report "$work_dir/runtime-cpio.json" \
  --report "$work_dir/verification.json"

mkdir -p "$(dirname "$output")"
install -m 0644 "$work_dir/boot.img" "$output"
sha256sum "$output" > "$output.sha256"
echo "ready=$output"
