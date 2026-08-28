# ColorOS 12.1 H.40 stock-first inputs

This directory makes the Guacamole recovery image reproducible without a local
stock ROM extraction or a previously repacked boot image. `manifest.json` is the
authority for every byte count and SHA-256 digest.

The boot header, kernel, stock ramdisk, recovery DTBO, and DTB were extracted
from the exact 96 MiB H.40 `boot.img` whose SHA-256 is
`991cf738f5a6dc874c6261fa073c89182e61935a9493dc27347699c4d0a68792`.
The assembler reconstructs its 78,548,992-byte boot payload exactly before any
TWRP overlay is applied.

`overlay/` contains only release-tested files absent from the raw H.40 recovery
ramdisk. In particular, `vendor.oplus.hardware.commondcs@1.0.so` is the
75,024-byte H.40 `system_ext/lib64` copy used by Guacamole RC2. The 76,160-byte
H.40 ODM copy used by Hotdog is intentionally rejected.

The stock-first verifier requires the original kernel, DTB, recovery DTBO,
stock recovery executable, SELinux policy, and every unrelated stock ramdisk
entry to remain exact. It also verifies the final `boot` AVB footer and the
96 MiB partition size.
