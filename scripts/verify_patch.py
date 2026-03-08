#!/usr/bin/env python3
"""
verify_patch.py — Smoke-test the patching pipeline.

Overwrites ALL occurrences of "Darwin" with "Levthn" in a
kernelcache IM4P to confirm that patch → repack → restore → boot works.

This script reuses the same PAYP-preserving IM4P repack logic from
fw_patch.py, so the output is restore-ready.

Usage:
    python3 verify_patch.py <kernelcache.im4p>

    --in-place    Overwrite the original file (default: writes .patched)

Typical workflow:
    make fw_prepare                     # extract clean firmware
    make fw_patch                       # apply all boot chain patches
    python3 scripts/verify_patch.py \\
        --in-place vm/iPhone*_Restore/kernelcache.research.vphone600
    make boot_dfu                       # DFU mode
    make restore                        # flash patched firmware
    make boot                           # boot and verify with:
                                        #   ssh root@localhost -p 2222 'sysctl kern.ostype'
"""

import sys, os

# Allow imports from the scripts directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fw_patch import load_firmware, save_firmware


def main():
    in_place = "--in-place" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--in-place"]

    if not args:
        print(f"Usage: {sys.argv[0]} [--in-place] <kernelcache.im4p>")
        sys.exit(1)

    path = args[0]
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    # Load firmware (handles IM4P decompression automatically)
    im4p, data, was_im4p, original_raw = load_firmware(path)
    fmt = "IM4P" if was_im4p else "raw"
    print(f"[*] Loaded {fmt}, {len(data)} bytes")

    # Find and replace ALL "Darwin" → "Levthn"
    needle = b"Darwin"
    replace = b"Levthn"
    count = 0
    offset = 0
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        # Show context (up to 40 bytes after) to identify which string
        context = data[idx : idx + 60].split(b"\x00")[0]
        data[idx : idx + len(replace)] = replace
        count += 1
        print(f"  [{count}] 0x{idx:06X}: {context}")
        offset = idx + len(replace)

    if count == 0:
        print("[!] 'Darwin' string not found in payload")
        sys.exit(1)

    print(f"[+] Patched {count} 'Darwin' → 'Levthn' occurrences")

    # Save with PAYP preservation (same as fw_patch.py)
    out_path = path if in_place else path + ".patched"
    save_firmware(out_path, im4p, data, was_im4p, original_raw)
    print(f"[+] Written to {out_path}")


if __name__ == "__main__":
    main()