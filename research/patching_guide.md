# Firmware Patching Guide

A hands-on guide to modifying, deploying, and testing patches in the vphone-cli
boot chain. Covers the kernelcache, iBoot (iBSS/iBEC/LLB), TXM, and AVPBooter.

---

## Prerequisites

| Requirement        | Notes                                              |
| -----------------
- | -------------------------------------------------- |
| macOS 15+ Sequoia  | SIP and AMFI disabled                              |
| Python venv        | `make setup_venv` (capstone, keystone, pyimg4)     |
| Build toolchain    | `make setup_tools` (brew deps, libimobiledevice)   |
| Prepared firmware  | `make fw_prepare` already run inside `vm/`         |
| Working VM         | `make setup_machine` completed at least once       |

Activate the venv before any Python work:

```sh
source .venv/bin/activate
```

---

## 1. Understanding the Boot Chain

The VM boots through a chain of firmware images, each loaded by the previous:

```
AVPBooter  →  iBSS  →  iBEC  →  LLB  →  TXM  →  kernelcache  →  iOS
```

Each component is stored as an **IM4P** container (Apple's IMG4 payload format)
inside the restore directory:

```
vm/
├── AVPBooter.vresearch1.bin                              # raw binary
└── iPhone*_Restore/
    ├── Firmware/dfu/iBSS.vresearch101.RELEASE.im4p
    ├── Firmware/dfu/iBEC.vresearch101.RELEASE.im4p
    ├── Firmware/all_flash/LLB.vresearch101.RELEASE.im4p
    ├── Firmware/txm.iphoneos.research.im4p
    └── kernelcache.research.vphone600                    # IM4P
```

IM4P files are typically LZFSE-compressed. The patching pipeline handles
decompression, patching, and recompression automatically.

---

## 2. Quick-Start: Verify the Pipeline

Before writing real patches, confirm the pipeline works end-to-end with a
trivial string replacement:

```sh
python3 scripts/verify_patch.py vm/iPhone*_Restore/kernelcache.research.vphone600
```

This overwrites the first `"Darwin"` string with `"Levthn"` in the
kernelcache IM4P, producing a `.patched` file alongside the original.

To verify the patch took effect after booting:

```sh
# SSH into the VM and check
ssh root@localhost -p 2222 'sysctl kern.ostype'
# Expected: kern.ostype: Levthn
```

---

## 3. Anatomy of a Patch

Every patch in the codebase follows the same pattern:

1. **Find** the patch site dynamically (no hardcoded offsets)
2. **Validate** the existing bytes match expectations
3. **Emit** replacement bytes
4. **Log** the patch with offset and before/after state

### Finding Patch Sites

The patchers use several anchor strategies:

| Strategy              | Example                                    | Used By          |
| --------------------- | ------------------------------------------ | ---------------- |
| String xref           | Find `"rootvp"` → trace ADRP+ADD callers  | kernel, iBoot    |
| Symbol lookup         | `_panic` via BL frequency analysis         | kernel           |
| Instruction pattern   | `tbnz w8, #5` near known string ref        | kernel           |
| Constant search       | `0x4447` (DGST magic)                      | AVPBooter        |
| Call-flow analysis    | Find function → scan for BL → follow       | kernel           |

**Rule:** Never hardcode file offsets or pre-assembled instruction bytes.
All instruction bytes come from Keystone assembly helpers (`asm()`, `NOP`,
`MOV_W0_0`, etc.).

### Example: Reading a Patch

From [kernel_patch_apfs_snapshot.py](../scripts/patchers/kernel_patch_apfs_snapshot.py):

```python
def patch_apfs_root_snapshot(self):
    # 1. Find the string "__APFS_ROOT_SNAPSHOT__" in the binary
    # 2. Trace ADRP+ADD xrefs to find the function referencing it
    # 3. Locate the tbnz w8, #5 instruction (sealed-volume check)
    # 4. Replace with NOP to skip the check
    self.emit(offset, NOP, "NOP tbnz w8,#5 (root snapshot seal check)")
```

---

## 4. Modifying Existing Patches

### Kernelcache

The kernel patcher lives in `scripts/patchers/kernel*.py` as a mixin class
hierarchy:

```
KernelPatcherBase                    # Mach-O parsing, ADRP/BL indexes, emit()
├── KernelPatchApfsSnapshotMixin     # Patch  1
├── KernelPatchApfsSealMixin         # Patch  2
├── KernelPatchBsdInitMixin          # Patch  3
├── ...                              # Patches 4-26
└── KernelPatcher                    # Top-level: find_all() + apply()
```

To modify an existing kernel patch:

```sh
# 1. Open the mixin file for the patch you want to change
#    e.g., scripts/patchers/kernel_patch_apfs_seal.py

# 2. Edit the patch logic (find + emit)

# 3. Test on an extracted kernelcache
python3 -c "
from patchers.kernel import KernelPatcher
from pyimg4 import IM4P

with open('vm/iPhone17,3_26.3.1_23D8133_Restore/kernelcache.research.vphone600', 'rb') as f:
    im4p = IM4P(f.read())
im4p.payload.decompress()
data = bytearray(im4p.payload.data)

kp = KernelPatcher(data, verbose=True)
patches = kp.find_all()
for off, bts, desc in patches:
    print(f'  0x{off:08X}: {desc}')
print(f'\n{len(patches)} patches found')
"
```

### iBoot (iBSS / iBEC / LLB)

The iBoot patcher is in `scripts/patchers/iboot.py`. All three stages share
the same binary payload (different IM4P fourcc). The `mode` parameter controls
which patches apply:

| Mode   | Patches Applied                                        |
| ------ | ------------------------------------------------------ |
| `ibss` | Serial labels, image4 callback bypass                  |
| `ibec` | Serial labels, image4 callback bypass, boot-args       |
| `llb`  | All of ibec + rootfs bypass + panic bypass              |

To test iBoot patches in isolation:

```python
from patchers.iboot import IBootPatcher
from pyimg4 import IM4P

with open('vm/iPhone*_Restore/Firmware/dfu/iBSS.vresearch101.RELEASE.im4p', 'rb') as f:
    im4p = IM4P(f.read())
im4p.payload.decompress()
data = bytearray(im4p.payload.data)

p = IBootPatcher(data, mode='ibss', label='Loaded iBSS', verbose=True)
n = p.apply()
print(f'{n} patches applied')
```

---

## 5. Writing a New Patch

### Step 1: Research the Target

Before writing any code, understand what you're patching:

```sh
# Extract the raw kernel for analysis
python3 -c "
from pyimg4 import IM4P
with open('vm/iPhone*_Restore/kernelcache.research.vphone600', 'rb') as f:
    im4p = IM4P(f.read())
im4p.payload.decompress()
with open('/tmp/kernel.raw', 'wb') as f:
    f.write(im4p.payload.data)
print(f'Extracted {len(im4p.payload.data)} bytes to /tmp/kernel.raw')
"

# Disassemble a region around a known string
python3 -c "
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open('/tmp/kernel.raw', 'rb').read()

# Find your target string
needle = b'your_target_string'
off = data.find(needle)
print(f'String at file offset 0x{off:X}')
"
```

Use the kernel symbol database for lookups:

```sh
# Search for symbol names
sqlite3 research/kernel_info/kernel_symbols.db \
  "SELECT name, fileoff FROM symbols WHERE name LIKE '%your_function%'"
```

### Step 2: Create a Mixin (Kernel) or Add to Existing Patcher

For kernel patches, create a new mixin file:

```
scripts/patchers/kernel_patch_your_feature.py
```

Follow the existing pattern — use `self.find_string_refs()`, `self.disas()`,
`self.emit()`, and the assembly helpers from `kernel_asm.py`.

Key helpers available in `KernelPatcherBase`:

| Method                        | Purpose                                      |
| ----------------------------- | -------------------------------------------- |
| `self.find_string_refs(s)`    | Find all ADRP+ADD xrefs to a string          |
| `self.disas(off, count)`      | Disassemble `count` instructions at `off`     |
| `self.func_start(off)`        | Walk backward to find function prologue       |
| `self.emit(off, bytes, desc)` | Record and apply a patch                      |
| `self.bl_callers[off]`        | List of offsets that BL to `off`              |
| `self.panic_off`              | File offset of `_panic`                       |

Assembly helpers from `kernel_asm.py`:

| Helper       | Output                                |
| ------------ | ------------------------------------- |
| `asm("...")`  | Assemble ARM64 instruction → bytes   |
| `NOP`        | 4-byte NOP                            |
| `MOV_W0_0`   | `mov w0, #0`                          |
| `MOV_W0_1`   | `mov w0, #1`                          |
| `MOV_X0_0`   | `mov x0, #0`                          |
| `MOV_X0_1`   | `mov x0, #1`                          |
| `RET`        | `ret`                                 |
| `CMP_W0_W0`  | `cmp w0, w0` (forces Z=1)            |

### Step 3: Wire It In

Add the mixin to the `KernelPatcher` class in `scripts/patchers/kernel.py`:

```python
from .kernel_patch_your_feature import KernelPatchYourFeatureMixin

class KernelPatcher(
    KernelPatchYourFeatureMixin,   # ← add here
    ...existing mixins...,
    KernelPatcherBase,
):
    def find_all(self):
        ...
        self.patch_your_feature()   # ← call here
        return self.patches
```

### Step 4: Test Before Deploying

```sh
# Dry run — find patches without applying
python3 -c "
from patchers.kernel import KernelPatcher
from pyimg4 import IM4P

with open('vm/iPhone*_Restore/kernelcache.research.vphone600', 'rb') as f:
    im4p = IM4P(f.read())
im4p.payload.decompress()

kp = KernelPatcher(bytearray(im4p.payload.data), verbose=True)
patches = kp.find_all()
print(f'{len(patches)} patches found')
for off, bts, desc in patches:
    print(f'  0x{off:08X} [{len(bts)}B] {desc}')
"
```

---

## 6. Deploying Patched Firmware

### Full Re-Patch (Recommended)

The safest way to deploy changes. Re-patches all components from clean IPSW
extracts:

```sh
# 1. Re-prepare firmware (re-extracts from IPSWs, overwrites previous patches)
make fw_prepare

# 2. Patch everything with your changes
make fw_patch          # regular (51 patches)
# OR
make fw_patch_dev      # dev mode (64 patches)
# OR
make fw_patch_jb       # jailbreak (126 patches)

# 3. Boot DFU → restore → boot
make boot_dfu          # VM enters DFU mode
make restore           # Flash patched firmware via idevicerestore
make boot              # Normal boot with GUI
```

### Single-Component Re-Patch

For faster iteration on a single component, you can re-extract and re-patch
just that component:

```sh
# Example: re-patch only the kernelcache
python3 -c "
import sys; sys.path.insert(0, 'scripts')
from fw_patch import load_firmware, save_firmware, patch_kernelcache

path = 'vm/iPhone17,3_26.3.1_23D8133_Restore/kernelcache.research.vphone600'

# Re-extract clean from IPSW first (optional — skip if you kept a backup)
# cp path path.bak

im4p, data, was_im4p, orig = load_firmware(path)
patch_kernelcache(data)
save_firmware(path, im4p, data, was_im4p, orig)
"

# Then restore
make boot_dfu
make restore
make boot
```

### CFW Installation (Post-Restore)

After restoring patched firmware, install custom filesystem modifications:

```sh
make cfw_install       # Base CFW (10 phases)
make cfw_install_dev   # Dev CFW (12 phases — adds rpcserver)
make cfw_install_jb    # JB CFW (14 phases — adds jetsam/procursus/basebin)
```

---

## 7. The Full Iteration Loop

```
 ┌──────────────────────────────────────────┐
 │  1. Edit patcher source                  │
 │     scripts/patchers/kernel_patch_*.py   │
 │     scripts/patchers/iboot.py            │
 └───────────────┬──────────────────────────┘
                 │
 ┌───────────────▼──────────────────────────┐
 │  2. Test patch finder (dry run)          │
 │     python3 -c "from patchers..."        │
 └───────────────┬──────────────────────────┘
                 │
 ┌───────────────▼──────────────────────────┐
 │  3. Apply patches to firmware            │
 │     make fw_patch                        │
 └───────────────┬──────────────────────────┘
                 │
 ┌───────────────▼──────────────────────────┐
 │  4. Deploy to VM                         │
 │     make boot_dfu                        │
 │     make restore                         │
 └───────────────┬──────────────────────────┘
                 │
 ┌───────────────▼──────────────────────────┐
 │  5. Boot and verify                      │
 │     make boot                            │
 │     ssh root@localhost -p 2222           │
 └───────────────┬──────────────────────────┘
                 │
 ┌───────────────▼──────────────────────────┐
 │  6. Install CFW (if needed)              │
 │     make cfw_install                     │
 └───────────────┬──────────────────────────┘
                 │
                 └──→ Back to step 1
```

---

## 8. Debugging Failed Patches

### Patch Finder Fails

If a patch site isn't found, the patcher exits with a descriptive error.
Run with `verbose=True` to see the search trace:

```python
kp = KernelPatcher(data, verbose=True)
```

Common causes:
- **String not present:** The kernel version changed and the anchor string
  was renamed or removed. Search for similar strings with `grep -a`.
- **Instruction pattern changed:** Apple recompiled the function with
  different register allocation. Use `self.disas()` to examine the new code
  and update the pattern match.
- **Function inlined:** The compiler inlined the target. Look for the
  inlined body at call sites.

### Boot Fails After Patching

| Symptom                | Likely Cause                         | Fix                           |
| ---------------------- | ------------------------------------ | ----------------------------- |
| DFU loop               | iBSS/iBEC image4 bypass incomplete   | Check iboot.py callback patch |
| Panic at iBoot         | LLB rootfs or panic bypass missed    | Check LLB patches             |
| Panic at kernel        | Kernel patch broke control flow      | Revert, boot clean, compare   |
| Mounts read-only       | APFS seal/snapshot patch missing     | Check patches 1-2             |
| App won't launch       | Launch constraints / sandbox         | Check patches 4-5, 17-26      |

### Comparing Patched vs Clean

```sh
# Extract clean kernel
python3 -c "
from pyimg4 import IM4P
# Use a backup or re-extract from IPSW
with open('kernelcache.clean.im4p', 'rb') as f:
    im4p = IM4P(f.read())
im4p.payload.decompress()
open('/tmp/kc_clean.raw', 'wb').write(im4p.payload.data)
"

# Binary diff
cmp -l /tmp/kc_clean.raw /tmp/kc_patched.raw | head -20
```

---

## 9. Reference

### Make Targets

| Target                | Action                                           |
| --------------------- | ------------------------------------------------ |
| `make fw_prepare`     | Download IPSWs, extract, merge cloudOS → iPhone  |
| `make fw_patch`       | Patch all 6 boot chain components (regular)      |
| `make fw_patch_dev`   | Regular + dev TXM patches                        |
| `make fw_patch_jb`    | Regular + JB kernel/iBoot/TXM patches            |
| `make boot_dfu`       | Boot VM in DFU mode (headless)                   |
| `make restore`        | Flash patched firmware via idevicerestore         |
| `make boot`           | Normal boot with GUI window                      |
| `make cfw_install`    | Install CFW mods over SSH                        |

### Patch Counts by Variant

| Variant     | Boot Chain | CFW Phases | Total Patches |
| ----------- | :--------: | :--------: | :-----------: |
| Regular     |     51     |     10     |      61       |
| Development |     64     |     12     |      76       |
| Jailbreak   |    126     |     14     |     140       |

### Key Files

| File                              | Purpose                               |
| --------------------------------- | ------------------------------------- |
| `scripts/fw_patch.py`             | Main firmware patcher (regular)       |
| `scripts/patchers/kernel.py`      | Kernel patcher entry point            |
| `scripts/patchers/kernel_base.py` | Base class (Mach-O parsing, indexes)  |
| `scripts/patchers/kernel_asm.py`  | Assembly helpers (Keystone wrappers)  |
| `scripts/patchers/iboot.py`       | iBSS/iBEC/LLB patcher                |
| `scripts/patchers/txm.py`         | TXM patcher                          |
| `scripts/verify_patch.py`         | Smoke test (Darwin → Levthn)          |


### Debugging Setup
---
Setting up debugserver to attach with in IDA is pretty easy, it allows us attach to the instance and emulator and debugging. 




### Kernelcache Debugging
---



### Enum Device Deployment.
---



