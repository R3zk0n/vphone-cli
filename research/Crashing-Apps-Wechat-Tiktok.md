# Crashing Apps: WeChat & TikTok

## Overview

Investigation into app crashes when running WeChat and TikTok on the vphone virtual iPhone environment. Goal: identify crash causes, determine if kernel/CFW patches or VM configuration changes are needed.

## Status

**Phase:** Patch 26 (entitlement constraint bypass) confirmed working. Patch 27 needed — OSEntitlements context consistency panic.

## Symptoms

### WeChat

AMFI kills the process at launch. Kernel log shows constraint violations for every embedded framework and dylib:

```
AMFI: constraint violation .../WeChat.app/Frameworks/owl.framework/owl has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/ilink_network.framework/ilink_network has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/SoundTouch.framework/SoundTouch has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/MMRouter.framework/MMRouter has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/Lottie.framework/Lottie has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/andromeda.framework/andromeda has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/openssl.framework/openssl has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/ProtobufLite.framework/ProtobufLite has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/matrixreport.framework/matrixreport has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/NewMessageRingUtil.framework/NewMessageRingUtil has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/App.framework/App has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/sutuplus.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/MiYou.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/DouTu.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/wechat.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/WeChatPure.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/MsgFilt.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/GameLogin.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/WeAppTool.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/wcplugins.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/Frameworks/Joker.dylib has entitlements but is not a main binary
AMFI: constraint violation .../WeChat.app/wcbg.dylib has entitlements but is not a main binary
```

Affected binaries include `.framework` bundles and standalone `.dylib` files (WeChat plugins like `wechat.dylib`, `MiYou.dylib`, `wcplugins.dylib`, etc.).

#### LLDB Confirmation

Attached to WeChat process (PID 636) at `_dyld_start`. On continue:

- **dyld loads successfully** — all frameworks and dylibs are mapped (ObjC runtime emits duplicate class warnings)
- **Process exits with status 45 (0x2d)** — AMFI policy kill, not a crash or app-level exit
- Exit code 45 = AMFI denial after code signature validation fails the constraint check

**Note:** This is a **modded WeChat IPA** with injected tweak dylibs:

| Dylib | Purpose |
|---|---|
| `HBWechatHelper.dylib` | Red envelope auto-grab |
| `libPineappleDylib.dylib` | ObjC method tracing/hooking |
| `libdkhelperDylib.dylib` | Method tracing + red envelope |
| `WeChatPure.dylib` | WeChat cleanup/purification tweak |
| `MiYou.dylib` | WeChat enhancement |
| `DouTu.dylib` | Sticker/meme tweak |
| `Joker.dylib` | WeChat tweak |
| `sutuplus.dylib` | WeChat enhancement |
| `MsgFilt.dylib` | Message filtering |
| `GameLogin.dylib` | Game login integration |
| `WeAppTool.dylib` | Mini program tools |
| `wcplugins.dylib` | Plugin loader |
| `wechat.dylib` | Core tweak |
| `wcbg.dylib` | Background execution |

**Secondary issue (post-AMFI fix):** Multiple ObjC duplicate class conflicts between tweaks:
- `WeChatRedEnvelopParam` — in `HBWechatHelper`, `WeChatPure`, and `libdkhelperDylib`
- `OCMethodTrace`, `OMTBlock`, `OMTMessageStub` — in `libPineappleDylib` and `libdkhelperDylib`
- `SSZipArchive` — in `HBWechatHelper` and `libdkhelperDylib`
- `XMLReader`, `MMServiceCenter` — in `libPineappleDylib` and main `WeChat` binary

These won't crash the app but may cause "mysterious crashes" per the ObjC runtime warning.

### TikTok

TBD — likely same AMFI issue since TikTok also ships embedded frameworks.

## Root Cause Analysis

### The Problem

AMFI enforces a launch constraint: **non-main binaries (frameworks, dylibs) must not carry entitlements**. The original App Store signature has a unified code directory that AMFI trusts, but after re-signing with `ldid`, each Mach-O gets its own independent ad-hoc signature — and AMFI checks each one individually.

### Signing Flow in `vphoned_install.m` (`vp_sign_app`)

1. **Per-bundle signing (lines 334-394):** Iterates all `Info.plist` files in the `.app`. Skips `CFBundlePackageType == "FMWK"` (line 354). Signs each non-framework bundle executable **with entitlements**.

2. **Recursive fallback (line 398):** Calls `vp_sign_binary(appPath, nil, ...)` which runs `ldid -S <appPath>` recursively on the entire `.app` directory. This is meant to catch any unsigned Mach-Os missed by step 1.

### Why It Breaks

The recursive `ldid -S` (no entitlements file) re-signs everything, but **`ldid -S` preserves existing embedded entitlements** from the original App Store binary. So frameworks/dylibs that shipped with entitlements (e.g. `get-task-allow`, keychain groups) retain them after re-signing, and AMFI rejects them as "has entitlements but is not a main binary."

WeChat is particularly affected because it ships ~20+ embedded dylibs (plugins) and frameworks, many with entitlements from the original build.

### Fix Options

| Option | Approach | Pros | Cons |
|---|---|---|---|
| **A: Strip entitlements on recursive sign** | Pass an empty entitlements plist to the recursive `ldid` call (`-S<empty.plist>`) to force-clear entitlements on non-main binaries | Clean, minimal change | Need to verify `ldid` behavior with empty plist |
| **B: Sign frameworks individually without entitlements** | After the per-bundle loop, enumerate all Mach-Os in `Frameworks/` and sign each with `-S` (no entitlements) explicitly | More control | More code, slower |
| **C: Kernel/AMFI patch** | Patch AMFI to skip the "entitlements on non-main binary" constraint check | No re-signing changes needed | Broader security impact, may mask other issues |

**Recommended: Option C (kernel patch)** — Options A/B failed because guest-side ldid doesn't reliably strip entitlements from frameworks during recursive signing. Kernel patch is the definitive fix.

## Investigation Plan

1. ~~Collect crash logs~~ — AMFI constraint violations identified from kernel log
2. ~~Identify crashing frameworks~~ — all embedded frameworks/dylibs affected
2b. ~~LLDB confirmation~~ — exit status 45 confirms AMFI kill; dyld loads fine, killed post-load
3. ~~Signing pipeline fix attempted~~ — Options A/B did not resolve (ldid recursive sign doesn't strip framework entitlements reliably)
4. ~~IDA analysis of AMFI kext~~ — identified constraint check function and patch point
5. ~~Kernel patch implemented~~ — patch 26: B.CC → B at version gate
6. ~~Verify fix with WeChat~~ — patch 26 works (no more constraint violations), but new panic in OSEntitlements
7. **Kernel patch 27 needed** — OSEntitlements context consistency check panics
8. **Re-test with WeChat** — verify patches 26+27 together resolve all crashes
9. **Test with TikTok** — confirm same fixes resolve TikTok crashes
10. **Check for secondary issues** — VM detection, GPU, network (may surface after AMFI fix)

## Fixes Applied

### Kernel Patch 26: AMFI Entitlement Constraint Bypass

**File:** `sources/FirmwarePatcher/Kernel/Patches/KernelPatchAmfiEntitlementConstraint.swift`

**IDA Analysis:**

Function `sub_FFFFFE00086442F8` in `com.apple.driver.AppleMobileFileIntegrity` kext handles entitlement validation during code signature verification. The constraint check flow:

```
0xfffffe000864444c  REV     W9, W25          ; byte-swap code signing version
0xfffffe0008644450  LSR     W9, W9, #0xA     ; extract version field
0xfffffe0008644454  CMP     W9, #0x81        ; version threshold (new format)
0xfffffe0008644458  B.CC    0xfffffe00086444B4  ← PATCH: B.CC → B (unconditional)
0xfffffe000864445c  ADD     X9, X24, #0x50
0xfffffe0008644460  LDRB    W9, [X9,#7]      ; isMainBinary flag
0xfffffe0008644464  TBNZ    W9, #0, 0xfffffe00086444B4  ; main binary → parse entitlements
                    ; --- falls through: NOT main binary → constraint violation ---
0xfffffe00086444a4  ADRL    X0, "AMFI: constraint violation %s has entitlements..."
0xfffffe00086444ac  BL      log
0xfffffe00086444b0  B       0xfffffe00086443F0  ; skip entitlement parsing (reject)
```

**Patch:** Change `B.CC` at `0xfffffe0008644458` to unconditional `B` to same target (`0xfffffe00086444B4`). This sends all binaries — regardless of code signing version or main-binary flag — to the entitlement parsing path. Non-main binaries with entitlements are no longer rejected.


**Kernel Panic**

```
Invalid denylist
apfs_clonegroup_cleanup_cookies:698: disk1s2 Removed 822 cookies and 822 mappings
[install] Installed via built-in installer as User: WeChat.app (com.tencent.qixiniphone)
apfs_clonegroup_cleanup_cookies:698: disk1s2 Removed 2883 cookies and 2883 mappings
panic(cpu 2 caller 0xfffffe002f6a6b68): "AMFI: inconsistency between instance and monitor context: 1 | 0" @OSEntitlements.cpp:239
Debugger message: panic
Memory ID: 0x0
OS release type: User
OS version: 23B85
Kernel version: Darwin Kernel Version 25.1.0: Thu Oct 23 11:11:48 PDT 2025; root:xnu-12377.42.6~55/RELEASE_ARM64_VRESEARCH1
Fileset Kernelcache UUID: 10C76B412BAD52CA8217AB748064C02B
Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F
Boot session UUID: B2C0DED3-040F-4F18-945B-D56B4047A712
iBoot version: iBoot-13822.42.2
iBoot Stage 2 version: 
secure boot?: YES
roots installed: 0
Paniclog version: 15
Debug Header address: 0xfffffe000e0f5000
Debug Header entry count: 3
TXM load address: 0xfffffe001e064000
TXM UUID: 01108044-259B-370C-891A-7FFF39799C39
Debug Header kernelcache load address: 0xfffffe002e064000
Debug Header kernelcache UUID: 10C76B41-2BAD-52CA-8217-AB748064C02B
SPTM load address: 0xfffffe000e064000
SPTM UUID: 483B7ACD-3530-3B47-A0D4-D54DF1297E2B
KernelCache slide: 0x0000000027060000
KernelCache base:  0xfffffe002e064000
Kernel slide:      0x0000000027064000
Kernel text base:  0xfffffe002e068000
Kernel text exec slide: 0x0000000027b10000
Kernel text exec base:  0xfffffe002eb14000
mach_absolute_time: 0x3de4b264
Epoch Time:        sec       usec
  Boot    : 0x69c0fe88 0x000e2822
  Sleep   : 0x00000000 0x00000000
  Wake    : 0x00000000 0x00000000
  Calendar: 0x69c0feb3 0x0007bba3

Zone info:
  Zone map: 0xfffffe1012000000 - 0xfffffe3612000000
  . VM    : 0xfffffe1012000000 - 0xfffffe15de000000
  . RO    : 0xfffffe15de000000 - 0xfffffe1878000000
  . GEN0  : 0xfffffe1878000000 - 0xfffffe1e44000000
  . GEN1  : 0xfffffe1e44000000 - 0xfffffe2410000000
  . GEN2  : 0xfffffe2410000000 - 0xfffffe29dc000000
  . GEN3  : 0xfffffe29dc000000 - 0xfffffe2fa8000000
  . DATA  : 0xfffffe2fa8000000 - 0xfffffe3612000000
  Metadata: 0xfffffe3b3c010000 - 0xfffffe3b45810000
  Bitmaps : 0xfffffe3b45810000 - 0xfffffe3b46fac000
  Extra   : 0 - 0

TPIDRx_ELy = {1: 0xfffffe28d9bd38d8  0: 0x0000000000000002  0ro: 0x0000000202f022e0 }
CORE 0: PC=0x00000001a43ad83c, LR=0x0000000198d46f18, FP=0x000000016b2518e0
CORE 1: PC=0x0000000195b92b74, LR=0x0000000234dd287c, FP=0x000000016d5ff8c0
CORE 2 is the one that panicked. Check the full backtrace for details.
CORE 3: PC=0x0000000195bcf384, LR=0x0000000195b9453c, FP=0x000000016f86db70
CORE 4: PC=0xfffffe002eb17dac, LR=0x000000024278a2d0, FP=0xfffffe7acc673f20
CORE 5: PC=0xfffffe002eb17dac, LR=0x000000024278eb94, FP=0xfffffe7acc34ff20
CORE 6: PC=0xfffffe002eb17dac, LR=0x00000001a4029038, FP=0xfffffe7acc5cbf20
CORE 7: PC=0xfffffe002eb17dac, LR=0x0000000242789cd4, FP=0xfffffe7acc71bf20
Compressor Info: 0% of compressed pages limit (OK) and 0% of segments limit (OK) with 0 swapfiles and OK swap space
Panicked task 0xfffffe29deb4b9b0: 13 pages, 1 threads: pid 442: WeChat
Panicked thread: 0xfffffe28d9bd38d8, backtrace: 0xfffffe7acc6d2e80, tid: 4959
                  lr: 0xfffffe002eb59164  fp: 0xfffffe7acc6d2f00
                  lr: 0xfffffe002ecb4120  fp: 0xfffffe7acc6d2f70
                  lr: 0xfffffe002ecb299c  fp: 0xfffffe7acc6d3030
                  lr: 0xfffffe002eb17d4c  fp: 0xfffffe7acc6d3040
                  lr: 0xfffffe002eb59250  fp: 0xfffffe7acc6d3550
                  lr: 0xfffffe002f35a850  fp: 0xfffffe7acc6d3570
                  lr: 0xfffffe002f6a6b68  fp: 0xfffffe7acc6d3650
                  lr: 0xfffffe002f69ccc0  fp: 0xfffffe7acc6d3670
                  lr: 0xfffffe002f08420c  fp: 0xfffffe7acc6d3710
                  lr: 0xfffffe002f082800  fp: 0xfffffe7acc6d3a70
                  lr: 0xfffffe002efeeda0  fp: 0xfffffe7acc6d3de0
                  lr: 0xfffffe002f187cd0  fp: 0xfffffe7acc6d3e50
                  lr: 0xfffffe002ecb2a88  fp: 0xfffffe7acc6d3f10
                  lr: 0xfffffe002eb17d4c  fp: 0xfffffe7acc6d3f20
                  lr: 0x0000000195c313f8  fp: 0x0000000000000000
      Kernel Extensions in backtrace:
         com.apple.driver.AppleMobileFileIntegrity(1.0.5)[DC4F4B6A-E3A4-3F23-8517-8534A1D40838]@0xfffffe002f692460->0xfffffe002f6bb05b
            dependency: com.apple.driver.ApplePMGR(1)[1497C1AD-9E67-39B6-9861-2B871441DD83]@0xfffffe002f712c60->0xfffffe002f77a6e3
            dependency: com.apple.iokit.CoreAnalyticsFamily(1)[0F1FB7DB-F11C-3B27-85B3-E593C2BF7A18]@0xfffffe002f9f7fc0->0xfffffe002fa01417
            dependency: com.apple.kec.corecrypto(26.0)[A80B80EC-469D-3B03-A024-36FDDD9AE18B]@0xfffffe0030589180->0xfffffe00305f3e97
            dependency: com.apple.kext.CoreTrust(1)[0B3E96FA-DA1E-30F2-BFB8-346ACDDE181B]@0xfffffe002fa01420->0xfffffe002fa0b25f
            dependency: com.apple.security.AppleImage4(7.0.0)[41E89479-AF32-305E-8061-931E08819969]@0xfffffe002f513630->0xfffffe002f536f7f


last started kext at 63940987: com.apple.driver.AppleUSBDeviceNCM       5.0.0 (addr 0xfffffe002e2d3e00, size 4471)
loaded kexts:
com.apple.driver.AppleUSBDeviceNCM      5.0.0
com.apple.driver.AppleUSBDeviceMux      1.0.0d1
com.apple.driver.AppleM68Buttons        1.0.0d1
com.apple.driver.AppleParavirtGPUIOGPUFamily    15.0.0
com.apple.IOTextEncryptionFamily        1.0.0
com.apple.filesystems.hfs.kext  704.40.4
com.apple.AppleFSCompression.AppleFSCompressionTypeZlib 1.0.0
com.apple.nke.l2tp      1.9
com.apple.filesystems.tmpfs     1
com.apple.filesystems.lifs      1
com.apple.driver.AppleVideoToolboxParavirtualization    15.0.0
com.apple.filesystems.apfs      2632.40.15
com.apple.driver.AppleARMGIC    1
com.apple.driver.AppleS8000AES  1
com.apple.driver.ApplePVPanic   1
com.apple.iokit.IOUserEthernet  1.0.1
com.apple.driver.AppleDiskImages2       514.40.7
com.apple.security.sandbox      300.0
com.apple.iokit.EndpointSecurity        1
com.apple.security.AKSAnalytics 1
com.apple.plugin.IOgPTPPlugin   1410.2
com.apple.driver.usb.cdc        5.0.0
com.apple.driver.usb.networking 5.0.0
com.apple.driver.usb.AppleUSBHostCompositeDevice        1.2
com.apple.iokit.IOMobileGraphicsFamily  343.0.0
com.apple.driver.AppleM2ScalerCSCDriver 265.0.0
com.apple.iokit.IOGPUFamily     129.2.10
com.apple.driver.AppleFirmwareKit       1
com.apple.driver.AppleVPIOP     1.0.2
com.apple.driver.AppleSPU       1
com.apple.driver.AppleFirmwareUpdateKext        1
com.apple.nke.ppp       1.9
com.apple.driver.AppleBSDKextStarter    3
com.apple.driver.usb.AppleUSBHostPacketFilter   1.0
com.apple.driver.AppleARMWatchdogTimer  1
com.apple.driver.AppleMobileApNonce     1
com.apple.driver.usb.AppleUSBXHCIPCI    1.2
com.apple.driver.usb.AppleUSBXHCI       1.2
com.apple.iokit.AppleParavirtIOSurface  15.0.0
com.apple.iokit.IOUSBMassStorageDriver  270
com.apple.iokit.IOSCSIArchitectureModelFamily   541.40.1
com.apple.iokit.IOUSBHostFamily 1.2
com.apple.iokit.IOPortFamily    1.0
com.apple.driver.AppleUSBHostMergeProperties    1.2
com.apple.driver.AppleSMC       3.1.9
com.apple.driver.RTBuddy        1.0.0
com.apple.driver.AppleEmbeddedTempSensor        1.0.0
com.apple.driver.AppleARMPMU    1.0
com.apple.iokit.IOTimeSyncFamily        1410.2
com.apple.driver.DiskImages     493.0.0
com.apple.driver.AppleSEPKeyStore       2
com.apple.driver.AppleEffaceableStorage 1.0
com.apple.driver.AppleSEPCredentialManager      1.0
com.apple.driver.AppleSEPManager        1.0.1
com.apple.driver.IODARTFamily   1
com.apple.driver.AppleA7IOP     1.0.2
com.apple.driver.IOSlaveProcessor       1
com.apple.driver.AppleLockdownMode      1
com.apple.AUC   1.0
com.apple.iokit.IOSurface       393.2.9
com.apple.iokit.IOAVFamily      1.0.0
com.apple.iokit.IOHDCPFamily    1.0.0
com.apple.iokit.IOCECFamily     1
com.apple.iokit.IOAudio2Family  1.0
com.apple.driver.AppleIISController     500.2
com.apple.driver.AppleAudioClockLibs    500.4
com.apple.driver.FairPlayIOKit  72.15.0
com.apple.driver.AppleVirtualPlatform   1
com.apple.iokit.IOUSBDeviceFamily       2.0.0
com.apple.driver.usb.AppleUSBCommon     1.0
com.apple.iokit.IOAccessoryManager      1.0.0
com.apple.driver.AppleOnboardSerial     1.0
com.apple.iokit.IOSkywalkFamily 1.0
com.apple.driver.mDNSOffloadUserClient-Embedded 1.0.1b8
com.apple.iokit.AppleVirtIOStorage      1.0.0
com.apple.driver.AppleVirtIO    248
com.apple.iokit.IOSerialFamily  11
com.apple.iokit.IOPCIFamily     2.9
com.apple.iokit.IONetworkingFamily      3.4
com.apple.iokit.IOHIDFamily     2.0.0
com.apple.driver.AppleCallbackPowerSource       1
com.apple.kext.AppleMatch       1.0.0d1
com.apple.driver.AppleMobileFileIntegrity       1.0.5
com.apple.security.AppleImage4  7.0.0
com.apple.iokit.IOCryptoAcceleratorFamily       1.0.1
com.apple.kext.CoreTrust        1
com.apple.iokit.CoreAnalyticsFamily     1
com.apple.driver.ApplePMGR      1
com.apple.driver.AppleARMPlatform       1.0.2
com.apple.iokit.IOStorageFamily 2.1
com.apple.iokit.IOSlowAdaptiveClockingFamily    1.0.0
com.apple.iokit.IOReportFamily  47
com.apple.kec.pthread   1
com.apple.kec.Libm      1
com.apple.kec.Compression       1.0
com.apple.kec.corecrypto        26.0


** Stackshot Succeeded ** Bytes Traced 313136 (Uncompressed 708912) **
```

It appears that core 2 was the one that panicked. Patch 26 worked — no more constraint violations — but allowing non-main binaries with entitlements triggers a downstream assertion in `OSEntitlements.cpp:239`.

### Root Cause: OSEntitlements Context Consistency Check

After patch 26 allows entitlement parsing for non-main binaries, the entitlement data flows into `OSEntitlements::mergeContexts` (at `0xfffffe0008646A68` unslid). This function merges two entitlement context pointers:

- **instance_ctx** (X20, from caller) — the newly-parsed entitlement context for this binary
- **monitor_ctx** (X21, from `[readonly+0x50]`) — a pre-existing monitor entitlement context

The function checks that **both exist or both are NULL**. For ad-hoc signed non-main binaries, the instance_ctx is NULL (no monitor provisioned it), but the monitor_ctx exists from the app's main binary — producing the `1 | 0` inconsistency → panic.

### Kernel Patch 27: OSEntitlements Context Consistency

**Patch:** Change `B.NE → panic` at `0xfffffe0008646AA8` to `B → return_epilogue` at `0xfffffe0008646B20`.

**Safety analysis:**
- No locks held at the check point (function only loads pointers and compares)
- No resources allocated that need cleanup
- Epilogue properly restores X19-X22, X29, X30, SP
- Returning early means the merge doesn't happen — correct behavior when instance_ctx is NULL (nothing to merge)
- The return value (X0) from `amfi_is_monitor_active()` flows through naturally

**Annotated flow (IDA addresses unslid):**

```
OSEntitlements::mergeContexts(X0=obj, X1=instance_ctx)
│
├─ 0x646A80  MOV  X20, X1              ; save instance_ctx
├─ 0x646A84  LDR  X19, [X0, #0x10]     ; readonly_data
├─ 0x646A88  LDR  X21, [X19, #0x50]    ; monitor_ctx
├─ 0x646A8C  BL   amfi_is_monitor_active
├─ 0x646A90  TBZ  W0, #0 → error       ; if not active → error
│
├─ 0x646A94  CMP  X20, #0              ; instance == NULL?
├─ 0x646A98  CSET W8, NE               ; W8 = (instance != NULL)
├─ 0x646A9C  CMP  X21, #0              ; monitor == NULL?
├─ 0x646AA0  CSET W9, NE               ; W9 = (monitor != NULL)
├─ 0x646AA4  CMP  W8, W9               ; consistent?
├─ 0x646AA8  B.NE → 0x646B38 (PANIC)   ★ PATCH: B → 0x646B20 (RETURN) ★
│
├─ [normal path: copy monitor+instance, merge, store result]
│
├─ 0x646B20  LDP  X29, X30, ...        ; return epilogue
├─ 0x646B30  RETAB
│
└─ 0x646B38  [panic path]
   0x646B5C  ADRL "AMFI: inconsistency between instance and monitor context: %u | %u"
   0x646B64  BL   panic()              ; KERNEL PANIC (noreturn)
```

**String anchor:** `"AMFI: inconsistency between instance and monitor context"`

**Strategy:** Find string → ADRP+ADD xref in AMFI range → walk backward for `CMP Wn, Wn; B.NE` pattern → decode the CBZ at B.NE+8 to find the return target → re-encode B.NE as unconditional B to return.

## References

- WeChat binary: `com.tencent.xin`
- TikTok binary: `com.zhiliaoapp.musically`
- IPA signing code: `scripts/vphoned/vphoned_install.m` — `vp_sign_app()` (line 316), `vp_sign_binary()` (line 268)
- AMFI launch constraint: non-main binaries must not carry entitlements in ad-hoc signatures



## Annotated Disassembly: `sub_FFFFFE00086442F8` (AMFI Entitlement Validator)

This function is called during code signature validation to extract and validate
entitlements from a Mach-O binary. It lives in the `com.apple.driver.AppleMobileFileIntegrity`
kext (AMFI).

**Arguments:**
- `X0` (→ X19) = `result_out` — pointer where the entitlement object is stored on success
- `X1` (→ X20) = `cs_blob` — the code signature blob being validated
- `X2` (→ X23) = `vnode_ctx` — vnode/process context (has path at +8, flags at +0x408)
- `X3` (→ X21) = `error_msg_out` — pointer to store error description string on failure

**Return:** `W0` = 1 on success, 0 on failure

```asm
; ============================================================
; PROLOGUE — save registers, zero stack locals
; ============================================================
fffffe00086442f8  PACIBSP                         ; sign return address (PAC)
fffffe00086442fc  SUB    SP, SP, #0x80            ; allocate 128 bytes of stack
fffffe0008644300  STP    X26, X25, [SP, #0x30]    ; save callee-saved registers
fffffe0008644304  STP    X24, X23, [SP, #0x40]
fffffe0008644308  STP    X22, X21, [SP, #0x50]
fffffe000864430c  STP    X20, X19, [SP, #0x60]
fffffe0008644310  STP    X29, X30, [SP, #0x70]    ; save frame pointer + return address
fffffe0008644314  ADD    X29, SP, #0x70           ; set frame pointer
fffffe0008644318  MOV    X21, X3                  ; X21 = error_msg_out
fffffe000864431c  MOV    X23, X2                  ; X23 = vnode_ctx
fffffe0008644320  MOV    X20, X1                  ; X20 = cs_blob
fffffe0008644324  MOV    X19, X0                  ; X19 = result_out
fffffe0008644328  STP    XZR, XZR, [SP, #0x20]    ; xml_ents_ptr = 0, xml_ents_size = 0
fffffe000864432c  STP    XZR, XZR, [SP, #0x10]    ; der_ents_ptr = 0, der_ents_size = 0

; ============================================================
; STEP 1 — Get the code signing info struct from cs_blob
; ============================================================
fffffe0008644330  MOV    X0, X1                  ; arg0 = cs_blob
fffffe0008644334  BL     sub_FFFFFE0007F82B84    ; get_cs_info(cs_blob) → returns cs_info struct
fffffe0008644338  MOV    X24, X0                 ; X24 = cs_info (has version at +8, flags at +0x57)
fffffe000864433c  LDR    W25, [X0, #8]           ; W25 = cs_info->version (big-endian, needs REV)

; ============================================================
; STEP 2 — Check if entitlements are already cached
; ============================================================
fffffe0008644340  MOV    X0, X20                 ; arg0 = cs_blob
fffffe0008644344  BL     sub_FFFFFE0007F82CB4    ; get_cached_entitlements(cs_blob)
fffffe0008644348  CBZ    X0, loc_358             ; if NULL → no cache, go extract them
fffffe000864434c  MOV    X22, X0                 ; X22 = cached entitlement object
fffffe0008644350  MOV    W0, #1                  ; return SUCCESS
fffffe0008644354  B      loc_3C0                 ; → epilogue (return cached)

; ============================================================
; STEP 3 — Extract XML entitlements from the code signature
; ============================================================
loc_358:
fffffe0008644358  ADD    X1, SP, #0x28           ; &xml_ents_ptr (stack var_48)
fffffe000864435c  ADD    X2, SP, #0x20           ; &xml_ents_size (stack var_50)
fffffe0008644360  MOV    X0, X20                 ; arg0 = cs_blob
fffffe0008644364  BL     loc_FFFFFE000801F488    ; extract_xml_entitlements(cs_blob, &ptr, &size)
fffffe0008644368  CBZ    W0, loc_38C             ; if success → continue to DER extraction
fffffe000864436c  ADRL   X0, "Error getting XML\n"
fffffe0008644374  BL     sub_FFFFFE00081A1134    ; amfi_log("Error getting XML")
fffffe0008644378  MOV    X22, #0                 ; no entitlement object
fffffe000864437c  MOV    W0, #0                  ; return FAILURE
fffffe0008644380  ADRL   X8, "failed getting entitlements"
fffffe0008644388  B      loc_3BC                 ; → set error msg + return

; ============================================================
; STEP 4 — Extract DER entitlements from the code signature
; ============================================================
loc_38C:
fffffe000864438c  ADD    X1, SP, #0x18           ; &der_ents_ptr (stack var_58)
fffffe0008644390  ADD    X2, SP, #0x10           ; &der_ents_size (stack var_60)
fffffe0008644394  MOV    X0, X20                 ; arg0 = cs_blob
fffffe0008644398  BL     sub_FFFFFE000801F650    ; extract_der_entitlements(cs_blob, &ptr, &size)
fffffe000864439c  CBZ    W0, loc_3E0             ; if success → check what we got
fffffe00086443a0  ADRL   X0, "Error getting DER\n"
fffffe00086443a8  BL     sub_FFFFFE00081A1134    ; amfi_log("Error getting DER")
fffffe00086443ac  MOV    X22, #0
fffffe00086443b0  MOV    W0, #0                  ; return FAILURE
fffffe00086443b4  ADRL   X8, "failed getting DER entitlements"

; ============================================================
; ERROR EXIT — store error message + return
; ============================================================
loc_3BC:
fffffe00086443bc  STR    X8, [X21]               ; *error_msg_out = error string
loc_3C0:
fffffe00086443c0  STR    X22, [X19]              ; *result_out = entitlement object (or NULL)
fffffe00086443c4  LDP    X29, X30, [SP, #0x70]   ; restore frame pointer + return address
fffffe00086443c8  LDP    X20, X19, [SP, #0x60]   ; restore callee-saved registers
fffffe00086443cc  LDP    X22, X21, [SP, #0x50]
fffffe00086443d0  LDP    X24, X23, [SP, #0x40]
fffffe00086443d4  LDP    X26, X25, [SP, #0x30]
fffffe00086443d8  ADD    SP, SP, #0x80           ; deallocate stack
fffffe00086443dc  RETAB                          ; return (PAC-authenticated)

; ============================================================
; STEP 5 — Check: do we have ANY entitlements (XML or DER)?
; ============================================================
loc_3E0:
fffffe00086443e0  LDR    X9, [SP, #0x28]         ; X9 = xml_ents_ptr
fffffe00086443e4  LDR    X8, [SP, #0x18]         ; X8 = der_ents_ptr
fffffe00086443e8  ORR    X9, X9, X8              ; X9 = xml_ents_ptr | der_ents_ptr
fffffe00086443ec  CBNZ   X9, loc_44C             ; if either is non-NULL → has entitlements, go validate
                  ; --- NO entitlements at all → create empty entitlement object ---

; ============================================================
; PATH A — No entitlements: create empty entitlement dict
; ============================================================
loc_3F0:
fffffe00086443f0  MOV    X0, X20                 ; arg0 = cs_blob
fffffe00086443f4  BL     sub_FFFFFE0007F829E0    ; get_signer_type(cs_blob)
fffffe00086443f8  BL     sub_FFFFFE0008646E84    ; create_empty_entitlement_dict(signer_type)
fffffe00086443fc  MOV    X23, X0                 ; X23 = empty ent object

; --- acquire lock, check cache again, store ---
fffffe0008644400  ADRP   X21, #qword_FFFFFE00099043B0@PAGE
fffffe0008644404  LDR    X0, [X21, #offset]      ; load AMFI entitlements lock
fffffe0008644408  BL     sub_FFFFFE0007B10274    ; lck_mtx_lock(amfi_ents_lock)
fffffe000864440c  MOV    X0, X20                 ; arg0 = cs_blob
fffffe0008644410  BL     sub_FFFFFE0007F82CB4    ; get_cached_entitlements(cs_blob) — re-check under lock
fffffe0008644414  CBZ    X0, loc_4D8             ; if still NULL → store our new object
fffffe0008644418  MOV    X22, X0                 ; someone else cached it first, use theirs
fffffe000864441c  CBZ    X23, loc_4E8            ; if our empty obj is NULL → skip release
                  ; --- release our duplicate object (PAC-authenticated vtable call) ---
fffffe0008644420  LDR    X16, [X23]              ; load vtable ptr
fffffe0008644424  MOV    X17, X23
fffffe0008644428  MOVK   X17, #0xCDA1, LSL#48    ; PAC discriminator
fffffe000864442c  AUTDA  X16, X17                ; authenticate vtable pointer
fffffe0008644430  LDR    X8, [X16, #0x28]!       ; load vtable[5] = release() method
fffffe0008644434  MOV    X9, X16
fffffe0008644438  MOV    X0, X23                 ; arg0 = our ent object
fffffe000864443c  MOV    X17, X9
fffffe0008644440  MOVK   X17, #0x3A87, LSL#48    ; PAC discriminator for release call
fffffe0008644444  BLRAA  X8, X17                 ; call release(our_ent_object)
fffffe0008644448  B      loc_4E8                 ; → unlock + return success

; ============================================================
; PATH B — HAS entitlements: version + main-binary gate
;          *** THIS IS WHERE THE CONSTRAINT VIOLATION LIVES ***
; ============================================================
loc_44C:
fffffe000864444c  REV    W9, W25                 ; byte-swap cs_info->version (big→little endian)
fffffe0008644450  LSR    W9, W9, #0xA            ; shift right 10 bits → extract major version
fffffe0008644454  CMP    W9, #0x81               ; compare against version threshold 0x81
fffffe0008644458  B.CC   loc_4B4                 ; if version < 0x81 → SKIP constraint check (old format OK)
                                                 ; ★ PATCH POINT: change B.CC → B (unconditional) ★

; --- version >= 0x81: check if this is the main binary ---
fffffe000864445c  ADD    X9, X24, #0x50          ; X9 = &cs_info->flags_block (offset +0x50)
fffffe0008644460  LDRB   W9, [X9, #7]            ; W9 = cs_info->is_main_binary (byte at +0x57)
fffffe0008644464  TBNZ   W9, #0, loc_4B4         ; if bit 0 set → IS main binary → OK, parse entitlements

; --- NOT main binary AND has entitlements → CONSTRAINT VIOLATION ---

; --- get the binary path for the log message ---
fffffe0008644468  LDRB   W8, [X23, #0x408]       ; W8 = vnode_ctx->path_resolved (cached flag)
fffffe000864446c  TBNZ   W8, #0, loc_49C         ; if already resolved → skip path resolution

; --- resolve the binary path (PAC-authenticated vtable call) ---
fffffe0008644470  LDR    X16, [X23]              ; load vnode_ctx vtable
fffffe0008644474  MOV    X17, X23
fffffe0008644478  MOVK   X17, #0x6712, LSL#48    ; PAC discriminator
fffffe000864447c  AUTDA  X16, X17                ; authenticate vtable
fffffe0008644480  LDR    X8, [X16, #0x10]!       ; load vtable[2] = get_path() method
fffffe0008644484  MOV    X9, X16
fffffe0008644488  MOV    X0, X23                 ; arg0 = vnode_ctx
fffffe000864448c  MOV    X17, X9
fffffe0008644490  MOVK   X17, #0xC647, LSL#48    ; PAC discriminator
fffffe0008644494  BLRAA  X8, X17                 ; W0 = get_path(vnode_ctx) — resolves path string
fffffe0008644498  STRB   W0, [X23, #0x408]       ; cache the resolved flag

; --- log the constraint violation ---
loc_49C:
fffffe000864449c  ADD    X8, X23, #8             ; X8 = &vnode_ctx->path (string at +8)
fffffe00086444a0  STR    X8, [SP, #0x00]         ; push path as printf arg (stack slot)
fffffe00086444a4  ADRL   X0, "AMFI: constraint violation %s has entitlements but is not a main binary\n"
fffffe00086444ac  BL     sub_FFFFFE00081A1134    ; amfi_log(format, path)
fffffe00086444b0  B      loc_3F0                 ; → jump to PATH A (create EMPTY ent dict)
                                                 ; entitlements are DISCARDED — binary runs with
                                                 ; no entitlements, which often causes sandbox/
                                                 ; container failures → AMFI kills the process

; ============================================================
; PATH C — Parse DER entitlements (the normal/happy path)
; ============================================================
loc_4B4:
fffffe00086444b4  CBZ    X8, loc_4F4             ; X8 = der_ents_ptr; if NULL → error "no DER slot"
fffffe00086444b8  LDR    X9, [SP, #0x10]         ; X9 = der_ents_size
fffffe00086444bc  CMP    X9, #7
fffffe00086444c0  B.HI   loc_508                 ; if size > 7 → proceed to parse
fffffe00086444c4  MOV    X22, #0                 ; too small
fffffe00086444c8  MOV    W0, #0
fffffe00086444cc  ADRL   X8, "entitlements too small"
fffffe00086444d4  B      loc_3BC                 ; → error exit

; --- store our entitlement object in the cs_blob cache ---
loc_4D8:
fffffe00086444d8  MOV    X0, X20                 ; arg0 = cs_blob
fffffe00086444dc  MOV    X1, X23                 ; arg1 = our entitlement object
fffffe00086444e0  BL     sub_FFFFFE0007F82C40    ; set_cached_entitlements(cs_blob, ent_obj)
fffffe00086444e4  MOV    X22, X23                ; X22 = entitlement object (for return)

; --- unlock + return success ---
loc_4E8:
fffffe00086444e8  LDR    X0, [X21, #offset]      ; load AMFI entitlements lock
fffffe00086444ec  BL     sub_FFFFFE0007B110B8    ; lck_mtx_unlock(amfi_ents_lock)
fffffe00086444f0  B      loc_350                 ; → MOV W0, #1; return SUCCESS

; --- error: has XML entitlements but no DER slot ---
loc_4F4:
fffffe00086444f4  MOV    X22, #0
fffffe00086444f8  MOV    W0, #0
fffffe00086444fc  ADRL   X8, "entitlement validation failed, binary has XML entitlements but no DER slot is present."
fffffe0008644504  B      loc_3BC                 ; → error exit

; --- parse the DER blob (skip 8-byte header, validate size) ---
loc_508:
fffffe0008644508  ADD    X0, X8, #8              ; skip 8-byte DER header
fffffe000864450c  SUB    X1, X9, #8              ; adjusted size
fffffe0008644510  STP    X1, X0, [SP, #0x10]     ; update der_size, der_ptr on stack
fffffe0008644514  CMP    X1, #0x20, LSL#12       ; compare against max size (0x20000 = 128KB)
fffffe0008644518  B.LS   loc_530                 ; if size <= 128KB → parse it
fffffe000864451c  MOV    X22, #0
fffffe0008644520  MOV    W0, #0
fffffe0008644524  ADRL   X8, "entitlements too large"
fffffe000864452c  B      loc_3BC                 ; → error exit

; --- actually parse the DER entitlements ---
loc_530:
fffffe0008644530  BL     sub_FFFFFE0008646D98    ; parse_der_entitlements(der_ptr, der_size) → ent object
fffffe0008644534  CBZ    X0, loc_554             ; if NULL → parse failed
fffffe0008644538  MOV    X23, X0                 ; X23 = parsed entitlement object
fffffe000864453c  MOV    X0, X20                 ; arg0 = cs_blob
fffffe0008644540  BL     sub_FFFFFE0007F829E0    ; get_signer_type(cs_blob)
fffffe0008644544  MOV    X1, X0                  ; arg1 = signer_type
fffffe0008644548  MOV    X0, X23                 ; arg0 = entitlement object
fffffe000864454c  BL     sub_FFFFFE0008646F04    ; set_signer_type(ent_obj, signer_type)
fffffe0008644550  B      loc_400                 ; → acquire lock, cache, return success

; --- DER parse failed ---
loc_554:
fffffe0008644554  MOV    X22, #0
fffffe0008644558  ADRL   X8, "failed parsing DER entitlements"
fffffe0008644560  B      loc_3BC                 ; → error exit
```

### Flow Summary

```
                    sub_FFFFFE00086442F8(result_out, cs_blob, vnode_ctx, error_msg_out)
                                    │
                         ┌──────────┴──────────┐
                         │ get cs_info struct   │
                         │ check ent cache      │
                         └──────────┬──────────┘
                                    │
                        ┌───── cached? ─────┐
                        │YES               NO│
                   return cached     extract XML ents
                                     extract DER ents
                                            │
                              ┌──── have ents? ────┐
                              │NO                YES│
                       PATH A: empty         PATH B: validate
                       (create empty dict)          │
                              ▲            ┌── version < 0x81? ──┐
                              │            │YES                 NO│
                              │            │                      │
                              │            │         ┌── is main binary? ──┐
                              │            │         │YES                 NO│
                              │            │         │                      │
                              │            ▼         ▼                      │
                              │     PATH C: parse DER ents          ★ VIOLATION ★
                              │     (normal happy path)             log + discard ents
                              │            │                              │
                              │            ▼                              │
                              │     cache + return 1 (SUCCESS)            │
                              │                                           │
                              └───────────────────────────────────────────┘
                                    (falls through to PATH A = empty ents
                                     → process runs with NO entitlements
                                     → sandbox/container init fails → AMFI kills)
```

The patch at `0xfffffe0008644458` changes `B.CC` → `B`, making the "version < 0x81?" branch always taken,
which sends ALL binaries (main or not) to PATH C (parse DER entitlements normally).

## Side Notes

* AMFI is being used when invoked due to the main binary being signed and when new binaries get loaded the signature isnt loaded.
* The constraint violation doesn't directly kill the process — it discards the entitlements and creates an empty dict instead. The process then fails downstream when it can't satisfy sandbox/container requirements (needs entitlements that were stripped), which is what produces exit status 45.


