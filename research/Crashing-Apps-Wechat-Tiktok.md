# Crashing Apps: WeChat & TikTok

## Overview

Investigation into app crashes when running WeChat and TikTok on the vphone virtual iPhone environment. Goal: identify crash causes, determine if kernel/CFW patches or VM configuration changes are needed.

## Status

**Phase:** Kernel patch implemented — AMFI entitlement constraint bypass (patch 26)

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
6. **Verify fix with WeChat** — re-patch kernel, restore, install, test
7. **Test with TikTok** — confirm same fix resolves TikTok crashes
8. **Check for secondary issues** — VM detection, GPU, network (may surface after AMFI fix)

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

**Strategy:** String anchor (`"AMFI: constraint violation %s has entitlements but is not a main binary"`) → ADRP+ADD xref → walk backward for `CMP Wn, #0x81` + `B.CC` pattern → patch conditional to unconditional.

## References

- WeChat binary: `com.tencent.xin`
- TikTok binary: `com.zhiliaoapp.musically`
- IPA signing code: `scripts/vphoned/vphoned_install.m` — `vp_sign_app()` (line 316), `vp_sign_binary()` (line 268)
- AMFI launch constraint: non-main binaries must not carry entitlements in ad-hoc signatures



## Side Notes 

_(Side Notes)_

* AMFI is being used when invoked due to the main binary being signed and when new binaries get loaded the signature isnt loaded.


