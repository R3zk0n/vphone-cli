# Apple Account Authentication Analysis (PCC VM)

**Date:** 2026-03-11
**Target:** `akd` daemon (AuthKit) on PCC research VM (vphone600, iOS 26.1/23B85)
**Goal:** Understand why Apple Account sign-in returns "Verification Failed" on the virtualized device
**Tools:** IDA Pro + MCP, lldb via debugserver over SSH/iproxy

---

## Summary

Apple Account sign-in fails on the PCC VM due to three compounding issues:
1. **Missing Anisette (OTP) headers** — ADI provisioning never succeeds
2. **Fake device identity** — serial `vphone-1337`, model `iPhone99,11`
3. **No SEP** — Secure Enclave absent in VM, blocking device attestation

The server returns **HTTP 503** to the GrandSlam auth endpoint, rejecting the request outright.

---

## Authentication Flow

```
Settings → Apple Account → Sign In
  → com.apple.Preferences (UI)
    → XPC to akd (com.apple.ak.auth.xpc)
      → AKAppleIDAuthenticationService authenticateWithContext:
        → AKAuthenticationTrafficController
          → AKNativeAnisetteService _signRequestWithProvisioningHeaders:forUrlKey:
            → Adds device identity headers to NSMutableURLRequest
            → POST to https://gsa.apple.com/grandslam/GsService2
              → Server returns 503 (Service Unavailable)
        → AKAuthenticationErrorAlertFactory creates "Verification Failed" alert
```

---

## Key Daemon: `akd`

`akd` is the AuthKit daemon located at `/System/Library/PrivateFrameworks/AuthKit.framework/Support/akd`. It handles all Apple ID authentication flows.

**Notable imports (1448 total):**

| Import | Framework | Purpose |
|--------|-----------|---------|
| `AKDevice` | AuthKit | Device identity (serial, UDID, model) |
| `AKAttestationData` / `AKAttestationSigner` | AuthKit | BAA device attestation |
| `AKAnisetteData` / `AKAnisetteProvisioningController` | AuthKit | Anisette OTP provisioning |
| `SecKeyCreateAttestation` | Security | SEP attestation certificate |
| `kSecKeyParameterSETokenAttestationNonce` | Security | SEP token nonce |
| `kSecAttrTokenIDAppleKeyStore` | Security | SEP-backed keychain |
| `MGCopyAnswer` | MobileGestalt | Device property queries |

---

## BAA (Basic Attestation Authority) Gate

### Function: `-[AKNativeAnisetteService _shouldAddBAAV1HeadersWithCompletion:]`

This function decides whether to include device attestation headers. Pseudocode:

```objc
- (void)_shouldAddBAAV1HeadersWithCompletion:(void (^)(BOOL))completion {

    // Gate 1: Does the device support strong identity (SEP)?
    if (![[AKDevice currentDevice] isStrongDeviceIdentitySupported]) {
        // "DeviceIdentity is not supported. No BAA V1 headers."
        completion(NO);  // SKIP attestation
        return;
    }

    // Gate 2: Are we in a VM?
    if ([[AKDevice currentDevice] isVirtualMachine]) {
        // Gate 2a: Is this process exempt from VM BAA?
        if ([self _isProcessExemptedFromVMBAA]) {
            completion(NO);  // SKIP attestation
            return;
        }
        // Gate 2b: Check server-side kill switch
        [[AKURLBag sharedBag] configurationValueForKey:AKURLBagKeyVMBAADisabled
                                             fromCache:YES
                                            completion:^(id value) { ... }];
        return;
    }

    // Gate 3: Physical device — is BAA enabled?
    if ([[AKFeatureManager sharedManager] isPhysicalDeviceBAAEnabled]) {
        // Check server-side kill switch for physical device
        [[AKURLBag sharedBag] configurationValueForKey:AKURLBagKeyDeviceBAADisabled
                                             fromCache:YES
                                            completion:^(id value) { ... }];
        return;
    }

    // BAA disabled entirely
    // "BAA feature is disabled."
    completion(NO);
}
```

**Bypass options (tested):**
1. `[AKDevice isStrongDeviceIdentitySupported]` → return NO — hits Gate 1, cleanest single-point bypass
2. `[AKDevice _isProcessExemptedFromVMBAA]` → return YES — uses Apple's own VM exemption path
3. `[AKDevice isVirtualMachine]` → return NO + `isPhysicalDeviceBAAEnabled` → return NO

**Runtime patch applied via lldb:**
```
memory write <addr_of_isStrongDeviceIdentitySupported> 0x00 0x00 0x80 0x52 0xc0 0x03 0x5f 0xd6
```
Writes `mov w0, #0; ret` — permanently returns NO. This successfully bypasses BAA but does not fix the sign-in.

**Notable:** Apple has a built-in `AKURLBagKeyVMBAADisabled` flag for disabling VM attestation — suggesting VM auth is an intentional but gated capability.

---

## Request Header Analysis

### Function: `-[AKNativeAnisetteService _signRequestWithProvisioningHeaders:forUrlKey:]`

This function adds all device identity headers to the HTTP request before sending to Apple:

```objc
- (void)_signRequestWithProvisioningHeaders:(NSMutableURLRequest *)req forUrlKey:(id)key {
    [req ak_addClientInfoHeader];
    [req ak_addClientTimeHeader];
    [req ak_addDeviceMLBHeader];
    [req ak_addDeviceROMHeader];
    [req ak_addDeviceSerialNumberHeader];
    [req ak_addDeviceUDIDHeader];
    [req ak_addLocalUserUUIDHashHeader];
    [req ak_addInternalBuildHeader];
    [req ak_addSeedBuildHeader];
    [req ak_addEffectiveUserIdentifierHeader];
    if ([AKDevice hasUniqueDeviceIdentifier])
        [req ak_addProvisioningUDIDHeader];
    if ([self.client.fullName length])
        [req ak_addClientApp:self.client.fullName];
}
```

### Captured Headers (from lldb at runtime)

```
X-Apple-I-Client-Time = "2026-03-10T13:05:40Z"
X-Apple-I-SRL-NO      = "vphone-1337"
X-Mme-Device-Id       = "0000FE01-73B6441259E19781"
X-MMe-Client-Info     = "<iPhone99,11> <iPhone OS;26.1;23B85> <com.apple.akd/1.0 (com.apple.akd/1.0)>"
```

**Only 4 headers present.** A real device sends 15+ headers including:

| Missing Header | Purpose |
|---------------|---------|
| `X-Apple-I-MD` | Anisette one-time password (OTP) |
| `X-Apple-I-MD-M` | Machine ID (ADI provisioned) |
| `X-Apple-I-MD-RINFO` | Routing/provisioning info |
| `X-Apple-I-MLB` | Main Logic Board serial number |
| `X-Apple-I-ROM` | Boot ROM address |
| `X-Apple-I-TimeZone` | Device timezone |
| `X-Apple-I-Locale` | Device locale |

### Why Headers Are Missing

- **MLB / ROM**: PCC VM has no real hardware board — `ak_addDeviceMLBHeader` and `ak_addDeviceROMHeader` return nil, so the headers are not added
- **Anisette (MD/MD-M)**: ADI (Apple Device Identity) provisioning requires valid device identity and likely SEP interaction. With fake serial and no SEP, provisioning fails silently — no OTP tokens are generated
- **Timezone/Locale**: May be missing due to incomplete VM environment setup

---

## MobileGestalt Queries

`akd` queries `MGCopyAnswer` extensively during authentication. Observed keys from lldb breakpoint trace:

| Key | Returned Value | Expected |
|-----|---------------|----------|
| `SerialNumber` | `vphone-1337` | 12-char Apple serial (e.g. `F2LXN4M1HG7J`) |
| `DeviceClass` | `iPhone` | OK |
| `HasBaseband` | (not captured) | `true` for iPhone |
| `DeviceColor` | (queried) | Color code |
| `DeviceEnclosureColor` | (queried) | Color code |
| `ModelNumber` | (queried) | e.g. `MU6A3LL/A` |

The serial `vphone-1337` is set in the VM's MobileGestalt cache and propagates through all identity checks.

---

## Server Response

- **URL bag fetch**: `GET https://gsa.apple.com/grandslam/GsService2/lookup/v2` → **200 OK** (36KB plist, cached 86400s)
- **Auth request**: → **503 Service Unavailable**

The 503 indicates Apple's GrandSlam server rejects the request at the transport level before reaching SRP authentication. The missing Anisette headers are the most likely cause — without `X-Apple-I-MD` and `X-Apple-I-MD-M`, the server cannot validate the request origin.

---

## AKAppleIDAuthenticationService Structure

From IDA struct recovery during live debugging:

```c
struct AKAppleIDAuthenticationService {  // sizeof >= 0x60
    NSObject          super;                            // 0x00
    AKAccountManager  *_accountManager;                 // 0x08 — [AKAccountManager sharedInstance]
    id                _client;                          // 0x10
    id                _authProxy;                       // 0x18
    AKTokenManager    *_tokenManager;                   // 0x20 — [AKTokenManager sharedInstance]
    AKAuthenticationTrafficController *_authTrafficController; // 0x28
    AKAuthenticationUILiaison *_authUILiaison;          // 0x30
    id                _proximityServiceProvider;        // 0x38
    id                _activeProximityAuthenticationToken; // 0x40
    CUTReachability   *_reachability;                   // 0x48 — host: gsa.apple.com
    id                _fidoHandler;                     // 0x50
    id                _eduController;                   // 0x58
    id                _passwordResetPresenter;          // 0x60
};
```

---

## Anisette Provisioning Path

The Anisette data flow in `akd`:

```
AKAnisetteProvisioningController
  → startProvisioning (AKURLBagKeyStartProvisioning)
    → ADI library generates machine identity
    → endProvisioning (AKURLBagKeyEndProvisioning)
      → _tq_processEndProvisioningResponse:error:cpimBytes:provisioningContext:completion:
        → Sets X-Apple-I-MD-RINFO, X-Apple-I-MD-M
  → syncAnisette (AKURLBagKeySyncAnisette)
    → _processSyncAnisetteResponse:completion:
      → Updates OTP tokens
```

Provisioning requires valid device identity (serial, UDID, MLB) to succeed. The PCC VM's fake identity causes provisioning to fail silently, resulting in no Anisette headers on subsequent requests.

---

## SSL/TLS Observations

- `www.apple.com` — HTTPS works (via system Certificates.bundle)
- `gsa.apple.com` — connection succeeds, TLS 1.3 handshake completes
- JB `curl` uses `/var/jb/etc/ssl/certs/cacert.pem` which lacks Apple's root CA → SSL verify fails in curl
- System frameworks (Security.framework) use `/System/Library/Security/Certificates.bundle/` → works correctly
- `/var/Keychains/TrustStore.sqlite3` does not exist on PCC VM (only used for user-added certs, not required for built-in CAs)

- Generally in iOS the root mount is sealed and writing to R/W only, however due to the way the patches have been done, it means that you can force the / to be writable 
using `mount -uw /`. This allows us to write into the `/etc/hosts` 


---

## Conclusions

### Why Sign-In Fails
1. **No Anisette OTP** — the critical `X-Apple-I-MD` and `X-Apple-I-MD-M` headers are absent because ADI provisioning fails with fake device identity
2. **Fake identity** — `vphone-1337` serial and `iPhone99,11` model are not recognized by Apple's servers
3. **No hardware roots** — MLB, ROM, SEP attestation all absent in the VM environment

### What Would Be Needed
To make App Store sign-in work on a PCC VM, all of the following would be required:
- Real device serial number, UDID, MLB, ROM values in MobileGestalt
- Successful ADI provisioning (may require real device identity or an external Anisette server)
- BAA bypass (achieved) or valid SEP attestation (not possible in VM)
- Activation records from a real device

### Practical Alternatives
- **TrollStore** — already installed in JB setup, installs any IPA with full entitlements
- **vphone-cli IPA installer** — Install menu pushes IPAs over vsock
- **ipatool** — CLI App Store client, authenticates from host Mac, downloads IPAs directly
- **Decrypt from real device** — use `bfdecrypt`/`clutch` on jailbroken physical device

### Potential Research Directions
- Hook `MGCopyAnswer` to return real device values and retry ADI provisioning
- Implement an external Anisette provisioning server (similar to AltStore's approach)
- Investigate `AKURLBagKeyVMBAADisabled` server-side configuration — Apple may have infrastructure for VM auth
- Trace `fairplayd.H2` interaction with `FairPlayIOKit.kext` and `AvpFairPlayDriver` (VirtIO bridge to host)
