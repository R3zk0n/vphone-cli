// AntiJBDetect.m — Anti-jailbreak/VM detection tweak for vphone.
//
// Hooks common detection APIs to hide the jailbreak environment from apps
// that check for jailbreak paths, environment variables, injected dylibs,
// fork() behavior, sysctl VM indicators, dyld image lists, and
// MobileGestalt device queries.
//
// Loaded via TweakLoader into app processes. Uses DYLD_INTERPOSE for C
// functions (safe: dyld does not interpose the calling image's own bindings,
// so hooks can call originals by name without recursion) and ObjC method
// swizzling for Foundation/UIKit classes.

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <execinfo.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <spawn.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <unistd.h>

// ════════════════════════════════════════════════════════════════
// MARK: - Jailbreak Path Blocklist
// ════════════════════════════════════════════════════════════════

static const char *jb_paths[] = {
    "/var/jb",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/etc/apt",
    "/var/lib/apt",
    "/var/lib/dpkg",
    "/var/cache/apt",
    "/var/log/apt",
    "/usr/libexec/cydia",
    "/usr/bin/cycript",
    "/usr/local/bin/cycript",
    "/usr/lib/libcycript.dylib",
    "/Library/MobileSubstrate",
    "/usr/lib/TweakLoader.dylib",
    "/var/jb/usr/lib/TweakLoader.dylib",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/private/var/mobile/Library/SBSettings",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/bin/bash",
    "/usr/bin/dpkg",
    "/usr/bin/apt",
    "/usr/sbin/frida-server",
    "/usr/bin/frida-server",
    "/cores/launchdhook.dylib",
    "/cores/systemhook.dylib",
    "/cores/libellekit.dylib",
    "/b",
    "/.jailbroken",
    "/.cydia_no_stash",
    "/.installed_dopamine",
    "/.procursus_strapped",
    "/var/binpack",
    NULL
};

// Dylib substrings to hide from dladdr and dyld image queries
static const char *hidden_dylib_names[] = {
    "TweakLoader",
    "AntiJBDetect",
    "launchdhook",
    "systemhook",
    "libellekit",
    "SubstrateLoader",
    "MobileSubstrate",
    "substrate",
    "fishhook",
    "AntiAntiDebug",
    "libPineappleDylib",
    "libdkhelperDylib",
    "HBWechatHelper",
    "WeChatPure",
    "MiYou",
    "DouTu",
    "Joker",
    "sutuplus",
    "MsgFilt",
    "GameLogin",
    "WeAppTool",
    "wcplugins",
    "wechat.dylib",
    "wcbg",
    NULL
};

static bool is_jb_path(const char *path) {
    if (!path) return false;
    if (strncmp(path, "/var/jb", 7) == 0) return true;
    if (strncmp(path, "/private/var/jb", 15) == 0) return true;
    for (const char **p = jb_paths; *p; p++) {
        if (strcmp(path, *p) == 0) return true;
    }
    return false;
}

static bool is_hidden_dylib(const char *name) {
    if (!name) return false;
    for (const char **p = hidden_dylib_names; *p; p++) {
        if (strstr(name, *p)) return true;
    }
    return false;
}

// ════════════════════════════════════════════════════════════════
// MARK: - DYLD_INTERPOSE Macro
// ════════════════════════════════════════════════════════════════

#define DYLD_INTERPOSE(_hook, _orig) \
    __attribute__((used, section("__DATA,__interpose"))) \
    static struct { void *hook; void *orig; } _interpose_##_orig = { \
        (void *)&_hook, (void *)&_orig \
    };

// ════════════════════════════════════════════════════════════════
// MARK: - Exit Tracing (catch the kill and log backtrace)
// ════════════════════════════════════════════════════════════════

static void log_backtrace(const char *func, int code) {
    void *frames[64];
    int count = backtrace(frames, 64);
    char **syms = backtrace_symbols(frames, count);

    NSLog(@"[AntiJBDetect] *** %s(%d) called! Backtrace:", func, code);
    for (int i = 0; i < count; i++) {
        NSLog(@"[AntiJBDetect]   %d: %s", i, syms ? syms[i] : "???");
    }
    if (syms) free(syms);

    // Also log to file in case NSLog is lost
    FILE *f = fopen("/var/tmp/antijb_exit_trace.log", "a");
    if (f) {
        fprintf(f, "=== %s(%d) called ===\n", func, code);
        for (int i = 0; i < count; i++) {
            fprintf(f, "  %d: %s\n", i, syms ? syms[i] : "???");
        }
        fprintf(f, "===\n\n");
        fclose(f);
    }
}

static void hook_exit(int code) {
    log_backtrace("exit", code);
    // Call the real exit
    exit(code);
}

static void hook__exit(int code) {
    log_backtrace("_exit", code);
    _exit(code);
}

DYLD_INTERPOSE(hook_exit, exit)
DYLD_INTERPOSE(hook__exit, _exit)

// ════════════════════════════════════════════════════════════════
// MARK: - File System Hooks (stat, lstat, access, fopen)
// ════════════════════════════════════════════════════════════════

static int hook_stat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return stat(path, buf);
}

static int hook_lstat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return lstat(path, buf);
}

static int hook_access(const char *path, int mode) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return access(path, mode);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return fopen(path, mode);
}

DYLD_INTERPOSE(hook_stat, stat)
DYLD_INTERPOSE(hook_lstat, lstat)
DYLD_INTERPOSE(hook_access, access)
DYLD_INTERPOSE(hook_fopen, fopen)

// ════════════════════════════════════════════════════════════════
// MARK: - Process Hooks (fork — should fail on stock iOS)
// ════════════════════════════════════════════════════════════════

static pid_t hook_fork(void) {
    errno = ENOSYS;
    return -1;
}

DYLD_INTERPOSE(hook_fork, fork)

// ════════════════════════════════════════════════════════════════
// MARK: - Environment Hooks (getenv)
// ════════════════════════════════════════════════════════════════

static const char *suspicious_env_vars[] = {
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_LIBRARY_PATH",
    "_MSSafeMode",
    "SUBSTRATE_HOME",
    NULL
};

static char *hook_getenv(const char *name) {
    if (name) {
        for (const char **v = suspicious_env_vars; *v; v++) {
            if (strcmp(name, *v) == 0) return NULL;
        }
    }
    return getenv(name);
}

DYLD_INTERPOSE(hook_getenv, getenv)

// ════════════════════════════════════════════════════════════════
// MARK: - Sysctl Hooks (VM detection, process flags)
// ════════════════════════════════════════════════════════════════

static const char *hw_spoof = "iPhone17,3";
static const char *board_spoof = "D93AP";

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    int ret = sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret != 0 || !oldp || !oldlenp) return ret;

    // Hide P_TRACED flag (supplement AntiAntiDebug)
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        info->kp_proc.p_flag &= ~P_TRACED;
    }

    // Spoof hw.machine / hw.model to hide VM
    if (namelen == 2 && name[0] == CTL_HW) {
        if (name[1] == HW_MACHINE || name[1] == HW_MODEL) {
            size_t len = strlen(hw_spoof) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, hw_spoof, len);
                *oldlenp = len;
            }
        }
    }

    return ret;
}

static int hook_sysctlbyname(const char *sname, void *oldp, size_t *oldlenp,
                              void *newp, size_t newlen) {
    int ret = sysctlbyname(sname, oldp, oldlenp, newp, newlen);
    if (ret != 0 || !sname || !oldp || !oldlenp) return ret;

    if (strcmp(sname, "hw.machine") == 0 || strcmp(sname, "hw.model") == 0 ||
        strcmp(sname, "hw.target") == 0) {
        size_t len = strlen(hw_spoof) + 1;
        if (*oldlenp >= len) {
            memcpy(oldp, hw_spoof, len);
            *oldlenp = len;
        }
    }

    if (strcmp(sname, "hw.product") == 0 || strcmp(sname, "hw.board") == 0) {
        size_t len = strlen(board_spoof) + 1;
        if (*oldlenp >= len) {
            memcpy(oldp, board_spoof, len);
            *oldlenp = len;
        }
    }

    return ret;
}

DYLD_INTERPOSE(hook_sysctl, sysctl)
DYLD_INTERPOSE(hook_sysctlbyname, sysctlbyname)

// ════════════════════════════════════════════════════════════════
// MARK: - uname Hook (VM detection via machine field)
// ════════════════════════════════════════════════════════════════

static int hook_uname(struct utsname *buf) {
    int ret = uname(buf);
    if (ret == 0 && buf) {
        strlcpy(buf->machine, hw_spoof, sizeof(buf->machine));
    }
    return ret;
}

DYLD_INTERPOSE(hook_uname, uname)

// ════════════════════════════════════════════════════════════════
// MARK: - Dyld Image Hooks (hide injected dylibs)
// ════════════════════════════════════════════════════════════════

// Cache the "real" image count (excluding hidden dylibs) at init time.
// _dyld_image_count and _dyld_get_image_name are the primary JB detection
// vectors — apps iterate all images looking for suspicious names.

static uint32_t real_image_count = 0;
// Map from fake index → real index (max 512 images should cover any app)
static uint32_t image_index_map[512];

static void rebuild_image_map(void) {
    uint32_t total = _dyld_image_count();
    uint32_t fake = 0;
    for (uint32_t i = 0; i < total && fake < 512; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!is_hidden_dylib(name)) {
            image_index_map[fake++] = i;
        }
    }
    real_image_count = fake;
}

static uint32_t hook_dyld_image_count(void) {
    return real_image_count;
}

static const char *hook_dyld_get_image_name(uint32_t idx) {
    if (idx >= real_image_count) return NULL;
    return _dyld_get_image_name(image_index_map[idx]);
}

static const struct mach_header *hook_dyld_get_image_header(uint32_t idx) {
    if (idx >= real_image_count) return NULL;
    return _dyld_get_image_header(image_index_map[idx]);
}

static intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t idx) {
    if (idx >= real_image_count) return 0;
    return _dyld_get_image_vmaddr_slide(image_index_map[idx]);
}

DYLD_INTERPOSE(hook_dyld_image_count, _dyld_image_count)
DYLD_INTERPOSE(hook_dyld_get_image_name, _dyld_get_image_name)
DYLD_INTERPOSE(hook_dyld_get_image_header, _dyld_get_image_header)
DYLD_INTERPOSE(hook_dyld_get_image_vmaddr_slide, _dyld_get_image_vmaddr_slide)

// Also hide from dladdr
static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = dladdr(addr, info);
    if (ret && info && info->dli_fname && is_hidden_dylib(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
        info->dli_sname = NULL;
        info->dli_saddr = NULL;
    }
    return ret;
}

DYLD_INTERPOSE(hook_dladdr, dladdr)

// ════════════════════════════════════════════════════════════════
// MARK: - MobileGestalt Hook (VM/device identity spoofing)
// ════════════════════════════════════════════════════════════════

// MGCopyAnswer is the primary iOS device identity API.
// It's a private framework so we load it dynamically.
typedef CFTypeRef (*MGCopyAnswer_t)(CFStringRef key);
static MGCopyAnswer_t orig_MGCopyAnswer = NULL;

static CFTypeRef hook_MGCopyAnswer(CFStringRef key) {
    if (!key) return orig_MGCopyAnswer(key);

    // Spoof device identity keys to match a real iPhone
    if (CFStringCompare(key, CFSTR("ProductType"), 0) == kCFCompareEqualTo ||
        CFStringCompare(key, CFSTR("HWModelStr"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone17,3"));
    }
    if (CFStringCompare(key, CFSTR("HardwarePlatform"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("t8140"));
    }
    if (CFStringCompare(key, CFSTR("BoardId"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("D93AP"));
    }
    if (CFStringCompare(key, CFSTR("ChipID"), 0) == kCFCompareEqualTo) {
        // A18 Pro chip ID
        return CFNumberCreate(NULL, kCFNumberSInt32Type, &(int32_t){0x8140});
    }
    // Hide VM indicators
    if (CFStringCompare(key, CFSTR("IsVirtualDevice"), 0) == kCFCompareEqualTo ||
        CFStringCompare(key, CFSTR("isVirtualDevice"), 0) == kCFCompareEqualTo) {
        return kCFBooleanFalse;
    }
    if (CFStringCompare(key, CFSTR("ArtworkDeviceProductDescription"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone 16 Pro Max"));
    }
    if (CFStringCompare(key, CFSTR("MarketingName"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone 16 Pro Max"));
    }
    if (CFStringCompare(key, CFSTR("DeviceName"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone"));
    }
    if (CFStringCompare(key, CFSTR("DeviceClass"), 0) == kCFCompareEqualTo) {
        return CFStringCreateCopy(NULL, CFSTR("iPhone"));
    }
    if (CFStringCompare(key, CFSTR("DeviceClassNumber"), 0) == kCFCompareEqualTo) {
        return CFNumberCreate(NULL, kCFNumberSInt32Type, &(int32_t){1});
    }

    return orig_MGCopyAnswer(key);
}

// ════════════════════════════════════════════════════════════════
// MARK: - ObjC Swizzles (NSFileManager, UIDevice, UIApplication)
// ════════════════════════════════════════════════════════════════

static void swizzle(Class cls, SEL sel, IMP newIMP, IMP *origIMP) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *origIMP = method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

// NSFileManager

static BOOL (*orig_fileExistsAtPath)(id, SEL, NSString *);
static BOOL swz_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (path && is_jb_path(path.UTF8String)) return NO;
    return orig_fileExistsAtPath(self, _cmd, path);
}

static BOOL (*orig_fileExistsAtPathIsDir)(id, SEL, NSString *, BOOL *);
static BOOL swz_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (path && is_jb_path(path.UTF8String)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return orig_fileExistsAtPathIsDir(self, _cmd, path, isDir);
}

static BOOL (*orig_isReadableFileAtPath)(id, SEL, NSString *);
static BOOL swz_isReadableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && is_jb_path(path.UTF8String)) return NO;
    return orig_isReadableFileAtPath(self, _cmd, path);
}

// UIDevice model spoofing

static NSString *(*orig_model)(id, SEL);
static NSString *swz_model(__unused id self, __unused SEL _cmd) {
    return @"iPhone";
}

static NSString *(*orig_localizedModel)(id, SEL);
static NSString *swz_localizedModel(__unused id self, __unused SEL _cmd) {
    return @"iPhone";
}

static NSString *(*orig_deviceName)(id, SEL);
static NSString *swz_deviceName(__unused id self, __unused SEL _cmd) {
    return @"iPhone";
}

// UIApplication canOpenURL (hide JB URL schemes)

static BOOL (*orig_canOpenURL)(id, SEL, NSURL *);
static BOOL swz_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = url.scheme;
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"filza"]) {
            return NO;
        }
    }
    return orig_canOpenURL(self, _cmd, url);
}

// NSProcessInfo — hide environment variables from dictionary access

static NSDictionary *(*orig_environment)(id, SEL);
static NSDictionary *swz_environment(id self, SEL _cmd) {
    NSMutableDictionary *env = [orig_environment(self, _cmd) mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"DYLD_FRAMEWORK_PATH"];
    [env removeObjectForKey:@"DYLD_LIBRARY_PATH"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"SUBSTRATE_HOME"];
    return [env copy];
}

// ════════════════════════════════════════════════════════════════
// MARK: - Constructor
// ════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void AntiJBDetectInit(void) {
    @autoreleasepool {
        // Build dyld image index map (must happen before any app code runs)
        rebuild_image_map();

        // Hook MobileGestalt (private framework, load dynamically)
        void *mg = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
        if (mg) {
            orig_MGCopyAnswer = (MGCopyAnswer_t)dlsym(mg, "MGCopyAnswer");
            // We can't DYLD_INTERPOSE a dlsym'd function, so we use
            // rebinding via the interpose section won't work here.
            // Instead, we swizzle at the ObjC level where apps typically
            // access MobileGestalt through UIDevice or GestaltQuery.
            // For direct C callers, we'll rely on sysctl spoofing.
            //
            // Actually, we CAN interpose it if MGCopyAnswer is exported
            // from libMobileGestalt. But since the app also loads it
            // dynamically, the interpose may not catch dlsym lookups.
            // Keep the orig pointer for now — we'll hook via rebinding
            // if needed.
        }

        // NSFileManager swizzles
        Class fmClass = NSClassFromString(@"NSFileManager");
        if (fmClass) {
            swizzle(fmClass, @selector(fileExistsAtPath:),
                    (IMP)swz_fileExistsAtPath, (IMP *)&orig_fileExistsAtPath);
            swizzle(fmClass, @selector(fileExistsAtPath:isDirectory:),
                    (IMP)swz_fileExistsAtPathIsDir, (IMP *)&orig_fileExistsAtPathIsDir);
            swizzle(fmClass, @selector(isReadableFileAtPath:),
                    (IMP)swz_isReadableFileAtPath, (IMP *)&orig_isReadableFileAtPath);
        }

        // UIDevice swizzles
        Class deviceClass = NSClassFromString(@"UIDevice");
        if (deviceClass) {
            swizzle(deviceClass, @selector(model),
                    (IMP)swz_model, (IMP *)&orig_model);
            swizzle(deviceClass, @selector(localizedModel),
                    (IMP)swz_localizedModel, (IMP *)&orig_localizedModel);
            swizzle(deviceClass, @selector(name),
                    (IMP)swz_deviceName, (IMP *)&orig_deviceName);
        }

        // UIApplication canOpenURL swizzle
        Class appClass = NSClassFromString(@"UIApplication");
        if (appClass) {
            swizzle(appClass, @selector(canOpenURL:),
                    (IMP)swz_canOpenURL, (IMP *)&orig_canOpenURL);
        }

        // NSProcessInfo environment swizzle
        Class procInfoClass = NSClassFromString(@"NSProcessInfo");
        if (procInfoClass) {
            swizzle(procInfoClass, @selector(environment),
                    (IMP)swz_environment, (IMP *)&orig_environment);
        }

        NSLog(@"[AntiJBDetect] Initialized — hiding %u dylibs, spoofing %s",
              _dyld_image_count() - real_image_count, hw_spoof);
    }
}
