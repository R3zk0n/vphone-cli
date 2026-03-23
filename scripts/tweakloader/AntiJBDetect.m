// AntiJBDetect.m — Anti-jailbreak/VM detection tweak for vphone.
//
// Hooks common detection APIs to hide the jailbreak environment from apps
// that check for jailbreak paths, environment variables, injected dylibs,
// fork() behavior, and sysctl VM indicators.
//
// Loaded via TweakLoader into app processes. Uses DYLD_INTERPOSE for C
// functions (safe: dyld does not interpose the calling image's own bindings,
// so hooks can call originals by name without recursion) and ObjC method
// swizzling for Foundation/UIKit classes.

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <spawn.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
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

// Dylib substrings to hide from dladdr queries
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
    // Match /var/jb/* and /private/var/jb/* prefixes
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
//
// DYLD_INTERPOSE replaces `orig` in all OTHER images' GOT/lazy bindings.
// Within THIS image, calls to `orig` still resolve to the real function —
// so our hooks can call the original by name without infinite recursion.

#define DYLD_INTERPOSE(_hook, _orig) \
    __attribute__((used, section("__DATA,__interpose"))) \
    static struct { void *hook; void *orig; } _interpose_##_orig = { \
        (void *)&_hook, (void *)&_orig \
    };

// ════════════════════════════════════════════════════════════════
// MARK: - File System Hooks (stat, lstat, access, open, fopen)
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
// MARK: - Dyld Image Hooks (hide injected dylibs from dladdr)
// ════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════
// MARK: - Constructor
// ════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void AntiJBDetectInit(void) {
    @autoreleasepool {
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

        // UIDevice swizzles (may not be loaded yet — TweakLoader runs early)
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

        NSLog(@"[AntiJBDetect] Initialized — file/env/sysctl/dyld/ObjC hooks active");
    }
}
