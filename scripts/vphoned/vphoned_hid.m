#import "vphoned_hid.h"
#include <dlfcn.h>
#include <mach/mach_time.h>
#include <unistd.h>

typedef void *IOHIDEventSystemClientRef;
typedef void *IOHIDEventRef;

static IOHIDEventSystemClientRef (*pCreate)(CFAllocatorRef);
static IOHIDEventRef (*pKeyboard)(CFAllocatorRef, uint64_t,
                                  uint32_t, uint32_t, int, int);
static void (*pSetSender)(IOHIDEventRef, uint64_t);
static void (*pDispatch)(IOHIDEventSystemClientRef, IOHIDEventRef);

// Accelerometer event creator (for shake simulation)
static IOHIDEventRef (*pAccel)(CFAllocatorRef, uint64_t,
                               double, double, double, int);

static IOHIDEventSystemClientRef gClient;
static dispatch_queue_t gHIDQueue;

BOOL vp_hid_load(void) {
    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!h) { NSLog(@"vphoned: dlopen IOKit failed"); return NO; }

    pCreate    = dlsym(h, "IOHIDEventSystemClientCreate");
    pKeyboard  = dlsym(h, "IOHIDEventCreateKeyboardEvent");
    pSetSender = dlsym(h, "IOHIDEventSetSenderID");
    pDispatch  = dlsym(h, "IOHIDEventSystemClientDispatchEvent");
    pAccel     = dlsym(h, "IOHIDEventCreateAccelerometerEvent");

    if (!pCreate || !pKeyboard || !pSetSender || !pDispatch) {
        NSLog(@"vphoned: missing IOKit symbols");
        return NO;
    }
    if (!pAccel) {
        NSLog(@"vphoned: IOHIDEventCreateAccelerometerEvent not found (shake disabled)");
    }

    gClient = pCreate(kCFAllocatorDefault);
    if (!gClient) { NSLog(@"vphoned: IOHIDEventSystemClientCreate returned NULL"); return NO; }

    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(
        DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INTERACTIVE, 0);
    gHIDQueue = dispatch_queue_create("com.vphone.vphoned.hid", attr);

    NSLog(@"vphoned: IOKit loaded");
    return YES;
}

static void send_hid_event(IOHIDEventRef event) {
    IOHIDEventRef strong = (IOHIDEventRef)CFRetain(event);
    dispatch_async(gHIDQueue, ^{
        pSetSender(strong, 0x8000000817319372);
        pDispatch(gClient, strong);
        CFRelease(strong);
    });
}

void vp_hid_press(uint32_t page, uint32_t usage) {
    IOHIDEventRef down = pKeyboard(kCFAllocatorDefault, mach_absolute_time(),
                                   page, usage, 1, 0);
    if (!down) return;
    send_hid_event(down);
    CFRelease(down);

    usleep(100000);

    IOHIDEventRef up = pKeyboard(kCFAllocatorDefault, mach_absolute_time(),
                                 page, usage, 0, 0);
    if (!up) return;
    send_hid_event(up);
    CFRelease(up);
}

void vp_hid_key(uint32_t page, uint32_t usage, BOOL down) {
    IOHIDEventRef ev = pKeyboard(kCFAllocatorDefault, mach_absolute_time(),
                                 page, usage, down ? 1 : 0, 0);
    if (ev) { send_hid_event(ev); CFRelease(ev); }
}

void vp_hid_shake(void) {
    if (!pAccel) {
        NSLog(@"vphoned: shake not available (no accelerometer API)");
        return;
    }

    // Simulate a shake gesture by injecting rapid X-axis oscillation.
    // UIKit's shake detector triggers when it sees >2g acceleration
    // changes in alternating directions within ~600ms.
    struct { double x; double y; double z; int delay_us; } seq[] = {
        { +3.0,  0.0,  -1.0,  80000 },  // strong right
        { -3.0,  0.0,  -1.0,  80000 },  // strong left
        { +3.0,  0.0,  -1.0,  80000 },  // strong right
        { -3.0,  0.0,  -1.0,  80000 },  // strong left
        {  0.0,  0.0,  -1.0,  0     },  // settle (gravity only)
    };
    int n = sizeof(seq) / sizeof(seq[0]);

    for (int i = 0; i < n; i++) {
        IOHIDEventRef ev = pAccel(kCFAllocatorDefault, mach_absolute_time(),
                                  seq[i].x, seq[i].y, seq[i].z, 0);
        if (ev) {
            send_hid_event(ev);
            CFRelease(ev);
        }
        if (seq[i].delay_us > 0) usleep(seq[i].delay_us);
    }
    NSLog(@"vphoned: shake injected");
}
