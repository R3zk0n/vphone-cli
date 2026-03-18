/*
 * vphoned_xpc — XPC/Mach service enumeration and introspection.
 *
 * Research tooling for inspecting the iOS XPC landscape:
 *   xpc_list     — enumerate all Mach services registered in launchd plists
 *   xpc_lookup   — resolve a Mach service name to its owning daemon + PID
 *   xpc_probe    — test if a Mach service is reachable (bootstrap_look_up)
 *   xpc_dump     — dump all XPC endpoints for a given launchd plist
 *   xpc_connect  — send a trivial XPC message and return the reply (or error)
 */

#import "vphoned_xpc.h"
#import "vphoned_protocol.h"

#import <Foundation/Foundation.h>
#include <bootstrap.h>
#include <xpc/xpc.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <signal.h>
#include <unistd.h>

// MARK: - Private API declarations

// bootstrap_look_up: resolve a Mach service name to a send right
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *name, mach_port_t *sp);

// xpc_connection introspection (private)
extern int xpc_connection_get_pid(xpc_connection_t conn);
extern uid_t xpc_connection_get_euid(xpc_connection_t conn);
extern au_asid_t xpc_connection_get_asid(xpc_connection_t conn);

// xpc_copy_description: human-readable dump of any xpc object
extern char *xpc_copy_description(xpc_object_t obj);

// MARK: - Helpers

/// Scan a directory for .plist files (non-recursive).
static NSArray<NSString *> *plist_files_in_dir(NSString *dir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *contents = [fm contentsOfDirectoryAtPath:dir error:&err];
    if (!contents) return @[];

    NSMutableArray *plists = [NSMutableArray array];
    for (NSString *name in contents) {
        if ([name hasSuffix:@".plist"]) {
            [plists addObject:[dir stringByAppendingPathComponent:name]];
        }
    }
    return plists;
}

/// Extract Mach services from a launchd plist dict.
static NSArray<NSDictionary *> *services_from_plist(NSString *path) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!plist) return @[];

    NSMutableArray *results = [NSMutableArray array];
    NSString *label = plist[@"Label"] ?: [path lastPathComponent];
    NSString *program = plist[@"Program"] ?: @"";
    NSArray *programArgs = plist[@"ProgramArguments"];
    if (program.length == 0 && programArgs.count > 0) {
        program = programArgs[0];
    }

    // MachServices dict: { "service.name": true/dict, ... }
    NSDictionary *machServices = plist[@"MachServices"];
    if ([machServices isKindOfClass:[NSDictionary class]]) {
        for (NSString *svcName in machServices) {
            [results addObject:@{
                @"service": svcName,
                @"label": label,
                @"program": program,
                @"plist": path,
                @"type": @"MachServices",
            }];
        }
    }

    // Some plists use XPCService dict
    NSDictionary *xpcService = plist[@"XPCService"];
    if ([xpcService isKindOfClass:[NSDictionary class]]) {
        NSString *svcName = xpcService[@"ServiceName"] ?: label;
        [results addObject:@{
            @"service": svcName,
            @"label": label,
            @"program": program,
            @"plist": path,
            @"type": @"XPCService",
        }];
    }

    return results;
}

/// Get PID for a launchd job label using launchctl-style lookup.
static pid_t pid_for_label(NSString *label) {
    // Use bootstrap to check — but first try /var/run or proc
    // Simpler: use our own bootstrap_look_up + audit_token approach
    // For now, scan /proc or use kill(0) after finding the binary
    return 0; // Will be filled by bootstrap_look_up probe
}

/// Try bootstrap_look_up for a Mach service name.
static NSDictionary *probe_service(NSString *serviceName) {
    mach_port_t bp = bootstrap_port;
    mach_port_t sp = MACH_PORT_NULL;

    kern_return_t kr = bootstrap_look_up(bp, serviceName.UTF8String, &sp);

    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"service"] = serviceName;
    result[@"status"] = @(kr);

    if (kr == KERN_SUCCESS && sp != MACH_PORT_NULL) {
        result[@"reachable"] = @YES;

        // Get port info
        mach_port_type_t type;
        kern_return_t tr = mach_port_type(mach_task_self(), sp, &type);
        if (tr == KERN_SUCCESS) {
            NSMutableArray *rights = [NSMutableArray array];
            if (type & MACH_PORT_TYPE_SEND) [rights addObject:@"send"];
            if (type & MACH_PORT_TYPE_RECEIVE) [rights addObject:@"receive"];
            if (type & MACH_PORT_TYPE_SEND_ONCE) [rights addObject:@"send_once"];
            if (type & MACH_PORT_TYPE_DEAD_NAME) [rights addObject:@"dead"];
            result[@"rights"] = rights;
        }

        mach_port_deallocate(mach_task_self(), sp);
    } else {
        result[@"reachable"] = @NO;
        result[@"error"] = kr == 1102 ? @"not found" :
                           kr == 1103 ? @"not privileged" :
                           [NSString stringWithFormat:@"kern_return %d", kr];
    }

    return result;
}

/// Try to send a ping/checkin XPC message and get a reply.
static NSDictionary *try_xpc_connect(NSString *serviceName, double timeout) {
    __block NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"service"] = serviceName;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_t conn = xpc_connection_create_mach_service(
        serviceName.UTF8String, NULL, 0);

    if (!conn) {
        result[@"ok"] = @NO;
        result[@"error"] = @"xpc_connection_create_mach_service returned NULL";
        return result;
    }

    __block BOOL gotEvent = NO;

    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            if (event == XPC_ERROR_CONNECTION_INVALID) {
                result[@"event"] = @"connection_invalid";
            } else if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                result[@"event"] = @"connection_interrupted";
            } else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
                result[@"event"] = @"termination_imminent";
            }
            if (!gotEvent) {
                gotEvent = YES;
                dispatch_semaphore_signal(sem);
            }
        }
    });

    xpc_connection_resume(conn);

    // Get connection metadata
    pid_t remote_pid = xpc_connection_get_pid(conn);
    uid_t remote_euid = xpc_connection_get_euid(conn);
    au_asid_t remote_asid = xpc_connection_get_asid(conn);

    result[@"remote_pid"] = @(remote_pid);
    result[@"remote_euid"] = @(remote_euid);
    result[@"remote_asid"] = @(remote_asid);

    // Send a trivial dictionary message
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "ping", "vphoned");

    xpc_connection_send_message_with_reply(conn, msg, dispatch_get_global_queue(0, 0),
        ^(xpc_object_t reply) {
            if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
                if (reply == XPC_ERROR_CONNECTION_INVALID) {
                    result[@"reply"] = @"connection_invalid";
                } else if (reply == XPC_ERROR_CONNECTION_INTERRUPTED) {
                    result[@"reply"] = @"connection_interrupted";
                } else {
                    result[@"reply"] = @"error";
                }
                result[@"ok"] = @NO;
            } else if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
                char *desc = xpc_copy_description(reply);
                if (desc) {
                    result[@"reply"] = [NSString stringWithUTF8String:desc];
                    free(desc);
                }
                result[@"ok"] = @YES;
            } else {
                char *desc = xpc_copy_description(reply);
                if (desc) {
                    result[@"reply"] = [NSString stringWithUTF8String:desc];
                    free(desc);
                }
                result[@"ok"] = @NO;
            }
            if (!gotEvent) {
                gotEvent = YES;
                dispatch_semaphore_signal(sem);
            }
        });

    // Wait with timeout
    long waitResult = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)));
    if (waitResult != 0) {
        result[@"ok"] = @NO;
        result[@"error"] = @"timeout";
    }

    xpc_connection_cancel(conn);
    return result;
}

/// Enumerate Mach ports for a given process task port.
static NSArray *enumerate_mach_ports(void) {
    mach_port_name_array_t names = NULL;
    mach_msg_type_number_t namesCnt = 0;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t typesCnt = 0;

    kern_return_t kr = mach_port_names(mach_task_self(), &names, &namesCnt, &types, &typesCnt);
    if (kr != KERN_SUCCESS) return @[];

    NSMutableArray *ports = [NSMutableArray array];
    for (mach_msg_type_number_t i = 0; i < namesCnt; i++) {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        info[@"name"] = @(names[i]);

        NSMutableArray *rights = [NSMutableArray array];
        if (types[i] & MACH_PORT_TYPE_SEND) [rights addObject:@"send"];
        if (types[i] & MACH_PORT_TYPE_RECEIVE) [rights addObject:@"receive"];
        if (types[i] & MACH_PORT_TYPE_SEND_ONCE) [rights addObject:@"send_once"];
        if (types[i] & MACH_PORT_TYPE_DEAD_NAME) [rights addObject:@"dead"];
        if (types[i] & MACH_PORT_TYPE_PORT_SET) [rights addObject:@"port_set"];
        info[@"rights"] = rights;

        [ports addObject:info];
    }

    vm_deallocate(mach_task_self(), (vm_address_t)names, namesCnt * sizeof(mach_port_name_t));
    vm_deallocate(mach_task_self(), (vm_address_t)types, typesCnt * sizeof(mach_port_type_t));

    return ports;
}

// MARK: - XPC Monitor (os_log streaming)

/// Monitor state — accumulates XPC-related log entries in a ring buffer.
static NSMutableArray *gXPCMonitorEntries = nil;
static BOOL gXPCMonitorActive = NO;
static NSTask *gLogStreamTask = nil;
static NSPipe *gLogStreamPipe = nil;

/// Start monitoring XPC messages via `log stream`.
static void start_xpc_monitor(NSString *filter, int maxEntries) {
    if (gXPCMonitorActive) return;
    gXPCMonitorActive = YES;
    gXPCMonitorEntries = [NSMutableArray array];

    // Use `log stream` with predicate filtering for XPC/Mach messages
    NSString *predicate = filter ?: @"subsystem == 'com.apple.xpc' OR "
                                     @"category == 'xpc' OR "
                                     @"subsystem == 'com.apple.launchd' OR "
                                     @"eventMessage CONTAINS 'xpc_connection' OR "
                                     @"eventMessage CONTAINS 'mach_msg' OR "
                                     @"eventMessage CONTAINS 'bootstrap'";

    gLogStreamPipe = [NSPipe pipe];

    gLogStreamTask = [[NSTask alloc] init];
    gLogStreamTask.launchPath = @"/usr/bin/log";
    gLogStreamTask.arguments = @[
        @"stream",
        @"--style", @"ndjson",
        @"--predicate", predicate,
        @"--level", @"debug",
    ];
    gLogStreamTask.standardOutput = gLogStreamPipe;
    gLogStreamTask.standardError = [NSPipe pipe]; // discard stderr

    NSFileHandle *fh = gLogStreamPipe.fileHandleForReading;
    int limit = maxEntries > 0 ? maxEntries : 500;

    // Read in background, parse JSON lines, accumulate
    fh.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = handle.availableData;
        if (data.length == 0) return;

        NSString *chunk = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!chunk) return;

        // Parse NDJSON lines
        NSArray *lines = [chunk componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
            if (!lineData) continue;

            NSDictionary *entry = [NSJSONSerialization JSONObjectWithData:lineData options:0 error:nil];
            if (!entry) continue;

            NSMutableDictionary *parsed = [NSMutableDictionary dictionary];
            parsed[@"timestamp"] = entry[@"timestamp"] ?: @"";
            parsed[@"process"] = entry[@"processImagePath"] ?: entry[@"process"] ?: @"";
            parsed[@"pid"] = entry[@"processID"] ?: @0;
            parsed[@"subsystem"] = entry[@"subsystem"] ?: @"";
            parsed[@"category"] = entry[@"category"] ?: @"";
            parsed[@"message"] = entry[@"eventMessage"] ?: @"";
            parsed[@"type"] = entry[@"messageType"] ?: @"";

            // Extract process name from path
            NSString *procPath = parsed[@"process"];
            if ([procPath isKindOfClass:[NSString class]] && procPath.length > 0) {
                parsed[@"processName"] = [procPath lastPathComponent];
            }

            @synchronized (gXPCMonitorEntries) {
                [gXPCMonitorEntries addObject:parsed];
                // Ring buffer: trim old entries
                while ((int)gXPCMonitorEntries.count > limit) {
                    [gXPCMonitorEntries removeObjectAtIndex:0];
                }
            }
        }
    };

    NSError *err = nil;
    [gLogStreamTask launchAndReturnError:&err];
    if (err) {
        NSLog(@"vphoned: xpc_monitor: log stream launch failed: %@", err);
        gXPCMonitorActive = NO;
    } else {
        NSLog(@"vphoned: xpc_monitor: started (predicate=%@)", predicate);
    }
}

/// Stop the XPC monitor.
static void stop_xpc_monitor(void) {
    if (!gXPCMonitorActive) return;
    gXPCMonitorActive = NO;

    if (gLogStreamTask && gLogStreamTask.isRunning) {
        [gLogStreamTask terminate];
    }
    gLogStreamTask = nil;

    if (gLogStreamPipe) {
        gLogStreamPipe.fileHandleForReading.readabilityHandler = nil;
    }
    gLogStreamPipe = nil;

    NSLog(@"vphoned: xpc_monitor: stopped");
}

/// Drain current entries and return them.
static NSArray *drain_xpc_monitor(void) {
    if (!gXPCMonitorEntries) return @[];
    NSArray *entries;
    @synchronized (gXPCMonitorEntries) {
        entries = [gXPCMonitorEntries copy];
        [gXPCMonitorEntries removeAllObjects];
    }
    return entries;
}

// MARK: - Command Handler

NSDictionary *vp_handle_xpc_command(NSDictionary *msg) {
    NSString *type = msg[@"t"];
    id reqId = msg[@"id"];

    // xpc_list — enumerate all registered Mach services from launchd plists
    if ([type isEqualToString:@"xpc_list"]) {
        NSArray *searchDirs = @[
            @"/System/Library/LaunchDaemons",
            @"/Library/LaunchDaemons",
            @"/System/Library/LaunchAgents",
            @"/Library/LaunchAgents",
            @"/System/Library/xpc",
        ];

        NSString *filter = msg[@"filter"]; // optional substring filter
        BOOL probeReachable = [msg[@"probe"] boolValue]; // optional: test bootstrap_look_up

        NSMutableArray *allServices = [NSMutableArray array];
        NSMutableSet *seen = [NSMutableSet set]; // dedup by service name

        for (NSString *dir in searchDirs) {
            NSArray *plists = plist_files_in_dir(dir);
            for (NSString *plistPath in plists) {
                NSArray *services = services_from_plist(plistPath);
                for (NSDictionary *svc in services) {
                    NSString *svcName = svc[@"service"];
                    if ([seen containsObject:svcName]) continue;
                    [seen addObject:svcName];

                    if (filter && ![svcName localizedCaseInsensitiveContainsString:filter]
                               && ![svc[@"label"] localizedCaseInsensitiveContainsString:filter]) {
                        continue;
                    }

                    if (probeReachable) {
                        NSMutableDictionary *entry = [svc mutableCopy];
                        NSDictionary *probeResult = probe_service(svcName);
                        entry[@"reachable"] = probeResult[@"reachable"];
                        if (probeResult[@"error"]) entry[@"probe_error"] = probeResult[@"error"];
                        [allServices addObject:entry];
                    } else {
                        [allServices addObject:svc];
                    }
                }
            }
        }

        NSMutableDictionary *r = vp_make_response(@"xpc_list", reqId);
        r[@"services"] = allServices;
        r[@"count"] = @(allServices.count);
        return r;
    }

    // xpc_probe — test if a specific service is reachable via bootstrap
    if ([type isEqualToString:@"xpc_probe"]) {
        NSString *serviceName = msg[@"service"];
        if (!serviceName) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing 'service' parameter";
            return r;
        }

        NSDictionary *probeResult = probe_service(serviceName);
        NSMutableDictionary *r = vp_make_response(@"xpc_probe", reqId);
        [r addEntriesFromDictionary:probeResult];
        return r;
    }

    // xpc_connect — attempt to connect and send a message to a Mach service
    if ([type isEqualToString:@"xpc_connect"]) {
        NSString *serviceName = msg[@"service"];
        if (!serviceName) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing 'service' parameter";
            return r;
        }

        double timeout = [msg[@"timeout"] doubleValue];
        if (timeout <= 0) timeout = 3.0;

        NSDictionary *connectResult = try_xpc_connect(serviceName, timeout);
        NSMutableDictionary *r = vp_make_response(@"xpc_connect", reqId);
        [r addEntriesFromDictionary:connectResult];
        return r;
    }

    // xpc_dump — dump a specific launchd plist's full content
    if ([type isEqualToString:@"xpc_dump"]) {
        NSString *path = msg[@"plist"];
        NSString *label = msg[@"label"];

        if (!path && label) {
            // Search for plist by label
            NSArray *searchDirs = @[
                @"/System/Library/LaunchDaemons",
                @"/Library/LaunchDaemons",
                @"/System/Library/LaunchAgents",
                @"/Library/LaunchAgents",
            ];
            for (NSString *dir in searchDirs) {
                NSString *candidate = [dir stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"%@.plist", label]];
                if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) {
                    path = candidate;
                    break;
                }
            }
        }

        if (!path) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing 'plist' or 'label' parameter";
            return r;
        }

        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];
        if (!plist) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"could not read %@", path];
            return r;
        }

        // Convert to JSON-safe representation
        NSError *jsonErr = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:plist
                                                          options:NSJSONWritingPrettyPrinted
                                                            error:&jsonErr];

        NSMutableDictionary *r = vp_make_response(@"xpc_dump", reqId);
        r[@"path"] = path;
        r[@"label"] = plist[@"Label"] ?: @"";
        if (jsonData && !jsonErr) {
            r[@"content"] = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        } else {
            r[@"content"] = [plist description];
        }

        // Extract key fields
        if (plist[@"MachServices"]) r[@"mach_services"] = [plist[@"MachServices"] allKeys];
        if (plist[@"Program"]) r[@"program"] = plist[@"Program"];
        if (plist[@"ProgramArguments"]) r[@"program_args"] = plist[@"ProgramArguments"];
        if (plist[@"Sockets"]) r[@"sockets"] = [[plist[@"Sockets"] allKeys] componentsJoinedByString:@", "];
        if (plist[@"UserName"]) r[@"user"] = plist[@"UserName"];
        if (plist[@"RunAtLoad"]) r[@"run_at_load"] = plist[@"RunAtLoad"];
        if (plist[@"KeepAlive"]) r[@"keep_alive"] = @YES;
        if (plist[@"EnablePressuredExit"]) r[@"pressured_exit"] = plist[@"EnablePressuredExit"];

        return r;
    }

    // xpc_ports — enumerate our own Mach ports (introspection)
    if ([type isEqualToString:@"xpc_ports"]) {
        NSArray *ports = enumerate_mach_ports();
        NSMutableDictionary *r = vp_make_response(@"xpc_ports", reqId);
        r[@"ports"] = ports;
        r[@"count"] = @(ports.count);
        r[@"pid"] = @(getpid());
        return r;
    }

    // xpc_monitor_start — start streaming XPC log messages
    if ([type isEqualToString:@"xpc_monitor_start"]) {
        NSString *filter = msg[@"filter"]; // optional custom predicate
        int maxEntries = [msg[@"max"] intValue];

        start_xpc_monitor(filter, maxEntries);

        NSMutableDictionary *r = vp_make_response(@"xpc_monitor_start", reqId);
        r[@"ok"] = @(gXPCMonitorActive);
        return r;
    }

    // xpc_monitor_stop — stop streaming
    if ([type isEqualToString:@"xpc_monitor_stop"]) {
        stop_xpc_monitor();
        NSMutableDictionary *r = vp_make_response(@"xpc_monitor_stop", reqId);
        r[@"ok"] = @YES;
        return r;
    }

    // xpc_monitor_poll — drain accumulated entries
    if ([type isEqualToString:@"xpc_monitor_poll"]) {
        NSArray *entries = drain_xpc_monitor();
        NSMutableDictionary *r = vp_make_response(@"xpc_monitor_poll", reqId);
        r[@"entries"] = entries;
        r[@"count"] = @(entries.count);
        r[@"active"] = @(gXPCMonitorActive);
        return r;
    }

    NSMutableDictionary *r = vp_make_response(@"err", reqId);
    r[@"msg"] = [NSString stringWithFormat:@"unknown xpc command: %@", type];
    return r;
}
