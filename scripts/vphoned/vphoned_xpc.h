/*
 * vphoned_xpc — XPC service enumeration and message introspection.
 *
 * Provides research tooling for inspecting the XPC/Mach service landscape:
 *   - Enumerate all registered Mach/XPC services from launchd plists
 *   - Look up service ownership (which process, what PID)
 *   - Inspect XPC endpoints and connections
 */

#pragma once
#import <Foundation/Foundation.h>

/// Handle an XPC research command. Returns a response dict.
NSDictionary *vp_handle_xpc_command(NSDictionary *msg);
