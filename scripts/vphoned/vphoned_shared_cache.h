/*
 * vphoned_shared_cache — Remote dyld shared cache listing and extraction.
 *
 * Handles cache_list, cache_images, cache_search, cache_extract.
 * cache_extract performs inline binary I/O on the socket (same pattern as file_get).
 */

#pragma once
#import <Foundation/Foundation.h>

/// Handle a shared cache command. Returns a response dict, or nil if the
/// response was already written inline (e.g. cache_extract with streaming data).
NSDictionary *vp_handle_cache_command(int fd, NSDictionary *msg);
