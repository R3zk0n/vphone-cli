#import "vphoned_shared_cache.h"
#import "vphoned_protocol.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// dyld_cache_header — subset of fields we need (stable across iOS versions)
struct dyld_cache_header {
    char magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffsetOld;      // pre-iOS 13 image info offset
    uint32_t imagesCountOld;       // pre-iOS 13 image count
    uint64_t dyldBaseAddress;
    uint64_t pad1[3];
    uint64_t slideInfoOffsetUnused;
    uint64_t slideInfoSizeUnused;
    uint64_t localSymbolsOffset;
    uint64_t localSymbolsSize;
    char uuid[16];
    uint64_t cacheType;
    uint32_t branchPoolsOffset;
    uint32_t branchPoolsCount;
    uint64_t pad2[4];
    uint64_t imagesTextOffset;     // offset to dyld_cache_image_text_info array
    uint64_t imagesTextCount;      // count of dyld_cache_image_text_info entries
    uint64_t pad3[2];
    uint64_t pad4[2];
    uint32_t imagesOffset;         // offset to dyld_cache_image_info array (modern)
    uint32_t imagesCount;          // count of dyld_cache_image_info entries (modern)
};

struct dyld_cache_mapping_info {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

struct dyld_cache_image_info {
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
};

#define DYLD_CACHE_DIR "/System/Library/Caches/com.apple.dyld/"

// MARK: - Helpers

/// Find all dyld shared cache files on the device.
static NSArray<NSDictionary *> *list_cache_files(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *contents = [fm contentsOfDirectoryAtPath:@DYLD_CACHE_DIR error:&err];
    if (!contents) return @[];

    NSMutableArray *result = [NSMutableArray array];
    for (NSString *name in contents) {
        if (![name hasPrefix:@"dyld_shared_cache"]) continue;
        // Skip .map files and subcache symbol files
        if ([name hasSuffix:@".map"]) continue;

        NSString *full = [@DYLD_CACHE_DIR stringByAppendingPathComponent:name];
        struct stat st;
        if (stat([full fileSystemRepresentation], &st) != 0) continue;

        [result addObject:@{
            @"name": name,
            @"path": full,
            @"size": @((unsigned long long)st.st_size),
        }];
    }
    return result;
}

/// Map the cache file into memory (read-only). Returns NULL on failure.
static void *map_cache(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }

    void *base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return NULL;

    *out_size = (size_t)st.st_size;
    return base;
}

/// List all images in a mapped cache. Returns array of {path, address, index}.
static NSArray<NSDictionary *> *list_images(void *base, size_t size) {
    struct dyld_cache_header *hdr = (struct dyld_cache_header *)base;

    // Use modern fields if available, fall back to old
    uint32_t count = hdr->imagesCount;
    uint32_t offset = hdr->imagesOffset;
    if (count == 0) {
        count = hdr->imagesCountOld;
        offset = hdr->imagesOffsetOld;
    }
    if (count == 0 || offset == 0) return @[];
    if (offset + count * sizeof(struct dyld_cache_image_info) > size) return @[];

    struct dyld_cache_image_info *images = (struct dyld_cache_image_info *)((uint8_t *)base + offset);

    NSMutableArray *result = [NSMutableArray arrayWithCapacity:count];
    for (uint32_t i = 0; i < count; i++) {
        uint32_t pathOff = images[i].pathFileOffset;
        if (pathOff >= size) continue;

        const char *path = (const char *)base + pathOff;
        // Safety: ensure null-terminated within bounds
        size_t maxLen = size - pathOff;
        size_t pathLen = strnlen(path, maxLen);
        if (pathLen == maxLen) continue;

        [result addObject:@{
            @"path": [NSString stringWithUTF8String:path],
            @"address": [NSString stringWithFormat:@"0x%llx", images[i].address],
            @"index": @(i),
        }];
    }
    return result;
}

/// Find the file region for a single Mach-O image in the cache.
/// Walks the cache mappings to locate contiguous segments.
/// Returns YES and fills out_offset/out_size on success.
static BOOL find_image_region(void *base, size_t cache_size,
                              uint64_t image_addr,
                              uint64_t *out_offset, uint64_t *out_size) {
    struct dyld_cache_header *hdr = (struct dyld_cache_header *)base;
    if (hdr->mappingOffset + hdr->mappingCount * sizeof(struct dyld_cache_mapping_info) > cache_size)
        return NO;

    struct dyld_cache_mapping_info *mappings =
        (struct dyld_cache_mapping_info *)((uint8_t *)base + hdr->mappingOffset);

    // Find which mapping contains the image header
    uint64_t headerFileOffset = 0;
    BOOL found = NO;
    for (uint32_t i = 0; i < hdr->mappingCount; i++) {
        uint64_t mapStart = mappings[i].address;
        uint64_t mapEnd = mapStart + mappings[i].size;
        if (image_addr >= mapStart && image_addr < mapEnd) {
            headerFileOffset = mappings[i].fileOffset + (image_addr - mapStart);
            found = YES;
            break;
        }
    }
    if (!found) return NO;
    if (headerFileOffset + sizeof(struct mach_header_64) > cache_size) return NO;

    // Read the Mach-O header to find its total size from load commands
    struct mach_header_64 *mh = (struct mach_header_64 *)((uint8_t *)base + headerFileOffset);
    if (mh->magic != MH_MAGIC_64) return NO;

    // Walk segments to find the total VM extent of this image
    uint64_t vmLow = UINT64_MAX;
    uint64_t vmHigh = 0;
    uint32_t cmdOffset = (uint32_t)(headerFileOffset + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmdOffset + sizeof(struct load_command) > cache_size) return NO;
        struct load_command *lc = (struct load_command *)((uint8_t *)base + cmdOffset);
        if (lc->cmdsize < sizeof(struct load_command)) return NO;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmsize > 0) {
                if (seg->vmaddr < vmLow) vmLow = seg->vmaddr;
                if (seg->vmaddr + seg->vmsize > vmHigh) vmHigh = seg->vmaddr + seg->vmsize;
            }
        }
        cmdOffset += lc->cmdsize;
    }

    if (vmLow >= vmHigh) return NO;

    // The extract payload is the Mach-O header + all load commands + __TEXT data.
    // For cache extraction, we output the file region from the header to the end
    // of the last segment that falls in the same mapping (usually __TEXT).
    // Full dylib reconstruction would require re-linking segments from multiple
    // mappings, but for analysis the __TEXT-mapped region is what callers need.
    //
    // Compute the contiguous file region starting at the header within its mapping.
    uint64_t mappingBase = 0;
    uint64_t mappingEnd = 0;
    for (uint32_t i = 0; i < hdr->mappingCount; i++) {
        uint64_t mapStart = mappings[i].address;
        uint64_t mapSize = mappings[i].size;
        if (image_addr >= mapStart && image_addr < mapStart + mapSize) {
            mappingBase = mappings[i].fileOffset;
            mappingEnd = mappings[i].fileOffset + mapSize;
            break;
        }
    }

    // Walk segments to find the furthest file extent within __TEXT mapping
    uint64_t fileHigh = headerFileOffset + sizeof(struct mach_header_64) + mh->sizeofcmds;
    cmdOffset = (uint32_t)(headerFileOffset + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmdOffset + sizeof(struct load_command) > cache_size) break;
        struct load_command *lc = (struct load_command *)((uint8_t *)base + cmdOffset);
        if (lc->cmdsize < sizeof(struct load_command)) break;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            // Only include segments whose file data is in the same mapping
            uint64_t segFileEnd = seg->fileoff + seg->filesize;
            if (seg->fileoff >= mappingBase && segFileEnd <= mappingEnd) {
                if (segFileEnd > fileHigh) fileHigh = segFileEnd;
            }
        }
        cmdOffset += lc->cmdsize;
    }

    if (fileHigh > cache_size) fileHigh = cache_size;

    *out_offset = headerFileOffset;
    *out_size = fileHigh - headerFileOffset;
    return YES;
}

// MARK: - Command Handler

NSDictionary *vp_handle_cache_command(int fd, NSDictionary *msg) {
    NSString *type = msg[@"t"];
    id reqId = msg[@"id"];

    // -- cache_list: list available shared cache files --
    if ([type isEqualToString:@"cache_list"]) {
        NSArray *caches = list_cache_files();
        NSMutableDictionary *r = vp_make_response(@"ok", reqId);
        r[@"caches"] = caches;
        return r;
    }

    // -- cache_images: list all images in a shared cache --
    if ([type isEqualToString:@"cache_images"]) {
        NSString *path = msg[@"path"];
        if (!path) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing path";
            return r;
        }

        size_t size = 0;
        void *base = map_cache([path fileSystemRepresentation], &size);
        if (!base) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"failed to map cache: %s", strerror(errno)];
            return r;
        }

        struct dyld_cache_header *hdr = (struct dyld_cache_header *)base;
        NSString *magic = [[NSString alloc] initWithBytes:hdr->magic
                                                   length:strnlen(hdr->magic, 16)
                                                 encoding:NSUTF8StringEncoding];

        NSArray *images = list_images(base, size);
        munmap(base, size);

        NSMutableDictionary *r = vp_make_response(@"ok", reqId);
        r[@"magic"] = magic ?: @"";
        r[@"count"] = @(images.count);
        r[@"images"] = images;
        return r;
    }

    // -- cache_search: search for images by name/path substring --
    if ([type isEqualToString:@"cache_search"]) {
        NSString *path = msg[@"path"];
        NSString *query = msg[@"query"];
        if (!path || !query) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing path or query";
            return r;
        }

        NSUInteger limit = [msg[@"limit"] unsignedIntegerValue];
        if (limit == 0) limit = 50;

        size_t size = 0;
        void *base = map_cache([path fileSystemRepresentation], &size);
        if (!base) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"failed to map cache: %s", strerror(errno)];
            return r;
        }

        NSArray *allImages = list_images(base, size);
        munmap(base, size);

        NSString *queryLower = [query lowercaseString];
        NSMutableArray *matches = [NSMutableArray array];
        for (NSDictionary *img in allImages) {
            NSString *imgPath = img[@"path"];
            if ([[imgPath lowercaseString] containsString:queryLower]) {
                [matches addObject:img];
                if (matches.count >= limit) break;
            }
        }

        NSMutableDictionary *r = vp_make_response(@"ok", reqId);
        r[@"query"] = query;
        r[@"count"] = @(matches.count);
        r[@"total"] = @(allImages.count);
        r[@"images"] = matches;
        return r;
    }

    // -- cache_extract: extract a single dylib from the cache --
    if ([type isEqualToString:@"cache_extract"]) {
        NSString *path = msg[@"path"];
        NSNumber *indexNum = msg[@"index"];
        if (!path || !indexNum) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing path or index";
            return r;
        }

        size_t cacheSize = 0;
        void *base = map_cache([path fileSystemRepresentation], &cacheSize);
        if (!base) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"failed to map cache: %s", strerror(errno)];
            return r;
        }

        struct dyld_cache_header *hdr = (struct dyld_cache_header *)base;
        uint32_t count = hdr->imagesCount;
        uint32_t offset = hdr->imagesOffset;
        if (count == 0) {
            count = hdr->imagesCountOld;
            offset = hdr->imagesOffsetOld;
        }

        uint32_t idx = [indexNum unsignedIntValue];
        if (idx >= count || offset + count * sizeof(struct dyld_cache_image_info) > cacheSize) {
            munmap(base, cacheSize);
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"index out of range";
            return r;
        }

        struct dyld_cache_image_info *images =
            (struct dyld_cache_image_info *)((uint8_t *)base + offset);
        uint64_t imageAddr = images[idx].address;

        // Get image path for response
        const char *imagePath = "";
        uint32_t pathOff = images[idx].pathFileOffset;
        if (pathOff < cacheSize) {
            imagePath = (const char *)base + pathOff;
        }

        uint64_t regionOffset = 0, regionSize = 0;
        if (!find_image_region(base, cacheSize, imageAddr, &regionOffset, &regionSize)) {
            munmap(base, cacheSize);
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"failed to locate image region in cache";
            return r;
        }

        // Send header with size, then stream the raw bytes
        NSMutableDictionary *header = vp_make_response(@"cache_data", reqId);
        header[@"size"] = @((unsigned long long)regionSize);
        header[@"image_path"] = [NSString stringWithUTF8String:imagePath];
        if (!vp_write_message(fd, header)) {
            munmap(base, cacheSize);
            return nil;
        }

        // Stream from the mmap in chunks
        uint8_t *src = (uint8_t *)base + regionOffset;
        uint64_t remaining = regionSize;
        while (remaining > 0) {
            size_t chunk = remaining < 32768 ? (size_t)remaining : 32768;
            if (!vp_write_fully(fd, src, chunk)) {
                NSLog(@"vphoned: cache_extract write failed");
                munmap(base, cacheSize);
                return nil;
            }
            src += chunk;
            remaining -= chunk;
        }

        munmap(base, cacheSize);
        NSLog(@"vphoned: cache_extract %s (%llu bytes)", imagePath, regionSize);
        return nil;  // Response already written inline
    }

    NSMutableDictionary *r = vp_make_response(@"err", reqId);
    r[@"msg"] = [NSString stringWithFormat:@"unknown cache command: %@", type];
    return r;
}
