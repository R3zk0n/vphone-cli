#import "vphoned_shared_cache.h"
#include <stdint.h>
#import "vphoned_protocol.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// dyld_cache_header — full layout from dyld source
struct dyld_cache_header {
    char        magic[16];                  // e.g. "dyld_v0  i386"
    uint32_t    mappingOffset;              // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;               // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffset;               // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;                // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;            // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;        // file offset of code signature blob
    uint64_t    codeSignatureSize;          // size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffset;            // file offset of kernel slid info
    uint64_t    slideInfoSize;              // size of kernel slid info
    uint64_t    localSymbolsOffset;         // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;           // size of local symbols information
    uint8_t     uuid[16];                   // unique value for each shared cache file
    uint64_t    cacheType;                  // 0 for development, 1 for production
    uint32_t    branchPoolsOffset;          // file offset to table of uint64_t pool addresses
    uint32_t    branchPoolsCount;           // number of uint64_t entries
    uint64_t    accelerateInfoAddr;         // (unslid) address of optimization info
    uint64_t    accelerateInfoSize;         // size of optimization info
    uint64_t    imagesTextOffset;           // file offset to first dyld_cache_image_text_info
    uint64_t    imagesTextCount;            // number of dyld_cache_image_text_info entries
    uint64_t    dylibsImageGroupAddr;       // (unslid) address of ImageGroup for dylibs in this cache
    uint64_t    dylibsImageGroupSize;       // size of ImageGroup for dylibs in this cache
    uint64_t    otherImageGroupAddr;        // (unslid) address of ImageGroup for other OS dylibs
    uint64_t    otherImageGroupSize;        // size of ImageGroup for other OS dylibs
    uint64_t    progClosuresAddr;           // (unslid) address of list of program launch closures
    uint64_t    progClosuresSize;           // size of list of program launch closures
    uint64_t    progClosuresTrieAddr;       // (unslid) address of trie of indexes into program launch closures
    uint64_t    progClosuresTrieSize;       // size of trie of indexes into program launch closures
    uint32_t    platform;                   // platform number (macOS=1, etc)
    uint32_t    formatVersion       : 8,    // launch_cache::binary_format::kFormatVersion
                dylibsExpectedOnDisk: 1,    // dyld should expect the dylib exists on disk and to compare inode/mtime
                simulator           : 1,    // for simulator of specified platform
                _padding            : 22;
    uint64_t    sharedRegionStart;          // base load address of cache if not slid
    uint64_t    sharedRegionSize;           // overall size of region cache can be mapped into
    uint64_t    maxSlide;                   // runtime slide of cache can be between zero and this value
    // Darwin 18+:
    uint64_t    dylibsImageArrayAddr;       // (unslid) address of ImageArray for dylibs in this cache
    uint64_t    dylibsImageArraySize;       // size of ImageArray for dylibs in this cache
    uint64_t    dylibsTrieAddr;             // (unslid) address of trie of indexes of all cached dylibs
    uint64_t    dylibsTrieSize;             // size of trie of cached dylib paths
    uint64_t    otherImageArrayAddr;        // (unslid) address of ImageArray for dylibs/bundles with dlopen closures
    uint64_t    otherImageArraySize;        // size of ImageArray for dylibs/bundles with dlopen closures
    uint64_t    otherTrieAddr;              // (unslid) address of trie of indexes of all dylibs/bundles with dlopen closures
    uint64_t    otherTrieSize;              // size of trie of dylibs/bundles with dlopen closures
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
#define MAX_CACHE_FILES 128
#define MAX_MAPPINGS    512

// MARK: - Multi-file cache context

/// A single mmapped cache file (main or subcache).
struct cache_file {
    void    *base;
    size_t   size;
};

/// One VM→file mapping entry, resolved across all subcache files.
struct resolved_mapping {
    uint64_t vmAddr;
    uint64_t vmSize;
    uint64_t fileOffset;    // offset within the specific cache_file
    int      fileIndex;     // index into cache_file array
};

/// Full context for working with a split shared cache.
struct cache_ctx {
    struct cache_file        files[MAX_CACHE_FILES];
    int                      fileCount;
    struct resolved_mapping  mappings[MAX_MAPPINGS];
    int                      mappingCount;
    // Image info (from main cache only)
    struct dyld_cache_image_info *images;
    uint32_t                 imageCount;
    void                    *mainBase;
    size_t                   mainSize;
};

/// Open the main cache + all subcache files, build unified mapping table.
/// `mainPath` should be the base cache file (e.g. dyld_shared_cache_arm64e).
/// Returns YES on success.
static BOOL ctx_open(struct cache_ctx *ctx, const char *mainPath) {
    memset(ctx, 0, sizeof(*ctx));

    // Map main file
    ctx->files[0].base = map_cache(mainPath, &ctx->files[0].size);
    if (!ctx->files[0].base) return NO;
    ctx->fileCount = 1;
    ctx->mainBase = ctx->files[0].base;
    ctx->mainSize = ctx->files[0].size;

    // Parse main header for image info
    struct dyld_cache_header *hdr = (struct dyld_cache_header *)ctx->mainBase;
    if (hdr->imagesOffset + hdr->imagesCount * sizeof(struct dyld_cache_image_info) <= ctx->mainSize) {
        ctx->images = (struct dyld_cache_image_info *)((uint8_t *)ctx->mainBase + hdr->imagesOffset);
        ctx->imageCount = hdr->imagesCount;
    }

    // Add main file's mappings
    if (hdr->mappingOffset + hdr->mappingCount * sizeof(struct dyld_cache_mapping_info) <= ctx->mainSize) {
        struct dyld_cache_mapping_info *maps =
            (struct dyld_cache_mapping_info *)((uint8_t *)ctx->mainBase + hdr->mappingOffset);
        for (uint32_t i = 0; i < hdr->mappingCount && ctx->mappingCount < MAX_MAPPINGS; i++) {
            ctx->mappings[ctx->mappingCount++] = (struct resolved_mapping){
                .vmAddr = maps[i].address,
                .vmSize = maps[i].size,
                .fileOffset = maps[i].fileOffset,
                .fileIndex = 0,
            };
        }
    }

    // Find and open all subcache files (same prefix + .01, .02, ... or .symbols)
    // Derive the base name: e.g. "/System/.../dyld_shared_cache_arm64e"
    NSString *mainStr = [NSString stringWithUTF8String:mainPath];
    NSString *dir = [mainStr stringByDeletingLastPathComponent];
    NSString *baseName = [mainStr lastPathComponent];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *contents = [fm contentsOfDirectoryAtPath:dir error:nil];
    for (NSString *name in contents) {
        if (![name hasPrefix:baseName]) continue;
        if ([name isEqualToString:baseName]) continue;  // skip main file
        if ([name hasSuffix:@".map"]) continue;

        // Must start with baseName + "." (e.g. ".01", ".symbols")
        if (name.length <= baseName.length || [name characterAtIndex:baseName.length] != '.')
            continue;

        if (ctx->fileCount >= MAX_CACHE_FILES) break;

        NSString *subPath = [dir stringByAppendingPathComponent:name];
        int idx = ctx->fileCount;
        ctx->files[idx].base = map_cache([subPath fileSystemRepresentation], &ctx->files[idx].size);
        if (!ctx->files[idx].base) continue;
        ctx->fileCount++;

        // Parse this subcache's mappings
        struct dyld_cache_header *subHdr = (struct dyld_cache_header *)ctx->files[idx].base;
        if (memcmp(subHdr->magic, "dyld_v", 6) != 0) continue;  // not a valid cache

        if (subHdr->mappingOffset + subHdr->mappingCount * sizeof(struct dyld_cache_mapping_info)
            <= ctx->files[idx].size) {
            struct dyld_cache_mapping_info *subMaps =
                (struct dyld_cache_mapping_info *)((uint8_t *)ctx->files[idx].base + subHdr->mappingOffset);
            for (uint32_t i = 0; i < subHdr->mappingCount && ctx->mappingCount < MAX_MAPPINGS; i++) {
                ctx->mappings[ctx->mappingCount++] = (struct resolved_mapping){
                    .vmAddr = subMaps[i].address,
                    .vmSize = subMaps[i].size,
                    .fileOffset = subMaps[i].fileOffset,
                    .fileIndex = idx,
                };
            }
        }
    }

    NSLog(@"vphoned: cache context: %d files, %d mappings, %u images",
          ctx->fileCount, ctx->mappingCount, ctx->imageCount);
    return YES;
}

/// Release all mmapped files.
static void ctx_close(struct cache_ctx *ctx) {
    for (int i = 0; i < ctx->fileCount; i++) {
        if (ctx->files[i].base) munmap(ctx->files[i].base, ctx->files[i].size);
    }
    memset(ctx, 0, sizeof(*ctx));
}

/// Resolve a VM address to a pointer in the mmapped cache data.
/// Returns NULL if the address is not covered by any mapping.
static const void *ctx_resolve(struct cache_ctx *ctx, uint64_t vmAddr, uint64_t size) {
    for (int i = 0; i < ctx->mappingCount; i++) {
        struct resolved_mapping *m = &ctx->mappings[i];
        if (vmAddr >= m->vmAddr && vmAddr + size <= m->vmAddr + m->vmSize) {
            uint64_t off = m->fileOffset + (vmAddr - m->vmAddr);
            if (off + size > ctx->files[m->fileIndex].size) return NULL;
            return (const uint8_t *)ctx->files[m->fileIndex].base + off;
        }
    }
    return NULL;
}

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

/// Map a single cache file into memory (read-only).
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

/// List all images in the main cache. Returns array of {path, address, index}.
static NSArray<NSDictionary *> *list_images(void *base, size_t size) {
    struct dyld_cache_header *hdr = (struct dyld_cache_header *)base;

    uint32_t count = hdr->imagesCount;
    uint32_t offset = hdr->imagesOffset;
    if (count == 0 || offset == 0) return @[];
    if (offset + count * sizeof(struct dyld_cache_image_info) > size) return @[];

    struct dyld_cache_image_info *images = (struct dyld_cache_image_info *)((uint8_t *)base + offset);

    NSMutableArray *result = [NSMutableArray arrayWithCapacity:count];
    for (uint32_t i = 0; i < count; i++) {
        uint32_t pathOff = images[i].pathFileOffset;
        if (pathOff >= size) continue;

        const char *path = (const char *)base + pathOff;
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

// MARK: - Dylib Extraction

/// Extract a single dylib from the split shared cache into a standalone Mach-O.
/// Resolves all segments across subcache files and rewrites file offsets.
/// Returns nil on failure.
static NSData *extract_dylib(struct cache_ctx *ctx, uint32_t imageIndex) {
    if (imageIndex >= ctx->imageCount) return nil;

    uint64_t imageAddr = ctx->images[imageIndex].address;

    // Resolve the Mach-O header
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)ctx_resolve(ctx, imageAddr, sizeof(struct mach_header_64));
    if (!mh || mh->magic != MH_MAGIC_64) return nil;

    uint32_t headerAndCmdsSize = sizeof(struct mach_header_64) + mh->sizeofcmds;
    const void *headerPtr = ctx_resolve(ctx, imageAddr, headerAndCmdsSize);
    if (!headerPtr) return nil;

    // First pass: calculate output size
    // Layout: [mach_header_64 + load commands] [segment data...]
    // We page-align segment data starts for correctness.
    uint64_t dataStart = (headerAndCmdsSize + 0x3FFF) & ~0x3FFFULL;  // 16K page align
    uint64_t outputSize = dataStart;

    // Count segments and compute total data size
    const uint8_t *cmdPtr = (const uint8_t *)headerPtr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmdPtr;
            if (seg->filesize > 0) {
                // Align each segment to page boundary in output
                outputSize = (outputSize + 0x3FFF) & ~0x3FFFULL;
                outputSize += seg->filesize;
            }
        }
        cmdPtr += lc->cmdsize;
    }

    if (outputSize > 512 * 1024 * 1024) return nil;  // sanity: 512MB max

    // Allocate output buffer
    NSMutableData *output = [NSMutableData dataWithLength:(NSUInteger)outputSize];
    uint8_t *outBuf = (uint8_t *)output.mutableBytes;

    // Copy header + load commands (we'll patch the commands in-place)
    memcpy(outBuf, headerPtr, headerAndCmdsSize);

    // Second pass: copy segment data and fix up file offsets in load commands
    uint64_t curOffset = dataStart;
    uint8_t *outCmdPtr = outBuf + sizeof(struct mach_header_64);
    struct mach_header_64 *outMH = (struct mach_header_64 *)outBuf;
    int segmentsResolved = 0;
    int segmentsFailed = 0;

    for (uint32_t i = 0; i < outMH->ncmds; i++) {
        struct load_command *lc = (struct load_command *)outCmdPtr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)outCmdPtr;

            if (seg->filesize > 0) {
                uint64_t alignedOffset = (curOffset + 0x3FFF) & ~0x3FFFULL;

                // Resolve segment data from the cache via VM address
                const void *segData = ctx_resolve(ctx, seg->vmaddr, seg->filesize);
                if (segData) {
                    memcpy(outBuf + alignedOffset, segData, seg->filesize);
                    segmentsResolved++;
                } else {
                    // Zero-fill if we can't resolve (segment in unmapped subcache)
                    memset(outBuf + alignedOffset, 0, seg->filesize);
                    segmentsFailed++;
                    NSLog(@"vphoned: extract: failed to resolve segment %.16s at 0x%llx",
                          seg->segname, seg->vmaddr);
                }

                // Patch file offset in the load command
                seg->fileoff = alignedOffset;
                curOffset = alignedOffset + seg->filesize;

                // Fix section file offsets too
                struct section_64 *sections = (struct section_64 *)(outCmdPtr + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (sections[s].offset != 0) {
                        // Section offset is relative to segment start in original cache;
                        // rebase to new segment file offset
                        uint64_t sectionVMOffset = sections[s].addr - seg->vmaddr;
                        sections[s].offset = (uint32_t)(seg->fileoff + sectionVMOffset);
                    }
                }
            } else {
                seg->fileoff = 0;
            }
        }
        outCmdPtr += lc->cmdsize;
    }

    // Trim output to actual used size
    if (curOffset < outputSize) {
        [output setLength:(NSUInteger)curOffset];
    }

    NSLog(@"vphoned: extract: %d segments resolved, %d failed, %lu bytes output",
          segmentsResolved, segmentsFailed, (unsigned long)output.length);

    return output;
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

    // -- cache_extract: extract a single dylib with multi-subcache resolution --
    if ([type isEqualToString:@"cache_extract"]) {
        NSString *path = msg[@"path"];
        NSNumber *indexNum = msg[@"index"];
        if (!path || !indexNum) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing path or index";
            return r;
        }

        struct cache_ctx ctx;
        if (!ctx_open(&ctx, [path fileSystemRepresentation])) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"failed to open cache: %s", strerror(errno)];
            return r;
        }

        uint32_t idx = [indexNum unsignedIntValue];
        if (idx >= ctx.imageCount) {
            ctx_close(&ctx);
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"index out of range";
            return r;
        }

        // Get image path for response
        const char *imagePath = "";
        uint32_t pathOff = ctx.images[idx].pathFileOffset;
        if (pathOff < ctx.mainSize) {
            imagePath = (const char *)ctx.mainBase + pathOff;
        }

        NSData *extracted = extract_dylib(&ctx, idx);
        ctx_close(&ctx);

        if (!extracted) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"failed to extract dylib from cache";
            return r;
        }

        // Send header with size, then stream the raw bytes
        NSMutableDictionary *header = vp_make_response(@"cache_data", reqId);
        header[@"size"] = @((unsigned long long)extracted.length);
        header[@"image_path"] = [NSString stringWithUTF8String:imagePath];
        if (!vp_write_message(fd, header)) {
            return nil;
        }

        // Stream extracted Mach-O in chunks
        const uint8_t *src = (const uint8_t *)extracted.bytes;
        NSUInteger remaining = extracted.length;
        while (remaining > 0) {
            size_t chunk = remaining < 32768 ? remaining : 32768;
            if (!vp_write_fully(fd, src, chunk)) {
                NSLog(@"vphoned: cache_extract write failed");
                return nil;
            }
            src += chunk;
            remaining -= chunk;
        }

        NSLog(@"vphoned: cache_extract %s (%lu bytes)", imagePath, (unsigned long)extracted.length);
        return nil;  // Response already written inline
    }

    // -- cache_download: stream a raw cache file to host (for offline analysis) --
    if ([type isEqualToString:@"cache_download"]) {
        NSString *path = msg[@"path"];
        if (!path) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"missing path";
            return r;
        }

        // Restrict to cache directory
        if (![path hasPrefix:@DYLD_CACHE_DIR]) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"path must be in cache directory";
            return r;
        }

        int fileFd = open([path fileSystemRepresentation], O_RDONLY);
        if (fileFd < 0) {
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = [NSString stringWithFormat:@"open failed: %s", strerror(errno)];
            return r;
        }

        struct stat st;
        if (fstat(fileFd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(fileFd);
            NSMutableDictionary *r = vp_make_response(@"err", reqId);
            r[@"msg"] = @"stat failed or not a regular file";
            return r;
        }

        // Send header then stream raw file
        NSMutableDictionary *header = vp_make_response(@"cache_data", reqId);
        header[@"size"] = @((unsigned long long)st.st_size);
        header[@"image_path"] = path;
        if (!vp_write_message(fd, header)) {
            close(fileFd);
            return nil;
        }

        uint8_t buf[32768];
        ssize_t n;
        while ((n = read(fileFd, buf, sizeof(buf))) > 0) {
            if (!vp_write_fully(fd, buf, (size_t)n)) {
                NSLog(@"vphoned: cache_download write failed for %@", path);
                close(fileFd);
                return nil;
            }
        }
        close(fileFd);
        NSLog(@"vphoned: cache_download %@ (%lld bytes)", path, (long long)st.st_size);
        return nil;  // Response already written inline
    }

    NSMutableDictionary *r = vp_make_response(@"err", reqId);
    r[@"msg"] = [NSString stringWithFormat:@"unknown cache command: %@", type];
    return r;
}
