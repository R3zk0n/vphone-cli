/*
 * vphoned_keychain — Remote keychain enumeration over vsock.
 *
 * Uses both SecItemCopyMatching (for decrypted values) and direct
 * sqlite3 access to /var/Keychains/keychain-2.db (for full enumeration).
 * SQLite is the ground truth for item discovery; SecItemCopyMatching
 * overlays decrypted values onto the sqlite results.
 */

#import "vphoned_keychain.h"
#import "vphoned_protocol.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sqlite3.h>
#import <dlfcn.h>

// Load SecurityFoundation so _SFAuthenticatedCiphertext etc. are available
__attribute__((constructor))
static void load_security_foundation(void) {
    dlopen("/System/Library/Frameworks/SecurityFoundation.framework/SecurityFoundation", RTLD_LAZY);
}

// MARK: - Helpers

/// Recursively convert an unarchived object graph into JSON-safe types.
static id jsonify(id obj) {
    if (!obj || obj == (id)kCFNull) return [NSNull null];
    if ([obj isKindOfClass:[NSString class]]) return obj;
    if ([obj isKindOfClass:[NSNumber class]]) return obj;
    if ([obj isKindOfClass:[NSDate class]])
        return [(NSDate *)obj description];
    if ([obj isKindOfClass:[NSURL class]])
        return [(NSURL *)obj absoluteString];
    if ([obj isKindOfClass:[NSUUID class]])
        return [(NSUUID *)obj UUIDString];
    if ([obj isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)obj;
        if (d.length <= 4096) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s) return s;
        }
        return [NSString stringWithFormat:@"<data:%lu bytes>", (unsigned long)d.length];
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *out = [NSMutableArray array];
        for (id item in (NSArray *)obj) [out addObject:jsonify(item)];
        return out;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        [(NSDictionary *)obj enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
            out[[key description]] = jsonify(val);
        }];
        return out;
    }
    return [obj description];
}

/// Collect all classes reachable from an NSKeyedArchiver blob.
/// Includes private SecurityFoundation classes for encrypted keychain blobs.
static NSSet *allowed_unarchive_classes(void) {
    NSMutableSet *classes = [NSMutableSet setWithArray:@[
        [NSString class], [NSNumber class], [NSData class], [NSDate class],
        [NSArray class], [NSDictionary class], [NSSet class], [NSURL class],
        [NSUUID class], [NSNull class],
    ]];

    NSArray *privateNames = @[
        @"_SFAuthenticatedCiphertext",
        @"_SFCiphertext",
        @"_SFInitializationVector",
        @"_SFAuthenticationCode",
        @"SFAuthenticatedCiphertext",
        @"SFCiphertext",
        @"SFInitializationVector",
        @"SFAuthenticationCode",
    ];
    for (NSString *name in privateNames) {
        Class cls = NSClassFromString(name);
        if (cls) [classes addObject:cls];
    }
    return classes;
}

/// Extract readable fields from an _SFAuthenticatedCiphertext object via KVC.
static NSDictionary *describe_encrypted_blob(id obj) {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"encrypted"] = @YES;

    @try {
        // Extract IV
        id iv = [obj valueForKey:@"initializationVector"];
        if (iv) {
            NSData *ivData = nil;
            @try { ivData = [iv valueForKey:@"data"]; } @catch(id e) {}
            if (!ivData) @try { ivData = [iv valueForKey:@"ivData"]; } @catch(id e) {}
            if (ivData && [ivData isKindOfClass:[NSData class]]) {
                info[@"iv"] = [ivData base64EncodedStringWithOptions:0];
                info[@"ivSize"] = @(ivData.length);
            }
        }

        // Extract ciphertext
        id ct = [obj valueForKey:@"ciphertext"];
        if (ct) {
            NSData *ctData = nil;
            @try { ctData = [ct valueForKey:@"data"]; } @catch(id e) {}
            if (!ctData) @try { ctData = [ct valueForKey:@"ciphertextData"]; } @catch(id e) {}
            if (ctData && [ctData isKindOfClass:[NSData class]]) {
                info[@"ciphertextSize"] = @(ctData.length);
                NSUInteger previewLen = MIN(32, ctData.length);
                const uint8_t *bytes = ctData.bytes;
                NSMutableString *hex = [NSMutableString stringWithCapacity:previewLen * 2];
                for (NSUInteger i = 0; i < previewLen; i++)
                    [hex appendFormat:@"%02x", bytes[i]];
                if (ctData.length > previewLen) [hex appendString:@"..."];
                info[@"ciphertextPreview"] = hex;
            }
        }

        // Extract authentication code (GCM tag)
        id ac = [obj valueForKey:@"authenticationCode"];
        if (ac) {
            NSData *acData = nil;
            @try { acData = [ac valueForKey:@"data"]; } @catch(id e) {}
            if (!acData) @try { acData = [ac valueForKey:@"authenticationCodeData"]; } @catch(id e) {}
            if (acData && [acData isKindOfClass:[NSData class]]) {
                info[@"authTag"] = [acData base64EncodedStringWithOptions:0];
                info[@"authTagSize"] = @(acData.length);
            }
        }
    } @catch (NSException *e) {
        info[@"introspectionError"] = e.reason ?: @"unknown";
    }

    return info;
}

/// Try to decode an NSData blob into a human-readable JSON-safe value.
/// For encrypted keychain blobs (_SFAuthenticatedCiphertext), extracts the
/// structure (IV, ciphertext size, auth tag) so the UI can display it.
static NSDictionary *decode_blob(NSData *data) {
    if (!data || data.length == 0) return nil;

    // 1. Try NSKeyedUnarchiver (handles the NSKeyedArchiver bplist blobs)
    @try {
        NSSet *allowed = allowed_unarchive_classes();
        NSError *err = nil;
        id decoded = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed fromData:data error:&err];
        if (decoded && !err) {
            NSString *className = NSStringFromClass([decoded class]);
            if ([className containsString:@"SFAuthenticatedCiphertext"] ||
                [className containsString:@"SFCiphertext"]) {
                NSDictionary *info = describe_encrypted_blob(decoded);
                return @{@"value": info, @"valueEncoding": @"encrypted", @"valueSize": @(data.length)};
            }
            id safe = jsonify(decoded);
            return @{@"value": safe, @"valueEncoding": @"unarchived", @"valueSize": @(data.length),
                     @"valueType": [NSString stringWithFormat:@"NSKeyedArchiver(%@)", className]};
        }
    } @catch (NSException *e) {
        // Fall through
    }

    // 2. Byte-scan fallback for encrypted containers (if dlopen/unarchiver failed)
    {
        static const char *markers[] = {
            "_SFAuthenticatedCiphertext", "SFAuthenticatedCiphertext",
            "_SFCiphertext", "SFCiphertext", NULL
        };
        const uint8_t *bytes = (const uint8_t *)data.bytes;
        NSUInteger len = data.length;
        for (int i = 0; markers[i]; i++) {
            size_t mlen = strlen(markers[i]);
            if (len < mlen) continue;
            for (NSUInteger j = 0; j + mlen <= len; j++) {
                if (memcmp(bytes + j, markers[i], mlen) == 0) {
                    NSMutableDictionary *info = [NSMutableDictionary dictionary];
                    info[@"encrypted"] = @YES;
                    info[@"ciphertextSize"] = @(len);
                    info[@"ciphertextPreview"] = @"(SecurityFoundation not loaded)";
                    return @{@"value": info, @"valueEncoding": @"encrypted",
                             @"valueSize": @(data.length),
                             @"valueType": [NSString stringWithUTF8String:markers[i]]};
                }
            }
        }
    }

    // 3. Try plain binary/XML plist
    NSError *plistErr = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable
                                                         format:NULL error:&plistErr];
    if (plist && !plistErr) {
        id safe = jsonify(plist);
        return @{@"value": safe, @"valueEncoding": @"plist", @"valueSize": @(data.length)};
    }

    // 4. Try UTF-8
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (str) {
        return @{@"value": str, @"valueEncoding": @"utf8", @"valueSize": @(data.length)};
    }

    // 4. Fallback to base64
    return @{@"value": [data base64EncodedStringWithOptions:0], @"valueEncoding": @"base64", @"valueSize": @(data.length)};
}

/// Convert a CFType keychain attribute value to a JSON-safe NSObject.
static id safe_value(id val) {
    if (!val || val == (id)kCFNull) return [NSNull null];
    if ([val isKindOfClass:[NSString class]]) return val;
    if ([val isKindOfClass:[NSNumber class]]) return val;
    if ([val isKindOfClass:[NSDate class]]) {
        return @([(NSDate *)val timeIntervalSince1970]);
    }
    if ([val isKindOfClass:[NSData class]]) {
        NSString *str = [[NSString alloc] initWithData:val encoding:NSUTF8StringEncoding];
        if (str) return str;
        return [(NSData *)val base64EncodedStringWithOptions:0];
    }
    return [val description];
}

// MARK: - SQLite-based keychain reader

static NSString *KEYCHAIN_DB_PATH = @"/var/Keychains/keychain-2.db";

/// Read a text column, returning @"" if NULL.
static NSString *col_text(sqlite3_stmt *stmt, int col) {
    const unsigned char *val = sqlite3_column_text(stmt, col);
    if (!val) return @"";
    return [NSString stringWithUTF8String:(const char *)val];
}

/// Query one table from the keychain DB via sqlite3.
static NSArray *query_db_table(sqlite3 *db, NSString *table, NSString *className, NSMutableArray *diag) {
    NSString *sql;
    BOOL isInet = [table isEqualToString:@"inet"];
    BOOL isCert = [table isEqualToString:@"cert"];
    BOOL isKeys = [table isEqualToString:@"keys"];

    if (isInet) {
        sql = [NSString stringWithFormat:
            @"SELECT rowid, acct, svce, agrp, labl, data, cdat, mdat, pdmn, srvr, ptcl, port, path FROM %@", table];
    } else if (isCert || isKeys) {
        sql = [NSString stringWithFormat:
            @"SELECT rowid, agrp, labl, data, cdat, mdat, pdmn FROM %@", table];
    } else {
        sql = [NSString stringWithFormat:
            @"SELECT rowid, acct, svce, agrp, labl, data, cdat, mdat, pdmn FROM %@", table];
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        [diag addObject:[NSString stringWithFormat:@"%@: sqlite error %d", className, rc]];
        return @[];
    }

    NSMutableArray *output = [NSMutableArray array];
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"class"] = className;

        int col = 0;
        int rowid = sqlite3_column_int(stmt, col++);

        if (!isCert && !isKeys) {
            entry[@"account"] = col_text(stmt, col++);
            entry[@"service"] = col_text(stmt, col++);
        }
        entry[@"accessGroup"] = col_text(stmt, col++);
        entry[@"label"] = col_text(stmt, col++);

        // Value data — decode archived/plist blobs
        const void *blob = sqlite3_column_blob(stmt, col);
        int blobSize = sqlite3_column_bytes(stmt, col);
        if (blob && blobSize > 0) {
            NSData *data = [NSData dataWithBytes:blob length:blobSize];
            NSDictionary *decoded = decode_blob(data);
            if (decoded) {
                entry[@"value"] = decoded[@"value"];
                entry[@"valueEncoding"] = decoded[@"valueEncoding"];
                if (decoded[@"valueType"]) entry[@"valueType"] = decoded[@"valueType"];
            }
            entry[@"valueSize"] = @(blobSize);
        }
        col++;

        NSString *cdat = col_text(stmt, col++);
        NSString *mdat = col_text(stmt, col++);
        if (cdat.length > 0) entry[@"createdStr"] = cdat;
        if (mdat.length > 0) entry[@"modifiedStr"] = mdat;

        NSString *pdmn = col_text(stmt, col++);
        if (pdmn.length > 0) entry[@"protection"] = pdmn;

        if (isInet) {
            NSString *server = col_text(stmt, col++);
            if (server.length > 0) entry[@"server"] = server;
            NSString *protocol = col_text(stmt, col++);
            if (protocol.length > 0) entry[@"protocol"] = protocol;
            int port = sqlite3_column_int(stmt, col++);
            if (port > 0) entry[@"port"] = @(port);
            NSString *path = col_text(stmt, col++);
            if (path.length > 0) entry[@"path"] = path;
        }

        entry[@"_rowid"] = @(rowid);
        [output addObject:entry];
    }

    sqlite3_finalize(stmt);

    NSUInteger count = output.count;
    if (count > 0) {
        [diag addObject:[NSString stringWithFormat:@"%@: %lu rows", className, (unsigned long)count]];
    } else {
        [diag addObject:[NSString stringWithFormat:@"%@: empty", className]];
    }
    return output;
}

/// Read all keychain items directly from the sqlite database.
static NSDictionary *query_keychain_db(NSString *filterClass, NSMutableArray *diag) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(KEYCHAIN_DB_PATH.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        [diag addObject:[NSString stringWithFormat:@"db open failed: %d", rc]];
        return @{@"items": @[]};
    }

    [diag addObject:[NSString stringWithFormat:@"opened %@", KEYCHAIN_DB_PATH]];

    NSMutableArray *allItems = [NSMutableArray array];
    struct { NSString *table; NSString *name; } tables[] = {
        { @"genp", @"genp" },
        { @"inet", @"inet" },
        { @"cert", @"cert" },
        { @"keys", @"keys" },
    };

    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        if (filterClass && ![filterClass isEqualToString:tables[i].name]) continue;
        NSArray *items = query_db_table(db, tables[i].table, tables[i].name, diag);
        [allItems addObjectsFromArray:items];
    }

    sqlite3_close(db);
    return @{@"items": allItems};
}

// MARK: - SecItemCopyMatching decryption pass

/// Extract all unique access groups from the keychain sqlite DB.
static NSArray *get_all_access_groups(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(KEYCHAIN_DB_PATH.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) return @[];

    NSMutableSet *groups = [NSMutableSet set];
    NSArray *tables = @[@"genp", @"inet", @"cert", @"keys"];
    for (NSString *table in tables) {
        NSString *sql = [NSString stringWithFormat:@"SELECT DISTINCT agrp FROM %@", table];
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
        if (rc != SQLITE_OK) continue;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *val = sqlite3_column_text(stmt, 0);
            if (val) {
                NSString *g = [NSString stringWithUTF8String:(const char *)val];
                if (g.length > 0) [groups addObject:g];
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return [groups allObjects];
}

/// Query SecItemCopyMatching for decrypted values for a given class and access group.
static NSArray *query_secitem(CFStringRef secClass, NSString *className, NSString *accessGroup, NSMutableArray *diag) {
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass:             (__bridge id)secClass,
        (__bridge id)kSecMatchLimit:        (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes:  @YES,
        (__bridge id)kSecReturnData:        @YES,
    } mutableCopy];

    if (accessGroup) {
        query[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    }

    CFArrayRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status != errSecSuccess || !result) {
        // Only log non-trivial failures (skip -25300 "not found" for per-group queries)
        if (!accessGroup || status != errSecItemNotFound) {
            NSString *msg = [NSString stringWithFormat:@"SecItem(%@%@%@): status %d (%@)",
                className,
                accessGroup ? @"/" : @"",
                accessGroup ?: @"",
                (int)status,
                status == errSecItemNotFound ? @"not found" :
                status == errSecAuthFailed ? @"auth failed" :
                status == errSecInteractionNotAllowed ? @"interaction not allowed" :
                @"error"];
            [diag addObject:msg];
        }
        return @[];
    }

    NSArray *items = (__bridge NSArray *)result;
    NSMutableArray *output = [NSMutableArray arrayWithCapacity:items.count];

    for (NSDictionary *attrs in items) {
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"class"] = className;
        entry[@"account"] = safe_value(attrs[(__bridge id)kSecAttrAccount]) ?: @"";
        entry[@"service"] = safe_value(attrs[(__bridge id)kSecAttrService]) ?: @"";
        entry[@"label"] = safe_value(attrs[(__bridge id)kSecAttrLabel]) ?: @"";
        entry[@"accessGroup"] = safe_value(attrs[(__bridge id)kSecAttrAccessGroup]) ?: @"";
        entry[@"server"] = safe_value(attrs[(__bridge id)kSecAttrServer]) ?: @"";

        // Protection class
        id pdmn = attrs[(__bridge id)kSecAttrAccessible];
        if (pdmn) {
            NSString *pdmnStr = (NSString *)pdmn;
            if ([pdmnStr isEqualToString:(__bridge NSString *)kSecAttrAccessibleWhenUnlocked])
                entry[@"protection"] = @"ak";
            else if ([pdmnStr isEqualToString:(__bridge NSString *)kSecAttrAccessibleAfterFirstUnlock])
                entry[@"protection"] = @"ck";
            else if ([pdmnStr isEqualToString:(__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly])
                entry[@"protection"] = @"aku";
            else if ([pdmnStr isEqualToString:(__bridge NSString *)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly])
                entry[@"protection"] = @"cku";
            else if ([pdmnStr isEqualToString:(__bridge NSString *)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly])
                entry[@"protection"] = @"akpu";
            else
                entry[@"protection"] = pdmnStr;
        }

        // Dates
        id cDate = attrs[(__bridge id)kSecAttrCreationDate];
        if (cDate && [cDate isKindOfClass:[NSDate class]])
            entry[@"created"] = @([(NSDate *)cDate timeIntervalSince1970]);
        id mDate = attrs[(__bridge id)kSecAttrModificationDate];
        if (mDate && [mDate isKindOfClass:[NSDate class]])
            entry[@"modified"] = @([(NSDate *)mDate timeIntervalSince1970]);

        // Decrypted value data
        NSData *valueData = attrs[(__bridge id)kSecValueData];
        if (valueData && [valueData isKindOfClass:[NSData class]]) {
            entry[@"valueSize"] = @(valueData.length);
            NSString *str = [[NSString alloc] initWithData:valueData encoding:NSUTF8StringEncoding];
            if (str) {
                entry[@"value"] = str;
                entry[@"valueEncoding"] = @"utf8";
            } else {
                NSError *pErr = nil;
                id plist = [NSPropertyListSerialization propertyListWithData:valueData
                    options:NSPropertyListImmutable format:NULL error:&pErr];
                if (plist && !pErr) {
                    entry[@"value"] = jsonify(plist);
                    entry[@"valueEncoding"] = @"plist";
                } else {
                    entry[@"value"] = [valueData base64EncodedStringWithOptions:0];
                    entry[@"valueEncoding"] = @"base64";
                }
            }
            entry[@"decrypted"] = @YES;
        }

        [output addObject:entry];
    }

    CFRelease(result);
    return output;
}

/// Get decrypted values via SecItemCopyMatching for all classes.
/// Discovers access groups from sqlite and queries each one explicitly,
/// since keychain-access-groups="*" is treated as the literal string "*"
/// by securityd, not as a wildcard.
static NSArray *query_secitem_all(NSString *filterClass, NSMutableArray *diag) {
    struct { CFStringRef secClass; NSString *name; } classes[] = {
        { kSecClassGenericPassword,  @"genp" },
        { kSecClassInternetPassword, @"inet" },
        { kSecClassCertificate,      @"cert" },
        { kSecClassKey,              @"keys" },
    };

    // Get all access groups from the sqlite DB
    NSArray *accessGroups = get_all_access_groups();
    [diag addObject:[NSString stringWithFormat:@"SecItem: discovered %lu access groups from sqlite",
        (unsigned long)accessGroups.count]];

    NSMutableArray *all = [NSMutableArray array];
    NSUInteger totalDecrypted = 0;

    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
        if (filterClass && ![filterClass isEqualToString:classes[i].name]) continue;

        // Try each access group explicitly
        for (NSString *group in accessGroups) {
            NSArray *items = query_secitem(classes[i].secClass, classes[i].name, group, diag);
            [all addObjectsFromArray:items];
            totalDecrypted += items.count;
        }

        // Also try without access group (gets items matching our own identity)
        NSArray *ownItems = query_secitem(classes[i].secClass, classes[i].name, nil, diag);
        [all addObjectsFromArray:ownItems];
        totalDecrypted += ownItems.count;
    }

    [diag addObject:[NSString stringWithFormat:@"SecItem: %lu total decrypted across all groups",
        (unsigned long)totalDecrypted]];
    return all;
}

// MARK: - Command Handler

NSDictionary *vp_handle_keychain_command(NSDictionary *msg) {
    id reqId = msg[@"id"];
    NSString *type = msg[@"t"];

    // Add a test keychain item (for debugging)
    if ([type isEqualToString:@"keychain_add"]) {
        NSString *account = msg[@"account"] ?: @"vphone-test";
        NSString *service = msg[@"service"] ?: @"vphone";
        NSString *password = msg[@"password"] ?: @"testpass123";

        NSDictionary *deleteQuery = @{
            (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount:  account,
            (__bridge id)kSecAttrService:  service,
        };
        SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

        NSDictionary *attrs = @{
            (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount:  account,
            (__bridge id)kSecAttrService:  service,
            (__bridge id)kSecAttrLabel:    [NSString stringWithFormat:@"%@ (%@)", service, account],
            (__bridge id)kSecValueData:    [password dataUsingEncoding:NSUTF8StringEncoding],
        };

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
        NSLog(@"vphoned: keychain_add: account=%@ service=%@ status=%d", account, service, (int)status);

        NSMutableDictionary *resp = vp_make_response(@"keychain_add", reqId);
        resp[@"status"] = @(status);
        resp[@"ok"] = @(status == errSecSuccess);
        if (status != errSecSuccess) {
            resp[@"msg"] = [NSString stringWithFormat:@"SecItemAdd failed: %d", (int)status];
        }
        return resp;
    }

    // Fetch a specific item's decrypted value via SecItemCopyMatching
    if ([type isEqualToString:@"keychain_get"]) {
        NSString *cls = msg[@"class"] ?: @"genp";
        NSString *account = msg[@"account"] ?: @"";
        NSString *service = msg[@"service"] ?: @"";
        NSString *accessGroup = msg[@"accessGroup"] ?: @"";
        NSString *server = msg[@"server"] ?: @"";
        NSMutableArray *diag = [NSMutableArray array];

        CFStringRef secClass = NULL;
        if ([cls isEqualToString:@"genp"]) secClass = kSecClassGenericPassword;
        else if ([cls isEqualToString:@"inet"]) secClass = kSecClassInternetPassword;
        else if ([cls isEqualToString:@"cert"]) secClass = kSecClassCertificate;
        else if ([cls isEqualToString:@"keys"]) secClass = kSecClassKey;

        NSMutableDictionary *resp = vp_make_response(@"keychain_get", reqId);

        if (secClass) {
            NSMutableDictionary *query = [NSMutableDictionary dictionary];
            query[(__bridge id)kSecClass] = (__bridge id)secClass;
            query[(__bridge id)kSecReturnData] = @YES;
            query[(__bridge id)kSecReturnAttributes] = @YES;
            query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
            if (account.length > 0) query[(__bridge id)kSecAttrAccount] = account;
            if (service.length > 0) query[(__bridge id)kSecAttrService] = service;
            if (accessGroup.length > 0) query[(__bridge id)kSecAttrAccessGroup] = accessGroup;
            if (server.length > 0) query[(__bridge id)kSecAttrServer] = server;

            CFTypeRef result = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

            if (status == errSecSuccess && result) {
                NSDictionary *attrs = (__bridge NSDictionary *)result;
                NSData *valueData = attrs[(__bridge id)kSecValueData];
                if (valueData && [valueData isKindOfClass:[NSData class]]) {
                    NSDictionary *decoded = decode_blob(valueData);
                    if (decoded) {
                        resp[@"value"] = decoded[@"value"];
                        resp[@"valueEncoding"] = decoded[@"valueEncoding"];
                        if (decoded[@"valueType"]) resp[@"valueType"] = decoded[@"valueType"];
                    }
                    resp[@"decrypted"] = @YES;
                    resp[@"ok"] = @YES;
                    [diag addObject:@"SecItemCopyMatching: got decrypted value"];
                }
                CFRelease(result);
            } else {
                [diag addObject:[NSString stringWithFormat:@"SecItemCopyMatching: %d", (int)status]];
            }
        }

        // Fallback: sqlite by rowid
        if (!resp[@"ok"]) {
            int rowid = [msg[@"rowid"] intValue];
            if (rowid > 0) {
                [diag addObject:[NSString stringWithFormat:@"trying sqlite rowid %d", rowid]];
                sqlite3 *db = NULL;
                int rc = sqlite3_open_v2(KEYCHAIN_DB_PATH.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
                if (rc == SQLITE_OK) {
                    NSString *sql = [NSString stringWithFormat:@"SELECT data FROM %@ WHERE rowid = ?", cls];
                    sqlite3_stmt *stmt = NULL;
                    rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_bind_int(stmt, 1, rowid);
                        if (sqlite3_step(stmt) == SQLITE_ROW) {
                            const void *blob = sqlite3_column_blob(stmt, 0);
                            int blobSize = sqlite3_column_bytes(stmt, 0);
                            if (blob && blobSize > 0) {
                                NSData *data = [NSData dataWithBytes:blob length:blobSize];
                                NSDictionary *decoded = decode_blob(data);
                                if (decoded) {
                                    resp[@"value"] = decoded[@"value"];
                                    resp[@"valueEncoding"] = decoded[@"valueEncoding"];
                                    if (decoded[@"valueType"]) resp[@"valueType"] = decoded[@"valueType"];
                                }
                                resp[@"ok"] = @YES;
                                resp[@"source"] = @"sqlite";
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
            }
        }

        if (!resp[@"ok"]) {
            resp[@"ok"] = @NO;
            resp[@"msg"] = @"could not retrieve decrypted value";
        }
        resp[@"diag"] = diag;
        return resp;
    }

    if ([type isEqualToString:@"keychain_list"]) {
        NSString *filterClass = msg[@"class"];
        NSMutableArray *diag = [NSMutableArray array];

        // 1. SQLite: full enumeration (ground truth, bypasses entitlements)
        NSDictionary *dbResult = query_keychain_db(filterClass, diag);
        NSArray *dbItems = dbResult[@"items"];

        // 2. SecItemCopyMatching: get decrypted values
        NSArray *secItems = query_secitem_all(filterClass, diag);

        // 3. Build lookup from (class, account, service, accessGroup) → decrypted entry
        NSMutableDictionary *decryptedLookup = [NSMutableDictionary dictionary];
        for (NSDictionary *si in secItems) {
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                si[@"class"] ?: @"", si[@"account"] ?: @"", si[@"service"] ?: @"",
                si[@"accessGroup"] ?: @""];
            decryptedLookup[key] = si;
        }

        // 4. Merge: overlay decrypted values onto sqlite items
        NSMutableArray *merged = [NSMutableArray arrayWithCapacity:dbItems.count];
        NSUInteger overlayCount = 0;
        for (NSDictionary *dbItem in dbItems) {
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                dbItem[@"class"] ?: @"", dbItem[@"account"] ?: @"", dbItem[@"service"] ?: @"",
                dbItem[@"accessGroup"] ?: @""];
            NSDictionary *decrypted = decryptedLookup[key];
            if (decrypted && decrypted[@"value"]) {
                NSMutableDictionary *m = [dbItem mutableCopy];
                m[@"value"] = decrypted[@"value"];
                m[@"valueEncoding"] = decrypted[@"valueEncoding"];
                if (decrypted[@"valueSize"]) m[@"valueSize"] = decrypted[@"valueSize"];
                m[@"decrypted"] = @YES;
                [merged addObject:m];
                overlayCount++;
            } else {
                [merged addObject:dbItem];
            }
        }

        // 5. Add SecItem-only entries not found in sqlite
        NSMutableSet *dbKeys = [NSMutableSet set];
        for (NSDictionary *dbItem in dbItems) {
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                dbItem[@"class"] ?: @"", dbItem[@"account"] ?: @"", dbItem[@"service"] ?: @"",
                dbItem[@"accessGroup"] ?: @""];
            [dbKeys addObject:key];
        }
        NSUInteger extraCount = 0;
        for (NSDictionary *si in secItems) {
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                si[@"class"] ?: @"", si[@"account"] ?: @"", si[@"service"] ?: @"",
                si[@"accessGroup"] ?: @""];
            if (![dbKeys containsObject:key]) {
                [merged addObject:si];
                extraCount++;
            }
        }

        if (overlayCount > 0)
            [diag addObject:[NSString stringWithFormat:@"decrypted: %lu values overlaid", (unsigned long)overlayCount]];
        if (extraCount > 0)
            [diag addObject:[NSString stringWithFormat:@"decrypted: %lu extra from SecItem", (unsigned long)extraCount]];

        NSLog(@"vphoned: keychain_list: %lu sqlite + %lu secitem → %lu merged (%lu decrypted)",
              (unsigned long)dbItems.count, (unsigned long)secItems.count,
              (unsigned long)merged.count, (unsigned long)overlayCount);

        NSMutableDictionary *resp = vp_make_response(@"keychain_list", reqId);
        resp[@"items"] = merged;
        resp[@"count"] = @(merged.count);
        resp[@"diag"] = diag;
        return resp;
    }

    NSMutableDictionary *r = vp_make_response(@"err", reqId);
    r[@"msg"] = [NSString stringWithFormat:@"unknown keychain command: %@", type];
    return r;
}
