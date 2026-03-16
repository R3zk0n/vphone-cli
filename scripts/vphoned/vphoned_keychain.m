/*
 * vphoned_keychain — Remote keychain enumeration over vsock.
 *
 * Uses both SecItemCopyMatching (for items we're entitled to) and direct
 * sqlite3 access to /var/Keychains/keychain-2.db (for everything else).
 * The sqlite approach bypasses access-group entitlement checks entirely.
 */

#import "vphoned_keychain.h"
#import "vphoned_protocol.h"
#import <Security/Security.h>
#import <sqlite3.h>

// MARK: - Helpers

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

/// Try to decode an NSData blob through multiple strategies:
/// 1. UTF-8 string
/// 2. NSKeyedUnarchiver (archived NSDictionary, NSString, NSArray, etc.)
/// 3. Property list (binary plist)
/// 4. Raw base64
/// Returns a dict with "value", "valueEncoding", "valueSize", and optionally "valueType".
static void decode_value_blob(NSData *data, NSMutableDictionary *entry) {
    if (!data || data.length == 0) return;

    entry[@"valueSize"] = @(data.length);

    // 1. Try UTF-8 string
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (str && str.length > 0) {
        // Validate it's actually readable (not just null bytes that happen to be "valid" UTF-8)
        unichar first = [str characterAtIndex:0];
        if (first >= 0x20 || first == '\n' || first == '\r' || first == '\t') {
            entry[@"value"] = str;
            entry[@"valueEncoding"] = @"utf8";
            return;
        }
    }

    // 2. Try NSKeyedUnarchiver
    @try {
        NSSet *classes = [NSSet setWithArray:@[
            [NSDictionary class], [NSMutableDictionary class],
            [NSArray class], [NSMutableArray class],
            [NSString class], [NSMutableString class],
            [NSNumber class], [NSDate class], [NSData class],
            [NSURL class], [NSUUID class],
            [NSSet class], [NSMutableSet class],
        ]];
        NSError *err = nil;
        id obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:classes fromData:data error:&err];
        if (obj && !err) {
            // Convert the unarchived object to a JSON-friendly representation
            if ([obj isKindOfClass:[NSString class]]) {
                entry[@"value"] = obj;
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(NSString)";
                return;
            }
            if ([obj isKindOfClass:[NSNumber class]]) {
                entry[@"value"] = [obj stringValue];
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(NSNumber)";
                return;
            }
            if ([obj isKindOfClass:[NSDate class]]) {
                entry[@"value"] = [NSString stringWithFormat:@"%@", obj];
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(NSDate)";
                return;
            }
            if ([obj isKindOfClass:[NSURL class]]) {
                entry[@"value"] = [(NSURL *)obj absoluteString] ?: [obj description];
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(NSURL)";
                return;
            }
            if ([obj isKindOfClass:[NSUUID class]]) {
                entry[@"value"] = [(NSUUID *)obj UUIDString];
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(NSUUID)";
                return;
            }
            if ([obj isKindOfClass:[NSData class]]) {
                // Archived NSData — try UTF-8 inside, else base64
                NSString *inner = [[NSString alloc] initWithData:obj encoding:NSUTF8StringEncoding];
                if (inner) {
                    entry[@"value"] = inner;
                    entry[@"valueEncoding"] = @"utf8";
                } else {
                    entry[@"value"] = [(NSData *)obj base64EncodedStringWithOptions:0];
                    entry[@"valueEncoding"] = @"base64";
                }
                entry[@"valueType"] = @"NSKeyedArchiver(NSData)";
                return;
            }
            if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
                // Try JSON serialization
                if ([NSJSONSerialization isValidJSONObject:obj]) {
                    NSData *json = [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingPrettyPrinted error:nil];
                    if (json) {
                        entry[@"value"] = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
                        entry[@"valueEncoding"] = @"json";
                        entry[@"valueType"] = [NSString stringWithFormat:@"NSKeyedArchiver(%@)",
                            [obj isKindOfClass:[NSDictionary class]] ? @"NSDictionary" : @"NSArray"];
                        return;
                    }
                }
                // Fallback: description
                entry[@"value"] = [obj description];
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"NSKeyedArchiver(collection)";
                return;
            }
            // Unknown archived type — use description
            entry[@"value"] = [obj description];
            entry[@"valueEncoding"] = @"utf8";
            entry[@"valueType"] = [NSString stringWithFormat:@"NSKeyedArchiver(%@)", NSStringFromClass([obj class])];
            return;
        }
    } @catch (NSException *e) {
        // Not a valid archive, continue to next strategy
    }

    // 3. Detect encrypted SecurityFoundation containers (bplist with known class names)
    //    _SFAuthenticatedCiphertext, _SFCiphertext, etc. are encrypted-at-rest blobs
    //    that need class keys (via SecItemCopyMatching) to decrypt.
    {
        // Known encrypted container class name signatures
        static const char *encrypted_markers[] = {
            "_SFAuthenticatedCiphertext",
            "_SFCiphertext",
            "SFAuthenticatedCiphertext",
            "SFCiphertext",
            NULL
        };
        const uint8_t *bytes = (const uint8_t *)data.bytes;
        NSUInteger len = data.length;
        for (int i = 0; encrypted_markers[i]; i++) {
            const char *marker = encrypted_markers[i];
            size_t markerLen = strlen(marker);
            if (len < markerLen) continue;
            // Scan for the class name in the bplist
            for (NSUInteger j = 0; j + markerLen <= len; j++) {
                if (memcmp(bytes + j, marker, markerLen) == 0) {
                    entry[@"value"] = [data base64EncodedStringWithOptions:0];
                    entry[@"valueEncoding"] = @"encrypted";
                    entry[@"valueType"] = [NSString stringWithUTF8String:marker];
                    return;
                }
            }
        }
    }

    // 4. Try binary plist
    {
        NSError *err = nil;
        id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:&err];
        if (plist && !err) {
            if ([plist isKindOfClass:[NSString class]]) {
                entry[@"value"] = plist;
                entry[@"valueEncoding"] = @"utf8";
                entry[@"valueType"] = @"plist(NSString)";
                return;
            }
            if ([NSJSONSerialization isValidJSONObject:plist]) {
                NSData *json = [NSJSONSerialization dataWithJSONObject:plist options:NSJSONWritingPrettyPrinted error:nil];
                if (json) {
                    entry[@"value"] = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
                    entry[@"valueEncoding"] = @"json";
                    entry[@"valueType"] = @"plist";
                    return;
                }
            }
            entry[@"value"] = [plist description];
            entry[@"valueEncoding"] = @"utf8";
            entry[@"valueType"] = @"plist";
            return;
        }
    }

    // 5. Fallback: base64
    entry[@"value"] = [data base64EncodedStringWithOptions:0];
    entry[@"valueEncoding"] = @"base64";
}

/// Map our class abbreviation to kSecClass constant.
static CFStringRef secClassForName(NSString *cls) {
    if ([cls isEqualToString:@"genp"]) return kSecClassGenericPassword;
    if ([cls isEqualToString:@"inet"]) return kSecClassInternetPassword;
    if ([cls isEqualToString:@"cert"]) return kSecClassCertificate;
    if ([cls isEqualToString:@"keys"]) return kSecClassKey;
    return NULL;
}

/// Try to fetch the decrypted value for a specific keychain item via SecItemCopyMatching.
/// Uses the item's known attributes (class, account, service, access group) to build a precise query.
static NSDictionary *fetch_value_via_secapi(NSString *cls, NSString *account, NSString *service,
                                             NSString *accessGroup, NSString *server,
                                             NSMutableArray *diag) {
    CFStringRef secClass = secClassForName(cls);
    if (!secClass) {
        [diag addObject:[NSString stringWithFormat:@"unknown class: %@", cls]];
        return nil;
    }

    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)secClass;
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    // Build precise query from known attributes
    if (account.length > 0) query[(__bridge id)kSecAttrAccount] = account;
    if (service.length > 0) query[(__bridge id)kSecAttrService] = service;
    if (accessGroup.length > 0) query[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    if (server.length > 0) query[(__bridge id)kSecAttrServer] = server;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status != errSecSuccess) {
        [diag addObject:[NSString stringWithFormat:@"SecItemCopyMatching: %d (agrp=%@)", (int)status, accessGroup ?: @"(none)"]];
        return nil;
    }

    NSDictionary *attrs = (__bridge_transfer NSDictionary *)result;
    NSMutableDictionary *out = [NSMutableDictionary dictionary];

    // Extract the decrypted value data
    NSData *valueData = attrs[(__bridge id)kSecValueData];
    if (valueData) {
        decode_value_blob(valueData, out);
        out[@"decrypted"] = @YES;
        [diag addObject:@"SecItemCopyMatching: got decrypted value"];
    } else {
        [diag addObject:@"SecItemCopyMatching: no value data returned"];
    }

    return out;
}

// MARK: - SQLite-based keychain reader

static NSString *KEYCHAIN_DB_PATH = @"/var/Keychains/keychain-2.db";

/// Map sqlite table name to our class abbreviation.
static NSDictionary *tableToClass(void) {
    return @{
        @"genp": @"genp",
        @"inet": @"inet",
        @"cert": @"cert",
        @"keys": @"keys",
    };
}

/// Read a text column, returning @"" if NULL.
static NSString *col_text(sqlite3_stmt *stmt, int col) {
    const unsigned char *val = sqlite3_column_text(stmt, col);
    if (!val) return @"";
    return [NSString stringWithUTF8String:(const char *)val];
}

/// Read a blob column as base64 string.
static NSString *col_blob_base64(sqlite3_stmt *stmt, int col) {
    const void *blob = sqlite3_column_blob(stmt, col);
    int size = sqlite3_column_bytes(stmt, col);
    if (!blob || size <= 0) return @"";
    NSData *data = [NSData dataWithBytes:blob length:size];
    // Try UTF-8 first
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (str) return str;
    return [data base64EncodedStringWithOptions:0];
}

/// Query one table from the keychain DB via sqlite3.
static NSArray *query_db_table(sqlite3 *db, NSString *table, NSString *className, NSMutableArray *diag) {
    // Columns available in genp/inet tables:
    //   rowid, acct, svce, agrp, labl, data, cdat, mdat, desc, icmt, type, crtr, pdmn
    // inet also has: srvr, ptcl, port, path
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

        // Value data — decode through NSKeyedUnarchiver/plist/UTF-8/base64 chain
        const void *blob = sqlite3_column_blob(stmt, col);
        int blobSize = sqlite3_column_bytes(stmt, col);
        if (blob && blobSize > 0) {
            NSData *data = [NSData dataWithBytes:blob length:blobSize];
            decode_value_blob(data, entry);
        }
        col++;

        // Dates (stored as text in sqlite, e.g. "2025-01-15 12:34:56")
        NSString *cdat = col_text(stmt, col++);
        NSString *mdat = col_text(stmt, col++);
        if (cdat.length > 0) entry[@"createdStr"] = cdat;
        if (mdat.length > 0) entry[@"modifiedStr"] = mdat;

        // Protection class (pdmn)
        NSString *pdmn = col_text(stmt, col++);
        if (pdmn.length > 0) entry[@"protection"] = pdmn;

        // inet-specific fields
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

        // Use rowid for unique ID generation
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
        NSLog(@"vphoned: sqlite3_open(%@) failed: %d", KEYCHAIN_DB_PATH, rc);
        return @{@"items": @[], @"diag": diag};
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

        NSDictionary *secResult = fetch_value_via_secapi(cls, account, service, accessGroup, server, diag);

        NSMutableDictionary *resp = vp_make_response(@"keychain_get", reqId);
        if (secResult) {
            [resp addEntriesFromDictionary:secResult];
            resp[@"ok"] = @YES;
        } else {
            // Fallback: try reading from sqlite by rowid if provided
            int rowid = [msg[@"rowid"] intValue];
            if (rowid > 0) {
                [diag addObject:[NSString stringWithFormat:@"SecAPI failed, trying sqlite rowid %d", rowid]];
                NSString *table = cls;
                sqlite3 *db = NULL;
                int rc = sqlite3_open_v2(KEYCHAIN_DB_PATH.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
                if (rc == SQLITE_OK) {
                    NSString *sql = [NSString stringWithFormat:@"SELECT data FROM %@ WHERE rowid = ?", table];
                    sqlite3_stmt *stmt = NULL;
                    rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
                    if (rc == SQLITE_OK) {
                        sqlite3_bind_int(stmt, 1, rowid);
                        if (sqlite3_step(stmt) == SQLITE_ROW) {
                            const void *blob = sqlite3_column_blob(stmt, 0);
                            int blobSize = sqlite3_column_bytes(stmt, 0);
                            if (blob && blobSize > 0) {
                                NSData *data = [NSData dataWithBytes:blob length:blobSize];
                                decode_value_blob(data, resp);
                                resp[@"ok"] = @YES;
                                resp[@"source"] = @"sqlite";
                                [diag addObject:[NSString stringWithFormat:@"sqlite fallback: %d bytes", blobSize]];
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
            }
            if (!resp[@"ok"]) {
                resp[@"ok"] = @NO;
                resp[@"msg"] = @"could not retrieve decrypted value";
            }
        }
        resp[@"diag"] = diag;

        NSLog(@"vphoned: keychain_get: class=%@ account=%@ ok=%@ diag=%@",
              cls, account, resp[@"ok"], diag);
        return resp;
    }

    if ([type isEqualToString:@"keychain_list"]) {
        NSString *filterClass = msg[@"class"];
        NSMutableArray *diag = [NSMutableArray array];

        // Primary: SecItemCopyMatching per class with kSecMatchLimitAll.
        // With '*' keychain-access-groups entitlement, this returns items from
        // ALL apps and gives us decrypted values directly.
        NSMutableArray *allItems = [NSMutableArray array];

        struct { NSString *name; CFStringRef secClass; } classes[] = {
            { @"genp", kSecClassGenericPassword },
            { @"inet", kSecClassInternetPassword },
            { @"cert", kSecClassCertificate },
            { @"keys", kSecClassKey },
        };

        int secApiTotal = 0;
        for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
            if (filterClass && ![filterClass isEqualToString:classes[i].name]) continue;

            NSDictionary *query = @{
                (__bridge id)kSecClass:            (__bridge id)classes[i].secClass,
                (__bridge id)kSecMatchLimit:        (__bridge id)kSecMatchLimitAll,
                (__bridge id)kSecReturnAttributes:  @YES,
                (__bridge id)kSecReturnData:         @YES,
            };

            CFTypeRef result = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

            if (status == errSecSuccess && result) {
                NSArray *items = (__bridge_transfer NSArray *)result;
                [diag addObject:[NSString stringWithFormat:@"SecAPI %@: %lu items",
                    classes[i].name, (unsigned long)items.count]];

                for (NSUInteger j = 0; j < items.count; j++) {
                    NSDictionary *attrs = items[j];
                    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
                    entry[@"class"] = classes[i].name;
                    id acct = attrs[(__bridge id)kSecAttrAccount];
                    id svce = attrs[(__bridge id)kSecAttrService];
                    id labl = attrs[(__bridge id)kSecAttrLabel];
                    id agrp = attrs[(__bridge id)kSecAttrAccessGroup];
                    id srvr = attrs[(__bridge id)kSecAttrServer];
                    entry[@"account"] = [acct isKindOfClass:[NSString class]] ? acct :
                                        [acct isKindOfClass:[NSData class]] ? ([[NSString alloc] initWithData:acct encoding:NSUTF8StringEncoding] ?: @"") : @"";
                    entry[@"service"] = [svce isKindOfClass:[NSString class]] ? svce : @"";
                    entry[@"label"] = [labl isKindOfClass:[NSString class]] ? labl : @"";
                    entry[@"accessGroup"] = [agrp isKindOfClass:[NSString class]] ? agrp : @"";
                    entry[@"server"] = [srvr isKindOfClass:[NSString class]] ? srvr : @"";

                    // Protection class
                    id pdmn = attrs[(__bridge id)kSecAttrAccessible];
                    if (pdmn) {
                        // Map kSecAttrAccessible constants to short codes matching sqlite pdmn
                        NSString *pdmnStr = (__bridge NSString *)(__bridge CFStringRef)pdmn;
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
                    NSDate *cdate = attrs[(__bridge id)kSecAttrCreationDate];
                    NSDate *mdate = attrs[(__bridge id)kSecAttrModificationDate];
                    if (cdate) entry[@"created"] = @([cdate timeIntervalSince1970]);
                    if (mdate) entry[@"modified"] = @([mdate timeIntervalSince1970]);

                    // Value — already decrypted by SecItemCopyMatching
                    NSData *valueData = attrs[(__bridge id)kSecValueData];
                    if (valueData && valueData.length > 0) {
                        decode_value_blob(valueData, entry);
                        entry[@"decrypted"] = @YES;
                    }

                    entry[@"_rowid"] = @(secApiTotal + (int)j);
                    entry[@"source"] = @"secapi";
                    [allItems addObject:entry];
                }
                secApiTotal += (int)items.count;
            } else if (status == errSecItemNotFound) {
                [diag addObject:[NSString stringWithFormat:@"SecAPI %@: empty", classes[i].name]];
            } else {
                [diag addObject:[NSString stringWithFormat:@"SecAPI %@: error %d, falling back to sqlite",
                    classes[i].name, (int)status]];
                // Fallback to sqlite for this class
                sqlite3 *db = NULL;
                int rc = sqlite3_open_v2(KEYCHAIN_DB_PATH.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
                if (rc == SQLITE_OK) {
                    NSArray *dbItems = query_db_table(db, classes[i].name, classes[i].name, diag);
                    [allItems addObjectsFromArray:dbItems];
                    sqlite3_close(db);
                }
            }
        }

        NSLog(@"vphoned: keychain_list: %lu items (secapi=%d), diag: %@",
              (unsigned long)allItems.count, secApiTotal, diag);

        NSMutableDictionary *resp = vp_make_response(@"keychain_list", reqId);
        resp[@"items"] = allItems;
        resp[@"count"] = @(allItems.count);
        resp[@"diag"] = diag;
        return resp;
    }

    NSMutableDictionary *r = vp_make_response(@"err", reqId);
    r[@"msg"] = [NSString stringWithFormat:@"unknown keychain command: %@", type];
    return r;
}
