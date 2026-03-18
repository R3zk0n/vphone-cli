import Foundation

struct VPhoneKeychainItem: Identifiable, Hashable {
    let id: String
    let itemClass: String
    let account: String
    let service: String
    let label: String
    let accessGroup: String
    let protection: String
    let server: String
    let value: String
    let valueEncoding: String
    let valueType: String?
    let valueSize: Int
    let rowid: Int
    let created: Date?
    let modified: Date?
    let isPreDecrypted: Bool
    let source: String

    var displayClass: String {
        switch itemClass {
        case "genp": "Password"
        case "inet": "Internet"
        case "cert": "Certificate"
        case "keys": "Key"
        case "idnt": "Identity"
        default: itemClass
        }
    }

    var classIcon: String {
        switch itemClass {
        case "genp": "key.fill"
        case "inet": "globe"
        case "cert": "checkmark.seal.fill"
        case "keys": "lock.fill"
        case "idnt": "person.badge.key.fill"
        default: "questionmark.circle"
        }
    }

    /// Whether the sqlite value is an encrypted container (needs SecItemCopyMatching to decrypt).
    var isEncrypted: Bool {
        valueEncoding == "encrypted"
    }

    /// Whether the value was successfully decoded to something readable.
    var isDecoded: Bool {
        !value.isEmpty && !isEncrypted && valueEncoding != "base64"
    }

    /// Lock state icon for the value column.
    var valueStateIcon: String {
        if isEncrypted { return "lock.fill" }
        if value.isEmpty { return "minus.circle" }
        if valueEncoding == "base64" { return "doc.questionmark" }
        return "lock.open.fill"
    }

    var displayValue: String {
        if value.isEmpty { return "-" }
        if isEncrypted {
            let sizeStr = ByteCountFormatter.string(fromByteCount: Int64(valueSize), countStyle: .file)
            return "[\(valueType ?? "encrypted") \(sizeStr)]"
        }
        if valueEncoding == "base64" {
            return "[\(ByteCountFormatter.string(fromByteCount: Int64(valueSize), countStyle: .file)) binary]"
        }
        if valueEncoding == "json" {
            if value.count > 80 {
                return String(value.prefix(77)) + "..."
            }
        }
        return value
    }

    var valueTypeLabel: String {
        if isEncrypted { return valueType ?? "encrypted" }
        return valueType ?? (valueEncoding == "base64" ? "binary" : "text")
    }

    var displayName: String {
        if !label.isEmpty { return label }
        if !account.isEmpty { return account }
        if !service.isEmpty { return service }
        if !server.isEmpty { return server }
        return "(unnamed)"
    }

    var protectionDescription: String {
        switch protection {
        case "ak": "WhenUnlocked"
        case "ck": "AfterFirstUnlock"
        case "dk": "Always"
        case "aku": "WhenUnlocked (ThisDevice)"
        case "cku": "AfterFirstUnlock (ThisDevice)"
        case "dku": "Always (ThisDevice)"
        case "akpu": "WhenPasscodeSet (ThisDevice)"
        default: protection
        }
    }

    var displayDate: String {
        if let modified {
            return Self.dateFormatter.string(from: modified)
        }
        if let created {
            return Self.dateFormatter.string(from: created)
        }
        return "-"
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()

    private static let sqliteDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()
}

extension VPhoneKeychainItem {
    init?(index: Int, entry: [String: Any]) {
        guard let cls = entry["class"] as? String else { return nil }

        itemClass = cls
        account = entry["account"] as? String ?? ""
        service = entry["service"] as? String ?? ""
        label = entry["label"] as? String ?? ""
        accessGroup = entry["accessGroup"] as? String ?? ""
        protection = entry["protection"] as? String ?? ""
        server = entry["server"] as? String ?? ""
        // Value can be a string (decoded) or a dictionary (encrypted blob info with IV, ciphertext, authTag)
        if let strVal = entry["value"] as? String {
            value = strVal
        } else if let dictVal = entry["value"] as? [String: Any] {
            // Encrypted blob info from _SFAuthenticatedCiphertext introspection
            if let ctSize = dictVal["ciphertextSize"] as? NSNumber {
                let preview = dictVal["ciphertextPreview"] as? String ?? ""
                let ivSize = (dictVal["ivSize"] as? NSNumber)?.intValue ?? 0
                let tagSize = (dictVal["authTagSize"] as? NSNumber)?.intValue ?? 0
                value = "ct:\(ctSize) iv:\(ivSize) tag:\(tagSize) | \(preview)"
            } else {
                // Try JSON representation
                if let data = try? JSONSerialization.data(withJSONObject: dictVal, options: .prettyPrinted),
                   let str = String(data: data, encoding: .utf8) {
                    value = str
                } else {
                    value = String(describing: dictVal)
                }
            }
        } else {
            value = ""
        }
        valueEncoding = entry["valueEncoding"] as? String ?? ""
        valueType = entry["valueType"] as? String
        valueSize = (entry["valueSize"] as? NSNumber)?.intValue ?? 0

        if let ts = entry["created"] as? Double {
            created = Date(timeIntervalSince1970: ts)
        } else if let ts = entry["created"] as? NSNumber {
            created = Date(timeIntervalSince1970: ts.doubleValue)
        } else if let str = entry["createdStr"] as? String {
            created = Self.sqliteDateFormatter.date(from: str)
        } else {
            created = nil
        }

        if let ts = entry["modified"] as? Double {
            modified = Date(timeIntervalSince1970: ts)
        } else if let ts = entry["modified"] as? NSNumber {
            modified = Date(timeIntervalSince1970: ts.doubleValue)
        } else if let str = entry["modifiedStr"] as? String {
            modified = Self.sqliteDateFormatter.date(from: str)
        } else {
            modified = nil
        }

        let rid = (entry["_rowid"] as? NSNumber)?.intValue ?? index
        rowid = rid
        id = "\(cls)-\(rid)"
        isPreDecrypted = (entry["decrypted"] as? Bool) == true
        source = entry["source"] as? String ?? "sqlite"
    }
}
