import Foundation

struct VPhoneKeychainItem: Identifiable, Hashable {
    let id: String
    let itemClass: String
    let account: String
    let service: String
    let label: String
    let accessGroup: String
    let server: String
    let value: String
    let valueEncoding: String
    let valueSize: Int
    let created: Date?
    let modified: Date?

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

    var displayValue: String {
        if value.isEmpty { return "—" }
        if valueEncoding == "base64" {
            return "[\(ByteCountFormatter.string(fromByteCount: Int64(valueSize), countStyle: .file)) binary]"
        }
        return value
    }

    var displayName: String {
        if !label.isEmpty { return label }
        if !account.isEmpty { return account }
        if !service.isEmpty { return service }
        if !server.isEmpty { return server }
        return "(unnamed)"
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()

    var displayDate: String {
        guard let modified else { return "—" }
        return Self.dateFormatter.string(from: modified)
    }
}

extension VPhoneKeychainItem {
    init?(index: Int, entry: [String: Any]) {
        guard let cls = entry["class"] as? String else { return nil }

        itemClass = cls
        account = entry["account"] as? String ?? ""
        service = entry["service"] as? String ?? ""
        label = entry["label"] as? String ?? ""
        accessGroup = entry["accessGroup"] as? String ?? ""
        server = entry["server"] as? String ?? ""
        value = entry["value"] as? String ?? ""
        valueEncoding = entry["valueEncoding"] as? String ?? ""
        valueSize = (entry["valueSize"] as? NSNumber)?.intValue ?? 0

        if let ts = entry["created"] as? Double {
            created = Date(timeIntervalSince1970: ts)
        } else {
            created = nil
        }
        if let ts = entry["modified"] as? Double {
            modified = Date(timeIntervalSince1970: ts)
        } else {
            modified = nil
        }

        // Unique ID from class + index
        id = "\(cls)-\(index)-\(account)-\(service)"
    }
}
