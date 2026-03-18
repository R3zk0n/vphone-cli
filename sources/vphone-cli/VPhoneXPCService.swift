import Foundation

struct VPhoneXPCService: Identifiable, Hashable {
    let id: String
    let service: String
    let label: String
    let program: String
    let plist: String
    let type: String
    var reachable: Bool?
    var probeError: String?

    var displayName: String {
        service
    }

    var ownerName: String {
        if !label.isEmpty { return label }
        if !program.isEmpty { return (program as NSString).lastPathComponent }
        return "(unknown)"
    }

    var programName: String {
        if program.isEmpty { return "-" }
        return (program as NSString).lastPathComponent
    }

    var reachableIcon: String {
        switch reachable {
        case .some(true): "checkmark.circle.fill"
        case .some(false): "xmark.circle"
        case .none: "questionmark.circle"
        }
    }

    init?(entry: [String: Any]) {
        guard let svc = entry["service"] as? String else { return nil }
        service = svc
        id = svc
        label = entry["label"] as? String ?? ""
        program = entry["program"] as? String ?? ""
        plist = entry["plist"] as? String ?? ""
        type = entry["type"] as? String ?? "MachServices"
        if let r = entry["reachable"] as? Bool {
            reachable = r
        }
        probeError = entry["probe_error"] as? String
    }
}
