import Foundation
import Observation

@Observable
@MainActor
class VPhoneXPCBrowserModel {
    let control: VPhoneControl

    var services: [VPhoneXPCService] = []
    var isLoading = false
    var error: String?
    var searchText = ""
    var selection = Set<VPhoneXPCService.ID>()
    var sortOrder = [KeyPathComparator(\VPhoneXPCService.service)]
    var filterType: String?
    var probeOnLoad = false

    // Detail panel
    var selectedDetail: XPCDetailInfo?
    var isProbing = false
    var isConnecting = false

    // Monitor
    var monitorEntries: [XPCMonitorEntry] = []
    var isMonitoring = false
    var monitorFilter = ""
    var monitorPollTimer: Timer?
    var monitorError: String?
    var monitorRawLines = 0
    var monitorPid = 0

    init(control: VPhoneControl) {
        self.control = control
    }

    // MARK: - Computed

    var filteredServices: [VPhoneXPCService] {
        var list = services
        if let filterType {
            list = list.filter { $0.type == filterType }
        }
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            list = list.filter {
                $0.service.lowercased().contains(query)
                    || $0.label.lowercased().contains(query)
                    || $0.program.lowercased().contains(query)
            }
        }
        return list.sorted(using: sortOrder)
    }

    var statusText: String {
        let count = filteredServices.count
        let total = services.count
        let suffix = count == 1 ? "service" : "services"
        if count != total {
            return "\(count)/\(total) \(suffix)"
        }
        return "\(count) \(suffix)"
    }

    // MARK: - Actions

    func loadServices() {
        guard !isLoading else { return }
        isLoading = true
        error = nil

        Task {
            do {
                let (resp, _) = try await control.sendRequest([
                    "t": "xpc_list",
                    "probe": probeOnLoad,
                ])
                let entries = resp["services"] as? [[String: Any]] ?? []
                services = entries.compactMap { VPhoneXPCService(entry: $0) }
                isLoading = false
            } catch {
                self.error = error.localizedDescription
                isLoading = false
            }
        }
    }

    func probeService(_ service: VPhoneXPCService) {
        isProbing = true
        Task {
            do {
                let (resp, _) = try await control.sendRequest([
                    "t": "xpc_probe",
                    "service": service.service,
                ])
                let reachable = resp["reachable"] as? Bool ?? false
                let rights = resp["rights"] as? [String]
                let probeError = resp["error"] as? String

                selectedDetail = XPCDetailInfo(
                    service: service.service,
                    reachable: reachable,
                    rights: rights ?? [],
                    probeError: probeError
                )

                // Update in-place
                if let idx = services.firstIndex(where: { $0.id == service.id }) {
                    services[idx].reachable = reachable
                    services[idx].probeError = probeError
                }

                isProbing = false
            } catch {
                selectedDetail = XPCDetailInfo(
                    service: service.service,
                    reachable: false,
                    rights: [],
                    probeError: error.localizedDescription
                )
                isProbing = false
            }
        }
    }

    func connectService(_ service: VPhoneXPCService) {
        isConnecting = true
        Task {
            do {
                let (resp, _) = try await control.sendRequest([
                    "t": "xpc_connect",
                    "service": service.service,
                    "timeout": 3.0,
                ])

                let ok = resp["ok"] as? Bool ?? false
                let remotePid = resp["remote_pid"] as? Int
                let remoteEuid = resp["remote_euid"] as? Int
                let reply = resp["reply"] as? String
                let event = resp["event"] as? String
                let connectError = resp["error"] as? String

                selectedDetail = XPCDetailInfo(
                    service: service.service,
                    reachable: ok,
                    rights: [],
                    probeError: connectError,
                    remotePid: remotePid,
                    remoteEuid: remoteEuid,
                    reply: reply,
                    event: event
                )

                isConnecting = false
            } catch {
                selectedDetail = XPCDetailInfo(
                    service: service.service,
                    reachable: false,
                    rights: [],
                    probeError: error.localizedDescription
                )
                isConnecting = false
            }
        }
    }

    // MARK: - Monitor

    func startMonitor() {
        guard !isMonitoring else { return }
        isMonitoring = true
        monitorEntries = []
        monitorError = nil
        monitorRawLines = 0
        monitorPid = 0

        Task {
            var req: [String: Any] = ["t": "xpc_monitor_start"]
            if !monitorFilter.isEmpty {
                req["filter"] = monitorFilter
            }
            req["max"] = 1000
            _ = try? await control.sendRequest(req)

            // Start polling every 1s
            monitorPollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.pollMonitor()
                }
            }
        }
    }

    func stopMonitor() {
        monitorPollTimer?.invalidate()
        monitorPollTimer = nil
        isMonitoring = false

        Task {
            _ = try? await control.sendRequest(["t": "xpc_monitor_stop"])
        }
    }

    func clearMonitor() {
        monitorEntries = []
    }

    private func pollMonitor() {
        Task {
            do {
                let (resp, _) = try await control.sendRequest(["t": "xpc_monitor_poll"])
                let entries = resp["entries"] as? [[String: Any]] ?? []
                for entry in entries {
                    if let parsed = XPCMonitorEntry(entry: entry) {
                        monitorEntries.append(parsed)
                    }
                }
                // Trim to 2000
                if monitorEntries.count > 2000 {
                    monitorEntries.removeFirst(monitorEntries.count - 2000)
                }
                // Capture diagnostics
                monitorRawLines = (resp["raw_lines"] as? NSNumber)?.intValue ?? monitorRawLines
                monitorPid = (resp["pid"] as? NSNumber)?.intValue ?? monitorPid
                if let err = resp["error"] as? String {
                    monitorError = err
                }
            } catch {
                // Ignore poll errors
            }
        }
    }

    func dumpPlist(for service: VPhoneXPCService) {
        Task {
            do {
                let (resp, _) = try await control.sendRequest([
                    "t": "xpc_dump",
                    "plist": service.plist,
                ])
                let content = resp["content"] as? String ?? "(empty)"
                let machServices = resp["mach_services"] as? [String] ?? []
                let programArgs = resp["program_args"] as? [String] ?? []

                selectedDetail = XPCDetailInfo(
                    service: service.service,
                    reachable: service.reachable,
                    rights: [],
                    probeError: nil,
                    plistContent: content,
                    machServices: machServices,
                    programArgs: programArgs
                )
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

struct XPCMonitorEntry: Identifiable {
    let id = UUID()
    let timestamp: String
    let process: String
    let processName: String
    let pid: Int
    let subsystem: String
    let category: String
    let message: String
    let type: String

    init?(entry: [String: Any]) {
        guard let msg = entry["message"] as? String else { return nil }
        message = msg
        timestamp = entry["timestamp"] as? String ?? ""
        process = entry["process"] as? String ?? ""
        processName = entry["processName"] as? String ?? ""
        pid = (entry["pid"] as? NSNumber)?.intValue ?? 0
        subsystem = entry["subsystem"] as? String ?? ""
        category = entry["category"] as? String ?? ""
        type = entry["type"] as? String ?? ""
    }

    var shortTimestamp: String {
        // "2026-03-18 12:34:56.789012+0000" → "12:34:56.789"
        if let range = timestamp.range(of: #"\d{2}:\d{2}:\d{2}\.\d{3}"#, options: .regularExpression) {
            return String(timestamp[range])
        }
        return timestamp
    }
}

struct XPCDetailInfo {
    var service: String
    var reachable: Bool?
    var rights: [String]
    var probeError: String?
    var remotePid: Int?
    var remoteEuid: Int?
    var reply: String?
    var event: String?
    var plistContent: String?
    var machServices: [String]?
    var programArgs: [String]?
}
