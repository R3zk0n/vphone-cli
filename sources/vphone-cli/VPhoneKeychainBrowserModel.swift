import Foundation
import Observation

@Observable
@MainActor
class VPhoneKeychainBrowserModel {
    let control: VPhoneControl

    var items: [VPhoneKeychainItem] = []
    var isLoading = false
    var error: String?
    var diagnostics: [String] = []
    var searchText = ""
    var selection = Set<VPhoneKeychainItem.ID>()
    var sortOrder = [KeyPathComparator(\VPhoneKeychainItem.displayName)]
    var filterClass: String?
    var showDiagnostics = false

    init(control: VPhoneControl) {
        self.control = control
    }

    // MARK: - Computed

    var filteredItems: [VPhoneKeychainItem] {
        var list = items
        if let filterClass {
            list = list.filter { $0.itemClass == filterClass }
        }
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            list = list.filter {
                $0.account.lowercased().contains(query)
                    || $0.service.lowercased().contains(query)
                    || $0.label.lowercased().contains(query)
                    || $0.accessGroup.lowercased().contains(query)
                    || $0.server.lowercased().contains(query)
                    || $0.protection.lowercased().contains(query)
                    || $0.value.lowercased().contains(query)
            }
        }
        return list.sorted(using: sortOrder)
    }

    var statusText: String {
        let count = filteredItems.count
        let total = items.count
        let suffix = count == 1 ? "item" : "items"
        if count != total {
            return "\(count)/\(total) \(suffix)"
        }
        if count == 0, !diagnostics.isEmpty {
            return diagnostics.joined(separator: " | ")
        }
        return "\(count) \(suffix)"
    }

    static let classFilters: [(label: String, value: String?)] = [
        ("All", nil),
        ("Passwords", "genp"),
        ("Internet", "inet"),
        ("Certificates", "cert"),
        ("Keys", "keys"),
        ("Identities", "idnt"),
    ]

    // MARK: - Selected Item Detail

    var selectedItem: VPhoneKeychainItem?
    var selectedItemValue: String?
    var selectedItemValueType: String?
    var isGettingValue = false

    func getValue(for item: VPhoneKeychainItem) async {
        isGettingValue = true
        selectedItem = item
        selectedItemValue = nil
        selectedItemValueType = nil
        do {
            let result = try await control.keychainGetValue(
                itemClass: item.itemClass,
                account: item.account,
                service: item.service,
                accessGroup: item.accessGroup,
                server: item.server,
                rowid: item.rowid
            )
            selectedItemValue = result.value
            selectedItemValueType = result.valueType
            diagnostics.append(contentsOf: result.diagnostics)
            if result.decrypted {
                diagnostics.append("value decrypted via SecItemCopyMatching")
            }
            if let source = result.source {
                diagnostics.append("source: \(source)")
            }
        } catch {
            self.error = "Get value: \(error)"
            diagnostics.append("keychain_get failed: \(error)")
        }
        isGettingValue = false
    }

    // MARK: - Actions

    func addTestItem() async {
        do {
            _ = try await control.addKeychainItem()
            print("[keychain] test item added, refreshing...")
            await refresh()
        } catch {
            self.error = "Add failed: \(error)"
            print("[keychain] add failed: \(error)")
        }
    }

    // MARK: - Refresh

    func refresh() async {
        guard control.isConnected else {
            error = "Waiting for vphoned connection..."
            return
        }
        isLoading = true
        error = nil
        do {
            let result = try await control.listKeychainItems()
            items = result.items.enumerated().compactMap { VPhoneKeychainItem(index: $0.offset, entry: $0.element) }
            diagnostics = result.diagnostics
            if items.isEmpty, !diagnostics.isEmpty {
                print("[keychain] 0 items, diag: \(diagnostics)")
            }
        } catch {
            self.error = "\(error)"
            items = []
        }
        isLoading = false
    }
}
