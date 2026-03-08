import SwiftUI

struct VPhoneKeychainBrowserView: View {
    @Bindable var model: VPhoneKeychainBrowserModel

    private let controlBarHeight: CGFloat = 24

    var body: some View {
        VStack(spacing: 0) {
            tableView
                .padding(.bottom, controlBarHeight)
                .overlay(controlBar.frame(maxHeight: .infinity, alignment: .bottom))
                .searchable(text: $model.searchText, prompt: "Filter keychain items")
                .toolbar { toolbarContent }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task { await model.refresh() }
        .alert(
            "Error",
            isPresented: .init(
                get: { model.error != nil },
                set: { if !$0 { model.error = nil } }
            )
        ) {
            Button("OK") { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
    }

    // MARK: - Table

    var tableView: some View {
        Table(of: VPhoneKeychainItem.self, selection: $model.selection, sortOrder: $model.sortOrder) {
            TableColumn("", value: \.itemClass) { item in
                Image(systemName: item.classIcon)
                    .foregroundStyle(.secondary)
                    .frame(width: 20)
                    .help(item.displayClass)
            }
            .width(28)

            TableColumn("Class", value: \.itemClass) { item in
                Text(item.displayClass)
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 60, ideal: 80, max: 100)

            TableColumn("Account", value: \.account) { item in
                Text(item.account.isEmpty ? "—" : item.account)
                    .lineLimit(1)
                    .help(item.account)
            }
            .width(min: 80, ideal: 150, max: .infinity)

            TableColumn("Service", value: \.service) { item in
                Text(item.service.isEmpty ? "—" : item.service)
                    .lineLimit(1)
                    .help(item.service)
            }
            .width(min: 80, ideal: 150, max: .infinity)

            TableColumn("Access Group", value: \.accessGroup) { item in
                Text(item.accessGroup.isEmpty ? "—" : item.accessGroup)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .help(item.accessGroup)
            }
            .width(min: 80, ideal: 160, max: .infinity)

            TableColumn("Value", value: \.value) { item in
                Text(item.displayValue)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .help(item.displayValue)
            }
            .width(min: 60, ideal: 120, max: .infinity)

            TableColumn("Modified", value: \.displayName) { item in
                Text(item.displayDate)
            }
            .width(min: 80, ideal: 120, max: .infinity)
        } rows: {
            ForEach(model.filteredItems) { item in
                TableRow(item)
            }
        }
        .contextMenu(forSelectionType: VPhoneKeychainItem.ID.self) { ids in
            contextMenu(for: ids)
        }
    }

    // MARK: - Control Bar

    var controlBar: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(model.control.isConnected ? Color.green : Color.orange)
                .frame(width: 8, height: 8)

            Divider()

            // Class filter picker
            Picker("Class", selection: $model.filterClass) {
                ForEach(VPhoneKeychainBrowserModel.classFilters, id: \.value) { filter in
                    Text(filter.label).tag(filter.value)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .frame(maxWidth: 120)

            Divider()

            Text(model.statusText)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(minWidth: 60)
        }
        .padding(.horizontal, 8)
        .frame(height: controlBarHeight)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    var toolbarContent: some ToolbarContent {
        ToolbarItem {
            Button {
                Task { await model.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .keyboardShortcut("r", modifiers: .command)
        }
        ToolbarItem {
            Button {
                Task { await model.addTestItem() }
            } label: {
                Label("Add Test", systemImage: "plus.circle")
            }
            .help("Add a test keychain item (debug)")
        }
        ToolbarItem {
            Button {
                copySelected()
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .disabled(model.selection.isEmpty)
        }
    }

    // MARK: - Context Menu

    @ViewBuilder
    func contextMenu(for ids: Set<VPhoneKeychainItem.ID>) -> some View {
        Button("Copy Account") { copyField(ids: ids, keyPath: \.account) }
        Button("Copy Service") { copyField(ids: ids, keyPath: \.service) }
        Button("Copy Value") { copyField(ids: ids, keyPath: \.value) }
        Button("Copy Access Group") { copyField(ids: ids, keyPath: \.accessGroup) }
        Divider()
        Button("Refresh") { Task { await model.refresh() } }
    }

    // MARK: - Actions

    func copySelected() {
        let selected = model.filteredItems.filter { model.selection.contains($0.id) }
        let text = selected.map { item in
            "\(item.displayClass)\t\(item.account)\t\(item.service)\t\(item.accessGroup)\t\(item.displayValue)"
        }.joined(separator: "\n")
        NSPasteboard.general.prepareForNewContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func copyField(ids: Set<VPhoneKeychainItem.ID>, keyPath: KeyPath<VPhoneKeychainItem, String>) {
        let values = model.filteredItems
            .filter { ids.contains($0.id) }
            .map { $0[keyPath: keyPath] }
            .joined(separator: "\n")
        NSPasteboard.general.prepareForNewContents()
        NSPasteboard.general.setString(values, forType: .string)
    }
}
