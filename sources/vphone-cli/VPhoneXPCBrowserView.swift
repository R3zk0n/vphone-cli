import SwiftUI

struct VPhoneXPCBrowserView: View {
    @Bindable var model: VPhoneXPCBrowserModel
    @State private var tab: XPCTab = .services

    enum XPCTab: String, CaseIterable {
        case services = "Services"
        case monitor = "Monitor"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Tab bar
            HStack(spacing: 0) {
                ForEach(XPCTab.allCases, id: \.self) { t in
                    Button {
                        tab = t
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: t == .services ? "list.bullet" : "waveform")
                                .font(.system(size: 10))
                            Text(t.rawValue)
                                .font(.system(.body, design: .monospaced, weight: tab == t ? .semibold : .regular))
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 6)
                        .background(tab == t ? Color.accentColor.opacity(0.15) : .clear)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                    .buttonStyle(.plain)
                }
                Spacer()

                // Monitor indicator
                if model.isMonitoring {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(.red)
                            .frame(width: 6, height: 6)
                        Text("Recording")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.red)
                    }
                    .padding(.trailing, 8)
                }
            }
            .padding(.horizontal, 8)
            .padding(.top, 4)
            .background(.bar)

            Divider()

            switch tab {
            case .services:
                servicesTab
            case .monitor:
                monitorTab
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                if tab == .services {
                    Button {
                        model.loadServices()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isLoading)
                    .keyboardShortcut("r", modifiers: .command)

                    Toggle(isOn: $model.probeOnLoad) {
                        Label("Probe", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .help("Test reachability via bootstrap_look_up (slower)")

                    Picker("Type", selection: $model.filterType) {
                        Text("All").tag(nil as String?)
                        Text("MachServices").tag("MachServices" as String?)
                        Text("XPCService").tag("XPCService" as String?)
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 240)
                } else {
                    Button {
                        if model.isMonitoring {
                            model.stopMonitor()
                        } else {
                            model.startMonitor()
                        }
                    } label: {
                        Label(
                            model.isMonitoring ? "Stop" : "Start",
                            systemImage: model.isMonitoring ? "stop.circle.fill" : "play.circle.fill"
                        )
                    }
                    .keyboardShortcut("r", modifiers: .command)

                    Button {
                        model.clearMonitor()
                    } label: {
                        Label("Clear", systemImage: "trash")
                    }
                    .disabled(model.monitorEntries.isEmpty)
                }
            }
        }
        .searchable(text: $model.searchText, prompt: tab == .services ? "Filter services..." : "Filter messages...")
        .onAppear {
            if model.services.isEmpty {
                model.loadServices()
            }
        }
    }

    // MARK: - Services Tab

    private var servicesTab: some View {
        HSplitView {
            VStack(spacing: 0) {
                serviceTable
                statusBar
            }
            .frame(minWidth: 400)

            detailPanel
                .frame(minWidth: 300, idealWidth: 350)
        }
    }

    // MARK: - Monitor Tab

    private var monitorTab: some View {
        VStack(spacing: 0) {
            monitorTable
            monitorStatusBar
        }
    }

    private var filteredMonitorEntries: [XPCMonitorEntry] {
        if model.searchText.isEmpty { return model.monitorEntries }
        let query = model.searchText.lowercased()
        return model.monitorEntries.filter {
            $0.message.lowercased().contains(query)
                || $0.processName.lowercased().contains(query)
                || $0.subsystem.lowercased().contains(query)
                || $0.category.lowercased().contains(query)
        }
    }

    private var monitorTable: some View {
        Table(filteredMonitorEntries) {
            TableColumn("Time") { entry in
                Text(entry.shortTimestamp)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .width(70)

            TableColumn("Process") { entry in
                HStack(spacing: 4) {
                    Text(entry.processName)
                        .font(.system(size: 11, design: .monospaced))
                        .lineLimit(1)
                    if entry.pid > 0 {
                        Text("(\(entry.pid))")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .width(min: 100, ideal: 140)

            TableColumn("Subsystem") { entry in
                Text(entry.subsystem.isEmpty ? "-" : entry.subsystem)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 80, ideal: 140)

            TableColumn("Message") { entry in
                Text(entry.message)
                    .font(.system(size: 11, design: .monospaced))
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
            .width(min: 200)
        }
    }

    private var monitorStatusBar: some View {
        HStack {
            if model.isMonitoring {
                Circle()
                    .fill(.red)
                    .frame(width: 6, height: 6)
                Text("Monitoring (pid \(model.monitorPid))")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text("raw:\(model.monitorRawLines)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            Text("\(filteredMonitorEntries.count) entries")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            if let err = model.monitorError {
                Text(err)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.red)
                    .lineLimit(1)
            }
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(.bar)
    }

    // MARK: - Service Table

    private var serviceTable: some View {
        Table(model.filteredServices, selection: $model.selection, sortOrder: $model.sortOrder) {
            TableColumn("Service", value: \.service) { svc in
                HStack(spacing: 4) {
                    Image(systemName: svc.reachableIcon)
                        .font(.system(size: 9))
                        .foregroundStyle(svc.reachable == true ? .green : svc.reachable == false ? .red : .secondary)
                    Text(svc.service)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                }
            }
            .width(min: 200)

            TableColumn("Owner", value: \.label) { svc in
                Text(svc.ownerName)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 120, ideal: 180)

            TableColumn("Binary", value: \.program) { svc in
                Text(svc.programName)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 80, ideal: 120)

            TableColumn("Type", value: \.type) { svc in
                Text(svc.type)
                    .font(.caption)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(.quaternary)
                    .clipShape(RoundedRectangle(cornerRadius: 3))
            }
            .width(80)
        }
        .contextMenu(forSelectionType: VPhoneXPCService.ID.self) { ids in
            if let id = ids.first,
               let svc = model.services.first(where: { $0.id == id }) {
                Button("Probe Service") { model.probeService(svc) }
                Button("Connect & Send Ping") { model.connectService(svc) }
                Button("Dump Plist") { model.dumpPlist(for: svc) }
                Divider()
                Button("Copy Service Name") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(svc.service, forType: .string)
                }
                Button("Copy Plist Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(svc.plist, forType: .string)
                }
            }
        } primaryAction: { ids in
            if let id = ids.first,
               let svc = model.services.first(where: { $0.id == id }) {
                model.probeService(svc)
            }
        }
    }

    // MARK: - Status Bar

    private var statusBar: some View {
        HStack {
            if model.isLoading {
                ProgressView()
                    .controlSize(.small)
                Text("Loading...")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if let error = model.error {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(1)
            } else {
                Text(model.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(.bar)
    }

    // MARK: - Detail Panel

    @ViewBuilder
    private var detailPanel: some View {
        if let detail = model.selectedDetail {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(detail.service)
                        .font(.system(.title3, design: .monospaced, weight: .semibold))
                        .textSelection(.enabled)

                    Divider()

                    if let reachable = detail.reachable {
                        detailRow("Reachable", value: reachable ? "Yes" : "No",
                                  color: reachable ? .green : .red)
                    }
                    if !detail.rights.isEmpty {
                        detailRow("Port Rights", value: detail.rights.joined(separator: ", "))
                    }
                    if let err = detail.probeError {
                        detailRow("Error", value: err, color: .red)
                    }

                    if let pid = detail.remotePid, pid > 0 {
                        detailRow("Remote PID", value: "\(pid)")
                    }
                    if let euid = detail.remoteEuid {
                        detailRow("Remote EUID", value: "\(euid)")
                    }
                    if let reply = detail.reply {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Reply")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(reply)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(6)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(nsColor: .controlBackgroundColor))
                                .clipShape(RoundedRectangle(cornerRadius: 4))
                        }
                    }
                    if let event = detail.event {
                        detailRow("Event", value: event, color: .orange)
                    }

                    if let machServices = detail.machServices, !machServices.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Mach Services (\(machServices.count))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            ForEach(machServices, id: \.self) { svc in
                                Text(svc)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    if let args = detail.programArgs, !args.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Program Arguments")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(args.joined(separator: " "))
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    if let content = detail.plistContent {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Plist Content")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            ScrollView(.horizontal) {
                                Text(content)
                                    .font(.system(size: 10, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            .padding(6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                        }
                    }

                    Spacer()
                }
                .padding()
            }
        } else {
            VStack {
                Spacer()
                Text("Select a service and right-click\nto probe, connect, or dump plist")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        }
    }

    private func detailRow(_ label: String, value: String, color: Color = .primary) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 80, alignment: .trailing)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(color)
                .textSelection(.enabled)
        }
    }
}
