import SwiftUI

struct VPhoneCacheBrowserView: View {
    @Bindable var model: VPhoneCacheBrowserModel

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar: cache picker + search
            HStack(spacing: 8) {
                if model.cacheFiles.count > 1 {
                    Picker("Cache", selection: Binding(
                        get: { model.selectedCache?.name ?? "" },
                        set: { name in
                            if let cache = model.cacheFiles.first(where: { $0.name == name }) {
                                model.selectCache(cache)
                            }
                        }
                    )) {
                        ForEach(model.cacheFiles, id: \.name) { cache in
                            Text(cache.name).tag(cache.name)
                        }
                    }
                    .frame(maxWidth: 300)
                } else if let cache = model.selectedCache {
                    Text(cache.name)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if !model.magic.isEmpty {
                    Text(model.magic)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }

                TextField("Search dylibs...", text: $model.searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                    .onSubmit {
                        model.search(query: model.searchText)
                    }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Image list
            if model.isLoading && model.images.isEmpty {
                Spacer()
                ProgressView("Loading...")
                Spacer()
            } else if let error = model.error {
                Spacer()
                Text(error)
                    .foregroundStyle(.red)
                    .font(.system(.body, design: .monospaced))
                    .padding()
                Spacer()
            } else {
                Table(model.filteredImages, selection: .constant(nil as Int?)) {
                    TableColumn("Path") { image in
                        Text(image.path)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(image.path)
                    }
                    .width(min: 300)

                    TableColumn("Address") { image in
                        Text(image.address)
                            .font(.system(.body, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 100, ideal: 140)

                    TableColumn("") { image in
                        Button("Extract") {
                            model.extract(image: image)
                        }
                        .buttonStyle(.borderless)
                        .disabled(model.isExtracting)
                    }
                    .width(60)
                }
            }

            // Status bar
            Divider()
            HStack {
                if model.isLoading {
                    ProgressView()
                        .controlSize(.small)
                }
                if let status = model.statusMessage {
                    Text(status)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let cache = model.selectedCache {
                    Text(ByteCountFormatter.string(fromByteCount: Int64(cache.size), countStyle: .file))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .frame(minWidth: 600, minHeight: 400)
        .onAppear {
            model.loadCacheList()
        }
    }
}

// MARK: - Identifiable conformance for Table

extension VPhoneControl.CacheImage: Identifiable {
    public var id: Int { index }
}
