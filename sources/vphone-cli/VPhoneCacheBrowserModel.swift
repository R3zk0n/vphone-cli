import AppKit
import Foundation
import Observation

@Observable
@MainActor
class VPhoneCacheBrowserModel {
    let control: VPhoneControl

    var cacheFiles: [VPhoneControl.CacheFile] = []
    var selectedCache: VPhoneControl.CacheFile?
    var magic = ""
    var images: [VPhoneControl.CacheImage] = []
    var totalImages = 0
    var searchText = ""
    var isLoading = false
    var isExtracting = false
    var error: String?
    var statusMessage: String?

    init(control: VPhoneControl) {
        self.control = control
    }

    // MARK: - Filtered

    var filteredImages: [VPhoneControl.CacheImage] {
        if searchText.isEmpty {
            return images
        }
        let query = searchText.lowercased()
        return images.filter { $0.path.lowercased().contains(query) }
    }

    // MARK: - Load Cache List

    func loadCacheList() {
        isLoading = true
        error = nil
        Task {
            do {
                let list = try await control.cacheList()
                cacheFiles = list
                if selectedCache == nil, let first = list.first {
                    selectedCache = first
                    await loadImages()
                }
            } catch {
                self.error = "\(error)"
            }
            isLoading = false
        }
    }

    // MARK: - Load Images

    func loadImages() async {
        guard let cache = selectedCache else { return }
        isLoading = true
        error = nil
        statusMessage = "Loading images..."
        do {
            let (cacheMagic, cacheImages) = try await control.cacheImages(path: cache.path)
            magic = cacheMagic
            images = cacheImages
            totalImages = cacheImages.count
            statusMessage = "\(cacheImages.count) images"
        } catch {
            self.error = "\(error)"
            statusMessage = nil
        }
        isLoading = false
    }

    // MARK: - Search (server-side)

    func search(query: String) {
        guard let cache = selectedCache, !query.isEmpty else {
            // If cleared, reload all
            if query.isEmpty, selectedCache != nil {
                Task { await loadImages() }
            }
            return
        }
        isLoading = true
        error = nil
        statusMessage = "Searching..."
        Task {
            do {
                let (total, results) = try await control.cacheSearch(
                    path: cache.path, query: query, limit: 200
                )
                images = results
                totalImages = total
                statusMessage = "\(results.count) matches (of \(total) total)"
            } catch {
                self.error = "\(error)"
                statusMessage = nil
            }
            isLoading = false
        }
    }

    // MARK: - Extract

    func extract(image: VPhoneControl.CacheImage) {
        guard let cache = selectedCache else { return }
        isExtracting = true
        statusMessage = "Extracting \(image.path.split(separator: "/").last ?? "")..."
        Task {
            do {
                let (imagePath, data) = try await control.cacheExtract(
                    path: cache.path, index: image.index
                )
                let filename = String(imagePath.split(separator: "/").last ?? "extracted")
                let panel = NSSavePanel()
                panel.nameFieldStringValue = filename
                panel.canCreateDirectories = true
                let response = panel.runModal()
                if response == .OK, let url = panel.url {
                    try data.write(to: url)
                    statusMessage = "Saved \(filename) (\(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file)))"
                } else {
                    statusMessage = nil
                }
            } catch {
                self.error = "\(error)"
                statusMessage = nil
            }
            isExtracting = false
        }
    }

    // MARK: - Download Cache

    var isDownloading = false

    func downloadCache() {
        guard let cache = selectedCache else { return }
        isDownloading = true
        statusMessage = "Downloading \(cache.name)..."
        Task {
            do {
                let data = try await control.cacheDownload(path: cache.path)
                let panel = NSSavePanel()
                panel.nameFieldStringValue = cache.name
                panel.canCreateDirectories = true
                let response = panel.runModal()
                if response == .OK, let url = panel.url {
                    try data.write(to: url)
                    statusMessage = "Saved \(cache.name) (\(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file)))"
                } else {
                    statusMessage = nil
                }
            } catch {
                self.error = "\(error)"
                statusMessage = nil
            }
            isDownloading = false
        }
    }

    // MARK: - Select Cache

    func selectCache(_ cache: VPhoneControl.CacheFile) {
        selectedCache = cache
        images = []
        searchText = ""
        Task { await loadImages() }
    }
}
