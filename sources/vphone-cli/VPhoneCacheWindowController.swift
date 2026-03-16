import AppKit
import SwiftUI

@MainActor
class VPhoneCacheWindowController {
    private var window: NSWindow?
    private var model: VPhoneCacheBrowserModel?

    func showWindow(control: VPhoneControl) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            return
        }

        let model = VPhoneCacheBrowserModel(control: control)
        self.model = model

        let view = VPhoneCacheBrowserView(model: model)
        let hostingController = NSHostingController(rootView: view)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 550),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Shared Cache"
        window.subtitle = "vphone"
        window.contentViewController = hostingController
        window.contentMinSize = NSSize(width: 600, height: 400)
        window.setContentSize(NSSize(width: 800, height: 550))
        window.center()
        window.toolbarStyle = .unified
        window.isReleasedWhenClosed = false

        window.makeKeyAndOrderFront(nil)
        self.window = window

        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.window = nil
                self?.model = nil
            }
        }
    }
}
