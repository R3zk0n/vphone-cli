import AppKit
import SwiftUI

@MainActor
class VPhoneXPCWindowController {
    private var window: NSWindow?
    private var model: VPhoneXPCBrowserModel?

    func showWindow(control: VPhoneControl) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            return
        }

        let model = VPhoneXPCBrowserModel(control: control)
        self.model = model

        let view = VPhoneXPCBrowserView(model: model)
        let hostingController = NSHostingController(rootView: view)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 600),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "XPC Services"
        window.subtitle = "vphone"
        window.contentViewController = hostingController
        window.contentMinSize = NSSize(width: 700, height: 400)
        window.setContentSize(NSSize(width: 1000, height: 600))
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
