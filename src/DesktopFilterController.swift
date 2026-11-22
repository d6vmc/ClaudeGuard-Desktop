import AppKit
import NetworkExtension
import SystemExtensions

final class DesktopFilterController: NSObject, OSSystemExtensionRequestDelegate {
    static let identifier = "com.claudeguard.app.desktop-filter"
    private let manager = NEFilterManager.shared()
    private let marker: URL
    private let status: URL
    private var activation: OSSystemExtensionRequest?
    private var inspection: OSSystemExtensionRequest?
    private(set) var changing = false
    private var lastConfirmation: TimeInterval = 0
    var didChange: (() -> Void)?

    init(configPath: String) {
        let directory = URL(fileURLWithPath: configPath).deletingLastPathComponent()
        marker = directory.appendingPathComponent("desktop-filter-required")
        status = directory.appendingPathComponent("desktop-filter-status.json")
    }

    var required: Bool { FileManager.default.fileExists(atPath: marker.path) }

    var configured: Bool {
        required && (0...8).contains(Date().timeIntervalSince1970 - lastConfirmation)
    }

    func refresh() {
        guard required, inspection == nil, !changing else { return }
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: Self.identifier, queue: .main)
        request.delegate = self
        inspection = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func toggle() {
        guard !changing else { return }
        guard NSRunningApplication.runningApplications(withBundleIdentifier: ClaudeDesktopPolicy.bundleIdentifier).isEmpty else {
            show("Quit Claude Desktop before changing the network filter.")
            return
        }
        if required {
            disable()
            return
        }
        do {
            try ClaudeDesktopPolicy.verify(URL(fileURLWithPath: "/Applications/Claude.app"))
            try Data().write(to: marker, options: .atomic)
        } catch {
            show(error.localizedDescription)
            return
        }
        confirm(false)
        changing = true
        didChange?()
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.identifier, queue: .main)
        request.delegate = self
        activation = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func confirm(_ enabled: Bool) {
        let previous = configured
        lastConfirmation = enabled ? Date().timeIntervalSince1970 : 0
        do {
            let data = try JSONSerialization.data(withJSONObject: ["verified_at": lastConfirmation])
            try data.write(to: status, options: .atomic)
        } catch {
            lastConfirmation = 0
            try? FileManager.default.removeItem(at: status)
        }
        if previous != configured { didChange?() }
    }

    private var ownsConfiguration: Bool {
        manager.providerConfiguration?.filterDataProviderBundleIdentifier == Self.identifier
    }

    private func configure() {
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                if let error { self.finish(error); return }
                if self.manager.providerConfiguration != nil && !self.ownsConfiguration {
                    self.finish(NSError(domain: "ClaudeGuard", code: 2, userInfo: [
                        NSLocalizedDescriptionKey: "A different content filter configuration was returned."
                    ]))
                    return
                }
                let configuration = NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterDataProviderBundleIdentifier = Self.identifier
                self.manager.localizedDescription = "ClaudeGuard Desktop Network Filter"
                self.manager.providerConfiguration = configuration
                self.manager.isEnabled = true
                self.manager.saveToPreferences { error in
                    DispatchQueue.main.async { self.finish(error); self.refresh() }
                }
            }
        }
    }

    private func disable() {
        changing = true
        confirm(false)
        didChange?()
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                if let error { self.finish(error); return }
                if !self.ownsConfiguration { self.clearRequirement(); return }
                self.manager.removeFromPreferences { error in
                    DispatchQueue.main.async {
                        if let error { self.finish(error); return }
                        self.clearRequirement()
                    }
                }
            }
        }
    }

    private func clearRequirement() {
        do {
            try FileManager.default.removeItem(at: marker)
            finish(nil)
        } catch {
            finish(error)
        }
    }

    private func finish(_ error: Error?) {
        changing = false
        didChange?()
        if let error { show(error.localizedDescription) }
    }

    private func show(_ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "ClaudeGuard Desktop Network Filter"
        alert.informativeText = text
        alert.runModal()
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        show("Allow ClaudeGuard in System Settings to activate its Desktop network filter.")
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard request === activation else { return }
        activation = nil
        guard result == .completed else {
            finish(NSError(domain: "ClaudeGuard", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Restart macOS, then toggle the Desktop filter off and back on in ClaudeGuard to finish setup."
            ]))
            return
        }
        configure()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if request === activation {
            activation = nil
            finish(error)
        } else if request === inspection {
            inspection = nil
            confirm(false)
        }
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        guard request === inspection else { return }
        guard properties.contains(where: { $0.isEnabled && !$0.isUninstalling }) else {
            inspection = nil
            confirm(false)
            return
        }
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                self.inspection = nil
                let enabled = error == nil && !self.changing && self.required &&
                    self.ownsConfiguration && self.manager.isEnabled
                self.confirm(enabled)
            }
        }
    }
}
