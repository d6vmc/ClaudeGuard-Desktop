import Foundation
import NetworkExtension
import OSLog
import Security

final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: "com.claudeguard.app.desktop-filter", category: "policy")
    // Audit-token keys include the kernel's process version. A reused PID
    // cannot inherit another process's classification.
    private var identities: [Data: Bool] = [:]
    private let identityLock = NSLock()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { error in
            if error == nil { self.log.info("Claude Desktop socket policy loaded") }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        identityLock.lock()
        identities.removeAll()
        identityLock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard isClaude(flow.sourceAppAuditToken) || isClaude(flow.sourceProcessAuditToken) else {
            return .allow()
        }
        guard let socket = flow as? NEFilterSocketFlow else { return .drop() }
        let outgoingTCP = flow.direction == .outbound && socket.socketProtocol == IPPROTO_TCP
        return ClaudeDesktopPolicy.allows(endpoint: socket.remoteFlowEndpoint, outgoingTCP: outgoingTCP)
            ? .allow() : .drop()
    }

    private func isClaude(_ token: Data?) -> Bool {
        guard let token else { return false }
        identityLock.lock()
        if let known = identities[token] {
            identityLock.unlock()
            return known
        }
        identityLock.unlock()

        var guest: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
              let guest else { return false }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode else {
            return false
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &information) == errSecSuccess,
              let signing = information as? [String: Any] else { return false }
        let belongsToClaude = ClaudeDesktopPolicy.identifies(
            team: signing[kSecCodeInfoTeamIdentifier as String] as? String,
            identifier: signing[kSecCodeInfoIdentifier as String] as? String,
            executable: (signing[kSecCodeInfoMainExecutable as String] as? URL)?.path
        )
        identityLock.lock()
        if identities.count >= 2048 { identities.removeAll(keepingCapacity: true) }
        identities[token] = belongsToClaude
        identityLock.unlock()
        return belongsToClaude
    }
}
