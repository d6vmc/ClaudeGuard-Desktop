import Foundation
import Network
import Security

enum ClaudeDesktopPolicy {
    static let bundleIdentifier = "com.anthropic.claudefordesktop"
    static let teamIdentifier = "Q6L2SF6YDW"
    static let bridgePort: UInt16 = 17943

    static func identifies(team: String?, identifier: String?, executable: String?) -> Bool {
        guard team == teamIdentifier, let identifier else { return false }
        if identifier == bundleIdentifier || identifier.hasPrefix(bundleIdentifier + ".") {
            return true
        }
        // The app ships additional independently signed executables, including
        // crash handlers and Claude's iOS simulator helper.
        return executable?.contains("/Claude.app/Contents/") == true
    }

    static func allows(endpoint: NWEndpoint?, outgoingTCP: Bool) -> Bool {
        guard outgoingTCP,
              case let .hostPort(.ipv4(address), port) = endpoint,
              address == IPv4Address("127.0.0.1") else { return false }
        return port.rawValue == bridgePort
    }

    static func verify(_ app: URL) throws {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        let expression = "identifier \"" + bundleIdentifier +
            "\" and anchor apple generic and certificate leaf[subject.OU] = " + teamIdentifier
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
              let code, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckNestedCode | kSecCSStrictValidate),
                                         requirement) == errSecSuccess else {
            throw NSError(domain: "ClaudeGuard", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Claude Desktop’s signature could not be verified at " + app.path
            ])
        }
    }
}
