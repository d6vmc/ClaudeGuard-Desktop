import AppKit
import ApplicationServices
import Carbon.HIToolbox

struct LuLuRulesImporter {
    static let appURL = URL(fileURLWithPath: "/Applications/LuLu.app", isDirectory: true)
    private static let identifier = "com.objective-see.lulu.app"
    private static let version = "4.5.7"

    enum Problem: Error {
        case unsupported, tools, menu, fileSelection, profileChanged, verification
    }

    struct Prepared {
        enum Status: String { case ready, inactive, settings, conflict, `import` }
        let status: Status
        let snapshot: String?
        let rules: Data?
    }

    let python: URL
    let helper: String

    static var isAllowed: Bool { AXIsProcessTrusted() }

    static func requestAccess() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true]
        if !AXIsProcessTrustedWithOptions(options as CFDictionary),
           let settings = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(settings)
        }
    }

    func prepare(template: URL) throws -> Prepared {
        _ = try checkedBundle()
        let data = try command(python, [helper, "lulu_import_prepare", template.path])
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawStatus = result["status"] as? String, let status = Prepared.Status(rawValue: rawStatus) else {
            throw Problem.tools
        }
        let rules = try result["rules"].map { try JSONSerialization.data(withJSONObject: $0) }
        return Prepared(status: status, snapshot: result["snapshot"] as? String, rules: rules)
    }

    func install(_ prepared: Prepared) throws {
        guard let snapshot = prepared.snapshot, Self.isAllowed else { throw Problem.tools }
        let bundle = try checkedBundle()
        guard let running = NSRunningApplication.runningApplications(withBundleIdentifier: Self.identifier).first(where: {
            $0.bundleURL?.standardizedFileURL == Self.appURL.standardizedFileURL
        }) else { throw Problem.menu }
        _ = running.activate()
        let pid = running.processIdentifier
        let application = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(application, 0.5)
        let ruleTitles = localizedTitles(bundle, key: "UuL-hi-gEf.title", fallback: "Rules")
        let importTitles = localizedTitles(bundle, key: "39l-3u-dUR.title", fallback: "Import...")
        let previousWindows: [AXUIElement] = read(application, kAXWindowsAttribute) ?? []
        guard let status = readElement(application, kAXExtrasMenuBarAttribute),
              let button = ([status] + children(status)).first(where: { role($0) == kAXMenuBarItemRole }) else { throw Problem.menu }

        let file = try stage(prepared)
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }

        try press(button)
        guard let rulesMenu = wait({ self.menuItem(in: button, titles: ruleTitles) }) else { throw Problem.menu }
        // AppKit can expose submenu items while the submenu is still closed.
        let shown = AXUIElementPerformAction(rulesMenu, kAXShowMenuAction as CFString)
        if shown != .success && shown != .cannotComplete {
            try? press(rulesMenu)
        }
        guard let importItem = wait({ self.menuItem(in: rulesMenu, titles: importTitles) }) else { throw Problem.menu }
        try press(importItem)
        guard let panel = wait(seconds: 7, { () -> AXUIElement? in
            let windows: [AXUIElement] = self.read(application, kAXWindowsAttribute) ?? []
            let focused = self.readElement(application, kAXFocusedWindowAttribute)
            return ((focused.map { [$0] } ?? []) + windows).first { window in
                !previousWindows.contains(where: { CFEqual($0, window) }) && self.role(window) == kAXWindowRole &&
                    self.descendants(window).contains { [kAXBrowserRole, kAXOutlineRole, kAXTableRole].contains(self.role($0)) }
            }
        }) else { throw Problem.fileSelection }

        try key(CGKeyCode(kVK_ANSI_G), flags: [.maskCommand, .maskShift], pid: pid)
        guard let field = wait({ () -> AXUIElement? in
            guard let element = self.readElement(application, kAXFocusedUIElementAttribute),
                  [kAXTextFieldRole, kAXComboBoxRole].contains(self.role(element)),
                  self.belongsTo(element, panel) else { return nil }
            return element
        }), AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, file.path as CFString) == .success,
           read(field, kAXValueAttribute) == file.path else { throw Problem.fileSelection }
        try key(CGKeyCode(kVK_Return), pid: pid)

        guard let open = wait({ () -> AXUIElement? in
            guard self.selection(of: file, in: panel),
                  let button = self.readElement(panel, kAXDefaultButtonAttribute),
                  self.read(button, kAXEnabledAttribute) == true else { return nil }
            return button
        }) else { throw Problem.fileSelection }
        guard try unchanged(snapshot) else { throw Problem.profileChanged }

        try press(open)
        guard wait(seconds: 6, { () -> Bool? in
            let current = try? self.command(python, [helper, "lulu_import_snapshot"])
            guard let current, String(decoding: current, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) != snapshot,
                  (try? self.command(python, [helper, "lulu_import_verify", file.path])) != nil else { return nil }
            return true
        }) == true else { throw Problem.verification }
    }

    func stage(_ prepared: Prepared) throws -> URL {
        guard let snapshot = prepared.snapshot, let rules = prepared.rules else { throw Problem.tools }
        guard try unchanged(snapshot) else { throw Problem.profileChanged }
        let files = FileManager.default
        let directory = files.temporaryDirectory.appendingPathComponent("claudeguard-lulu-\(UUID())", isDirectory: true)
        try files.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let file = directory.appendingPathComponent("ClaudeGuard-\(UUID()).json")
        do {
            try rules.write(to: file, options: .atomic)
            return file
        } catch {
            try? files.removeItem(at: directory)
            throw error
        }
    }

    private func checkedBundle() throws -> Bundle {
        guard let bundle = Bundle(url: Self.appURL), bundle.bundleIdentifier == Self.identifier,
              bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == Self.version else {
            throw Problem.unsupported
        }
        let requirement = "anchor apple generic and identifier \"\(Self.identifier)\" and certificate leaf[subject.OU] = VBG97UB4TA"
        do {
            _ = try command(URL(fileURLWithPath: "/usr/bin/codesign"),
                            ["--verify", "--strict", "-R", "=" + requirement, Self.appURL.path])
        } catch {
            throw Problem.unsupported
        }
        return bundle
    }

    private func unchanged(_ token: String) throws -> Bool {
        let result = try command(python, [helper, "lulu_import_snapshot"])
        return String(decoding: result, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == token
    }

    private func command(_ executable: URL, _ arguments: [String]) throws -> Data {
        let task = Process()
        let output = Pipe()
        task.executableURL = executable
        task.arguments = arguments
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        try task.run()
        let result = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw Problem.tools }
        return result
    }

    private func localizedTitles(_ bundle: Bundle, key: String, fallback: String) -> Set<String> {
        var titles = Set([fallback])
        for language in bundle.localizations {
            if let path = bundle.path(forResource: "MainMenu", ofType: "strings", inDirectory: nil, forLocalization: language),
               let table = NSDictionary(contentsOfFile: path), let title = table[key] as? String {
                titles.insert(title)
            }
        }
        return Set(titles.map { $0.replacingOccurrences(of: "…", with: "...") })
    }

    private func read<T>(_ element: AXUIElement, _ key: String) -> T? {
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, key as CFString, &raw) == .success else { return nil }
        return raw as? T
    }

    private func readElement(_ element: AXUIElement, _ key: String) -> AXUIElement? {
        let value: CFTypeRef? = read(element, key)
        guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
        return (value as! AXUIElement)
    }

    private func children(_ element: AXUIElement) -> [AXUIElement] { read(element, kAXChildrenAttribute) ?? [] }
    private func role(_ element: AXUIElement) -> String { read(element, kAXRoleAttribute) ?? "" }

    private func descendants(_ root: AXUIElement) -> [AXUIElement] {
        var remaining = [root]
        var index = 0
        while index < min(remaining.count, 96) {
            remaining.append(contentsOf: children(remaining[index]).prefix(96 - min(96, remaining.count)))
            index += 1
        }
        return remaining
    }

    private func belongsTo(_ element: AXUIElement, _ panel: AXUIElement) -> Bool {
        var parent = element
        for _ in 0..<12 {
            if CFEqual(parent, panel) { return true }
            guard let next = readElement(parent, kAXParentAttribute) else { return false }
            parent = next
        }
        return false
    }

    private func menuItem(in parent: AXUIElement, titles: Set<String>) -> AXUIElement? {
        descendants(parent).first {
            let title: String = read($0, kAXTitleAttribute) ?? ""
            return role($0) == kAXMenuItemRole && titles.contains(title.replacingOccurrences(of: "…", with: "..."))
        }
    }

    private func selection(of file: URL, in panel: AXUIElement) -> Bool {
        let names = [file.lastPathComponent, file.deletingPathExtension().lastPathComponent]
        for node in descendants(panel) {
            let rows: [AXUIElement] = read(node, kAXSelectedRowsAttribute) ?? []
            let selected: [AXUIElement] = read(node, kAXSelectedChildrenAttribute) ?? []
            let single = read(node, kAXSelectedAttribute) == true ? [node] : []
            for element in rows + selected + single where descendants(element).contains(where: {
                names.contains(self.read($0, kAXTitleAttribute) ?? "") ||
                    names.contains(self.read($0, kAXValueAttribute) ?? "")
            }) { return true }
        }
        return false
    }

    private func press(_ element: AXUIElement) throws {
        let result = AXUIElementPerformAction(element, kAXPressAction as CFString)
        guard result == .success || result == .cannotComplete else { throw Problem.menu }
    }

    private func key(_ code: CGKeyCode, flags: CGEventFlags = [], pid: pid_t) throws {
        for down in [true, false] {
            guard let event = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: down) else { throw Problem.fileSelection }
            event.flags = flags
            event.postToPid(pid)
        }
    }

    private func wait<T>(seconds: Double = 4, _ value: () -> T?) -> T? {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        repeat {
            if let result = value() { return result }
            Thread.sleep(forTimeInterval: 0.1)
        } while ProcessInfo.processInfo.systemUptime < deadline
        return nil
    }
}
