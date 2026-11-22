import AppKit
import Foundation
import SystemConfiguration
import Network

private let runtimePython: URL = {
    let bundled = "/Library/Application Support/ClaudeGuard/python3"
    return URL(fileURLWithPath: FileManager.default.isExecutableFile(atPath: bundled) ? bundled : "/usr/bin/python3")
}()

// ClaudeGuard menu bar daemon.
//
// State machine: compute one GuardState, touch the system only on transitions
// (blocking/unblocking domains, killing the app, alerting) — never on every
// poll. Owns two enforcement surfaces: the Claude Desktop app (force-quit +
// alert) and the claude/anthropic domains (/etc/hosts + pf). The `claude` CLI
// enforces itself from src/cli_wrapper.py — a background daemon has no terminal.

enum GuardState: Equatable {
    case disabled              // protection off
    case offline               // no internet — can't verify
    case allowed(ip: String)   // public IP is whitelisted
    case blocked(ip: String)   // online, IP not whitelisted

    // Fail closed: domains open only on a confirmed good IP; offline blocks too.
    var domainsShouldBeBlocked: Bool {
        switch self {
        case .allowed, .disabled: return false
        case .blocked, .offline:  return true
        }
    }
}

enum MenuHealth: Equatable {
    case checking, ready, paused, blocked

    var symbol: String {
        switch self {
        case .checking: return "shield"
        case .ready: return "checkmark.shield.fill"
        case .paused: return "shield.lefthalf.filled"
        case .blocked: return "xmark.shield.fill"
        }
    }

    var tint: NSColor {
        switch self {
        case .checking: return .secondaryLabelColor
        case .ready: return .systemGreen
        case .paused: return .systemOrange
        case .blocked: return .systemRed
        }
    }
}

private final class MenuStatusCard: NSView {
    private let icon = NSImageView()
    private let name = NSTextField(labelWithString: "ClaudeGuard")
    private let status = NSTextField(labelWithString: "")
    private let route = NSTextField(labelWithString: "")
    private var health: MenuHealth?
    private let symbolBounds = NSRect(x: 22, y: 23, width: 42, height: 42)

    override var isFlipped: Bool { true }

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 348, height: 88))
        autoresizingMask = [.width]
        icon.frame = symbolBounds.insetBy(dx: 10, dy: 10)
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.setAccessibilityElement(false)
        addSubview(icon)

        name.font = .systemFont(ofSize: 11, weight: .semibold)
        name.textColor = .secondaryLabelColor
        status.font = .systemFont(ofSize: 15, weight: .semibold)
        route.font = .monospacedDigitSystemFont(ofSize: 11, weight: .medium)
        route.textColor = .secondaryLabelColor
        for label in [name, status, route] {
            label.lineBreakMode = .byTruncatingTail
            addSubview(label)
        }
        needsLayout = true
    }

    required init?(coder: NSCoder) { nil }

    override func layout() {
        super.layout()
        let width = bounds.width - 98
        name.frame = NSRect(x: 77, y: 16, width: width, height: 15)
        status.frame = NSRect(x: 77, y: 32, width: width, height: 22)
        route.frame = NSRect(x: 77, y: 57, width: width, height: 16)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let card = NSBezierPath(roundedRect: bounds.insetBy(dx: 10, dy: 5), xRadius: 13, yRadius: 13)
        NSColor.labelColor.withAlphaComponent(0.055).setFill()
        card.fill()
        NSColor.separatorColor.setStroke()
        card.lineWidth = 0.5
        card.stroke()
        (health ?? .checking).tint.withAlphaComponent(0.15).setFill()
        NSBezierPath(roundedRect: symbolBounds, xRadius: 11, yRadius: 11).fill()
    }

    func update(health: MenuHealth, title: String, detail: String, tooltip: String?) {
        if self.health != health {
            self.health = health
            icon.image = NSImage(systemSymbolName: health.symbol, accessibilityDescription: nil)
            icon.contentTintColor = health.tint
            needsDisplay = true
        }
        status.stringValue = title
        route.stringValue = detail
        toolTip = tooltip
    }
}

// Diagnostics only: no user data, endpoints, IPs or exception text in labels.
private enum SwitchTrace {
    static var enabled = ProcessInfo.processInfo.environment["CLAUDEGUARD_TRACE"] == "1"
    static let path = NSString(string: "~/.config/claudeguard/trace.log").expandingTildeInPath
    static func begin() -> TimeInterval? { enabled ? ProcessInfo.processInfo.systemUptime : nil }
    static func end(_ start: TimeInterval?, _ stage: String, _ result: String = "completed") {
        guard let start = start else { return }
        let duration = (ProcessInfo.processInfo.systemUptime - start) * 1000
        let line = "\(ISO8601DateFormatter().string(from: Date())) stage=\(stage) duration_ms=\(String(format: "%.3f", duration)) result=\(result)\n"
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return }
        line.withCString { bytes in _ = write(fd, bytes, strlen(bytes)) }
    }
}

// Shared native input window for IPs, model IDs and proxy profiles.
final class SettingsInputWindow: NSWindow, NSWindowDelegate {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.intersection(.deviceIndependentFlagsMask).contains(.command),
           let editor = firstResponder as? NSTextView {
            // Physical-key fallback keeps editing shortcuts working with Russian layouts.
            let key = event.charactersIgnoringModifiers?.lowercased() ?? ""
            let shortcut = ["c", "v", "x", "a", "z"].contains(key) ? key
                : ([UInt16(8): "c", 9: "v", 7: "x", 0: "a", 6: "z"][event.keyCode] ?? key)
            switch shortcut {
            case "c": editor.copy(nil)
            case "v": editor.paste(nil)
            case "x": editor.cut(nil)
            case "a": editor.selectAll(nil)
            case "z":
                if event.modifierFlags.contains(.shift) { editor.undoManager?.redo() }
                else { editor.undoManager?.undo() }
            default: return super.performKeyEquivalent(with: event)
            }
            return true
        }
        return super.performKeyEquivalent(with: event)
    }
    @objc func acceptInput() { NSApp.stopModal(withCode: .OK) }
    @objc func cancelInput() { NSApp.abortModal() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApp.abortModal(); return true }
}

private final class ManagedProxySupervisor {
    private let helper: String
    private let didStop: () -> Void
    private let lock = NSLock()
    private var child: Process?
    private var childGeneration: String?
    private var childReady = false
    private var target: String?
    private var nextAttempt: TimeInterval = 0
    private var backoff: TimeInterval = 2

    init(helper: String, didStop: @escaping () -> Void) {
        self.helper = helper
        self.didStop = didStop
    }

    func process(for generation: String) -> Process? {
        lock.lock()
        defer { lock.unlock() }
        guard generation == childGeneration, childReady, child?.isRunning == true else { return nil }
        return child
    }

    // Called on the main queue. The network check may inspect the process
    // from its worker queue, including between a stop and the exit callback.
    func update(_ generation: String?) {
        if target != generation {
            target = generation
            nextAttempt = 0
            backoff = 2
            lock.lock()
            childGeneration = nil
            childReady = false
            let obsolete = child
            lock.unlock()
            if obsolete?.isRunning == true { obsolete?.terminate() }
        }
        let now = ProcessInfo.processInfo.systemUptime
        guard let generation, child == nil, now >= nextAttempt else { return }
        let task = Process()
        task.executableURL = runtimePython
        task.arguments = [helper, "managed_run", generation]
        task.standardInput = FileHandle.nullDevice
        let output = Pipe()
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        task.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                self?.finished(process, generation: generation, startedAt: now)
            }
        }
        output.fileHandleForReading.readabilityHandler = { [weak self, weak task] handle in
            let data = handle.availableData
            handle.readabilityHandler = nil
            guard data == Data("ready\n".utf8), let self, let task else { return }
            self.lock.lock()
            if self.child === task, self.childGeneration == generation { self.childReady = true }
            self.lock.unlock()
        }
        lock.lock()
        child = task
        childGeneration = generation
        lock.unlock()
        do {
            try task.run()
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            lock.lock()
            child = nil
            childGeneration = nil
            lock.unlock()
            delayRetry(startedAt: now)
        }
    }

    private func finished(_ task: Process, generation: String, startedAt: TimeInterval) {
        lock.lock()
        if child === task {
            child = nil
            childGeneration = nil
            childReady = false
        }
        lock.unlock()
        guard target == generation else {
            update(target)
            return
        }
        delayRetry(startedAt: startedAt)
        didStop()
    }

    private func delayRetry(startedAt: TimeInterval) {
        let now = ProcessInfo.processInfo.systemUptime
        if now - startedAt >= 30 { backoff = 2 }
        nextAttempt = now + backoff
        backoff = min(30, backoff * 2)
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private static let helperPath = NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath
    var statusItem: NSStatusItem!
    var menu: NSMenu!

    var state: GuardState = .offline
    var currentIP: String = "…"
    var protectionEnabled: Bool = true
    var modelOverrideEnabled: Bool = false
    var defaultModel: String = "claude-opus-4-8"
    var proxyEndpoint = "Not configured"
    var proxyEnabled = true
    var proxyProfileID = ""
    var proxyVerifiedAt: TimeInterval = 0
    var expectedExitIP = ""
    var usesLuLu = false
    var desktopPACURL: String?
    private var managedProfile: [String: Any]?
    private var pacServices: [String] = []
    private lazy var managedProxy = ManagedProxySupervisor(helper: Self.helperPath) { [weak self] in
        self?.managedProxyStopped()
    }
    var proxyError = ""
    var connectionMode: ConnectionMode = .vpn
    var menuIsOpen = false
    var menuRows: [String: NSMenuItem] = [:]
    private lazy var statusCard = MenuStatusCard()
    private enum UpdateActivity { case idle, checking, downloading }
    private var updateActivity = UpdateActivity.idle
    private var availableUpdate: DesktopUpdater.Update?
    private var stagedUpdate: (update: DesktopUpdater.Update, package: URL)?
    private let updateVersion = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
        .flatMap(DesktopUpdater.Version.init)
    private var russianMenu = (UserDefaults.standard.string(forKey: "MenuLanguage")
        ?? Locale.preferredLanguages.first ?? "en").hasPrefix("ru")

    private func menuText(_ english: String, _ russian: String) -> String {
        russianMenu ? russian : english
    }
    lazy var modeControl: ModeSegmentedControl = {
        let control = ModeSegmentedControl(selected: connectionMode)
        control.onChange = { [weak self] mode in self?.onModeChanged(mode) }
        return control
    }()
    lazy var modeMenuItem: NSMenuItem = {
        let item = NSMenuItem()
        item.view = modeControl
        return item
    }()
    func menuWillOpen(_ menu: NSMenu) {
        menuIsOpen = true
        refreshLuLu(force: true)
        rebuildMenu()
    }
    func menuDidClose(_ menu: NSMenu) { menuIsOpen = false; rebuildMenu() }
    private var switchTiming: (id: UUID, start: TimeInterval, stage: String)?
    func onModeChanged(_ mode: ConnectionMode) {
        if let started = SwitchTrace.begin() {
            if let previous = switchTiming { SwitchTrace.end(previous.start, previous.stage, "superseded") }
            switchTiming = (UUID(), started, "switch." + connectionMode.rawValue + "_to_" + mode.rawValue)
        }
        connectionMode = mode
        if mode == .proxy && managedProfile == nil { proxyEnabled = true }
        proxyError = ""
        proxyProfileID = ""
        proxyVerifiedAt = 0
        currentIP = "…"
        state = .offline
        saveConfig()
        reconcileManagedProxy()
        writeStateFile()
        lastAppliedDomainsBlocked = nil
        rebuildMenu()
        recheckAsync()
    }

    var allowedIPs: [String] = []

    var dynamicStore: SCDynamicStore?
    var pathMonitor: NWPathMonitor?
    // Usable network route, from NWPathMonitor — lets us declare "offline" the
    // instant Wi-Fi drops instead of waiting for HTTP timeouts.
    var hasNetworkPath: Bool = true
    var blinkTimer: Timer?
    var blinkState: Bool = false
    // Serialize + coalesce rechecks. A plain "drop if busy" lock loses the
    // network event that arrives mid-check — the classic cause of a boot (or a
    // VPN handoff) that latches on offline/blocked until a reboot. Instead:
    // while a check runs, fold new requests into a flag and run one more pass
    // when it finishes, so the newest event is always acted on.
    let checkLock = NSLock()
    var checkRunning = false
    var recheckQueued = false
    #if CLAUDEGUARD_DESKTOP_FILTER
    private lazy var desktopFilter = DesktopFilterController(configPath: configPath)
    #endif
    let configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath

    // Last enforcement pushed to the system, to skip redundant work. nil = never
    // applied, force a first apply.
    var lastAppliedDomainsBlocked: Bool? = nil
    var enforcementError: String? = nil
    var lastEnforcementAt = Date.distantPast
    // Alerted once for the current blocked episode (reset on leaving blocked).
    var hasAlertedThisBlock: Bool = false
    private var luluCheckRunning = false
    private var luluFailure: String?
    private var luluImporting = false
    private var desktopLaunchRequested = false
    private var blockedAlert: NSAlert?

    // MARK: - Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single-instance guard. LaunchAgent runs the bare binary, Launchpad
        // runs the .app — match both names and the bundle id.
        let myPID = getpid()
        for app in NSWorkspace.shared.runningApplications where app.processIdentifier != myPID {
            let name = app.localizedName ?? ""
            if name == "ClaudeGuardMenuBar" || name == "ClaudeGuard" || app.bundleIdentifier == "com.claudeguard.app" {
                NSApplication.shared.terminate(nil)
                return
            }
        }

        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImage = NSImage(contentsOfFile: iconPath) {
            NSApplication.shared.applicationIconImage = iconImage
        }

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        updateStatusDisplay()
        menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        loadConfig()
        #if CLAUDEGUARD_DESKTOP_FILTER
        desktopFilter.didChange = { [weak self] in self?.rebuildMenu() }
        desktopFilter.refresh()
        #endif
        // Migrate the removed standalone Disconnect state. Mode + Protection now control access.
        if !proxyEnabled && managedProfile == nil { proxyEnabled = true; saveConfig() }
        reconcileManagedProxy()
        rebuildMenu()

        setupAppLaunchInterceptor()

        // Bring the network monitors up first so no early Wi-Fi/VPN transition
        // is missed, then verify. State is unknown until the first check returns.
        setupPathMonitor()      // connectivity up/down
        setupNetworkObserver()  // VPN/route/IP changes while online
        setupWakeObserver()     // re-verify after the Mac wakes from sleep
        refreshLuLu(force: true)

        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }

        // Fallback poll — catches a public-IP change with no local network event,
        // and (paired with the coalescing recheck) guarantees the daemon
        // self-heals from a bad boot within one interval instead of needing a
        // reboot. .utility so the OS won't suspend it the way it can .background.
        let checkTimer = Timer(timeInterval: 3, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.reconcileManagedProxy()
            self.refreshLuLu()
            #if CLAUDEGUARD_DESKTOP_FILTER
            self.desktopFilter.refresh()
            if self.desktopFilter.required && (!self.desktopFilter.configured || !self.protectionEnabled || self.connectionMode != .proxy) {
                _ = self.killDesktopIfRunning()
            }
            #endif
            DispatchQueue.global(qos: .utility).async { self.recheck() }
        }
        checkTimer.tolerance = 0.5
        RunLoop.main.add(checkTimer, forMode: .common)

        // Hook self-heal. Separate from recheck() because it guards a different
        // failure: not a network change, but Claude being reinstalled underneath
        // us and quietly detaching the guard.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) { self.runIntegrityRepair() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in self?.checkForDesktopUpdate(interactive: false) }
        Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.runIntegrityRepair() }
            self.checkForDesktopUpdate(interactive: false)
        }
    }

    func runIntegrityRepair() {
        runHelper("integrity", "", "")
    }

    func applicationWillTerminate(_ notification: Notification) {
        managedProxy.update(nil)
    }

    /// True when /etc/hosts no longer matches what we last applied — an OS
    /// update, another tool or a manual edit reverted our block.
    func hostsDrifted() -> Bool {
        guard let wantDomains = lastAppliedDomainsBlocked,
              let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        else { return false }
        let hasDomains = content.contains("# BEGIN CLAUDEGUARD BLOCKS")
        let hasUpdates = content.contains("# BEGIN CLAUDEGUARD UPDATE BLOCKS")
        let expectHostsBlock = wantDomains && connectionMode != .vpn
        return hasDomains != expectHostsBlock || hasUpdates
    }

    /// Claude Desktop, matched by bundle-id *prefix* — the exact id has already
    /// changed once (claudefor-mac → claudefordesktop). The name is only a
    /// fallback: it's localized, so it can't be the primary test.
    static func isClaudeDesktop(_ app: NSRunningApplication) -> Bool {
        if let bundleID = app.bundleIdentifier {
            if bundleID.hasPrefix("com.claudeguard") { return false }   // never ourselves
            if bundleID.hasPrefix("com.anthropic.claude") { return true }
        }
        return (app.localizedName ?? "") == "Claude"
    }

    // MARK: - Connectivity monitor (Network framework)

    func setupPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let satisfied = (path.status == .satisfied)
            let changed = (self.hasNetworkPath != satisfied)
            self.hasNetworkPath = satisfied
            // Connectivity flipped — re-verify. Down → recheck() declares offline
            // instantly; up → recheck() runs the IP check.
            if changed { self.lastAppliedDomainsBlocked = nil; self.startBlinking() }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + (satisfied ? 0.4 : 0.0)) {
                self.recheck()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.claudeguard.path"))
        self.pathMonitor = monitor
    }

    // MARK: - Real-time network observer

    func setupNetworkObserver() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)

        let callback: SCDynamicStoreCallBack = { (_, _, info) in
            guard let info = info else { return }
            let me = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            // Network event fired — don't act blindly, just re-verify once it
            // settles; recheck() decides.
            me.lastAppliedDomainsBlocked = nil
            me.startBlinking()
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.3) { me.recheck() }
        }

        guard let store = SCDynamicStoreCreate(kCFAllocatorDefault, "com.claudeguard.app" as CFString, callback, &context) else { return }
        self.dynamicStore = store
        let patterns = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Interface/.*",
            "State:/Network/Service/.*"
        ] as CFArray
        SCDynamicStoreSetNotificationKeys(store, nil, patterns)
        if let src = SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), src, .defaultMode)
        }
    }

    // MARK: - Wake-from-sleep

    /// After the Mac wakes, the route and VPN re-establish over several seconds
    /// and NWPathMonitor may not emit a clean transition. Fire a few staggered
    /// rechecks so we never sit on a stale pre-sleep verdict.
    func setupWakeObserver() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lastAppliedDomainsBlocked = nil
            self.startBlinking()
            self.refreshLuLu(force: true)
            for delay in [0.5, 3.0, 8.0] {
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) {
                    self.recheck()
                }
            }
        }
    }

    // MARK: - Desktop app launch interceptor

    func setupAppLaunchInterceptor() {
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] note in
            guard let self, let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  Self.isClaudeDesktop(app) else { return }
            if self.usesLuLu { self.refreshLuLu(force: true) }
            #if CLAUDEGUARD_DESKTOP_FILTER
            if self.desktopFilter.required && (!self.desktopFilter.configured || !self.protectionEnabled || self.connectionMode != .proxy) {
                app.forceTerminate()
                return
            }
            #endif
            guard let reason = self.desktopLaunchBlockReason() else { return }
            app.forceTerminate()
            self.runPkill(target: "Claude.app")
            self.showBlockedAlert(reason: reason)
        }
    }

    func desktopLaunchBlockReason() -> String? {
        if usesLuLu {
            if let failure = luluFailure { return failure }
            if let expected = desktopPACURL, !systemPACMatches(expected) {
                return menuText("macOS proxy routing is inactive. Check Protection → macOS Proxy Routing.",
                                "Маршрутизация macOS не активна. Проверьте «Защита → Маршрутизация macOS».")
            }
        }
        guard protectionEnabled else { return nil }
        if case .allowed = state, enforcementError == nil,
           connectionMode == .vpn || (hasFreshProxyProof && currentIP == expectedExitIP) {
            return nil
        }
        if connectionMode == .proxy {
            return menuText("The proxy hasn't been verified. Open ClaudeGuard and choose Check Connection.",
                            "Прокси ещё не прошёл проверку. Выберите «Проверить соединение» в ClaudeGuard.")
        }
        if case .offline = state {
            return menuText("The current IP couldn’t be verified.", "Текущий IP пока не удалось проверить.")
        }
        return menuText("The current IP is outside the VPN allowlist.", "Текущий IP отсутствует в списке разрешённых VPN.")
    }

    func systemPACMatches(_ expected: String) -> Bool {
        guard expected.hasPrefix("data:"),
              let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return false }
        return (proxies["ProxyAutoConfigEnable"] as? NSNumber)?.intValue == 1
            && proxies["ProxyAutoConfigURLString"] as? String == expected
    }

    private var hasFreshProxyProof: Bool {
        proxyEnabled && (0...7).contains(Date().timeIntervalSince1970 - proxyVerifiedAt)
    }

    // MARK: - Core check

    private func refreshLuLu(force: Bool = false) {
        // Only the main queue owns the watchdog; it never waits on DNS or the
        // IP proof and does no polling work while Claude Desktop is closed.
        guard usesLuLu, !luluCheckRunning,
              force || NSWorkspace.shared.runningApplications.contains(where: Self.isClaudeDesktop) else { return }
        luluCheckRunning = true
        let task = Process()
        task.executableURL = runtimePython
        task.arguments = [NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath, "lulu_check"]
        task.standardOutput = FileHandle.nullDevice
        let error = Pipe()
        task.standardError = error
        task.terminationHandler = { [weak self] process in
            let data = error.fileHandleForReading.readDataToEndOfFile()
            let message = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                self?.finishLuLuCheck(process.terminationStatus == 0 ? nil : message ?? "")
            }
        }
        do { try task.run() } catch { finishLuLuCheck("") }
    }

    private func finishLuLuCheck(_ failure: String?) {
        luluCheckRunning = false
        luluFailure = failure.map { $0.isEmpty ? "ClaudeGuard could not verify the LuLu content filter." : $0 }
        if let reason = luluFailure, killDesktopIfRunning() { showBlockedAlert(reason: reason) }
        updateStatusDisplay()
        rebuildMenu()
        if desktopLaunchRequested {
            desktopLaunchRequested = false
            if let reason = luluFailure {
                showBlockedAlert(reason: reason, closed: false)
            } else {
                runDesktopLauncher()
            }
        }
    }

    func recheck() {
        // Coalescing gate: at most one check runs at a time; a request that
        // arrives while one is in flight sets a flag so exactly one more pass
        // runs afterwards. No network event is ever silently dropped, and two
        // quick config toggles can't leave enforcement out of sync.
        checkLock.lock()
        if checkRunning {
            recheckQueued = true
            checkLock.unlock()
            return
        }
        checkRunning = true
        checkLock.unlock()

        while true {
            checkLock.lock(); recheckQueued = false; checkLock.unlock()

            performCheck()

            checkLock.lock()
            if recheckQueued { checkLock.unlock(); continue }
            checkRunning = false
            checkLock.unlock()
            break
        }
        stopBlinking()
    }

    /// One verification pass: resolve the public IP, fold it into a GuardState,
    /// push enforcement on transitions, publish the verdict.
    func performCheck() {
        let timingID = switchTiming?.id
        let configurationSnapshot = try? Data(contentsOf: URL(fileURLWithPath: configPath))
        loadConfig()

        // Install the VPN denial before the first network verification.
        if protectionEnabled && connectionMode == .vpn && lastAppliedDomainsBlocked == nil {
            if runHelper("sync_hosts", "true", "") {
                lastAppliedDomainsBlocked = true
                lastEnforcementAt = Date()
            }
        }
        let newState: GuardState
        // Keep results local until the configuration snapshot is validated.
        // A completed proxy probe must not overwrite the IP of a new VPN mode.
        var checkedIP = currentIP
        var checkedError = proxyError
        var checkedProfileID = proxyProfileID
        var checkedProxyVerifiedAt: TimeInterval = 0
        if !protectionEnabled {
            newState = .disabled
        } else if connectionMode == .proxy {
            let result = checkProxy()
            checkedError = result.error
            checkedProfileID = result.profileID
            if let ip = result.ip, ip == expectedExitIP,
               (0...7).contains(Date().timeIntervalSince1970 - result.verifiedAt) {
                checkedIP = ip
                checkedProxyVerifiedAt = result.verifiedAt
                newState = .allowed(ip: ip)
            } else {
                checkedIP = "Unavailable"
                if checkedError.isEmpty { checkedError = "Proxy verification expired" }
                newState = .blocked(ip: checkedIP)
            }
        } else {
            // `hasNetworkPath` is only a *hint* for snappy offline detection —
            // never a latch. Even when it says "no route" we still attempt a
            // short resolve, because that flag can go stale across a Wi-Fi/VPN
            // handoff and would otherwise pin us to offline until a reboot. A
            // resolved IP always overrides the hint (and repairs it).
            let ip = hasNetworkPath ? resolvePublicIPWithRetry()
                                    : resolvePublicIP(deadline: 1.5)
            if let ip = ip {
                checkedIP = ip
                if !hasNetworkPath { hasNetworkPath = true }   // hint was stale
                let ok = Self.isIPAllowed(ip, allowedList: allowedIPs)
                newState = ok ? .allowed(ip: ip) : .blocked(ip: ip)
            } else {
                checkedIP = "No Internet"
                newState = .offline
            }
        }

        // Discard a network result obtained for settings changed during the check.
        // In particular, a late VPN result must never approve a newly selected proxy.
        guard configurationSnapshot == (try? Data(contentsOf: URL(fileURLWithPath: configPath))) else {
            checkLock.lock(); recheckQueued = true; checkLock.unlock()
            return
        }
        currentIP = checkedIP
        proxyError = checkedError
        proxyProfileID = checkedProfileID
        proxyVerifiedAt = checkedProxyVerifiedAt
        if protectionEnabled && connectionMode == .proxy {
            // The proxy helper owns preparation and denial for this mode.
            // A generic sync after a failed proof must not start the engine.
            enforcementError = nil
            lastAppliedDomainsBlocked = nil
        }
        let previous = state
        state = newState
        // Publish a denial before waiting for the privileged helper, so CLI
        // sessions stop promptly even if applying network rules is slow.
        if newState.domainsShouldBeBlocked { writeStateFile() }
        apply(from: previous, to: newState)
        if protectionEnabled && enforcementError != nil { state = .blocked(ip: currentIP) }
        writeStateFile()  // publish verdict for the CLI wrapper

        DispatchQueue.main.async {
            self.updateStatusDisplay(); self.rebuildMenu()
            if let timing = self.switchTiming, timing.id == timingID {
                SwitchTrace.end(timing.start, timing.stage, self.enforcementError == nil ? "completed" : "error")
                self.switchTiming = nil
            }
        }
    }

    /// Publishes the verdict to state.json (single source of truth for the CLI
    /// wrapper). Written atomically each recheck; a stale file signals the
    /// daemon is down and the wrapper should fall back to its own check.
    func writeStateFile() {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "state_json.write") }
        let stateStr: String
        switch state {
        case .allowed:  stateStr = "allowed"
        case .blocked:  stateStr = "blocked"
        case .offline:  stateStr = "offline"
        case .disabled: stateStr = "disabled"
        }
        var dict: [String: Any] = [
            "state": stateStr,
            "mode": connectionMode.rawValue,
            "proxy_profile_id": proxyProfileID,
            "proxy_verified_at": proxyVerifiedAt,
            "ip": currentIP,
            "protection_enabled": protectionEnabled,
            "updated_at": Date().timeIntervalSince1970
        ]
        if let error = enforcementError { dict["enforcement_error"] = error }
        let path = NSString(string: "~/.config/claudeguard/state.json").expandingTildeInPath
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    /// The only place that touches the system. Each piece runs only when its
    /// input actually changed.
    func apply(from previous: GuardState, to new: GuardState) {
        // Transition-only enforcement assumes nothing else edits /etc/hosts;
        // drift means "pretend we never applied anything" and re-apply.
        if hostsDrifted() {
            lastAppliedDomainsBlocked = nil
        }

        // Desktop app kill + alert.
        switch new {
        case .blocked:
            let killed = killDesktopIfRunning()
            if killed && !hasAlertedThisBlock {   // alert once per blocked episode
                hasAlertedThisBlock = true
                showBlockedAlert(reason: connectionMode == .proxy ? "Proxy connection could not be verified. Check Configure Proxy and connection status." : "Your public IP (\(currentIP)) is not in your allowed VPN whitelist.")
            }
        case .allowed, .disabled, .offline:
            // offline: don't kill a running app — nothing to protect against.
            hasAlertedThisBlock = false
        }
        if protectionEnabled && connectionMode == .proxy { return }
        let wantBlocked = new.domainsShouldBeBlocked
        // Also refresh an active block periodically: another firewall can
        // reload PF without touching hosts, or DNS targets can change.
        let refreshBlock = (wantBlocked || protectionEnabled) && Date().timeIntervalSince(lastEnforcementAt) >= 60
        if lastAppliedDomainsBlocked != wantBlocked || refreshBlock {
            if runHelper("sync_hosts", wantBlocked ? "true" : "false", "") {
                lastAppliedDomainsBlocked = wantBlocked
                lastEnforcementAt = Date()
                enforcementError = nil
            } else {
                lastAppliedDomainsBlocked = nil
                enforcementError = "Network rules could not be applied; check /tmp/claudeguard.err"
            }
        }
        _ = previous
    }

    // MARK: - IP fetch (STUN-first, HTTP fallback, raced)

    let stunServers: [(String, UInt16)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]
    let httpServices = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://api.myip.com"
    ]

    /// Resolves the public IP with a brief retry — right after a VPN/Wi-Fi
    /// handshake the route is momentarily unstable, and a single failed lookup
    /// used to falsely flash "offline".
    func resolvePublicIPWithRetry(attempts: Int = 2, deadline: TimeInterval = 2.0) -> String? {
        for attempt in 0..<attempts {
            if let ip = resolvePublicIP(deadline: deadline) { return ip }
            if attempt < attempts - 1 { Thread.sleep(forTimeInterval: 0.5) }
        }
        return nil
    }

    /// Races a STUN query against the HTTP IP services in parallel; first valid
    /// answer wins. STUN wins instantly when online; HTTP covers networks that
    /// block UDP/STUN. A single ~2s deadline bounds the offline case.
    func resolvePublicIP(deadline: TimeInterval = 2.0) -> String? {
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String? = nil
        func offer(_ ip: String?) {
            guard let ip = ip, !ip.isEmpty else { return }
            lock.lock()
            let first = (result == nil)
            if first { result = ip }
            lock.unlock()
            if first { sem.signal() }
        }

        // STUN (fast path)
        var conns: [NWConnection] = []
        for (host, port) in stunServers {
            if let c = stunQuery(host: host, port: port, completion: { offer($0) }) {
                conns.append(c)
            }
        }

        // HTTP (fallback, in parallel)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = deadline
        cfg.timeoutIntervalForResource = deadline
        let session = URLSession(configuration: cfg)
        for service in httpServices {
            guard let url = URL(string: service) else { continue }
            var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: deadline)
            req.setValue("ClaudeGuard/1.0", forHTTPHeaderField: "User-Agent")
            session.dataTask(with: req) { data, _, err in
                guard err == nil else { return }
                offer(Self.parseHTTPIP(data))
            }.resume()
        }

        _ = sem.wait(timeout: .now() + deadline)
        conns.forEach { $0.cancel() }
        session.invalidateAndCancel()

        lock.lock(); let ip = result; lock.unlock()
        return ip
    }

    static func parseHTTPIP(_ data: Data?) -> String? {
        guard let data = data,
              let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !str.isEmpty else { return nil }
        if str.contains("{"), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let ip = json["ip"] as? String {
            return ip.trimmingCharacters(in: .whitespacesAndNewlines)
        } else if !str.contains("<") {
            return str
        }
        return nil
    }

    /// Fires one STUN Binding Request over UDP and calls `completion` with the
    /// mapped public IP (or nil). Returns the live connection so the caller can
    /// cancel it. Non-blocking.
    func stunQuery(host: String, port: UInt16, completion: @escaping (String?) -> Void) -> NWConnection? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { completion(nil); return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)

        // STUN Binding Request: type 0x0001, length 0, magic cookie, 12-byte txid.
        var req = Data([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42])
        for _ in 0..<12 { req.append(UInt8.random(in: 0...255)) }

        let lock = NSLock()
        var done = false
        func finish(_ ip: String?) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            completion(ip)
        }

        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                conn.send(content: req, completion: .contentProcessed { err in
                    if err != nil { finish(nil) }
                })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.flatMap { Self.parseStun([UInt8]($0)) })
                }
            case .failed, .cancelled:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "com.claudeguard.stun"))
        return conn
    }

    /// Parses a STUN Binding Success Response, returning the IPv4 from the
    /// XOR-MAPPED-ADDRESS (0x0020) or plain MAPPED-ADDRESS (0x0001) attribute.
    static func parseStun(_ b: [UInt8]) -> String? {
        guard b.count >= 20, b[0] == 0x01, b[1] == 0x01 else { return nil } // 0x0101 success
        let msgLen = Int(b[2]) << 8 | Int(b[3])
        let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        var i = 20
        let end = min(20 + msgLen, b.count)
        while i + 4 <= end {
            let attrType = Int(b[i]) << 8 | Int(b[i + 1])
            let attrLen = Int(b[i + 2]) << 8 | Int(b[i + 3])
            let vs = i + 4
            if vs + attrLen > b.count { break }
            if (attrType == 0x0020 || attrType == 0x0001), attrLen >= 8, b[vs + 1] == 0x01 {
                let a0, a1, a2, a3: UInt8
                if attrType == 0x0020 { // XOR-MAPPED: address XOR'd with the magic cookie
                    a0 = b[vs + 4] ^ cookie[0]
                    a1 = b[vs + 5] ^ cookie[1]
                    a2 = b[vs + 6] ^ cookie[2]
                    a3 = b[vs + 7] ^ cookie[3]
                } else {
                    a0 = b[vs + 4]; a1 = b[vs + 5]; a2 = b[vs + 6]; a3 = b[vs + 7]
                }
                return "\(a0).\(a1).\(a2).\(a3)"
            }
            i = vs + attrLen
            if attrLen % 4 != 0 { i += 4 - (attrLen % 4) } // pad to 4-byte boundary
        }
        return nil
    }

    /// Matches an IP against exact entries or IPv4 CIDR ranges — mirrors
    /// ip_checker.py so the daemon and the CLI agree on what's whitelisted.
    static func isIPAllowed(_ ip: String, allowedList: [String]) -> Bool {
        for raw in allowedList {
            let entry = raw.trimmingCharacters(in: .whitespaces)
            if entry.isEmpty { continue }
            if entry == ip { return true }
            if entry.contains("/"), let ipv = ipv4ToUInt32(ip) {
                let parts = entry.split(separator: "/")
                if parts.count == 2, let net = ipv4ToUInt32(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits) {
                    let mask: UInt32 = bits == 0 ? 0 : (~UInt32(0)) << (32 - bits)
                    if (ipv & mask) == (net & mask) { return true }
                }
            }
        }
        return false
    }

    static func ipv4ToUInt32(_ ip: String) -> UInt32? {
        let p = ip.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 <= 255 }) else { return nil }
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    }

    // MARK: - Process control

    func runPkill(target: String) {
        let t1 = Process()
        t1.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        t1.arguments = ["-15", "-f", target]
        try? t1.run()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) {
            let t2 = Process()
            t2.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            t2.arguments = ["-9", "-f", target]
            try? t2.run()
        }
    }

    @discardableResult
    func killDesktopIfRunning() -> Bool {
        let victims = NSWorkspace.shared.runningApplications.filter { Self.isClaudeDesktop($0) }
        guard !victims.isEmpty else { return false }
        // Terminate the matched processes directly (precise wherever the app was
        // installed); pkill is the second pass for helpers it spawns.
        victims.forEach { $0.forceTerminate() }
        runPkill(target: "Claude.app")
        return true
    }

    func showBlockedAlert(reason: String, closed: Bool = true) {
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = self.menuText("ClaudeGuard · Launch blocked", "ClaudeGuard · Доступ заблокирован")
            let message = closed ? self.menuText("Claude Desktop was closed.\n\n", "Claude Desktop закрыт.\n\n") : ""
            alert.informativeText = message + reason
            let button = alert.addButton(withTitle: "OK")
            button.target = self
            button.action = #selector(self.dismissBlockedAlert)
            self.blockedAlert?.window.orderOut(nil)
            self.blockedAlert = alert
            alert.window.level = .floating
            alert.window.center()
            alert.window.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func dismissBlockedAlert() {
        blockedAlert?.window.orderOut(nil)
        blockedAlert = nil
    }

    @discardableResult
    func runHelper(_ cmd: String, _ a1: String, _ a2: String) -> Bool {
        let timing = SwitchTrace.begin()
        var traceResult = "error"
        defer { SwitchTrace.end(timing, "helper." + (["sync_hosts", "integrity"].contains(cmd) ? cmd : "other"), traceResult) }
        let task = Process()
        task.executableURL = runtimePython
        let script = NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath
        task.arguments = [script, cmd, a1, a2]
        do {
            try task.run()
            task.waitUntilExit()
            traceResult = task.terminationStatus == 0 ? "ok" : "error"
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: - Config

    func loadConfig() {
        guard secureConfigPermissions() else { return }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        SwitchTrace.enabled = ProcessInfo.processInfo.environment["CLAUDEGUARD_TRACE"] == "1" || json["trace"] as? Bool == true
        proxyEnabled = json["proxy_enabled"] as? Bool ?? true
        expectedExitIP = json["expected_exit_ip"] as? String ?? ""
        usesLuLu = (json["desktop_firewall"] as? String) == "lulu"
        desktopPACURL = json["desktop_pac_url"] as? String
        managedProfile = json["managed_proxy"] as? [String: Any]
        pacServices = json["desktop_pac_services"] as? [String] ?? []
        if let profile = json["proxy_profile"] as? [String: Any],
           let host = profile["server"] as? String, let port = profile["server_port"] as? Int {
            proxyEndpoint = "\(profile["type"] as? String ?? "proxy")://\(host):\(port)"
        } else { proxyEndpoint = "Not configured" }
        let loadedMode = ConnectionMode(rawValue: json["connection_mode"] as? String ?? "vpn") ?? .vpn
        if loadedMode != connectionMode {
            lastAppliedDomainsBlocked = nil
            currentIP = "…"
            proxyProfileID = ""
            proxyVerifiedAt = 0
            proxyError = ""
            state = protectionEnabled ? .offline : .disabled
        }
        connectionMode = loadedMode
        if let ips = json["allowed_ips"] as? [String] { allowedIPs = ips }
        if let p = json["protection_enabled"] as? Bool { protectionEnabled = p }
        if let m = json["model_override_enabled"] as? Bool { modelOverrideEnabled = m }
        if let d = json["default_model"] as? String { defaultModel = d }
    }

    func saveConfig() {
        guard secureConfigPermissions() else { return }
        var json: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { json = existing }
        json["proxy_enabled"] = proxyEnabled
        json["connection_mode"] = connectionMode.rawValue
        json["allowed_ips"] = allowedIPs
        json["protection_enabled"] = protectionEnabled
        json["model_override_enabled"] = modelOverrideEnabled
        json["default_model"] = defaultModel
        if let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) {
            let fd = open(configPath, O_WRONLY | O_CREAT | O_NOFOLLOW, mode_t(0o600))
            guard fd >= 0 else { return }
            defer { close(fd) }
            guard fchmod(fd, mode_t(0o600)) == 0, ftruncate(fd, 0) == 0 else { return }
            data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { return }
                    offset += count
                }
            }
        }
    }

    private func secureConfigPermissions() -> Bool {
        let directory = (configPath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return false }
        guard chmod(directory, mode_t(0o700)) == 0 else { return false }
        if !FileManager.default.fileExists(atPath: configPath) { return true }
        let fd = open(configPath, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        return fchmod(fd, mode_t(0o600)) == 0
    }

    // MARK: - UI

    func menuStatus() -> (health: MenuHealth, title: String) {
        if !protectionEnabled { return (.paused, menuText("Protection paused", "Защита приостановлена")) }
        if usesLuLu && luluFailure != nil { return (.blocked, menuText("Check LuLu", "Проверьте LuLu")) }
        if menuIsOpen && usesLuLu, let expected = desktopPACURL, !systemPACMatches(expected) {
            return (.blocked, menuText("macOS routing inactive", "Маршрут macOS не активен"))
        }
        if connectionMode == .proxy && proxyEndpoint == "Not configured" {
            return (.blocked, menuText("Proxy not configured", "Прокси не настроен"))
        }
        if connectionMode == .proxy && !proxyEnabled {
            return (.blocked, menuText("Proxy disconnected", "Прокси отключён"))
        }
        switch state {
        case .offline:  return (.checking, menuText("Checking connection", "Проверяем соединение"))
        case .disabled: return (.paused, menuText("Protection paused", "Защита приостановлена"))
        case .allowed:
            if connectionMode == .proxy && !hasFreshProxyProof {
                return (.checking, menuText("Checking proxy", "Проверяем прокси"))
            }
            return (.ready, menuText("Protection active", "Защита активна"))
        case .blocked:  return (.blocked, menuText("Connection blocked", "Соединение заблокировано"))
        }
    }

    func updateStatusDisplay(isDimmed: Bool = false) {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "ui.status.update") }
        guard let button = statusItem.button else { return }
        button.title = ""
        button.attributedTitle = NSAttributedString(string: "")

        let status = menuStatus()
        if let image = NSImage(systemSymbolName: status.health.symbol, accessibilityDescription: status.title)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)) {
            image.isTemplate = true
            button.image = image
            button.alphaValue = isDimmed ? 0.35 : 1.0
        }
    }

    func startBlinking() {
        DispatchQueue.main.async { [self] in
            guard blinkTimer == nil else { return }
            blinkState = false
            // Quick, smooth opacity pulse that fades in/out (like the system's
            // menu-bar input-source switcher) instead of a slow hard blink.
            blinkTimer = Timer.scheduledTimer(withTimeInterval: 0.16, repeats: true) { [weak self] _ in
                guard let self = self, let button = self.statusItem.button else { return }
                self.blinkState.toggle()
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = self.blinkState ? 0.45 : 1.0
                }
            }
        }
    }

    func stopBlinking() {
        DispatchQueue.main.async { [self] in
            blinkTimer?.invalidate()
            blinkTimer = nil
            updateStatusDisplay()
            if let button = statusItem.button {
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = 1.0
                }
            }
            rebuildMenu()
        }
    }

    func rebuildMenu() {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "ui.menu.update") }
        // Keep menu objects alive during tracking, including the mode control.
        if menuRows.isEmpty {
            menu.autoenablesItems = false
            func row(_ key: String, _ action: Selector? = nil, symbol: String? = nil,
                     in parent: NSMenu? = nil) -> NSMenuItem {
                let item = NSMenuItem(title: "", action: action, keyEquivalent: "")
                item.target = action == nil ? nil : self
                item.isEnabled = action != nil
                if let symbol {
                    item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
                        .withSymbolConfiguration(.init(pointSize: 13, weight: .medium))
                }
                menuRows[key] = item
                (parent ?? menu).addItem(item)
                return item
            }
            func section(_ key: String, symbol: String) -> NSMenu {
                let submenu = NSMenu()
                submenu.autoenablesItems = false
                let item = row(key, symbol: symbol)
                item.submenu = submenu
                item.isEnabled = true
                return submenu
            }
            row("status").view = statusCard
            _ = row("launchDesktop", #selector(onLaunchDesktop), symbol: "arrow.up.right.square")
            _ = row("recheck", #selector(onRecheck), symbol: "arrow.clockwise")
            menu.addItem(.separator())
            let connection = section("connection", symbol: "network")
            connection.addItem(modeMenuItem)
            _ = row("endpoint", in: connection)
            _ = row("proxyToggle", #selector(onToggleManagedProxy), in: connection)
            _ = row("proxy", #selector(onConfigureProxy), in: connection)
            _ = row("sshProxy", #selector(onConfigureSSH), in: connection)
            _ = row("realityProxy", #selector(onConfigureReality), in: connection)
            _ = row("addIP", #selector(onAddCurrentIP), in: connection)
            _ = row("manageIPs", #selector(onManageIPs), in: connection)
            let protection = section("protectionSettings", symbol: "checkmark.shield")
            _ = row("desktopPAC", #selector(onConfigureDesktopPAC), in: protection)
            _ = row("luluInstaller", #selector(onOpenLuLuInstaller), in: protection)
            _ = row("installLuLuRules", #selector(onInstallLuLuRules), in: protection)
            _ = row("luluRules", #selector(onShowLuLuRules), in: protection)
            #if CLAUDEGUARD_DESKTOP_FILTER
            _ = row("desktopFilter", #selector(onDesktopFilter), in: protection)
            #endif
            _ = row("protection", #selector(onToggleProtection), in: protection)
            let code = section("code", symbol: "chevron.left.forwardslash.chevron.right")
            _ = row("model", #selector(onToggleModelOverride), in: code)
            _ = row("changeModel", #selector(onChangeModel), in: code)
            let language = section("language", symbol: "globe")
            _ = row("english", #selector(onMenuLanguage), in: language)
            _ = row("russian", #selector(onMenuLanguage), in: language)
            menuRows["english"]?.representedObject = "en"
            menuRows["russian"]?.representedObject = "ru"
            menu.addItem(.separator())
            _ = row("updates", #selector(onDesktopUpdate), symbol: "arrow.down.circle")
            _ = row("uninstall", #selector(onUninstall), symbol: "trash")
            _ = row("quit", #selector(onQuit), symbol: "power")
        }
        let isProxy = connectionMode == .proxy
        let transport = managedProfile?["kind"] as? String
        let route: String
        switch transport {
        case "ssh" where isProxy: route = "SSH"
        case "xray" where isProxy: route = "VLESS/REALITY"
        default: route = isProxy ? menuText("External proxy", "Внешний прокси") : "VPN"
        }
        let status = menuStatus()
        let detail: String
        if case .allowed(let ip) = state, status.health == .ready {
            detail = "\(route)  ·  IP \(ip)"
        } else {
            detail = isProxy && proxyEndpoint == "Not configured" ? "" : route
        }
        menuRows["status"]?.title = status.title
        statusCard.update(health: status.health, title: status.title, detail: detail,
                          tooltip: luluFailure ?? (proxyError.isEmpty ? nil : proxyError))
        menuRows["connection"]?.title = menuText("Connection", "Подключение")
        menuRows["protectionSettings"]?.title = menuText("Protection", "Защита")
        menuRows["language"]?.title = menuText("Language", "Язык")
        menuRows["english"]?.title = "English"
        menuRows["russian"]?.title = "Русский"
        menuRows["english"]?.state = russianMenu ? .off : .on
        menuRows["russian"]?.state = russianMenu ? .on : .off
        modeControl.setSelectedMode(connectionMode, animated: false)
        modeControl.isEnabled = protectionEnabled
        modeMenuItem.isHidden = usesLuLu && isProxy
        let endpoint = transport == "ssh" ? "SSH" : transport == "xray" ? "VLESS/REALITY" : proxyEndpoint
        menuRows["endpoint"]?.title = isProxy ? menuText("Proxy: \(endpoint)", "Прокси: \(endpoint)") : "VPN"
        menuRows["endpoint"]?.isHidden = isProxy && proxyEndpoint == "Not configured"
        menuRows["recheck"]?.title = menuText("Check Connection", "Проверить соединение")
        menuRows["protection"]?.title = protectionEnabled
            ? menuText("Pause Protection", "Приостановить защиту") : menuText("Resume Protection", "Включить защиту")
        menuRows["code"]?.title = "Claude Code"
        menuRows["code"]?.isHidden = usesLuLu
        menuRows["model"]?.title = modelOverrideEnabled
            ? menuText("Default Model: \(defaultModel)", "Модель по умолчанию: \(defaultModel)")
            : menuText("Override Default Model", "Переопределить модель")
        menuRows["model"]?.state = modelOverrideEnabled ? .on : .off
        menuRows["changeModel"]?.title = menuText("Change Model…", "Изменить модель…")
        menuRows["changeModel"]?.isHidden = !modelOverrideEnabled
        menuRows["addIP"]?.title = menuText("Allow Current IP (\(currentIP))", "Разрешить текущий IP (\(currentIP))")
        menuRows["addIP"]?.isHidden = isProxy || currentIP.isEmpty || ["No Internet", "…", "Unavailable"].contains(currentIP) || allowedIPs.contains(currentIP)
        menuRows["manageIPs"]?.title = menuText("Allowed VPN IPs…", "Разрешённые IP VPN…")
        menuRows["manageIPs"]?.isHidden = isProxy
        menuRows["proxy"]?.title = menuText("External Proxy…", "Сторонний прокси…")
        menuRows["proxy"]?.isHidden = !isProxy
        menuRows["sshProxy"]?.title = menuText("SSH Tunnel…", "SSH-туннель…")
        menuRows["sshProxy"]?.isHidden = !isProxy
        menuRows["realityProxy"]?.title = menuText("Import VLESS/REALITY…", "Импорт VLESS/REALITY…")
        menuRows["realityProxy"]?.isHidden = !isProxy || !FileManager.default.isExecutableFile(atPath: "/Library/Application Support/ClaudeGuard/xray")
        menuRows["proxyToggle"]?.title = proxyEnabled
            ? menuText("Disconnect Proxy", "Отключить прокси") : menuText("Connect Proxy", "Подключить прокси")
        menuRows["proxyToggle"]?.isHidden = !isProxy || managedProfile == nil
        menuRows["desktopPAC"]?.title = menuText("macOS Proxy Routing…", "Маршрутизация macOS…")
        menuRows["desktopPAC"]?.isHidden = !usesLuLu || !isProxy
        menuRows["luluInstaller"]?.title = menuText("Open LuLu Installer", "Открыть установщик LuLu")
        menuRows["luluInstaller"]?.isHidden = !usesLuLu || Bundle.main.url(forResource: "LuLu", withExtension: "dmg") == nil
        menuRows["installLuLuRules"]?.title = luluImporting
            ? menuText("Setting Up LuLu Rules…", "Настраиваем правила LuLu…")
            : menuText("Set Up LuLu Rules…", "Настроить правила LuLu…")
        menuRows["installLuLuRules"]?.isEnabled = !luluImporting
        menuRows["installLuLuRules"]?.isHidden = !usesLuLu || Bundle.main.url(forResource: "ClaudeGuard-LuLu-rules", withExtension: "json") == nil
        menuRows["luluRules"]?.title = menuText("Show LuLu Rules File", "Показать файл правил LuLu")
        menuRows["luluRules"]?.isHidden = !usesLuLu || Bundle.main.url(forResource: "ClaudeGuard-LuLu-rules", withExtension: "json") == nil
        #if CLAUDEGUARD_DESKTOP_FILTER
        menuRows["desktopFilter"]?.title = desktopFilter.required ? "Disable Desktop Network Filter…" : "Enable Desktop Network Filter…"
        menuRows["desktopFilter"]?.isEnabled = !desktopFilter.changing && (isProxy || desktopFilter.required)
        let bundledFilterConfigured = desktopFilter.configured
        let requiresBundledFilter = desktopFilter.required
        #else
        let bundledFilterConfigured = false
        let requiresBundledFilter = false
        #endif
        menuRows["launchDesktop"]?.title = menuText("Open Claude", "Открыть Claude")
        menuRows["launchDesktop"]?.isHidden = !requiresBundledFilter && !usesLuLu
        menuRows["launchDesktop"]?.isEnabled = isProxy && protectionEnabled && (bundledFilterConfigured || usesLuLu)
        menuRows["updates"]?.isHidden = !usesLuLu || updateVersion == nil
        menuRows["updates"]?.isEnabled = updateActivity == .idle
        switch updateActivity {
        case .checking:
            menuRows["updates"]?.title = menuText("Checking for Updates…", "Проверяем обновления…")
        case .downloading:
            menuRows["updates"]?.title = menuText("Downloading Update…", "Скачиваем обновление…")
        case .idle:
            if let update = availableUpdate {
                menuRows["updates"]?.title = menuText("Update to \(update.version)…", "Обновить до \(update.version)…")
            } else {
                menuRows["updates"]?.title = menuText("Check for Updates…", "Проверить обновления…")
            }
        }
        menuRows["uninstall"]?.title = menuText("Uninstall ClaudeGuard…", "Удалить ClaudeGuard…")
        menuRows["uninstall"]?.isHidden = !FileManager.default.fileExists(atPath: uninstallerURL.path)
        menuRows["uninstall"]?.isEnabled = !luluImporting && updateActivity == .idle
        menuRows["quit"]?.title = menuText("Quit ClaudeGuard", "Выйти из ClaudeGuard")
        menu.update()
    }

    func checkProxy() -> (ip: String?, error: String, profileID: String, verifiedAt: TimeInterval) {
        let timing = SwitchTrace.begin()
        defer { SwitchTrace.end(timing, "helper.proxy_check") }
        let generation = managedProfile?["generation"] as? String
        let managed = generation.flatMap { managedProxy.process(for: $0) }
        if generation != nil && (!proxyEnabled || managed == nil) {
            return (nil, proxyEnabled ? "Starting or reconnecting the managed proxy" : "Managed proxy disconnected", "", 0)
        }
        let task = Process()
        task.executableURL = runtimePython
        task.arguments = [NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath, "proxy_check"]
        let pipe = Pipe(); task.standardOutput = pipe
        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            if let generation, let managed, managedProxy.process(for: generation) !== managed {
                return (nil, "The managed proxy connection restarted", "", 0)
            }
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return (nil, "Invalid proxy check response", "", 0)
            }
            let ok = json["ok"] as? Bool == true
            return (ok ? json["ip"] as? String : nil, json["error"] as? String ?? "",
                    json["profile_id"] as? String ?? "", json["verified_at"] as? TimeInterval ?? 0)
        } catch { return (nil, "Proxy check failed", "", 0) }
    }

    func promptText(title: String, prompt: String, value: String) -> String? {
        let window = SettingsInputWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 210),
                                         styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title
        window.isReleasedWhenClosed = false
        window.delegate = window
        let label = NSTextField(wrappingLabelWithString: prompt)
        label.frame = NSRect(x: 24, y: 124, width: 472, height: 56)
        label.font = .systemFont(ofSize: 14)
        let field = NSTextField(frame: NSRect(x: 24, y: 78, width: 472, height: 28))
        field.font = .systemFont(ofSize: 14)
        field.stringValue = value
        let cancel = NSButton(title: "Cancel", target: window, action: #selector(SettingsInputWindow.cancelInput))
        cancel.frame = NSRect(x: 302, y: 22, width: 94, height: 32)
        cancel.bezelStyle = .rounded; cancel.keyEquivalent = "\u{1b}"
        let okay = NSButton(title: "OK", target: window, action: #selector(SettingsInputWindow.acceptInput))
        okay.frame = NSRect(x: 402, y: 22, width: 94, height: 32)
        okay.bezelStyle = .rounded; okay.keyEquivalent = "\r"
        [label, field, cancel, okay].forEach { window.contentView?.addSubview($0) }
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(field)
        field.selectText(nil)
        let response = NSApp.runModal(for: window)
        let entered = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        window.orderOut(nil); window.close()
        return response == .OK ? entered : nil
    }

    func currentProxyInput() -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let config = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = config["proxy_profile"] as? [String: Any] else { return "" }
        // Keep advanced profiles intact; simple HTTP/SOCKS profiles are easier to edit as URLs.
        let urlFields: Set<String> = ["type", "server", "server_port", "username", "password", "version"]
        if Set(profile.keys).isSubset(of: urlFields),
           let type = profile["type"] as? String, ["http", "socks"].contains(type),
           let host = profile["server"] as? String, let port = profile["server_port"] as? Int {
            var url = URLComponents()
            url.scheme = type == "socks" ? "socks\(profile["version"] as? String ?? "5")" : "http"
            url.host = host; url.port = port
            url.user = profile["username"] as? String
            url.password = profile["password"] as? String
            if let value = url.string { return value }
        }
        guard let encoded = try? JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys]),
              let value = String(data: encoded, encoding: .utf8) else { return "" }
        return value
    }

    #if CLAUDEGUARD_DESKTOP_FILTER
    @objc func onDesktopFilter() {
        desktopFilter.toggle()
    }
    #endif

    @objc func onLaunchDesktop() {
        if usesLuLu {
            desktopLaunchRequested = true
            refreshLuLu(force: true)
        } else {
            runDesktopLauncher()
        }
    }

    private func runDesktopLauncher() {
        let task = Process()
        task.executableURL = runtimePython
        let script = NSString(string: "~/.local/share/ClaudeGuard/src/app_launcher.py").expandingTildeInPath
        task.arguments = [script]
        try? task.run()
    }

    private func reconcileManagedProxy() {
        let enabled = protectionEnabled && connectionMode == .proxy && proxyEnabled
        managedProxy.update(enabled ? managedProfile?["generation"] as? String : nil)
    }

    private func managedProxyStopped() {
        guard connectionMode == .proxy, managedProfile != nil else { return }
        proxyVerifiedAt = 0
        proxyProfileID = ""
        currentIP = "Unavailable"
        state = .blocked(ip: currentIP)
        writeStateFile()
        if killDesktopIfRunning() {
            showBlockedAlert(reason: "The managed proxy stopped. ClaudeGuard will verify the exit IPv4 after reconnecting.")
        }
        recheckAsync()
    }

    private func promptProxyFields(_ title: String, _ message: String,
                                   _ entries: [(String, String, String)]) -> [String: String]? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 32 * entries.count))
        let fields = entries.enumerated().map { index, entry -> NSTextField in
            let y = CGFloat((entries.count - index - 1) * 32)
            let label = NSTextField(labelWithString: entry.1)
            label.frame = NSRect(x: 0, y: y + 4, width: 145, height: 20)
            let field = NSTextField(frame: NSRect(x: 150, y: y, width: 290, height: 24))
            field.stringValue = entry.2
            view.addSubview(label)
            view.addSubview(field)
            return field
        }
        alert.accessoryView = view
        if let first = fields.first { alert.window.initialFirstResponder = first }
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return Dictionary(uniqueKeysWithValues: zip(entries.map { $0.0 }, fields.map { $0.stringValue }))
    }

    @objc func onConfigureSSH() {
        let old = managedProfile?["kind"] as? String == "ssh" ? managedProfile : nil
        guard let values = promptProxyFields(
            "SSH Proxy", "Use public-key authentication. Confirm the server's SHA256 host fingerprint with your provider.",
            [("host", "Server", old?["host"] as? String ?? ""),
             ("user", "SSH user", old?["user"] as? String ?? ""),
             ("port", "SSH port", String(old?["port"] as? Int ?? 22)),
             ("identity", "Key file (optional)", old?["identity"] as? String ?? ""),
             ("fingerprint", "Host fingerprint", old?["fingerprint"] as? String ?? ""),
             ("exit_ip", "Expected exit IPv4", expectedExitIP)]
        ), let data = try? JSONSerialization.data(withJSONObject: values) else { return }
        applyManagedSettings(["managed_ssh_save"], input: data)
    }

    @objc func onConfigureReality() {
        guard let values = promptProxyFields(
            "VLESS/REALITY Proxy", "To keep this profile independent of Happ, enter a Wi-Fi or Ethernet interface and the server's literal IPv4.",
            [("url", "VLESS/REALITY URL", ""), ("interface", "Interface (optional)", ""),
             ("address", "Server IPv4 (optional)", ""), ("exit_ip", "Expected exit IPv4", expectedExitIP)]
        ), let data = try? JSONSerialization.data(withJSONObject: values) else { return }
        applyManagedSettings(["managed_xray_save"], input: data)
    }

    @objc func onToggleManagedProxy() {
        applyManagedSettings(["managed_toggle", proxyEnabled ? "stop" : "start"])
    }

    @objc func onConfigureDesktopPAC() {
        let old = pacServices.isEmpty ? "Wi-Fi, Happ" : pacServices.joined(separator: ", ")
        guard let services = promptText(title: "macOS Proxy Routing",
            prompt: "List the network services to configure. This also routes requests to Claude, Anthropic, and hCaptcha in browsers.",
            value: old), !services.isEmpty else { return }
        applyManagedSettings(["desktop_pac_save"], input: Data(services.utf8), routingOnly: true)
    }

    @objc func onOpenLuLuInstaller() {
        if let url = Bundle.main.url(forResource: "LuLu", withExtension: "dmg") { NSWorkspace.shared.open(url) }
    }

    @objc private func onInstallLuLuRules() {
        guard !luluImporting, let template = Bundle.main.url(forResource: "ClaudeGuard-LuLu-rules", withExtension: "json") else { return }
        guard FileManager.default.fileExists(atPath: LuLuRulesImporter.appURL.path) else {
            onOpenLuLuInstaller()
            return
        }
        setLuLuImporting(true)
        let importer = LuLuRulesImporter(python: runtimePython, helper: Self.helperPath)
        DispatchQueue.global(qos: .userInitiated).async {
            let prepared = Result { try importer.prepare(template: template) }
            DispatchQueue.main.async {
                self.setLuLuImporting(false)
                switch prepared {
                case .success(let rules): self.reviewLuLuImport(rules, with: importer)
                case .failure(let error): self.showLuLuImportError(error)
                }
            }
        }
    }

    private func setLuLuImporting(_ importing: Bool) {
        luluImporting = importing
        rebuildMenu()
    }

    private func reviewLuLuImport(_ rules: LuLuRulesImporter.Prepared, with importer: LuLuRulesImporter) {
        let title = menuText("LuLu Rules", "Правила LuLu")
        switch rules.status {
        case .ready:
            refreshLuLu(force: true)
            showMenuMessage(title, menuText("The active LuLu profile already contains the required rules.",
                                            "Все нужные правила уже есть в активном профиле LuLu."))
        case .inactive:
            showMenuMessage(title, menuText("Open LuLu and approve its network filter in macOS. Then run setup again.",
                                            "Откройте LuLu и подтвердите сетевой фильтр в macOS. Затем повторите настройку."))
            NSWorkspace.shared.open(LuLuRulesImporter.appURL)
        case .settings:
            showMenuMessage(title, menuText("In LuLu, turn off Allow Localhost Traffic, Allow DNS Traffic, Allow Already Installed Programs, Block Mode and Allow List. Then try again.",
                                            "В LuLu выключите Allow Localhost Traffic, Allow DNS Traffic, Allow Already Installed Programs, Block Mode и Allow List. Затем повторите настройку."))
            NSWorkspace.shared.open(LuLuRulesImporter.appURL)
        case .conflict:
            showMenuMessage(title, menuText("The active profile has an Allow rule that covers Claude. Remove the conflicting rule or select a separate LuLu profile.",
                                            "В активном профиле есть разрешающее правило, которое охватывает Claude. Удалите это правило или выберите отдельный профиль LuLu."))
        case .import:
            guard LuLuRulesImporter.isAllowed else {
                let access = NSAlert()
                access.messageText = title
                access.informativeText = menuText("Allow ClaudeGuard in Privacy & Security → Accessibility, then choose Set Up LuLu Rules again.",
                                                  "Разрешите ClaudeGuard в разделе «Конфиденциальность и безопасность → Универсальный доступ». Затем снова выберите «Настроить правила LuLu»." )
                access.addButton(withTitle: menuText("Open Settings", "Открыть настройки"))
                access.addButton(withTitle: menuText("Prepare File", "Подготовить файл"))
                access.addButton(withTitle: menuText("Cancel", "Отмена"))
                NSApp.activate(ignoringOtherApps: true)
                switch access.runModal() {
                case .alertFirstButtonReturn: LuLuRulesImporter.requestAccess()
                case .alertSecondButtonReturn: stageLuLuRules(rules, with: importer)
                default: break
                }
                return
            }
            let alert = NSAlert()
            alert.messageText = menuText("Install ClaudeGuard Rules in LuLu?", "Установить правила ClaudeGuard в LuLu?")
            alert.informativeText = menuText("ClaudeGuard will keep the existing permanent rules. LuLu may clear temporary rules during import.",
                                             "ClaudeGuard сохранит постоянные правила. При импорте LuLu может сбросить временные правила.")
            alert.addButton(withTitle: menuText("Install Rules", "Установить правила"))
            alert.addButton(withTitle: menuText("Cancel", "Отмена"))
            NSApp.activate(ignoringOtherApps: true)
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            setLuLuImporting(true)
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try importer.install(rules) }
                DispatchQueue.main.async {
                    self.setLuLuImporting(false)
                    self.refreshLuLu(force: true)
                    if case .failure(let error) = result {
                        switch error {
                        case LuLuRulesImporter.Problem.menu, LuLuRulesImporter.Problem.fileSelection:
                            self.stageLuLuRules(rules, with: importer)
                        default: self.showLuLuImportError(error)
                        }
                    }
                }
            }
        }
    }

    private func stageLuLuRules(_ rules: LuLuRulesImporter.Prepared, with importer: LuLuRulesImporter) {
        setLuLuImporting(true)
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try importer.stage(rules) }
            DispatchQueue.main.async {
                self.setLuLuImporting(false)
                switch result {
                case .success(let file):
                    self.showMenuMessage(self.menuText("LuLu Import File Prepared", "Файл для LuLu готов"),
                        self.menuText("Import the file highlighted in Finder through LuLu → Rules → Import. Keep the current profile until it is imported. LuLu may clear temporary rules.",
                                      "Импортируйте выделенный в Finder файл через LuLu → Rules → Import. До импорта оставьте текущий профиль. LuLu может сбросить временные правила."))
                    NSWorkspace.shared.activateFileViewerSelecting([file])
                case .failure(let error): self.showLuLuImportError(error)
                }
            }
        }
    }

    private func showLuLuImportError(_ error: Error) {
        let detail: String
        switch error {
        case LuLuRulesImporter.Problem.unsupported:
            detail = menuText("Automatic import requires the official LuLu 4.5.7 in Applications.",
                              "Для автоматического импорта нужна официальная LuLu 4.5.7 в папке «Программы».")
        case LuLuRulesImporter.Problem.profileChanged:
            detail = menuText("The active profile or its rules changed. Close the LuLu dialog and run setup again.",
                              "Профиль LuLu или его правила изменились. Закройте окно LuLu и повторите настройку.")
        case LuLuRulesImporter.Problem.verification:
            detail = menuText("ClaudeGuard could not verify the imported rules. Check LuLu's import result and try again.",
                              "Не удалось подтвердить импорт. Проверьте результат в LuLu и повторите настройку.")
        default:
            detail = menuText("Keep the LuLu menu bar icon visible and close other LuLu dialogs before trying again.",
                              "Проверьте, что значок LuLu виден в строке меню. Закройте открытые окна LuLu и повторите настройку.")
        }
        showMenuMessage(menuText("Could Not Set Up LuLu Rules", "Не удалось настроить правила LuLu"), detail)
    }

    @objc func onShowLuLuRules() {
        if let url = Bundle.main.url(forResource: "ClaudeGuard-LuLu-rules", withExtension: "json") {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    private func applyManagedSettings(_ arguments: [String], input: Data = Data(), routingOnly: Bool = false) {
        proxySettingsQueue.async {
            let task = Process()
            task.executableURL = runtimePython
            task.arguments = [Self.helperPath] + arguments
            let stdin = Pipe(), stderr = Pipe()
            task.standardInput = stdin
            task.standardError = stderr
            task.standardOutput = FileHandle.nullDevice
            var failure: String?
            do {
                try task.run()
                try stdin.fileHandleForWriting.write(contentsOf: input)
                try stdin.fileHandleForWriting.close()
                let output = stderr.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                if task.terminationStatus != 0 {
                    failure = String(data: output, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                        ?? "Could not save the settings."
                }
            } catch { failure = "Could not save the settings." }
            let message = failure
            DispatchQueue.main.async {
                if let message {
                    let alert = NSAlert()
                    alert.messageText = "Settings were not saved"
                    alert.informativeText = message
                    alert.runModal()
                    return
                }
                self.loadConfig()
                if !routingOnly {
                    _ = self.killDesktopIfRunning()
                    self.proxyVerifiedAt = 0
                    self.proxyProfileID = ""
                    self.state = .blocked(ip: "Unavailable")
                    self.writeStateFile()
                    self.reconcileManagedProxy()
                }
                self.rebuildMenu()
                self.recheckAsync()
                if routingOnly {
                    let alert = NSAlert()
                    alert.messageText = "macOS proxy settings saved"
                    alert.informativeText = "Reconnect Happ if macOS still uses the previous proxy configuration."
                    alert.runModal()
                }
            }
        }
    }

    @objc func onConfigureProxy() {
        guard let entered = promptText(title: "ClaudeGuard Proxy",
            prompt: "Enter proxy URL or outbound JSON. Leave empty to remove the profile:", value: currentProxyInput()) else { return }
        let exitIP: String
        if entered.isEmpty {
            exitIP = ""
        } else {
            guard let address = promptText(title: "ClaudeGuard Proxy Exit IP",
                prompt: "Enter the fixed public IPv4 of this proxy:", value: expectedExitIP) else { return }
            exitIP = address
        }
        proxySettingsQueue.async {
            let task = Process(); task.executableURL = runtimePython
            task.arguments = [NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath, "proxy_save", exitIP]
            let input = Pipe(); let errors = Pipe()
            task.standardInput = input; task.standardError = errors
            var failureMessage: String?
            do {
                try task.run()
                input.fileHandleForWriting.write(Data(entered.utf8))
                try input.fileHandleForWriting.close()
                let errorData = errors.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                if task.terminationStatus != 0 {
                    failureMessage = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                        ?? "Check the proxy URL or JSON profile."
                }
            } catch { failureMessage = "Could not save proxy settings. Please try again." }
            let message = failureMessage
            DispatchQueue.main.async {
                if let message = message {
                    let failure = NSAlert(); failure.messageText = "Proxy settings were not saved"
                    failure.informativeText = message
                    failure.runModal()
                    return
                }
                self.loadConfig()
                self.proxyEnabled = true; self.connectionMode = .proxy; self.proxyError = ""
                self.currentIP = "…"; self.proxyProfileID = ""; self.proxyVerifiedAt = 0
                self.state = entered.isEmpty && self.protectionEnabled ? .blocked(ip: "Unavailable") : .offline
                self.saveConfig(); self.writeStateFile(); self.lastAppliedDomainsBlocked = nil
                self.reconcileManagedProxy()
                self.rebuildMenu(); self.recheckAsync()
            }
        }
    }

    private let proxySettingsQueue = DispatchQueue(label: "com.claudeguard.proxy-settings", qos: .userInitiated)

    private func recheckAsync() {
        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }
    }

    @objc func onRecheck() {
        refreshLuLu(force: true)
        recheckAsync()
    }

    @objc func onToggleProtection() {
        protectionEnabled.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleModelOverride() {
        modelOverrideEnabled.toggle()
        saveConfig()
        rebuildMenu()
    }

    @objc func onChangeModel() {
        guard let entered = promptText(title: "ClaudeGuard Default Model",
            prompt: "Enter Claude model ID (e.g. claude-opus-4-8):", value: defaultModel), !entered.isEmpty else { return }
        defaultModel = entered
        saveConfig(); rebuildMenu()
    }

    func validWhitelistEntry(_ entry: String) -> Bool {
        let parts = entry.components(separatedBy: "/")
        guard parts.count <= 2, !parts[0].isEmpty,
              parts[0].utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...70).contains(byte)
                      || (97...102).contains(byte) || byte == 46 || byte == 58
              }) else { return false }
        // Darwin accepts leading-zero IPv4 octets; Python/root validation does not.
        if parts[0].contains(".") {
            let dotted = parts[0].components(separatedBy: ":").last!
            let octets = dotted.components(separatedBy: ".")
            guard octets.count == 4, octets.allSatisfy({
                !$0.isEmpty && ($0.count == 1 || !$0.hasPrefix("0"))
                    && $0.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
            }) else { return false }
        }
        var v4 = in_addr()
        var v6 = in6_addr()
        let maxPrefix: Int
        if inet_pton(AF_INET, parts[0], &v4) == 1 { maxPrefix = 32 }
        else if inet_pton(AF_INET6, parts[0], &v6) == 1 { maxPrefix = 128 }
        else { return false }
        if parts.count == 1 { return true }
        let prefix = parts[1]
        return !prefix.isEmpty && prefix.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
            && Int(prefix).map { $0 <= maxPrefix } == true
    }

    @objc func onAddCurrentIP() {
        if validWhitelistEntry(currentIP), !allowedIPs.contains(currentIP) {
            allowedIPs.append(currentIP)
            saveConfig()
            recheckAsync()
        }
    }

    @objc func onManageIPs() {
        guard let entered = promptText(title: "ClaudeGuard IP Whitelist",
            prompt: "Enter Whitelisted VPN IPs (comma separated):", value: allowedIPs.joined(separator: ", ")) else { return }
        let entries = entered.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? [] :
            entered.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard entries.allSatisfy({ validWhitelistEntry($0) }) else {
            let alert = NSAlert()
            alert.messageText = "Invalid IP/CIDR"
            alert.informativeText = "Enter IPv4/IPv6 addresses or CIDR ranges, separated by commas. No changes saved."
            alert.alertStyle = .warning
            alert.runModal()
            return
        }
        allowedIPs = entries
        saveConfig(); rebuildMenu(); recheckAsync()
    }

    @objc private func onDesktopUpdate() {
        guard updateActivity == .idle else { return }
        if let update = availableUpdate {
            offerDesktopUpdate(update)
        } else {
            checkForDesktopUpdate(interactive: true)
        }
    }

    private func checkForDesktopUpdate(interactive: Bool) {
        guard usesLuLu, let current = updateVersion, updateActivity == .idle else { return }
        let key = "LastDesktopUpdateCheck"
        let now = Date().timeIntervalSince1970
        let last = UserDefaults.standard.double(forKey: key)
        guard interactive || !(0..<86400).contains(now - last) else { return }
        UserDefaults.standard.set(now, forKey: key)
        updateActivity = .checking
        rebuildMenu()
        Task { @MainActor in
            do {
                let update = try await DesktopUpdater.findUpdate(after: current)
                self.updateActivity = .idle
                self.availableUpdate = update
                self.rebuildMenu()
                guard interactive else { return }
                if let update {
                    self.offerDesktopUpdate(update)
                } else {
                    self.showMenuMessage(self.menuText("ClaudeGuard Is Up to Date", "ClaudeGuard уже обновлён"),
                                           self.menuText("Version \(current) is installed.", "Установлена версия \(current)."))
                }
            } catch {
                self.updateActivity = .idle
                self.rebuildMenu()
                if interactive { self.showUpdateError(error) }
            }
        }
    }

    private func offerDesktopUpdate(_ update: DesktopUpdater.Update) {
        let alert = NSAlert()
        alert.messageText = menuText("ClaudeGuard \(update.version) Is Available", "Доступен ClaudeGuard \(update.version)")
        alert.informativeText = menuText("ClaudeGuard will verify the package from GitHub and open the macOS Installer for confirmation. Your settings will be kept.",
                                         "ClaudeGuard проверит пакет с GitHub и откроет установщик macOS. Твои настройки сохранятся.")
        alert.addButton(withTitle: menuText("Download and Open", "Скачать и открыть"))
        alert.addButton(withTitle: menuText("Later", "Позже"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        updateActivity = .downloading
        rebuildMenu()
        let cached = stagedUpdate?.update == update ? stagedUpdate?.package : nil
        Task { @MainActor in
            do {
                let package = try await DesktopUpdater.download(update, reusing: cached)
                self.stagedUpdate = (update, package)
                let installer = URL(fileURLWithPath: "/System/Library/CoreServices/Installer.app")
                _ = try await NSWorkspace.shared.open([package], withApplicationAt: installer, configuration: .init())
            } catch {
                self.showUpdateError(error)
            }
            self.updateActivity = .idle
            self.rebuildMenu()
        }
    }

    private func showUpdateError(_ error: Error) {
        let detail: String
        switch error {
        case DesktopUpdater.Failure.unverifiedRelease, DesktopUpdater.Failure.unverifiedPackage:
            detail = menuText("The installer could not be verified against the GitHub release.",
                              "Не удалось сверить установщик с релизом на GitHub.")
        default:
            detail = menuText("Check that GitHub is reachable and try again.", "Проверь доступ к GitHub и попробуй ещё раз.")
        }
        showMenuMessage(menuText("ClaudeGuard Update Failed", "Обновление ClaudeGuard не удалось"), detail)
    }

    private func showMenuMessage(_ title: String, _ detail: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = detail
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    @objc private func onMenuLanguage(_ sender: NSMenuItem) {
        guard let language = sender.representedObject as? String else { return }
        UserDefaults.standard.set(language, forKey: "MenuLanguage")
        russianMenu = language == "ru"
        rebuildMenu()
        updateStatusDisplay()
    }

    private var uninstallerURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/ClaudeGuard Uninstaller.app", isDirectory: true)
    }

    @objc private func onUninstall() {
        if !NSWorkspace.shared.open(uninstallerURL) {
            showMenuMessage(menuText("Could Not Open the Uninstaller", "Не удалось открыть деинсталлятор"),
                            menuText("Reinstall the Desktop package to repair the uninstaller.",
                                     "Переустановите пакет Desktop, чтобы восстановить деинсталлятор."))
        }
    }

    @objc func onQuit() { NSApplication.shared.terminate(nil) }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
