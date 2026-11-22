#!/usr/bin/env python3
"""Native regression of real menu mode handling; no UI or real settings touched."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/main.swift').read_text().split('let app = NSApplication.shared\n')[0]
source = source.replace(
    'let configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath',
    'var configPath = ""')
harness = r'''
final class ModeHarness: AppDelegate {
    var changeModeDuringProbe = false
    var proofAge: TimeInterval = 0
    var reportedIP = "93.184.216.34"
    var syncCalls = 0
    var probeCalls = 0
    var syncArguments: [String] = []
    var failAllow = false
    var activePAC = true
    override func systemPACMatches(_ expected: String) -> Bool { activePAC }
    override func resolvePublicIPWithRetry(attempts: Int = 2, deadline: TimeInterval = 2.0) -> String? {
        precondition(syncArguments.last == "true", "VPN must be blocked before first IP lookup")
        return "192.0.2.1"
    }
    override func killDesktopIfRunning() -> Bool { false }
    override func checkProxy() -> (ip: String?, error: String, profileID: String, verifiedAt: TimeInterval) {
        probeCalls += 1
        if changeModeDuringProbe { onModeChanged(.vpn) }
        if proxyEndpoint == "Not configured" { return (nil, "Proxy is not configured", "", 0) }
        return (reportedIP, "", "test-profile", Date().timeIntervalSince1970 - proofAge)
    }
    override func runHelper(_ command: String, _ a1: String, _ a2: String) -> Bool {
        syncCalls += 1
        syncArguments.append(a1)
        return !(failAllow && a1 == "false")
    }
    override func hostsDrifted() -> Bool { false }
    override func writeStateFile() {}
    override func rebuildMenu() {}
    override func updateStatusDisplay(isDimmed: Bool = false) {}
    override func startBlinking() {}
    override func recheck() {}
}
let check = ModeHarness()
for entry in ["192.0.2.1", "192.0.2.1/24", "0.0.0.0/0", "2001:db8::1", "2001:db8::1/64", "::/0", "::1/128"] {
    precondition(check.validWhitelistEntry(entry), entry)
}
for entry in ["", "example.com", "999.1.1.1", "127.1", "01.2.3.4", "192.0.2.1/33", "::1/129", "::1/-1", "::1/", "::1/1/2", "fe80::1%en0", "192.0.2.1/255.255.255.0"] {
    precondition(!check.validWhitelistEntry(entry), entry)
}
check.configPath = CommandLine.arguments[1]
let initial: [String: Any] = ["expected_exit_ip": "93.184.216.34", "proxy_profile": ["type": "http", "server": "localhost", "server_port": 3128]]
try! JSONSerialization.data(withJSONObject: initial).write(to: URL(fileURLWithPath: check.configPath))
check.connectionMode = .proxy
check.currentIP = "192.0.2.2"
check.proxyProfileID = "old-profile"
check.saveConfig()
precondition((try! FileManager.default.attributesOfItem(atPath: check.configPath)[.posixPermissions] as! NSNumber).intValue == 0o600)
precondition((try! FileManager.default.attributesOfItem(atPath: (check.configPath as NSString).deletingLastPathComponent)[.posixPermissions] as! NSNumber).intValue == 0o700)
check.onModeChanged(.vpn)
precondition(check.currentIP == "…" && check.proxyProfileID.isEmpty)
precondition(check.state == .offline)

check.connectionMode = .proxy
check.saveConfig()
check.changeModeDuringProbe = true
check.performCheck()
precondition(check.connectionMode == .vpn && check.currentIP == "…")
precondition(check.proxyProfileID.isEmpty && check.state == .offline)
precondition(check.syncCalls == 0)

check.changeModeDuringProbe = false
check.connectionMode = .proxy
check.saveConfig()
check.performCheck()
precondition(check.currentIP == "93.184.216.34")
precondition(check.state == .allowed(ip: "93.184.216.34"))
precondition(check.syncCalls == 0, "The proxy helper owns enforcement")

check.proofAge = 8
check.performCheck()
precondition(check.state == .blocked(ip: "Unavailable"))
check.proofAge = 0
check.reportedIP = "93.184.216.35"
check.performCheck()
precondition(check.state == .blocked(ip: "Unavailable"))
let calls = check.probeCalls
try! JSONSerialization.data(withJSONObject: ["connection_mode": "proxy", "protection_enabled": true]).write(to: URL(fileURLWithPath: check.configPath))
check.performCheck()
precondition(check.probeCalls == calls + 1, "The proxy helper must enforce a missing profile")
precondition(check.state == .blocked(ip: "Unavailable"))
precondition(check.menuStatus().health == .blocked)
precondition(check.syncCalls == 0, "Generic sync must never reopen a denied proxy")
check.connectionMode = .vpn
check.allowedIPs = ["192.0.2.1"]
check.saveConfig()
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.state == .allowed(ip: "192.0.2.1"))
precondition(Array(check.syncArguments.suffix(2)) == ["true", "false"])
check.failAllow = true
check.lastAppliedDomainsBlocked = nil
check.performCheck()
precondition(check.state == .blocked(ip: "192.0.2.1"))
precondition(check.menuStatus().health == .blocked)
print("PASS: mode reset, expired and different proxy proof denied, VPN enforcement")

check.usesLuLu = true
check.desktopPACURL = "data:test"
check.menuIsOpen = true
check.connectionMode = .proxy
check.proxyEndpoint = "Configured"
check.enforcementError = nil
check.expectedExitIP = "93.184.216.34"
check.currentIP = check.expectedExitIP
check.state = .allowed(ip: check.currentIP)
check.proxyVerifiedAt = Date().timeIntervalSince1970
precondition(check.desktopLaunchBlockReason() == nil, "Dock launch can use the verified PAC")
precondition(check.menuStatus().health == .ready)
check.activePAC = false
precondition(check.desktopLaunchBlockReason() != nil, "A different macOS PAC must block a Dock launch")
precondition(check.menuStatus().health == .blocked)
check.activePAC = true
check.proxyVerifiedAt -= 8
precondition(check.desktopLaunchBlockReason() != nil, "An expired proxy proof must block a Dock launch")
precondition(check.menuStatus().health == .checking)
check.proxyVerifiedAt = Date().timeIntervalSince1970
check.proxyEnabled = false
precondition(check.desktopLaunchBlockReason() != nil, "Disconnecting the proxy must block a Dock launch")
check.proxyEnabled = true
check.currentIP = "93.184.216.35"
precondition(check.desktopLaunchBlockReason() != nil, "A different egress must block a Dock launch")
print("PASS: normal Desktop launch checks active PAC and a fresh, matching proxy proof")

let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
func release(_ tag: String, draft: Bool = false, digest: String? = "sha256:\(abcHash)", foreign: Bool = false) -> DesktopUpdater.Release {
    DesktopUpdater.Release(tag_name: tag, draft: draft, assets: [.init(name: "ClaudeGuard-Desktop.pkg", state: "uploaded",
        size: 3, digest: digest, browser_download_url: foreign ? "https://example.org/package.pkg" :
            "https://github.com/d6vmc/ClaudeGuard-Desktop/releases/download/\(tag)/ClaudeGuard-Desktop.pkg")])
}
let current = DesktopUpdater.Version("2.9.9")!
let releases = [release("v2.10.0-desktop"), release("v3.0.0"), release("v2.9.10-desktop"),
                release("v2.10.0-desktop.2"), release("v4.0.0-desktop", draft: true)]
let update = try! DesktopUpdater.newestUpdate(in: releases, after: current)!
precondition(update.url.path.contains("v2.10.0-desktop.2"))
precondition(try! DesktopUpdater.newestUpdate(in: releases, after: update.version) == nil)
precondition(try! DesktopUpdater.newestUpdate(in: [release("v2.0.0-desktop")], after: current) == nil)
for invalid in [release("v2.10.1-desktop", digest: nil), release("v2.10.1-desktop", foreign: true)] {
    do {
        _ = try DesktopUpdater.newestUpdate(in: [invalid], after: current)
        preconditionFailure("Unverified release metadata must be rejected")
    } catch DesktopUpdater.Failure.unverifiedRelease {}
}
precondition(!DesktopUpdater.isOfficialURL(URL(string: "http://github.com/package.pkg")!))
precondition(!DesktopUpdater.isOfficialURL(URL(string: "https://github.com.example.org/package.pkg")!))
let staged = URL(fileURLWithPath: check.configPath).deletingLastPathComponent().appendingPathComponent("update.pkg")
try! Data("abc".utf8).write(to: staged)
try! DesktopUpdater.verify(staged, for: update)
try! Data("abd".utf8).write(to: staged)
do {
    try DesktopUpdater.verify(staged, for: update)
    preconditionFailure("A modified download must be rejected")
} catch DesktopUpdater.Failure.unverifiedPackage {}
print("PASS: Desktop updater selects newer releases and rejects unverified metadata and package contents")

func waitFor(_ seconds: TimeInterval, _ test: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    repeat {
        if test() { return true }
        RunLoop.main.run(until: Date().addingTimeInterval(0.025))
    } while Date() < deadline
    return false
}
var interruptions = 0
private let supervisor = ManagedProxySupervisor(helper: CommandLine.arguments[2]) { interruptions += 1 }
supervisor.update("test-generation")
precondition(waitFor(2) { supervisor.process(for: "test-generation") != nil })
let first = supervisor.process(for: "test-generation")
precondition(first != nil, "A selected proxy starts without a terminal")
precondition(waitFor(2) { interruptions == 1 }, "The supervisor must report a terminated process")
supervisor.update("test-generation")
precondition(supervisor.process(for: "test-generation") == nil, "Retries must respect backoff")
precondition(waitFor(4) {
    supervisor.update("test-generation")
    guard let next = supervisor.process(for: "test-generation") else { return false }
    return next !== first
}, "The supervisor must launch a new proxy process after backoff")
supervisor.update(nil)
precondition(supervisor.process(for: "test-generation") == nil, "Pausing invalidates the running connection")
precondition(interruptions == 1, "A pause is not an unexpected interruption")
print("PASS: managed proxy exit, retry backoff, restart and pause")
'''
with tempfile.TemporaryDirectory(prefix='cg-menu-mode-') as directory:
    path = Path(directory)
    (path / 'main.swift').write_text(source + harness)
    (path / 'transport.py').write_text(
        'from pathlib import Path\n'
        'import time\n'
        'marker = Path(__file__).with_suffix(".started")\n'
        'print("ready", flush=True)\n'
        'if not marker.exists():\n'
        '    marker.touch()\n'
        '    time.sleep(0.4)\n'
        'else:\n'
        '    time.sleep(5)\n'
    )
    subprocess.run(['xcrun', 'swiftc', '-module-cache-path', str(path / 'modules'),
                    str(path / 'main.swift'), str(root / 'src/ModeSegmentedControl.swift'),
                    str(root / 'src/DesktopUpdater.swift'),
                    str(root / 'src/LuLuRulesImporter.swift'),
                    '-o', str(path / 'check')], check=True)
    subprocess.run([str(path / 'check'), str(path / 'config.json'), str(path / 'transport.py')], check=True)
