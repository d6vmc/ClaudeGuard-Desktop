#!/usr/bin/env python3
"""Compile and exercise the flow policy without loading a system extension."""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "src/desktop_filter/DesktopPolicy.swift"
test = """
import Foundation
import Network

let policy = ClaudeDesktopPolicy.self
let team = "Q6L2SF6YDW"
let desktop = "com.anthropic.claudefordesktop"
precondition(policy.identifies(team: team, identifier: desktop, executable: nil))
precondition(policy.identifies(team: team, identifier: desktop + ".helper", executable: nil))
precondition(policy.identifies(team: team, identifier: "com.anthropic.claude.ios-sim",
    executable: "/Applications/Claude.app/Contents/Helpers/Claude iOS Sim.app/Contents/MacOS/Claude iOS Sim"))
precondition(!policy.identifies(team: "another-team", identifier: desktop, executable: nil))
precondition(!policy.identifies(team: team, identifier: "claude", executable: "/opt/homebrew/bin/claude"))
precondition(!policy.identifies(team: nil, identifier: nil, executable: nil))

let bridge = NWEndpoint.hostPort(host: "127.0.0.1", port: 17943)
precondition(policy.allows(endpoint: bridge, outgoingTCP: true))
// Network.framework canonicalizes IPv4-mapped literals to their IPv4 peer.
precondition(policy.allows(endpoint: .hostPort(host: "::ffff:127.0.0.1", port: 17943), outgoingTCP: true))
precondition(!policy.allows(endpoint: bridge, outgoingTCP: false))
precondition(!policy.allows(endpoint: nil, outgoingTCP: true))
for host in ["127.0.0.2", "::1", "::ffff:127.0.0.2", "192.0.2.4", "2001:db8::123", "api.anthropic.com"] {
    precondition(!policy.allows(endpoint: .hostPort(host: NWEndpoint.Host(host), port: 17943), outgoingTCP: true), host)
}
for port: NWEndpoint.Port in [53, 443, 8080, 17944] {
    precondition(!policy.allows(endpoint: .hostPort(host: "127.0.0.1", port: port), outgoingTCP: true))
}
if let path = CommandLine.arguments.dropFirst().first {
    try policy.verify(URL(fileURLWithPath: path))
}
print("PASS: signed Desktop identity and proxy-only socket policy")
"""
with tempfile.TemporaryDirectory(prefix="cg-desktop-filter-") as directory:
    path = Path(directory)
    (path / "main.swift").write_text(test)
    subprocess.run(["xcrun", "swiftc", "-module-cache-path", str(path / "modules"),
                    str(source), str(path / "main.swift"), "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check"), *sys.argv[1:]], check=True)
