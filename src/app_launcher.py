#!/usr/bin/env python3
import sys
import os
import json
import time
from pathlib import Path
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.brain import get_verdict
from src.integrity import discover_desktop_app
from src.lulu import filter_is_active, has_desktop_policy
from src.network_guard import sync_hosts_file

def launch_claude_desktop():
    config = ConfigManager()

    directory = Path(config.path).parent
    isolated = (directory / "desktop-filter-required").exists()
    uses_lulu = config.config.get("desktop_firewall") == "lulu"
    if uses_lulu and not lulu_ready(config):
        show_mac_alert("ClaudeGuard Protection", "Enable LuLu, import the ClaudeGuard rules, then enable Proxy mode before opening Claude Desktop.")
        sys.exit(1)
    if isolated and not isolation_configured(config, directory):
        show_mac_alert("ClaudeGuard Protection", "Allow the Desktop network filter and enable Proxy mode before opening Claude.")
        sys.exit(1)

    if not config.protection_enabled:
        open_real_app(config)
        return

    if config.config.get("connection_mode", "vpn") == "vpn" and not config.allowed_ips:
        show_mac_alert(
            "ClaudeGuard Protection 🚫",
            "Access to Claude Desktop blocked.\n\nReason: No allowed VPN IPs configured in whitelist.\n\nUse 'claudeguard add-ip <IP>' to configure."
        )
        sys.exit(1)

    # Fail closed — only "allowed" launches; "blocked"/"offline" both refuse.
    verdict, ip, err = get_verdict(config, timeout=2.0, verify_proxy=True)

    if verdict != "allowed":
        if config.config.get("connection_mode") == "proxy":
            show_mac_alert("ClaudeGuard Protection", err or "Proxy unavailable. Check Configure Proxy.")
        elif verdict == "offline":
            show_mac_alert(
                "ClaudeGuard Protection 🚫",
                "Access to Claude Desktop BLOCKED.\n\nNo internet connection — your IP can't be verified.\n\nExecution cancelled to prevent region ban."
            )
        else:
            ip_str = ip if ip else "Unknown"
            err_msg = f"\nError: {err}" if err else ""
            show_mac_alert(
                "ClaudeGuard Protection 🚫",
                f"Access to Claude Desktop BLOCKED.\n\nCurrent Public IP: {ip_str}\nStatus: NOT IN ALLOWED VPN WHITELIST{err_msg}\n\nExecution cancelled to prevent region ban."
            )
        sys.exit(1)

    # IP is valid! Unblock domain and start app
    ok, message = (True, "") if config.config.get("connection_mode") == "proxy" else sync_hosts_file(block_claude_domains=False, config=config)
    if not ok:
        print(message, file=sys.stderr)
        show_mac_alert("ClaudeGuard Error", "Network protection could not be updated. See the helper logs.")
        sys.exit(1)
    if isolated:
        # Recheck after the network probe so a settings change can't approve
        # an isolated launch using an older status.
        if not isolation_configured(config, directory):
            show_mac_alert("ClaudeGuard Protection", "Desktop network filter status changed during verification.")
            sys.exit(1)
        launch_isolated_desktop()
    elif uses_lulu:
        # Reject an unverified launch if LuLu changed while the proxy was probed.
        if not lulu_ready(config):
            show_mac_alert("ClaudeGuard Protection", "LuLu status changed during proxy verification.")
            sys.exit(1)
        launch_isolated_desktop(config.config.get("desktop_pac_url"))
    else:
        open_real_app(config)


def isolation_configured(config, directory):
    if not config.protection_enabled or config.config.get("connection_mode") != "proxy":
        return False
    if not (directory / "desktop-filter-required").exists():
        return False
    try:
        proof = json.loads((directory / "desktop-filter-status.json").read_text())
        checked = proof.get("verified_at")
        return type(checked) in (int, float) and 0 <= time.time() - checked <= 8
    except (OSError, ValueError, AttributeError):
        return False


def lulu_ready(config):
    """Require the registered LuLu extension and its saved Desktop policy."""
    if not config.protection_enabled or config.config.get("connection_mode") != "proxy":
        return False
    return has_desktop_policy() and filter_is_active()


def launch_isolated_desktop(pac_url=None):
    from src.proxy_config import PORT
    app = "/Applications/Claude.app"
    requirement = ('identifier "com.anthropic.claudefordesktop" and anchor apple generic '
                   'and certificate leaf[subject.OU] = Q6L2SF6YDW')
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--deep",
                               "-R", "=" + requirement, app], capture_output=True)
    if verified.returncode:
        show_mac_alert("ClaudeGuard Protection", "The Anthropic signature of /Applications/Claude.app could not be verified.")
        sys.exit(1)
    command = ["/usr/bin/open", "-a", app]
    if pac_url is None:
        # Legacy launches need startup switches. With PAC the normal open
        # action may bring an existing Claude window to the front.
        running = subprocess.run(["/usr/bin/pgrep", "-x", "Claude"], capture_output=True)
        if running.returncode != 1:
            show_mac_alert("ClaudeGuard Protection", "Quit Claude Desktop before restarting it through the proxy.")
            sys.exit(1)
        command.extend(["--args", f"--proxy-server=http://127.0.0.1:{PORT}",
                        "--host-resolver-rules=MAP * ~NOTFOUND", "--dns-prefetch-disable"])
    elif not system_pac_matches(pac_url):
        show_mac_alert("ClaudeGuard Protection", "The configured macOS proxy auto-configuration is inactive. Check your network proxy settings.")
        sys.exit(1)
    subprocess.run(command, check=True)


def system_pac_matches(expected_url):
    if not isinstance(expected_url, str) or not expected_url.startswith("data:"):
        return False
    try:
        result = subprocess.run(["/usr/sbin/scutil", "--proxy"], capture_output=True, text=True,
                                timeout=3, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    lines = result.stdout.splitlines()
    return ("  ProxyAutoConfigEnable : 1" in lines
            and f"  ProxyAutoConfigURLString : {expected_url}" in lines)


def open_real_app(config):
    # Re-discover if the recorded location is stale (app moved or reinstalled).
    app_path = config.real_claude_app
    if not os.path.exists(app_path):
        app_path = discover_desktop_app(config)
        if app_path:
            config.config["real_claude_app_path"] = app_path
            config.save_config()

    if app_path and os.path.exists(app_path):
        subprocess.run(["open", "-a", app_path], check=False)
    else:
        show_mac_alert("ClaudeGuard Error", "Claude Desktop app not found. Run 'claudeguard doctor'.")

def show_mac_alert(title, message):
    script = 'on run argv\n    display alert (item 1 of argv) message (item 2 of argv) as critical\nend run'
    subprocess.run(["osascript", "-e", script, "--", title, message], check=False)

if __name__ == "__main__":
    launch_claude_desktop()
