"""
The brain: the one place that decides "may Claude run right now".

Verdict: "allowed" (protection off, or IP whitelisted) / "blocked" (online, IP
not whitelisted) / "offline" (IP can't be verified). Fail closed — only a
confirmed "allowed" gets through.

Proxy mode requires a matching, fresh IPv4 proof from the daemon. Launchers
also probe the live listener. Only VPN mode can use a local STUN-first fallback.
"""
import json
import os
import time

from src.ip_checker import perform_ip_check

STATE_PATH = os.path.expanduser("~/.config/claudeguard/state.json")
# The daemon rewrites state.json at least every 3s; 7s tolerates one missed tick.
STATE_MAX_AGE_SECONDS = 7.0


def read_daemon_state(max_age=STATE_MAX_AGE_SECONDS):
    """The daemon's state dict while it's fresh, or None if missing/stale."""
    try:
        with open(STATE_PATH) as f:
            d = json.load(f)
        if is_fresh(d.get("updated_at"), max_age):
            return d
    except Exception:
        pass
    return None


def is_fresh(timestamp, max_age=STATE_MAX_AGE_SECONDS):
    return type(timestamp) in (int, float) and 0 <= time.time() - timestamp <= max_age


def daemon_is_up():
    """True if the daemon is running and publishing fresh state."""
    return read_daemon_state() is not None


def get_verdict(config, timeout=2.0, allow_fallback=True, verify_proxy=False):
    """
    Returns (verdict, ip, err), verdict ∈ "allowed"/"blocked"/"offline".

    Order: protection off → allowed; the daemon's verdict (instant); else, when
    allow_fallback, our own STUN-first check. allow_fallback=False returns
    "offline" while the daemon is down in VPN mode. verify_proxy checks the
    live listener before starting a new process.
    """
    if not config.protection_enabled:
        return "allowed", None, None

    if config.config.get("connection_mode", "vpn") == "proxy":
        if not config.config.get("proxy_profile"):
            return "blocked", None, "Proxy is not configured"
        from src.proxy import profile_id, probe
        from src.proxy_egress import validate_exit_ip
        try:
            expected = validate_exit_ip(config.config.get("expected_exit_ip"))
        except ValueError as error:
            return "blocked", None, str(error)
        st = read_daemon_state()
        if (not st or st.get("mode") != "proxy" or st.get("proxy_profile_id") != profile_id(config)
                or not config.config.get("proxy_enabled", True)):
            return "blocked", None, "Proxy is disconnected or not verified"
        if st.get("enforcement_error") or st.get("state") != "allowed":
            return "blocked", st.get("ip"), st.get("enforcement_error") or "Proxy unavailable"
        if st.get("ip") != expected or not is_fresh(st.get("proxy_verified_at")):
            return "blocked", st.get("ip"), "Proxy exit IPv4 is different or its verification has expired"
        if verify_proxy:
            try:
                probe(expected, timeout=timeout)
            except RuntimeError as error:
                return "blocked", None, str(error)
        return "allowed", expected, None

    st = read_daemon_state()
    if st is not None and st.get("mode", "vpn") == "vpn":
        if st.get("enforcement_error"):
            verdict = "blocked" if st.get("state") == "blocked" else "offline"
            return verdict, st.get("ip"), st["enforcement_error"]
        v = st.get("state", "offline")
        if v == "disabled":  # the daemon has its own vocabulary; normalise it
            return "allowed", st.get("ip"), None
        return v, st.get("ip"), None

    if not allow_fallback:
        return "offline", None, "ClaudeGuard daemon not running"

    ip, is_allowed, err = perform_ip_check(config.allowed_ips, timeout=timeout)
    if ip is None:
        return "offline", None, err
    return ("allowed" if is_allowed else "blocked"), ip, err


def resolve_display_ip(config, timeout=2.0):
    """The current public IP for display only, never for a decision. Prefers the
    daemon's last known IP, else a live STUN-first lookup. IP string or None."""
    st = read_daemon_state()
    if st is not None:
        ip = st.get("ip")
        if ip and ip not in ("No Internet", "…"):
            return ip
    try:
        from src.ip_checker import fetch_public_ip
        ip, _ = fetch_public_ip(timeout=timeout)
        return ip
    except Exception:
        return None
