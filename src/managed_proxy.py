"""User-owned proxy transports. Nothing here executes with elevated privileges."""
from contextlib import closing
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from src.proxy_egress import validate_exit_ip

PORT = 17945
XRAY = "/Library/Application Support/ClaudeGuard/xray"


def ssh_profile(settings):
    host = settings["host"].strip().lower()
    user = settings["user"].strip()
    port = int(settings["port"])
    key = settings.get("identity", "").strip()
    fingerprint = settings["fingerprint"].strip()
    if (not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host)
            or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user)
            or not 1 <= port <= 65535):
        raise ValueError("Enter a valid IPv4 or hostname, SSH user, and port.")
    if key:
        key = str(Path(key).expanduser().absolute())
        if not Path(key).is_file():
            raise ValueError("The SSH identity file does not exist.")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise ValueError("Enter the server's SHA256 host-key fingerprint from a trusted source.")
    known_host = pinned_host_key(host, port, fingerprint)
    return {"kind": "ssh", "host": host, "user": user, "port": port, "identity": key,
            "fingerprint": fingerprint, "known_host": known_host}


def pinned_host_key(host, port, fingerprint):
    target = host if port == 22 else f"[{host}]:{port}"
    saved = subprocess.run(["/usr/bin/ssh-keygen", "-F", target], capture_output=True, text=True, timeout=2)
    entries = saved.stdout
    for source in ("saved", "server"):
        if source == "server":
            scanned = subprocess.run(["/usr/bin/ssh-keyscan", "-T", "4", "-p", str(port), host],
                                     capture_output=True, text=True, timeout=9)
            entries = scanned.stdout
        for line in entries.splitlines():
            fields = line.split()
            if len(fields) < 3 or not re.fullmatch(r"(?:ssh-|ecdsa-sha2-)[A-Za-z0-9-]+", fields[1]):
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[2]):
                continue
            verified = subprocess.run(["/usr/bin/ssh-keygen", "-lf", "-"], input=" ".join(fields[1:3]) + "\n",
                                      capture_output=True, text=True, timeout=2)
            if verified.returncode == 0 and fingerprint in verified.stdout.split():
                return f"{target} {fields[1]} {fields[2]}\n"
    raise ValueError("The SSH server did not present the expected host key.")


def ssh_command(profile, known_hosts):
    command = ["/usr/bin/ssh", "-4", "-F", "/dev/null", "-NT", "-D", f"127.0.0.1:{PORT}",
               "-p", str(profile["port"]), "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
               "-o", "ConnectTimeout=6", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
               "-o", "PasswordAuthentication=no", "-o", "UseKeychain=yes"]
    if profile.get("identity"):
        command.extend(["-o", "IdentitiesOnly=yes", "-i", profile["identity"]])
    return command + ["--", f'{profile["user"]}@{profile["host"]}']


def xray_profile(settings):
    url = urlsplit(settings["url"].strip())
    query = parse_qs(url.query, keep_blank_values=True)
    if (url.scheme != "vless" or url.password is not None or url.path not in ("", "/")
            or any(len(values) != 1 for values in query.values())):
        raise ValueError("Paste one VLESS/REALITY profile.")
    options = {key: values[0] for key, values in query.items()}
    if (set(options) - {"security", "encryption", "type", "sni", "fp", "pbk", "sid", "flow", "spx"}
            or options.get("security") != "reality" or options.get("type", "tcp") not in ("tcp", "raw")
            or options.get("encryption", "none") != "none"
            or options.get("flow", "") not in ("", "xtls-rprx-vision")):
        raise ValueError("This import supports TCP VLESS/REALITY profiles with Vision or no flow.")
    interface = settings.get("interface", "").strip()
    if interface:
        if not re.fullmatch(r"en[0-9]{1,3}", interface):
            raise ValueError("Enter a macOS Wi-Fi or Ethernet interface such as en0.")
        address = str(ipaddress.IPv4Address(settings["address"].strip()))
    else:
        address = url.hostname
    if not address or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", address):
        raise ValueError("Enter the VLESS server hostname or IPv4.")
    port = url.port or 443
    if not port or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", options["sni"]):
        raise ValueError("The VLESS port or REALITY server name is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", options["pbk"]) or not re.fullmatch(r"(?:[A-Fa-f0-9]{2}){0,8}", options["sid"]):
        raise ValueError("The REALITY public key or short ID is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", options.get("fp", "chrome")):
        raise ValueError("The REALITY fingerprint is invalid.")
    return {"kind": "xray", "host": address, "port": port, "uuid": str(UUID(url.username)),
            "flow": options.get("flow", ""), "sni": options["sni"], "fingerprint": options.get("fp", "chrome"),
            "public_key": options["pbk"], "short_id": options["sid"], "interface": interface,
            "spider_x": options.get("spx", "")}


def xray_config(profile):
    stream = {"network": "raw", "security": "reality",
              "realitySettings": {"serverName": profile["sni"], "fingerprint": profile["fingerprint"],
                                  "password": profile["public_key"], "shortId": profile["short_id"],
                                  "spiderX": profile.get("spider_x", "")}}
    if profile.get("interface"):
        stream["sockopt"] = {"interface": profile["interface"]}
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": PORT, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "streamSettings": stream, "settings": {"vnext": [
                {"address": profile["host"], "port": profile["port"],
                 "users": [{"id": profile["uuid"], "flow": profile["flow"], "encryption": "none"}]}]}}]}


def save(config, kind, settings):
    expected = validate_exit_ip(settings.get("exit_ip"))
    profile = ssh_profile(settings) if kind == "ssh" else xray_profile(settings)
    profile["generation"] = uuid4().hex
    config.config.update(managed_proxy=profile, expected_exit_ip=expected, proxy_enabled=True,
                         connection_mode="proxy", proxy_profile={"type": "socks", "version": "5",
                                                                "server": "127.0.0.1", "server_port": PORT})
    config.save_config()


def private_write(path, content):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(config, generation):
    profile = config.config.get("managed_proxy")
    if (not isinstance(profile, dict) or profile.get("generation") != generation
            or config.config.get("connection_mode") != "proxy" or not config.protection_enabled
            or not config.config.get("proxy_enabled")):
        raise ValueError("The managed proxy is paused or its settings changed.")
    directory = Path(config.path).parent
    # The lock spans both the listener check and the child lifecycle. Xray
    # permits SO_REUSEPORT, so a successful child start alone proves nothing
    # about which transport owns the traffic.
    descriptor = os.open(directory / "managed_transport.lock",
                         os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "rb"):
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", PORT))
        if profile["kind"] == "ssh":
            known_hosts = directory / "managed_known_hosts"
            private_write(known_hosts, profile["known_host"])
            command = ssh_command(profile, known_hosts)
        elif profile["kind"] == "xray":
            path = directory / "managed_xray.json"
            private_write(path, json.dumps(xray_config(profile)))
            command = [XRAY, "run", "-c", str(path)]
        else:
            raise ValueError("Unsupported managed proxy.")
        supervise(command, os.getppid(), descriptor)


def supervise(command, parent, lock_descriptor):
    if parent <= 1:
        return
    exit_flags = select.KQ_EV_ADD | select.KQ_EV_ONESHOT

    def watch(queue, pid):
        queue.control([select.kevent(pid, filter=select.KQ_FILTER_PROC, flags=exit_flags,
                                     fflags=select.KQ_NOTE_EXIT)], 0, 0)

    def interrupted(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, interrupted)
    with closing(select.kqueue()) as queue:
        watch(queue, parent)
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, pass_fds=(lock_descriptor,))
        try:
            watch(queue, child.pid)
            deadline = time.monotonic() + 9
            while time.monotonic() < deadline:
                events = queue.control(None, 2, 0.15)
                if events:
                    return
                try:
                    with socket.create_connection(("127.0.0.1", PORT), timeout=0.15):
                        break
                except OSError:
                    continue
            else:
                raise RuntimeError("The managed proxy did not open its local listener.")
            print("ready", flush=True)
            queue.control(None, 2)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
