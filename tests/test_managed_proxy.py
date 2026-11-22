import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import managed_proxy, proxy
from src.config import ConfigManager


class ManagedProxyTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "requires macOS process events")
    def test_transport_is_reaped_after_application_exit(self):
        payload = ("import socket, sys, time; "
                   "s=socket.socket(); s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(); "
                   "open(sys.argv[2], 'w').write(str(__import__('os').getpid())); time.sleep(20)")
        watcher = '''
import os, sys
from src import managed_proxy
managed_proxy.PORT = int(sys.argv[1])
with open(sys.argv[2], "wb") as lock:
    managed_proxy.supervise([sys.executable, "-c", sys.argv[3], sys.argv[1], sys.argv[4]], os.getppid(), lock.fileno())
'''
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "transport.pid"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            # The real GUI is replaced by an expendable parent process.
            parent = subprocess.Popen(
                [sys.executable, "-c", "import subprocess, sys; sys.exit(subprocess.call(sys.argv[1:]))",
                 sys.executable, "-c", watcher, str(port), str(Path(directory) / "lock"), payload, str(marker)],
                stdout=subprocess.PIPE, text=True, cwd=Path(__file__).resolve().parents[1],
            )
            try:
                self.assertTrue(select.select([parent.stdout], [], [], 5)[0])
                self.assertEqual(parent.stdout.readline().strip(), "ready")
                parent.kill()
                parent.wait(timeout=2)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            pass
                    except ConnectionRefusedError:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("The listener is still accepting connections after its parent exited")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=2)
                parent.stdout.close()
                if marker.exists():
                    try:
                        os.kill(int(marker.read_text()), signal.SIGTERM)
                    except ProcessLookupError:
                        pass

    def test_only_verified_ssh_host_key_can_be_pinned(self):
        host = "proxy.example"
        fingerprint = "SHA256:" + "A" * 43
        candidate = f"[{host}]:2222 ssh-ed25519 Zm9vYg==\n"
        with patch.object(managed_proxy.subprocess, "run", side_effect=[
            SimpleNamespace(stdout=""), SimpleNamespace(stdout=candidate),
            SimpleNamespace(returncode=0, stdout=f"256 {fingerprint} (ED25519)"),
        ]):
            self.assertEqual(managed_proxy.pinned_host_key(host, 2222, fingerprint), candidate)
        with patch.object(managed_proxy.subprocess, "run", side_effect=[
            SimpleNamespace(stdout=""), SimpleNamespace(stdout=candidate),
            SimpleNamespace(returncode=0, stdout="256 SHA256:invalid (ED25519)"),
        ]):
            with self.assertRaisesRegex(ValueError, "expected host key"):
                managed_proxy.pinned_host_key(host, 2222, fingerprint)

    def test_ssh_never_inherits_config_or_accepts_unknown_hosts(self):
        command = managed_proxy.ssh_command(
            {"host": "proxy.example", "user": "alice", "port": 2222, "identity": "/tmp/SSH Key"},
            "/tmp/known_hosts")
        for argument in ("BatchMode=yes", "StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes",
                         "127.0.0.1:17945", "/dev/null", "/tmp/SSH Key"):
            self.assertIn(argument, command)
        self.assertEqual(command[-2:], ["--", "alice@proxy.example"])

    def test_switching_managed_profile_expires_proof_even_with_same_exit_and_port(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / "config.json"))
            settings = {"exit_ip": "93.184.216.34", "host": "proxy.example",
                        "user": "alice", "port": "2222", "fingerprint": "SHA256:" + "A" * 43}
            with patch.object(managed_proxy, "pinned_host_key", return_value="host ssh-ed25519 KEY\n"):
                managed_proxy.save(config, "ssh", settings)
                original = proxy.profile_id(config)
                old_generation = config.config["managed_proxy"]["generation"]
                managed_proxy.save(config, "ssh", settings)
            self.assertNotEqual(original, proxy.profile_id(config))
            with patch.object(managed_proxy.os, "execv") as launch:
                with self.assertRaises(ValueError):
                    managed_proxy.run(config, old_generation)
                config.config["proxy_enabled"] = False
                with self.assertRaises(ValueError):
                    managed_proxy.run(config, config.config["managed_proxy"]["generation"])
                launch.assert_not_called()
            proxy.save_profile(config, "socks5://localhost:1080")
            self.assertNotIn("managed_proxy", config.config)

    def test_reality_import_has_single_outbound_and_loopback_listener(self):
        url = ("vless://11111111-1111-4111-8111-111111111111@proxy.example:8443?"
               "security=reality&type=tcp&flow=xtls-rprx-vision&sni=proxy.example&fp=firefox&sid=0000&pbk=" + "A" * 43)
        profile = managed_proxy.xray_profile({"url": url, "interface": "en0", "address": "192.0.2.10"})
        config = managed_proxy.xray_config(profile)
        self.assertEqual(config["outbounds"][0]["streamSettings"]["sockopt"]["interface"], "en0")
        self.assertEqual(config["outbounds"][0]["settings"]["vnext"][0]["address"], "192.0.2.10")
        self.assertEqual(len(config["outbounds"]), 1)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertFalse(config["inbounds"][0]["settings"]["udp"])
        with self.assertRaises(ValueError):
            managed_proxy.xray_profile({"url": url.replace("type=tcp", "type=xhttp")})
