"""Alert text is data, never executable AppleScript. No apps are launched."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import app_launcher


class AlertTests(unittest.TestCase):
    def test_untrusted_text_is_passed_as_arguments(self):
        script = 'on run argv\n    display alert (item 1 of argv) message (item 2 of argv) as critical\nend run'
        cases = [
            ('ClaudeGuard', 'Обычная ошибка 🚫'),
            ('--title', '-e'),
            ('Title "quoted"', '"\ndo shell script "echo injected"\n--'),
            ('', 'Backslash \\ and newline\nsecond line'),
        ]
        for title, message in cases:
            with self.subTest(title=title, message=message), \
                    patch.object(app_launcher.subprocess, 'run') as run:
                app_launcher.show_mac_alert(title, message)
                run.assert_called_once_with(
                    ['osascript', '-e', script, '--', title, message], check=False)


class DesktopFilterLaunchTests(unittest.TestCase):
    def test_required_filter_without_fresh_configuration_blocks_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "desktop-filter-required").touch()
            config = SimpleNamespace(path=str(path / "config.json"), protection_enabled=True,
                                     config={"connection_mode": "proxy"})
            for proof in (None, 0, time.time() + 20):
                with self.subTest(proof=proof), patch.object(app_launcher, "ConfigManager", return_value=config), \
                        patch.object(app_launcher, "show_mac_alert"), patch.object(app_launcher, "get_verdict") as verdict, \
                        patch.object(app_launcher, "open_real_app") as launch:
                    if proof is not None:
                        (path / "desktop-filter-status.json").write_text(json.dumps({"verified_at": proof}))
                    with self.assertRaises(SystemExit):
                        app_launcher.launch_claude_desktop()
                    verdict.assert_not_called()
                    launch.assert_not_called()

    def test_verified_filter_launch_uses_the_isolated_entry_point(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "desktop-filter-required").touch()
            (path / "desktop-filter-status.json").write_text(json.dumps({"verified_at": time.time()}))
            config = SimpleNamespace(path=str(path / "config.json"), protection_enabled=True,
                                     config={"connection_mode": "proxy"})
            with patch.object(app_launcher, "ConfigManager", return_value=config), \
                    patch.object(app_launcher, "get_verdict", return_value=("allowed", "93.184.216.34", None)), \
                    patch.object(app_launcher, "launch_isolated_desktop") as launch, \
                    patch.object(app_launcher, "open_real_app") as ordinary:
                app_launcher.launch_claude_desktop()
                launch.assert_called_once_with()
                ordinary.assert_not_called()

    def test_invalid_desktop_signature_blocks_proxy_launch(self):
        with patch.object(app_launcher.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as run, \
                patch.object(app_launcher, "show_mac_alert"):
            with self.assertRaises(SystemExit):
                app_launcher.launch_isolated_desktop()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][0], "/usr/bin/codesign")


class LuLuDesktopLaunchTests(unittest.TestCase):
    @patch.object(app_launcher, "has_desktop_policy", return_value=True)
    def test_only_approved_lulu_extension_allows_proxy_preflight(self, _policy):
        config = SimpleNamespace(protection_enabled=True, config={"connection_mode": "proxy"})
        active = '* * VBG97UB4TA com.objective-see.lulu.extension (4.5.7/4.5.7) LuLu [activated enabled]'
        process = "0 /Library/SystemExtensions/12345678-0000-0000-0000-000000000000/com.objective-see.lulu.extension.systemextension/Contents/MacOS/com.objective-see.lulu.extension"
        for result, expected in ((active, True), (active.replace('enabled', 'waiting for user'), False),
                                 (active.replace('VBG97UB4TA', 'SOMEONELSE'), False), ('', False)):
            with self.subTest(result=result), patch.object(app_launcher.subprocess, "run",
                    side_effect=[SimpleNamespace(stdout=process), SimpleNamespace(stdout=result)]):
                self.assertEqual(app_launcher.lulu_ready(config), expected)
        with patch.object(app_launcher.subprocess, "run", return_value=SimpleNamespace(stdout="")) as run:
            self.assertFalse(app_launcher.lulu_ready(config))
            self.assertEqual(run.call_count, 1)

    def test_lulu_disappearing_after_the_proxy_probe_prevents_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(path=str(Path(directory) / "config.json"), protection_enabled=True,
                                     config={"connection_mode": "proxy", "desktop_firewall": "lulu"})
            with patch.object(app_launcher, "ConfigManager", return_value=config), \
                    patch.object(app_launcher, "lulu_ready", side_effect=[True, False]), \
                    patch.object(app_launcher, "get_verdict", return_value=("allowed", "93.184.216.34", None)), \
                    patch.object(app_launcher, "show_mac_alert"), \
                    patch.object(app_launcher, "launch_isolated_desktop") as launch:
                with self.assertRaises(SystemExit):
                    app_launcher.launch_claude_desktop()
                launch.assert_not_called()

    def test_running_desktop_is_not_reused_without_proxy_arguments(self):
        with patch.object(app_launcher.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(app_launcher, "show_mac_alert"):
            with self.assertRaises(SystemExit):
                app_launcher.launch_isolated_desktop()
            self.assertEqual(run.call_count, 2)
            self.assertTrue(any(arg.startswith('=identifier ') for arg in run.call_args_list[0].args[0]))
            self.assertEqual(run.call_args.args[0], ["/usr/bin/pgrep", "-x", "Claude"])

    def test_inline_system_pac_launches_desktop_without_network_switches(self):
        url = "data:application/x-ns-proxy-autoconfig;base64,YQ=="
        system_proxy = SimpleNamespace(stdout=f"  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : {url}\n")
        with patch.object(app_launcher.subprocess, "run", side_effect=[
            SimpleNamespace(returncode=0), system_proxy, None,
        ]) as run:
            app_launcher.launch_isolated_desktop(url)
        self.assertNotIn("/usr/bin/pgrep", [call.args[0][0] for call in run.call_args_list])
        self.assertEqual(run.call_args.args[0], ["/usr/bin/open", "-a", "/Applications/Claude.app"])

    def test_disabled_or_mismatched_system_pac_blocks_desktop_launch(self):
        url = "data:application/x-ns-proxy-autoconfig;base64,YQ=="
        for flags in ("  ProxyAutoConfigEnable : 0", "    ProxyAutoConfigEnable : 1"):
            system_proxy = SimpleNamespace(stdout=f"{flags}\n  ProxyAutoConfigURLString : {url}\n")
            with self.subTest(flags=flags), patch.object(app_launcher.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=0), system_proxy,
            ]) as run, patch.object(app_launcher, "show_mac_alert"):
                with self.assertRaises(SystemExit):
                    app_launcher.launch_isolated_desktop(url)
                self.assertEqual(run.call_args.args[0], ["/usr/sbin/scutil", "--proxy"])
