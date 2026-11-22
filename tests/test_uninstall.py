"""Uninstall regressions with mocked dispatch and temporary hosts fixtures only."""
import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'uninstall.sh').read_text()
DESKTOP_REMOVAL = runpy.run_path(str(ROOT / 'packaging/scripts/remove_desktop.py'))


class UninstallTests(unittest.TestCase):
    def test_desktop_removal_preserves_other_apps_and_removes_owned_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / '.config/claudeguard/config.json'
            lu_lu = home / 'Applications/LuLu.app/Contents/Info.plist'
            claude = home / 'Applications/Claude.app/Contents/Info.plist'
            agent = home / 'Library/LaunchAgents/com.claudeguard.daemon.plist'
            for path in (config, lu_lu, claude, agent):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('test file')
            own = home / '.local/share/ClaudeGuard/bin/claudeguard'
            own.parent.mkdir(parents=True)
            own.touch()
            bin_dir = home / '.local/bin'
            bin_dir.mkdir()
            (bin_dir / 'claudeguard').symlink_to(own)
            (bin_dir / 'claude').symlink_to(claude)
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')):
                DESKTOP_REMOVAL['remove_user'](home, {})
            self.assertTrue(lu_lu.is_file())
            self.assertTrue(claude.is_file())
            self.assertEqual((bin_dir / 'claude').resolve(), claude.resolve())
            self.assertFalse((bin_dir / 'claudeguard').is_symlink())
            self.assertFalse(config.exists())
            self.assertFalse(agent.exists())
            self.assertFalse(own.exists())

    def test_desktop_hosts_cleanup_preserves_foreign_lines_and_rejects_unpaired_markers(self):
        strip = DESKTOP_REMOVAL['strip_hosts']
        original = b'127.0.0.1 localhost\r\n# foreign comment\n'
        owned = b'# BEGIN CLAUDEGUARD BLOCKS\n127.0.0.1 claude.ai\n# END CLAUDEGUARD BLOCKS\n'
        self.assertEqual(strip(original + owned), original)
        with self.assertRaises(ValueError):
            strip(original + owned.split(b'# END')[0])

    def test_desktop_pac_restore_skips_deleted_services_and_foreign_pac(self):
        from src import desktop_pac
        settings = {'desktop_pac_url': 'ours', 'desktop_pac_previous': {
            'Wi-Fi': ['(null)', False], 'Happ': ['', False], 'Ethernet': ['', False],
        }}
        with patch.object(subprocess, 'check_output', return_value='Network services\nWi-Fi\n*Ethernet\n'), \
                patch.object(desktop_pac, 'service_proxy', side_effect=[('ours', True), ('foreign', True)]) as current, \
                patch.object(subprocess, 'run') as run:
            desktop_pac.restore(settings)
        self.assertEqual([c.args[0] for c in current.call_args_list], ['Wi-Fi', 'Ethernet'])
        self.assertEqual([c.args[0][1:] for c in run.call_args_list], [
            ['-setautoproxyurl', 'Wi-Fi', ''], ['-setautoproxystate', 'Wi-Fi', 'off'],
        ])

    def test_restore_existing_binary_skip_missing_and_preserve_foreign_link(self):
        block = SCRIPT.split('# Put the real binary back where its own installer would have put it.', 1)[1].split('# Remove the shared application', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'real-claude'
            bin_dir = root / '.local/bin'
            bin_dir.mkdir(parents=True)
            link = bin_dir / 'claude'
            def restore():
                return subprocess.run(['/bin/bash', '-c', block],
                    env={**os.environ, 'HOME': directory, 'REAL_CLAUDE_TARGET': str(target)},
                    capture_output=True, text=True)
            result = restore()
            self.assertEqual(result.returncode, 0)
            self.assertIn('restoration skipped', result.stdout)
            self.assertNotIn('Reinstall', result.stdout)
            self.assertFalse(link.is_symlink())
            target.touch()
            self.assertEqual(restore().returncode, 0)
            self.assertEqual(link.resolve(), target.resolve())
            link.unlink()
            link.symlink_to(root / 'foreign-missing-binary')
            self.assertEqual(restore().returncode, 0)
            self.assertEqual(os.readlink(link), str(root / 'foreign-missing-binary'))
            link.unlink()
            bin_dir.rmdir()
            result = restore()
            self.assertEqual(result.returncode, 1)
            self.assertIn('destination directory is missing or not writable', result.stderr)

    def test_cli_dispatch_propagates_failure_without_loading_config(self):
        cli = runpy.run_path(str(ROOT / 'bin/claudeguard'))
        main = cli['main']
        with patch.dict(main.__globals__, ConfigManager=lambda: self.fail('config loaded')), \
                patch.object(sys, 'argv', ['claudeguard', 'uninstall']), \
                patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            with self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 7)
            run.assert_called_once_with(['/bin/bash', str(ROOT / 'uninstall.sh')], check=False)

    def test_cli_missing_script_reports_error(self):
        main = runpy.run_path(str(ROOT / 'bin/claudeguard'))['main']
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(main.__globals__, PROJECT_DIR=directory), \
                patch.object(sys, 'argv', ['claudeguard', 'uninstall']), \
                patch.object(subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 1)
            run.assert_not_called()

    def test_hosts_cleanup_keeps_foreign_lines_and_rejects_partial_block(self):
        hosts_section = SCRIPT.split('# 3. Restore /etc/hosts file', 1)[1]
        body = hosts_section.split("<<'PYTHON'\n", 1)[1].split('\nPYTHON', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / 'hosts'
            output = Path(directory) / 'clean'
            body = body.replace("HOSTS_PATH = '/etc/hosts'", f'HOSTS_PATH = {str(hosts)!r}')
            hosts.write_text('127.0.0.1 localhost\n# BEGIN CLAUDEGUARD BLOCKS\n127.0.0.1 claude.ai\n# END CLAUDEGUARD BLOCKS\n# foreign\n')
            with patch.object(sys, 'argv', ['cleanup', str(output)]):
                exec(compile(body, 'hosts cleanup', 'exec'), {})
                self.assertEqual(output.read_text(), '127.0.0.1 localhost\n# foreign\n')
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                output.unlink()
                hosts.write_text('# BEGIN CLAUDEGUARD BLOCKS\nunfinished\n')
                with self.assertRaises(ValueError):
                    exec(compile(body, 'hosts cleanup', 'exec'), {})
                self.assertFalse(output.exists())

    def test_failed_cleanup_exits_and_removes_private_temp_directory(self):
        block = SCRIPT.split('# 3. Restore /etc/hosts file', 1)[1].split('# Flush DNS', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            # No Python cleanup or privileged command is executed in this shell.
            result = subprocess.run(['/bin/bash', '-c',
                'python3() { return 1; }; sudo() { echo UNEXPECTED_SUDO; return 99; };\n' + block],
                env={**os.environ, 'TMPDIR': directory, 'CG_PYTHON': 'python3'}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Hosts cleanup failed', result.stderr)
            self.assertNotIn('UNEXPECTED_SUDO', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_failed_copy_exits_and_removes_private_temp_directory(self):
        block = SCRIPT.split('# 3. Restore /etc/hosts file', 1)[1].split('# Flush DNS', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['/bin/bash', '-c',
                'python3() { return 0; }; sudo() { return 1; };\n' + block],
                env={**os.environ, 'TMPDIR': directory, 'CG_PYTHON': 'python3'}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Cannot restore /etc/hosts', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])
