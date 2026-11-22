"""Proxy denial ordering; no real PF, hosts, launchd or engine calls."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from src import pf_controller as backend


class ProxyFailureHostsTests(unittest.TestCase):
    def test_engine_failure_denies_before_cleaning_hosts_and_pf_failure_keeps_fallback(self):
        for pf_fails in (False, 'all'):
            with self.subTest(pf_fails=pf_fails), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pending = root / 'pending'
                pending.mkdir()
                (pending / 'request').write_text('a' * 32)
                (pending / 'hosts.tmp').write_text('127.0.0.1 localhost\n')
                (pending / 'pf.rule').write_text(backend.make_rule(['160.79.104.10'], proxy=True))
                (pending / 'proxy.json').write_text(json.dumps({'domains': ['claude.ai'], 'addresses': ['160.79.104.10']}))
                controller = Mock(directory=root)
                events = []
                def block(addresses, **kwargs):
                    events.append(('pf', kwargs.get('proxy', False)))
                    if pf_fails == 'all':
                        raise backend.PFError('PF unavailable')
                controller.block.side_effect = block
                def ensure(profile, before_start):
                    before_start()
                    events.append(('engine', None))
                    raise RuntimeError('engine unavailable')
                def hosts(content):
                    events.append(('hosts', backend.HEADER in content))
                with patch('proxy_service.ensure', side_effect=ensure), \
                        patch('proxy_service.stop', side_effect=lambda: events.append(('stop', None))), \
                        patch.object(backend, 'apply_hosts', side_effect=hosts):
                    with self.assertRaises(backend.PFError):
                        backend.apply_request(root, controller)
                if pf_fails == 'all':
                    self.assertEqual(events, [('pf', False), ('pf', False), ('hosts', True), ('stop', None)])
                else:
                    self.assertEqual(events, [('pf', False), ('engine', None), ('pf', False), ('hosts', False), ('stop', None)])
                self.assertFalse(json.loads((root / 'network-status.json').read_text())['ok'])

    def test_profile_removal_blocks_before_stop_and_hosts_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = root / 'pending'
            pending.mkdir()
            (pending / 'request').write_text('a' * 32)
            (pending / 'hosts.tmp').write_text(backend.HEADER + '::1 claude.ai\n' + backend.FOOTER)
            (pending / 'pf.rule').write_text(backend.make_rule(['160.79.104.10']))
            (pending / 'proxy.json').write_text('null')
            events = []
            controller = Mock(directory=root)
            controller.block.side_effect = lambda *a, **k: events.append('pf')
            with patch('proxy_service.stop', side_effect=lambda: events.append('stop')), \
                    patch.object(backend, 'apply_hosts', side_effect=lambda text: events.append(('hosts', backend.HEADER in text))):
                backend.apply_request(root, controller)
            self.assertEqual(events, ['pf', 'stop', ('hosts', True)])

    def test_root_start_restores_denial_and_drops_previous_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'network-status.json'
            path.write_text(json.dumps({'request': 'a' * 32, 'ok': True, 'proxy': True,
                                        'protected_addresses': ['160.79.104.10', '2607:6bc0::/32']}))
            controller = Mock(directory=root)
            controller.read_token.return_value = '123'
            controller.token_is_live.return_value = False
            self.assertEqual(backend.restore_denial(controller), 'a' * 32)
            controller.block.assert_called_once_with(['160.79.104.10', '2607:6bc0::/32'])
            self.assertFalse(json.loads(path.read_text())['proxy'])
