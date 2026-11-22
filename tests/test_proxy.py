import json
from contextlib import nullcontext
import os
import subprocess
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from src import brain, proxy_config, proxy, proxy_egress
from src.config import ConfigManager
from src.pf_controller import parse_rule, make_rule


class ProxyTests(unittest.TestCase):
    def test_empty_profile_has_setup_message(self):
        with self.assertRaisesRegex(ValueError, 'not configured'):
            proxy_config.validate(None)
        with self.assertRaisesRegex(ValueError, 'Enter a proxy URL'):
            proxy_config.parse_profile('  ')

    def test_urls_credentials_and_ipv6(self):
        p = proxy_config.parse_profile('socks5://user:p%40ss@[::1]:1080')
        self.assertEqual((p['server'], p['password'], p['version']), ('::1', 'p@ss', '5'))
        p = proxy_config.parse_profile('https://user:pass@proxy.example:443')
        self.assertTrue(p['tls']['enabled'])
        self.assertEqual(p['type'], 'http')

    def test_profile_cannot_supply_privileged_engine_options(self):
        base = {'type': 'http', 'server': 'proxy.example', 'server_port': 443}
        for extra in [{'detour': 'direct'}, {'tls': {'enabled': True, 'insecure': True}},
                      {'tls': {'enabled': True, 'certificate_path': '/etc/shadow'}},
                      {'transport': {'type': 'ws', 'file': '/etc/passwd'}},
                      {'server_port': 65536}, {'server': 'localhost', 'server_port': proxy_config.PORT}, {'server': 'bad\nserver'}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                proxy_config.validate(dict(base, **extra))

    def test_proxy_can_bind_its_remote_connection_to_a_mac_network_interface(self):
        profile = {
            'type': 'vless', 'server': '192.0.2.1', 'server_port': 8443,
            'uuid': '12345678-1234-1234-1234-123456789abc', 'bind_interface': 'en0',
        }
        parsed = proxy_config.parse_profile(json.dumps(profile))
        config = proxy_config.engine_config(parsed, [], ['claude.ai'])
        self.assertEqual(config['outbounds'], [dict(profile, tag='proxy')])
        for changes in ({'bind_interface': 'utun25'}, {'bind_interface': 'en0\n'},
                        {'bind_interface': ''}, {'server': 'proxy.example'},
                        {'server': '127.0.0.1'}, {'server': '::'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                proxy_config.validate(dict(profile, **changes))

    def test_engine_routes_are_scoped_and_local_listener_is_loopback(self):
        config = proxy_config.engine_config(proxy_config.parse_profile('socks5://localhost:1080'),
                                             ['192.0.2.1', '2001:db8::1'], ['claude.ai'])
        self.assertNotIn('0.0.0.0/0', config['inbounds'][0]['route_address'])
        self.assertEqual(config['inbounds'][1]['listen'], '127.0.0.1')
        self.assertNotIn('platform', config['inbounds'][0])
        self.assertEqual([outbound['tag'] for outbound in config['outbounds']], ['proxy'])
        self.assertEqual(config['route']['final'], 'proxy')

    def test_environment_overrides_bypass_without_changing_parent(self):
        env = {'HTTPS_PROXY': 'http://old:1234', 'no_proxy': '*', 'PATH': '/bin'}
        result = proxy.environment(env)
        self.assertEqual(result['NO_PROXY'], '')
        self.assertEqual(result['no_proxy'], '')
        self.assertEqual(result['HTTPS_PROXY'], 'http://127.0.0.1:17943')
        self.assertEqual(env['no_proxy'], '*')

    def test_owned_quic_rejected_before_sniff_without_silent_drop(self):
        config = proxy_config.engine_config(proxy_config.parse_profile('http://localhost:1080'),
                                             ['192.0.2.1'], ['claude.ai'])
        rules = config['route']['rules']
        reject = rules[0]
        self.assertEqual(reject['network'], 'udp')
        self.assertNotIn('ip_cidr', reject)
        self.assertEqual(reject['action'], 'reject')
        self.assertEqual(reject['method'], 'default')
        self.assertTrue(reject['no_drop'])
        self.assertEqual(rules[1]['action'], 'sniff')

    def test_proxy_never_accepts_vpn_or_old_profile_verdict(self):
        config = SimpleNamespace(protection_enabled=True, config={'connection_mode': 'proxy',
            'expected_exit_ip': '93.184.216.34',
            'proxy_profile': proxy_config.parse_profile('http://localhost:3128')})
        for state in [None, {'mode': 'vpn', 'state': 'allowed'},
                      {'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': 'old'}]:
            with patch.object(brain, 'read_daemon_state', return_value=state):
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')
        state = {'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': proxy.profile_id(config), 'ip': '93.184.216.34', 'proxy_verified_at': time.time()}
        with patch.object(brain, 'read_daemon_state', return_value=state):
            self.assertEqual(brain.get_verdict(config)[0], 'allowed')
            config.config['proxy_enabled'] = False
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_health_check_tolerates_one_echo_service_outage(self):
        expected = '93.184.216.34'
        responses = [subprocess.CalledProcessError(22, 'curl'), SimpleNamespace(stdout=expected + '\n')]
        with patch.object(proxy_egress.subprocess, 'run', side_effect=responses) as run:
            self.assertEqual(proxy.probe(expected), expected)
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                self.assertIn('http://127.0.0.1:17943', call.args[0])
                self.assertIn('--noproxy', call.args[0])
                self.assertNotIn('HTTPS_PROXY', call.kwargs['env'])

    def test_wrong_ipv4_or_ipv6_is_not_retried(self):
        for observed in ('93.184.216.35', '2606:4700::1111'):
            with self.subTest(observed=observed), patch.object(proxy_egress.subprocess, 'run',
                    return_value=SimpleNamespace(stdout=observed)) as run:
                with self.assertRaisesRegex(proxy_egress.ExitIPMismatch, 'expected 93.184.216.34'):
                    proxy.probe('93.184.216.34')
                run.assert_called_once()

    def test_missing_stale_and_mismatched_proofs_cannot_authorize_launch(self):
        config = SimpleNamespace(protection_enabled=True, config={'connection_mode': 'proxy',
            'expected_exit_ip': '93.184.216.34', 'proxy_profile': {'type': 'http'}})
        now = time.time()
        allowed = {'mode': 'proxy', 'state': 'allowed', 'ip': '93.184.216.34',
                   'proxy_profile_id': proxy.profile_id(config), 'proxy_verified_at': now}
        for fields in ({'proxy_verified_at': 0}, {'proxy_verified_at': now - 8},
                       {'proxy_verified_at': now + 10}, {'ip': '93.184.216.35'}):
            with self.subTest(fields=fields), patch.object(brain, 'read_daemon_state',
                    return_value=dict(allowed, **fields)):
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')
        with patch.object(brain, 'read_daemon_state', return_value=allowed), patch.object(proxy, 'probe',
                side_effect=RuntimeError('Proxy connection failed')):
            self.assertEqual(brain.get_verdict(config, verify_proxy=True)[0], 'blocked')
            config.config['expected_exit_ip'] = '93.184.216.35'
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')
            config.config.pop('expected_exit_ip')
            self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_credentials_saved_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(os.path.join(directory, 'config.json'))
            proxy.save_profile(config, 'http://user:secret@localhost:3128')
            self.assertEqual(os.stat(config.path).st_mode & 0o777, 0o600)

    def test_removing_profile_clears_credentials_and_denies_stale_allow(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(os.path.join(directory, 'config.json'))
            config.config.update(connection_mode='proxy', protection_enabled=True)
            proxy.save_profile(config, 'http://user:secret@localhost:3128')
            self.assertIsNone(proxy.save_profile(config, ' \n'))
            saved = json.loads(Path(config.path).read_text())
            self.assertIsNone(saved['proxy_profile'])
            self.assertNotIn('secret', Path(config.path).read_text())
            with patch.object(brain, 'read_daemon_state', return_value={
                    'mode': 'proxy', 'state': 'allowed', 'proxy_profile_id': proxy.profile_id(config)}):
                self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_pf_exempts_only_our_interface(self):
        rule = make_rule(['192.0.2.1'], proxy=True)
        self.assertIn('on ! utun199', rule)
        active = proxy_config.DEDICATED
        from src.pf_controller import make_proxy_rule
        self.assertIn('on utun199 proto { tcp, udp } to <claude_guard> keep state (if-bound)', make_proxy_rule(active))
        self.assertNotIn('user != 0', make_proxy_rule(active))
        self.assertEqual(parse_rule(rule), ['192.0.2.1'])
        with self.assertRaises(Exception):
            parse_rule(rule.replace('utun199', 'en0'))

class ProxyBackendTests(unittest.TestCase):
    def test_only_owned_ranges_are_accepted_as_networks(self):
        self.assertEqual(parse_rule(make_rule(['160.79.104.0/24'], proxy=True)), ['160.79.104.0/24'])
        for value in ['0.0.0.0/0', '192.0.2.0/24', '::/0']:
            with self.assertRaises(Exception):
                parse_rule(make_rule([value], proxy=True))

    def test_refresh_keeps_established_connections(self):
        from src.pf_controller import PFController
        controller = PFController()
        with patch.object(controller, 'pf') as pf, patch.object(controller, 'ensure_attachment'), \
                patch.object(controller, 'enable'), patch.object(controller, 'clear_anchor'):
            controller.block(['192.0.2.1'], proxy=True, kill_states=False)
            self.assertFalse(any(call.args[0] == '-k' for call in pf.call_args_list))

    def test_vpn_default_is_transport_not_conflicting_route(self):
        from src.proxy_service import route_conflicts
        self.assertFalse(route_conflicts('destination: default\nmask: default\ninterface: utun4', '160.79.104.0/24'))
        self.assertFalse(route_conflicts('destination: 160.79.104.10\nflags: <HOST,WASCLONED>\ninterface: utun4', '160.79.104.10/32'))
        self.assertTrue(route_conflicts('destination: 160.79.104\nmask: 255.255.255.0\ninterface: utun4', '160.79.104.0/24'))
        self.assertTrue(route_conflicts('destination: 2607:6bc0::\nmask: ffff:ffff::\ninterface: utun4', '2607:6bc0::/32'))
        self.assertFalse(route_conflicts('destination: 0.0.0.0\nmask: 128.0.0.0\ninterface: utun4', '160.79.104.0/24'))
        self.assertTrue(route_conflicts('destination: 160.79.104.10\nflags: <HOST,STATIC>\ninterface: utun4', '160.79.104.10/32'))

    def test_tunnel_owner_conflict_stops_before_writing_config(self):
        from src import proxy_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def runner(*args, **kwargs):
                if args[0] == '/sbin/ifconfig':
                    return SimpleNamespace(returncode=0, stdout='utun199')
                return SimpleNamespace(returncode=1, stdout='')
            request = {'profile': proxy_config.parse_profile('http://localhost:3128'),
                       'expected_exit_ip': '93.184.216.34',
                       'addresses': ['192.0.2.1'], 'domains': ['claude.ai']}
            with patch.object(proxy_service, 'ROOT', root), patch.object(proxy_service, 'run', side_effect=runner):
                with self.assertRaisesRegex(RuntimeError, 'occupied'):
                    proxy_service.ensure(request, before_start=Mock())
            self.assertEqual(list(root.iterdir()), [])

    def test_terminated_engine_is_reported_as_installation_failure(self):
        from src import proxy_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sing-box').touch()
            def runner(*args, **kwargs):
                if args[0] == str(root / 'sing-box'):
                    return SimpleNamespace(returncode=-9, stdout='')
                return SimpleNamespace(returncode=1, stdout='')
            request = {'profile': proxy_config.parse_profile('http://localhost:3128'),
                       'expected_exit_ip': '93.184.216.34',
                       'addresses': [], 'domains': ['claude.ai']}
            with patch.object(proxy_service, 'ROOT', root), \
                    patch.object(proxy_service, 'run', side_effect=runner), \
                    patch.object(proxy_service, 'stop') as stop:
                with self.assertRaisesRegex(RuntimeError, 'terminated by macOS'):
                    proxy_service.ensure(request, before_start=Mock())
                stop.assert_not_called()

    def test_mismatch_never_loads_the_working_engine(self):
        from src import proxy_service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sing-box').touch()
            request = {'profile': proxy_config.parse_profile('http://localhost:3128'),
                       'expected_exit_ip': '93.184.216.34', 'addresses': [], 'domains': ['claude.ai']}
            events = []

            def runner(*args, **kwargs):
                events.append(args)
                return SimpleNamespace(returncode=int(args[0] != str(root / 'sing-box')), stdout='')

            with patch.object(proxy_service, 'ROOT', root), patch.object(proxy_service, 'run', side_effect=runner), \
                    patch.object(proxy_service, 'stop') as stop, patch.object(proxy_service, 'require_free_port'), \
                    patch.object(proxy_service, 'probe_engine', return_value=nullcontext()), \
                    patch.object(proxy_service, 'probe_exit', side_effect=proxy_egress.ExitIPMismatch('unexpected IP')) as proof:
                before_start = Mock()
                with self.assertRaisesRegex(RuntimeError, 'unexpected IP'):
                    proxy_service.ensure(request, before_start=before_start)
                before_start.assert_called_once()
                stop.assert_called_once()
                proof.assert_called_once_with('93.184.216.34', proxy_config.PROBE_PORT)
                self.assertFalse(any('bootstrap' in args for args in events))
                self.assertFalse((root / 'proxy.json').exists())

    def test_watchdog_stops_on_failed_proof(self):
        from src import proxy_service
        with patch.object(proxy_service, 'run_engine') as engine, \
                patch.object(proxy_service, 'probe_exit', side_effect=RuntimeError('unreachable')):
            lifecycle = engine.return_value
            lifecycle.__enter__.return_value.poll.return_value = None
            with self.assertRaisesRegex(RuntimeError, 'unreachable'):
                proxy_service.supervise('93.184.216.34')
            self.assertEqual(lifecycle.__exit__.call_args.args[0], RuntimeError)


if __name__ == '__main__':
    unittest.main()
