"""User-side proxy preparation, health check and CLI environment."""
import hashlib
import json
import os
import time
from src import trace_timing as trace
from src.proxy_config import parse_profile, validate, PORT
from src.proxy_egress import ExitIPMismatch, probe_exit, validate_exit_ip


def profile_id(config):
    policy = [config.config.get('proxy_profile'), config.config.get('expected_exit_ip')]
    if managed := config.config.get('managed_proxy'):
        policy.append(managed.get('generation'))
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def save_profile(config, text, exit_ip=None):
    # An empty settings field explicitly removes the saved profile.
    profile = parse_profile(text) if text.strip() else None
    if profile is None:
        config.config['expected_exit_ip'] = None
    elif exit_ip is not None:
        config.config['expected_exit_ip'] = validate_exit_ip(exit_ip)
    config.config['proxy_profile'] = profile
    config.config.pop('managed_proxy', None)
    config.save_config()
    os.chmod(config.path, 0o600)
    return profile


def environment(env):
    env = dict(env)
    for key in list(env):
        if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
            del env[key]
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env[key] = f'http://127.0.0.1:{PORT}'
    env['NO_PROXY'] = env['no_proxy'] = ''
    return env


@trace.stage("proxy.exit_ip")
def probe(expected, timeout=3):
    return probe_exit(expected, PORT, timeout=timeout)


@trace.stage("proxy.prepare.retry_3_sleep_300ms")
def prepare(config):
    from src.network_guard import sync_hosts_file
    validate(config.config.get('proxy_profile'))
    expected = validate_exit_ip(config.config.get('expected_exit_ip'))
    ok, error = sync_hosts_file(False, config)
    if not ok:
        raise RuntimeError(error)
    # launchd may need a moment to start the listeners.
    error = None
    for _ in range(3):
        try:
            return probe(expected)
        except ExitIPMismatch:
            raise
        except RuntimeError as exc:
            error = exc
            time.sleep(0.3)
    raise error
