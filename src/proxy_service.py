"""Root-owned sing-box lifecycle. Called under the network helper's lock."""
import hashlib
import ipaddress
import json
import plistlib
import sys
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

# The launchd job uses isolated Python. The installed script and its modules
# are in the same root-owned directory.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import trace_timing as trace

from proxy_config import engine_config, INTERFACE, PORT, PROBE_PORT
from proxy_egress import ENDPOINTS, probe_exit, validate_exit_ip

ROOT = Path('/Library/Application Support/ClaudeGuard')
PLIST = ROOT / 'proxy.plist'
LEGACY_PLIST = Path('/Library/LaunchDaemons/com.claudeguard.proxy.plist')
LABEL = 'system/com.claudeguard.proxy'

@trace.stage("macos.command.timeout_20s")
def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=check)

@trace.stage("engine.stop")
@trace.stage("routes.teardown.engine_owned")
def stop():
    stopped = run('/bin/launchctl', 'bootout', LABEL, check=False)
    if stopped.returncode and run('/bin/launchctl', 'print', LABEL, check=False).returncode == 0:
        raise RuntimeError('Could not stop ClaudeGuard proxy service; firewall protection retained')
    polling = trace.begin() if trace.enabled else None
    deadline = time.monotonic() + 5
    while run('/bin/launchctl', 'print', LABEL, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            raise RuntimeError('Proxy service is still stopping; retry shortly')
        time.sleep(0.1)
    if trace.enabled:
        trace.end(polling, "macos.stop.poll_100ms_deadline_5s")
    PLIST.unlink(missing_ok=True)
    LEGACY_PLIST.unlink(missing_ok=True)
    (ROOT / 'proxy-fingerprint').unlink(missing_ok=True)

def route_conflicts(output, requested):
    fields = {}
    for line in output.splitlines():
        if ':' in line:
            key, value = line.strip().split(':', 1)
            fields[key] = value.strip()
    destination = fields.get('destination', '')
    flags = fields.get('flags', '')
    if destination in {'', 'default'} or 'WASCLONED' in flags or fields.get('interface') == INTERFACE:
        return False
    try:
        if '/' in destination:
            existing = ipaddress.ip_network(destination, strict=False)
        else:
            if ':' not in destination:
                destination += '.0' * (4 - len(destination.split('.')))
            address = ipaddress.ip_address(destination)
            mask = fields.get('mask')
            prefix = address.max_prefixlen
            if mask and mask != 'default':
                bits = bin(int(ipaddress.ip_address(mask)))[2:].zfill(address.max_prefixlen)
                if '01' in bits:
                    raise ValueError('Non-contiguous route mask')
                prefix = bits.count('1')
            existing = ipaddress.ip_network(str(address) + '/' + str(prefix), strict=False)
        return existing == ipaddress.ip_network(requested)
    except ValueError:
        raise RuntimeError('Could not inspect an existing route safely')


def require_free_port(port):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', port))
        except OSError as error:
            raise RuntimeError('A ClaudeGuard proxy port is occupied by another application') from error


@contextmanager
def run_engine(binary, path, port, **streams):
    with subprocess.Popen([str(binary), 'run', '-c', str(path)], **streams) as process:
        try:
            deadline = time.monotonic() + 3
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError('Could not start the proxy listener')
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()


@contextmanager
def probe_engine(binary, path, config):
    # Probe the same outbound without opening a Claude data listener or a TUN.
    require_free_port(PROBE_PORT)
    proof = dict(config, inbounds=[dict(config['inbounds'][1], listen_port=PROBE_PORT)],
                 route={**config['route'], 'rules': [
                     {'domain': list(ENDPOINTS), 'action': 'route', 'outbound': 'proxy'},
                     {'action': 'reject'},
                 ]})
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    try:
        path.write_text(json.dumps(proof))
        with run_engine(binary, path, PROBE_PORT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            yield
            if process.poll() is not None:
                raise RuntimeError('Proxy verification listener stopped during the check')
    finally:
        path.unlink(missing_ok=True)


def supervise(expected):
    # launchd owns the entire process group. The engine stops on a failed
    # proof even if the menu bar agent has quit or crashed.
    with run_engine(ROOT / 'sing-box', ROOT / 'proxy.json', PORT) as process:
        while process.poll() is None:
            probe_exit(expected, PORT, timeout=2)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                continue
        raise RuntimeError('Proxy engine stopped unexpectedly')


@trace.stage("engine.ensure")
def ensure(request, before_start):
    expected = validate_exit_ip(request.get('expected_exit_ip'))
    addresses = [str(ipaddress.ip_address(a)) for a in request['addresses']]
    config = engine_config(request['profile'], addresses, request['domains'])
    content = json.dumps(config, sort_keys=True)
    fingerprint = hashlib.sha256((expected + '\n' + content).encode()).hexdigest()
    stamp = ROOT / 'proxy-fingerprint'
    status = run('/bin/launchctl', 'print', LABEL, check=False)
    if stamp.exists() and stamp.read_text() == fingerprint and 'state = running' in status.stdout:
        return
    before_start()
    if status.returncode != 0:
        interface = run('/sbin/ifconfig', INTERFACE, check=False)
        if interface.returncode == 0:
            raise RuntimeError('Proxy interface is occupied by another application')
    if status.returncode != 0:
        # A default/broader VPN route remains installed beneath our more-specific
        # routes. Refuse only an exact route collision, not the VPN transport.
        for network in config['inbounds'][0]['route_address']:
            destination = str(ipaddress.ip_network(network).network_address)
            family = ['-inet6'] if ':' in destination else []
            route = run('/sbin/route', '-n', 'get', *family, destination, check=False)
            if route_conflicts(route.stdout, network):
                raise RuntimeError('An existing route overlaps a ClaudeGuard route exactly; it was left unchanged')
    binary = ROOT / 'sing-box'
    if not binary.is_file():
        raise RuntimeError('Proxy engine is missing; reinstall ClaudeGuard')
    candidate = ROOT / 'proxy-next.json'
    candidate.touch(mode=0o600, exist_ok=True)
    candidate.chmod(0o600)
    candidate.write_text(content)
    checked = run(str(binary), 'check', '-c', str(candidate), check=False)
    if checked.returncode < 0:
        raise RuntimeError('Proxy engine was terminated by macOS; reinstall ClaudeGuard to repair the executable')
    if checked.returncode:
        raise RuntimeError('Proxy profile rejected by sing-box; check protocol settings')
    stop()
    require_free_port(PORT)
    with probe_engine(binary, ROOT / 'proxy-proof.json', config):
        probe_exit(expected, PROBE_PORT)
    candidate.replace(ROOT / 'proxy.json')
    bundled = ROOT / 'python3'
    body = {'Label': 'com.claudeguard.proxy',
            'ProgramArguments': [str(bundled) if bundled.is_file() else '/usr/bin/python3',
                                 '-I', str(ROOT / 'proxy_service.py'), expected],
            'RunAtLoad': True,
            'StandardOutPath': str(ROOT / 'proxy.log'), 'StandardErrorPath': str(ROOT / 'proxy.log')}
    log = ROOT / 'proxy.log'
    log.touch(mode=0o600, exist_ok=True)
    log.chmod(0o600)
    with PLIST.open('wb') as stream:
        plistlib.dump(body, stream)
    PLIST.chmod(0o644)
    timing = trace.begin() if trace.enabled else None
    started = run('/bin/launchctl', 'bootstrap', 'system', str(PLIST), check=False)
    if trace.enabled:
        trace.end(timing, "engine.start.bootstrap", "ok" if not started.returncode else "error")
        trace.end(timing, "routes.setup.engine_owned.submitted", "ok" if not started.returncode else "error")
    if started.returncode:
        loaded = run('/bin/launchctl', 'print', LABEL, check=False)
        if loaded.returncode or 'state = running' not in loaded.stdout or str(ROOT / 'proxy_service.py') not in loaded.stdout:
            raise RuntimeError('Proxy service could not start; check the engine log')
    stamp.write_text(fingerprint)


if __name__ == '__main__':
    try:
        supervise(validate_exit_ip(sys.argv[1]))
    except (OSError, RuntimeError, ValueError) as error:
        print(f'ClaudeGuard proxy: {error}', file=sys.stderr, flush=True)
        sys.exit(1)
