"""IPv4 pin validation and a proxy-only HTTPS egress proof."""
import ipaddress
import subprocess

if __package__:
    from . import trace_timing as trace
else:
    import trace_timing as trace

ENDPOINTS = ('api.ipify.org', 'checkip.amazonaws.com')


class ExitIPMismatch(RuntimeError):
    pass


def validate_exit_ip(value):
    try:
        address = ipaddress.IPv4Address(value.strip())
        if not address.is_global or address.is_multicast:
            raise ValueError
    except (AttributeError, ValueError):
        raise ValueError('Set the expected public exit IPv4 in Configure Proxy or with claudeguard set-exit-ip') from None
    return str(address)


def probe_exit(expected, port, timeout=3):
    expected = validate_exit_ip(expected)
    for attempt, endpoint in enumerate(ENDPOINTS, 1):
        started = trace.begin()
        outcome = "error"
        try:
            result = subprocess.run(
                ['/usr/bin/curl', '-q', '--silent', '--fail', '--max-time', str(timeout),
                 '--max-filesize', '128', '--proxy', f'http://127.0.0.1:{port}',
                 '--noproxy', '', f'https://{endpoint}'],
                capture_output=True, text=True, timeout=timeout + 1, check=True,
                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
            )
            observed = str(ipaddress.ip_address(result.stdout.strip()))
            if observed != expected:
                raise ExitIPMismatch(f'Proxy exit IP is {observed}; expected {expected}')
            outcome = "ok"
            return observed
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        finally:
            trace.end(started, f"proxy.exit_ip.attempt_{attempt}", outcome)
    raise RuntimeError('Proxy connection failed (authentication, server or network unavailable)')
