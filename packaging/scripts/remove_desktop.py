"""Remove a Desktop PKG installation after macOS administrator authorization."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


ROOT = Path('/Library/Application Support/ClaudeGuard')
PYTHON = ROOT / 'python3'
APP = Path('/Applications/ClaudeGuard.app')
SCRIPT = ROOT / 'remove_desktop.py'
HOSTS = Path('/etc/hosts')
RECEIPT = 'com.claudeguard.installer'
DOMAIN = 'com.claudeguard.app'
MARKERS = {
    b'# BEGIN CLAUDEGUARD BLOCKS': b'# END CLAUDEGUARD BLOCKS',
    b'# BEGIN CLAUDEGUARD UPDATE BLOCKS': b'# END CLAUDEGUARD UPDATE BLOCKS',
}


def strip_hosts(content):
    retained = []
    end = None
    for line in content.splitlines(keepends=True):
        marker = line.rstrip(b'\r\n')
        if marker in MARKERS and end is None:
            end = MARKERS[marker]
        elif end is not None and marker == end:
            end = None
        elif marker in MARKERS or marker in MARKERS.values():
            raise ValueError('Malformed ClaudeGuard markers in /etc/hosts. Review the file and retry.')
        elif end is None:
            retained.append(line)
    if end is not None:
        raise ValueError('Unterminated ClaudeGuard block in /etc/hosts. Review the file and retry.')
    return b''.join(retained)


def restore_hosts(path):
    content = path.read_bytes()
    cleaned = strip_hosts(content)
    if cleaned == content:
        return
    info = path.stat()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.claudeguard-hosts.', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(cleaned)
            stream.flush()
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            shutil.copystat(path, temporary)
            if path.read_bytes() != content:
                raise RuntimeError('/etc/hosts changed during cleanup. Retry removal.')
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def read_config(path, uid):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > 1024 * 1024:
            raise ValueError('ClaudeGuard configuration could not be read safely.')
        settings = json.loads(stream.read(1024 * 1024 + 1))
    if not isinstance(settings, dict):
        raise ValueError('ClaudeGuard configuration is invalid.')
    return settings


def remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def remove_user(home, settings):
    runtime = home / '.local/share/ClaudeGuard'
    bin_dir = home / '.local/bin'
    command = bin_dir / 'claudeguard'
    if command.is_symlink() and command.resolve() == (runtime / 'bin/claudeguard').resolve():
        command.unlink()
    claude = bin_dir / 'claude'
    if claude.is_symlink() and claude.resolve() == (runtime / 'src/cli_wrapper.py').resolve():
        original = Path(settings.get('real_claude_cli_path') or '')
        claude.unlink()
        if original.is_absolute() and original.is_file():
            claude.symlink_to(original)
    link = home / 'Applications/ClaudeGuard.app'
    if link.is_symlink() and link.readlink() == runtime / 'ClaudeGuard.app':
        link.unlink()
    subprocess.run(['/usr/bin/tccutil', 'reset', 'Accessibility', DOMAIN], capture_output=True)
    subprocess.run(['/usr/bin/defaults', 'delete', DOMAIN], capture_output=True)
    for owned in (
        home / 'Library/LaunchAgents/com.claudeguard.daemon.plist',
        home / f'Library/Preferences/{DOMAIN}.plist', home / f'Library/Caches/{DOMAIN}',
        home / f'Library/Saved Application State/{DOMAIN}.savedState',
        runtime, home / '.config/claudeguard',
    ):
        remove_path(owned)
    result = subprocess.run(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        temporary = Path(result.stdout.strip())
        for path in temporary.iterdir():
            if re.fullmatch(r'(?:ClaudeGuard|claudeguard-lulu)-[0-9a-fA-F-]{36}', path.name):
                remove_path(path)


def bootout(target):
    command = ['/bin/launchctl']
    result = subprocess.run(command + ['bootout', target], capture_output=True)
    if result.returncode and subprocess.run(command + ['print', target], capture_output=True).returncode == 0:
        raise RuntimeError(f'Could not stop {target}. Retry removal.')


def uninstall():
    # The installer supplies both configure.py and Runtime in its root-owned payload.
    sys.path[:0] = [str(ROOT), str(ROOT / 'Runtime')]
    from configure import check_existing_owner, console_account, run_as_user, stop_orphaned_transports
    from src.desktop_pac import restore

    account = console_account()
    home = Path(account.pw_dir)
    check_existing_owner(home)
    strip_hosts(HOSTS.read_bytes())
    bootout(f'gui/{account.pw_uid}/com.claudeguard.daemon')
    processes = subprocess.check_output(['/bin/ps', '-ww', '-A', '-o', 'uid=,pid=,comm='], text=True)
    for line in processes.splitlines():
        fields = line.strip().split(maxsplit=2)
        if (len(fields) == 3 and fields[0] == str(account.pw_uid) and fields[1].isdecimal()
                and fields[2] == str(APP / 'Contents/MacOS/ClaudeGuardMenuBar')):
            subprocess.run(['/bin/kill', '-TERM', fields[1]], capture_output=True)
    settings = read_config(home / '.config/claudeguard/config.json', account.pw_uid)
    restore(settings)
    stop_orphaned_transports(account)
    bootout('system/com.claudeguard.helper')
    bootout('system/com.claudeguard.proxy')
    subprocess.run([str(PYTHON), '-I', str(ROOT / 'pf_controller.py'), '--unblock'], check=True)
    restore_hosts(HOSTS)
    subprocess.run(['/usr/bin/dscacheutil', '-flushcache'], capture_output=True)
    run_as_user(account, str(PYTHON), '-I', str(SCRIPT), '--user')
    for owned in (
        Path('/Library/LaunchDaemons/com.claudeguard.helper.plist'),
        Path('/Library/LaunchDaemons/com.claudeguard.proxy.plist'),
        Path('/etc/sudoers.d/claudeguard'),
        *(Path('/private/tmp') / name for name in (
            'claudeguard.log', 'claudeguard.err', 'claudeguard-helper.log', 'claudeguard-helper.err')),
    ):
        owned.unlink(missing_ok=True)
    pkgutil = '/usr/sbin/pkgutil'
    if subprocess.run([pkgutil, '--pkg-info', RECEIPT], capture_output=True).returncode == 0:
        subprocess.run([pkgutil, '--forget', RECEIPT], check=True, capture_output=True)
    remove_path(APP)
    remove_path(ROOT)


if __name__ == '__main__':
    try:
        uid = os.geteuid()
        if sys.argv[1:] == ['--user'] and uid != 0:
            home = Path.home()
            remove_user(home, read_config(home / '.config/claudeguard/config.json', uid))
        elif len(sys.argv) == 1 and uid == 0:
            uninstall()
        else:
            raise RuntimeError('ClaudeGuard removal requires macOS administrator approval.')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
