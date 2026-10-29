#!/usr/bin/env python3
"""Install the native Linux application with fixed, root-owned launch authority.

The installed controller shares the adjacent flock for its entire lifetime.
All new files are staged under a private root directory before promotion; an
old user-owned inode or open write handle cannot modify newly trusted code.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/opt/router-vpn-client')
SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
CODE_TREES = {'client', 'modes', 'runtime'}
CODE_FILES = {
    'modes.json', 'logical-modes.json', 'router-vpn-client', 'router-vpn-dns',
    'router-vpn-start-layer-relay', 'router-vpn-update', 'router-vpn-app',
    'RouterVPN.ico', 'router-vpn.png', 'router-vpn.desktop', 'MODES.md',
    'CLIENT.md', 'SECURITY.md', 'LICENSE', 'DNS-PROXY-NOTICES.json',
    'ROUTER-VPN-SOURCE.json',
}
REQUIRED_FILES = {
    'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay',
    'router-vpn-update', 'router-vpn-app', 'modes.json', 'logical-modes.json',
    'router-vpn.png', 'router-vpn.desktop', 'ROUTER-VPN-SOURCE.json',
}
EARLY_NAME = 'router-vpn-killswitch-early.service'
NETWORK_UNITS = ('NetworkManager.service', 'systemd-networkd.service',
                 'networking.service', 'connman.service', 'wicked.service')
EARLY_UNIT = '''# Router VPN owned early protection; no HTTP controller runs at boot.
[Unit]
Description=Router VPN persistent always kill switch
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOMEVPN_ROOT=/opt/router-vpn-client /usr/bin/python3 -Es /opt/router-vpn-client/modes/kill-switch.py reassert

[Install]
WantedBy=multi-user.target
RequiredBy=network-pre.target
'''
NETWORK_DROPIN = '''# Router VPN owned: a failed Always reassertion blocks network startup.
[Unit]
Requires=router-vpn-killswitch-early.service
After=router-vpn-killswitch-early.service
'''
LAUNCHER = '''#!/bin/sh
if [ -x /opt/router-vpn-client/router-vpn-update ]; then
  /opt/router-vpn-client/router-vpn-update --download --json >/dev/null 2>&1 &
fi
exec /opt/router-vpn-client/router-vpn-app "$@"
'''
RECOVERY = '''#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" -eq 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOMEVPN_ROOT=/opt/router-vpn-client /usr/bin/python3 -Es /opt/router-vpn-client/modes/kill-switch.py force-off
/usr/bin/systemctl reset-failed router-vpn-killswitch-early.service || :
printf '%s\n' 'Router VPN Always protection disabled for local recovery. Review the saved policy before rebooting.'
'''


def command(arguments, *, check=True):
    return subprocess.run(list(map(str, arguments)), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': SYSTEM_PATH, 'LC_ALL': 'C'}, timeout=120)


def ordinary(path: Path, *, directory=False, trusted=False):
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or (not directory and info.st_nlink != 1):
        raise ValueError('Refusing a linked or nonregular installation object: ' + str(path))
    if trusted and (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
        raise ValueError('Installation authority must be root-owned and not writable by another user: ' + str(path))
    return info


@contextmanager
def installation_lock(root: Path):
    ordinary(root.parent, directory=True, trusted=True)
    path = root.with_name(root.name + '.install.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        actual, named = os.fstat(descriptor), ordinary(path, trusted=True)
        if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino) or actual.st_mode & 0o077:
            raise ValueError('The native installation lock is unsafe')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Close Router VPN and wait for its tunnel cleanup before upgrading.') from error
        yield
    finally:
        os.close(descriptor)


def reject_running_previous(root: Path, proc=Path('/proc')):
    # Older installations predate the shared lock. Read executable identities;
    # never signal a printed PID or kill another process to force an upgrade.
    prefix = str(root) + '/'
    for process in proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = os.readlink(process / 'exe').removesuffix(' (deleted)')
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise RuntimeError('Cannot prove that the previous native installation is idle') from error
        if executable.startswith(prefix):
            raise RuntimeError('Close Router VPN and its owned native processes before upgrading.')
        legacy = False
        if Path(executable).name == 'router-vpn-client':
            try:
                environment = (process / 'environ').read_bytes().split(b'\0')
                legacy = ('HOMEVPN_ROOT=' + str(root)).encode() in environment
            except FileNotFoundError:
                continue
        if legacy:
            raise RuntimeError('Close Router VPN and its owned native processes before upgrading.')


def copy_checked(source: Path, destination: Path, *, private=False):
    # Open every ancestor without following symlinks, then recurse by retained
    # directory descriptors. A user-owned package/private subdirectory cannot
    # redirect a later root open by replacing an ancestor during the copy.
    source = Path(os.path.abspath(source))
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in source.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        _copy_at(parent, source.name, destination, private=private)
    finally:
        os.close(parent)


def _copy_at(parent: int, name: str, destination: Path, *, private: bool):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('Installation directory changed during open: ' + name)
            destination.mkdir(mode=0o700)
            for child in os.listdir(descriptor):
                _copy_at(descriptor, child, destination / child, private=private)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Installation directory changed during capture: ' + name)
        finally:
            os.close(descriptor)
        os.chown(destination, 0, 0)
        destination.chmod(0o700 if private else 0o755)
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Refusing a linked or nonregular installation object: ' + name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
        if fingerprint(info) != fingerprint(opened):
            raise ValueError('Installation input changed during open: ' + name)
        with os.fdopen(descriptor, 'rb', closefd=False) as incoming, destination.open('xb') as output:
            shutil.copyfileobj(incoming, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if fingerprint(opened) != fingerprint(os.fstat(descriptor)) or fingerprint(opened) != fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            raise ValueError('Installation input changed during capture: ' + name)
    finally:
        os.close(descriptor)
    executable = bool(info.st_mode & 0o111)
    os.chown(destination, 0, 0)
    destination.chmod((0o700 if executable else 0o600) if private else (0o755 if executable else 0o644))


def validate_config(path: Path, root: Path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get('listen', '127.0.0.1:8788') not in ('', '127.0.0.1:8788'):
        raise ValueError('Native Linux controller configuration must use 127.0.0.1:8788')
    for key, name in (('modes_file', 'modes.json'), ('scripts_dir', 'modes'),
                      ('profiles_file', 'routers.json'), ('state_file', 'state.json')):
        if value.get(key, './' + name) not in ('', name, './' + name, str(root / name)):
            raise ValueError('Native Linux configuration must keep ' + key + ' inside its fixed installation')


def stage_application(source: Path, root: Path, stage: Path):
    captured_source = ordinary(source, directory=True)
    if root.exists() or root.is_symlink():
        ordinary(root, directory=True, trusted=True)
    for name in CODE_TREES | REQUIRED_FILES:
        ordinary(source / name, directory=name in CODE_TREES)
    for name in sorted(CODE_TREES | CODE_FILES):
        if (source / name).exists() or (source / name).is_symlink():
            copy_checked(source / name, stage / name)
    if root.exists():
        for child in root.iterdir():
            if child.name not in CODE_TREES | CODE_FILES:
                copy_checked(child, stage / child.name, private=True)
    for name in ('client.json', 'routers.json', 'generated'):
        if not (stage / name).exists():
            copy_checked(source / name, stage / name, private=True)
    validate_config(stage / 'client.json', root)
    # The only new trust root is the completed private staging directory.
    # Its parent remains 0700 until every engine verifies and promotion begins.
    for binary in ('router-vpn-client', 'router-vpn-app', 'router-vpn-dns',
                   'router-vpn-start-layer-relay', 'router-vpn-update'):
        if not os.access(stage / binary, os.X_OK):
            raise ValueError('Required native executable is not executable: ' + binary)
    final_source = ordinary(source, directory=True)
    if (captured_source.st_dev, captured_source.st_ino, captured_source.st_mtime_ns, captured_source.st_ctime_ns) != (final_source.st_dev, final_source.st_ino, final_source.st_mtime_ns, final_source.st_ctime_ns):
        raise ValueError('The source package changed during installation capture')


def verify_runtimes(stage: Path):
    for flag in ('--verify-native-runtime', '--verify-amnezia-runtime'):
        command([stage / 'router-vpn-client', flag, stage])
    command(['/usr/bin/python3', '-Es', stage / 'client/verify-bundled-xray.py', stage / 'runtime/xray'])


class SystemIntegration:
    def __init__(self, filesystem=Path('/'), run=command):
        self.filesystem, self.run = filesystem, run
        self.previous = []
        self.was_enabled = False
        self.legacy_enabled = False
        self.enable_attempted = False
        self.changed = False

    def path(self, name):
        return self.filesystem / name.lstrip('/')

    def write(self, name, data, mode=0o644):
        target = self.path(name)
        parents = []
        parent = target.parent
        while not parent.exists():
            parents.append(parent)
            parent = parent.parent
        while parent != self.filesystem.parent:
            ordinary(parent, directory=True, trusted=True)
            if parent == self.filesystem:
                break
            parent = parent.parent
        for directory in reversed(parents):
            directory.mkdir(mode=0o755)
        if target.exists() or target.is_symlink():
            info = ordinary(target, trusted=True)
            prior = (target.read_bytes(), stat.S_IMODE(info.st_mode))
        else:
            prior = None
        self.previous.append((target, prior))
        fd, temporary = tempfile.mkstemp(prefix='.routervpn-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
                os.fchown(stream.fileno(), 0, 0)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def install(self, root: Path):
        legacy = self.run(['/usr/bin/systemctl', 'is-active', 'router-vpn-client.service'], check=False)
        if legacy.returncode == 0:
            raise RuntimeError('Stop the legacy router-vpn-client service before upgrading to the native authenticated controller.')
        if legacy.returncode not in (3, 4):
            raise RuntimeError('Cannot prove that the legacy controller service is inactive')
        legacy = self.run(['/usr/bin/systemctl', 'is-enabled', 'router-vpn-client.service'], check=False)
        if legacy.returncode not in (0, 1, 3, 4):
            raise RuntimeError('Cannot read the legacy controller service enablement state')
        self.legacy_enabled = legacy.returncode == 0
        result = self.run(['/usr/bin/systemctl', 'is-enabled', EARLY_NAME], check=False)
        if result.returncode not in (0, 1, 3, 4):
            raise RuntimeError('Cannot read the existing early-protection service state')
        self.was_enabled = result.returncode == 0
        self.changed = True
        if self.legacy_enabled:
            self.run(['/usr/bin/systemctl', 'disable', 'router-vpn-client.service'])
        self.write('/usr/local/bin/router-vpn', LAUNCHER.encode(), 0o755)
        self.write('/usr/local/sbin/router-vpn-killswitch-recovery', RECOVERY.encode(), 0o755)
        self.write('/usr/share/applications/router-vpn.desktop', (root / 'router-vpn.desktop').read_bytes())
        self.write('/usr/share/icons/hicolor/256x256/apps/router-vpn.png', (root / 'router-vpn.png').read_bytes())
        self.write('/usr/share/polkit-1/actions/com.eabusham.routervpn.controller.policy',
                   (root / 'client/linux/com.eabusham.routervpn.controller.policy').read_bytes())
        self.write('/etc/systemd/system/' + EARLY_NAME, EARLY_UNIT.encode())
        for unit in NETWORK_UNITS:
            self.write('/etc/systemd/system/' + unit + '.d/50-router-vpn-protection.conf', NETWORK_DROPIN.encode())
        self.run(['/usr/bin/systemctl', 'daemon-reload'])
        self.enable_attempted = True
        self.run(['/usr/bin/systemctl', 'enable', EARLY_NAME])
        # Reassert directly without stopping a service required by an already
        # running network manager. Restarting that dependency can stop normal
        # networking even when Always is Off. Start activates an inactive unit
        # and leaves an already-active, successfully reasserted unit running.
        self.run(['/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                  'HOMEVPN_ROOT=' + str(root), '/usr/bin/python3', '-Es',
                  root / 'modes/kill-switch.py', 'reassert'])
        self.run(['/usr/bin/systemctl', 'start', EARLY_NAME])

    def rollback(self):
        if not self.changed:
            return
        if self.enable_attempted and not self.was_enabled:
            self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME])
        for target, prior in reversed(self.previous):
            if prior is None:
                target.unlink(missing_ok=True)
            else:
                data, mode = prior
                with target.open('wb') as stream:
                    stream.write(data)
                target.chmod(mode)
        self.run(['/usr/bin/systemctl', 'daemon-reload'])
        if self.legacy_enabled:
            self.run(['/usr/bin/systemctl', 'enable', 'router-vpn-client.service'])


def install(source: Path, root=ROOT, *, integration=None, verifier=verify_runtimes, proc=Path('/proc')):
    if os.geteuid() != 0:
        raise PermissionError('Run the native installer with sudo.')
    integration = integration if integration is not None else SystemIntegration()
    with installation_lock(root):
        prefix = '.' + root.name + '.install-'
        pending = list(root.parent.glob(prefix + '*'))
        if pending:
            raise RuntimeError('An interrupted native installation needs recovery; retained files: ' + ', '.join(map(str, pending)))
        reject_running_previous(root, proc)
        temporary = Path(tempfile.mkdtemp(prefix=prefix, dir=root.parent))
        stage, previous = temporary / 'new', temporary / 'previous'
        stage.mkdir(mode=0o700)
        os.chown(stage, 0, 0)
        promoted = False
        try:
            stage_application(source, root, stage)
            verifier(stage)
            # An old application cannot acquire the shared launch lock while
            # staged state is captured. Recheck legacy executables as well.
            reject_running_previous(root, proc)
            if root.exists():
                os.rename(root, previous)
            os.rename(stage, root)
            promoted = True
            root.chmod(0o755)
            integration.install(root)
        except BaseException:
            if promoted:
                try:
                    integration.rollback()
                    os.rename(root, stage)
                    if previous.exists():
                        os.rename(previous, root)
                except BaseException as rollback_error:
                    raise RuntimeError('Installation rollback needs recovery; previous bytes retained at ' + str(temporary)) from rollback_error
            elif previous.exists():
                os.rename(previous, root)
            shutil.rmtree(temporary)
            raise
        shutil.rmtree(temporary)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: install-linux-native.py /path/to/extracted/native/package')
    try:
        ordinary(Path('/'), directory=True, trusted=True)
        ordinary(Path('/opt'), directory=True, trusted=True)
        if not Path('/run/systemd/system').is_dir():
            raise RuntimeError('This native installer requires a running systemd manager for persistent Always protection.')
        install(Path(os.path.abspath(sys.argv[1])))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('Router VPN installation failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
    print('Router VPN installed. Open Router VPN from the application menu and approve its administrator request.')
    print('Linked nodes and private state were preserved. Emergency local recovery: sudo router-vpn-killswitch-recovery')
