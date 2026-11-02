"""Transfer one retained installer lock to its exact reassert descendants.

The channel and received open file description are the authority. Numeric fd
arguments and a transaction generation merely select and bind that authority.
No borrower releases the flock: closing a duplicate preserves live descendants.
"""
from __future__ import annotations

import array
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import threading
import time

ROOT = Path('/opt/router-vpn-client')
LOCK = ROOT.with_name(ROOT.name + '.install.lock')
LIMIT = 1024
FIELDS = {'schema', 'generation', 'operation', 'phase', 'sequence', 'pid',
          'device', 'inode', 'root_device', 'root_inode', 'lease_device', 'lease_inode'}
PHASES = ('reassert', 'plan', 'apply', 'reference')
_ACTIVE = None


class RetainedAuthorityError(RuntimeError):
    """Current root/journal and original backup must remain available."""


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError('installer capability has duplicate fields')
        value[key] = item
    return value


def _frame(value):
    if (type(value) is not dict or set(value) != FIELDS or
            type(value['schema']) is not int or value['schema'] != 1 or
            type(value['generation']) is not str or not re.fullmatch('[0-9a-f]{32}', value['generation']) or
            value['operation'] not in ('adopt', 'grant', 'ready', 'ack', 'done', 'mutation') or
            value['phase'] not in PHASES):
        raise RuntimeError('installer capability has a malformed transaction')
    for key, low, high in (('sequence', 0, 64), ('pid', 1, 2**31-1),
                           ('device', 0, 2**64-1), ('inode', 0, 2**64-1),
                           ('lease_device', 0, 2**64-1), ('lease_inode', 0, 2**64-1),
                           ('root_device', 0, 2**64-1), ('root_inode', 0, 2**64-1)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise RuntimeError('installer capability has an invalid numeric identity')
    return value


def _send(channel, value, descriptors=()):
    body = json.dumps(_frame(value), separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(body) > LIMIT:
        raise RuntimeError('installer capability exceeds its private bound')
    raw = struct.pack('!I', len(body)) + body
    ancillary = [] if not descriptors else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', descriptors))]
    if channel.sendmsg([raw], ancillary) != len(raw):
        raise RuntimeError('installer capability transfer was incomplete')


def _exact(channel, size, prefix=b''):
    while len(prefix) < size:
        part = channel.recv(size-len(prefix))
        if not part:
            raise EOFError('installer capability owner closed its channel')
        prefix += part
    return prefix


def _receive(channel, *, descriptors=0):
    header, ancillary, flags, _ = channel.recvmsg(4, socket.CMSG_SPACE(4*4))
    if not header:
        raise EOFError('installer capability owners have closed')
    received, foreign = [], False
    for level, kind, raw in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(raw) % array.array('i').itemsize:
            foreign = True
            continue
        values = array.array('i'); values.frombytes(raw)
        received.extend(values)
    try:
        if foreign or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(received) != descriptors:
            raise RuntimeError('installer capability has another descriptor count')
        header = _exact(channel, 4, header)
        size = struct.unpack('!I', header)[0]
        if not 0 < size <= LIMIT:
            raise RuntimeError('installer capability frame exceeds its bound')
        value = _frame(json.loads(_exact(channel, size).decode('ascii'), object_pairs_hook=_object))
        for fd in received:
            os.set_inheritable(fd, False)
        return value, received
    except BaseException:
        for fd in received:
            os.close(fd)
        raise


def _ordinary(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not kind or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o6022:
        raise RuntimeError('installer capability object is not protected')
    return info


def _identity(descriptor, root_info):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('installer capability requires the original root helper')
    for path in (ROOT.parent, *ROOT.parent.parents):
        _ordinary(path, directory=True)
    current_root = _ordinary(ROOT, directory=True)
    if not os.path.samestat(current_root, root_info):
        raise RuntimeError('installer capability belongs to another installed generation')
    named, actual = _ordinary(LOCK), os.fstat(descriptor)
    if not os.path.samestat(named, actual) or actual.st_mode & 0o777 != 0o600:
        raise RuntimeError('installer capability has another original lock')
    return actual


def _locked_file(descriptor, path):
    info, named = os.fstat(descriptor), _ordinary(path)
    if not os.path.samestat(info, named) or info.st_mode & 0o777 != 0o600:
        raise RuntimeError('installer capability has another original locked file')
    probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not os.path.samestat(os.fstat(probe), info):
            raise RuntimeError('installer lock changed during capability validation')
        try:
            fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise RuntimeError('installer capability was released or downgraded')
        # The issuer retains the original EX while this executes. A separate
        # open description cannot borrow it. The issuer rechecks before ACK,
        # so this assertion alone never authorizes a later mutation.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(probe)
    return info


def _locked(descriptor, root_info):
    _identity(descriptor, root_info)
    return _locked_file(descriptor, LOCK)


def _peer(channel, expected):
    info = os.fstat(channel.fileno())
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
            channel.getsockname() != '' or channel.getpeername() != ''):
        raise RuntimeError('installer capability is not its inherited anonymous root stream')
    # These are Darwin's public xucred and LOCAL_PEERPID interfaces. Pipe
    # metadata, a process name, or a caller-supplied PID never supplies trust.
    raw = channel.getsockopt(0, 1, 76)
    version, uid, groups, _, *_ = struct.unpack('=IIhh16I', raw)
    pid = struct.unpack('=i', channel.getsockopt(0, 2, 4))[0]
    if version != 0 or uid != 0 or not 1 <= groups <= 16 or pid != expected:
        raise RuntimeError('installer capability has another original kernel peer')


def _record(generation, operation, phase, sequence, pid, lock, root, lease=None):
    return dict(schema=1, generation=generation, operation=operation, phase=phase,
                sequence=sequence, pid=pid, device=lock.st_dev, inode=lock.st_ino,
                root_device=root.st_dev, root_inode=root.st_ino,
                lease_device=lease.st_dev if lease else 0, lease_inode=lease.st_ino if lease else 0)


def _lease_directory(generation):
    return ROOT/'run'/('install-'+generation)


def _private_directory(path):
    info = _ordinary(path, directory=True)
    if info.st_mode & 0o777 != 0o700:
        raise RuntimeError('installer borrower directory is not private')
    return info


class _Broker:
    def __init__(self, descriptor, deadline):
        self.descriptor, self.deadline = descriptor, deadline
        self.root = _ordinary(ROOT, directory=True)
        self.lock = _locked(self.descriptor, self.root)
        self.generation = secrets.token_hex(16)
        try:
            (ROOT/'run').mkdir(mode=0o700)
        except FileExistsError:
            pass
        self.run_info = _private_directory(ROOT/'run')
        self.directory = _lease_directory(self.generation)
        self.directory.mkdir(mode=0o700)
        self.directory_info = _private_directory(self.directory)
        self.leases = {}
        self.parent, self.child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        duplicate = None
        try:
            duplicate = os.dup(descriptor)
            os.set_inheritable(duplicate, False)
            self.descriptor = duplicate
        except BaseException:
            if duplicate is not None:
                os.close(duplicate)
            self.parent.close()
            self.child.close()
            if os.path.samestat(self.directory_info, _private_directory(self.directory)):
                self.directory.rmdir()
            raise
        self.active, self.pending = {}, None
        self.error = None
        self.reassert_complete = False
        self.mutation_possible = False
        self.drained = False
        self.eof = threading.Event()
        self.thread = threading.Thread(target=self._serve, name='routervpn-installer-capability', daemon=True)

    def _current(self):
        if not os.path.samestat(_locked(self.descriptor, self.root), self.lock):
            raise RuntimeError('installer original lock changed before acknowledgement')
        if (not os.path.samestat(self.run_info, _private_directory(ROOT/'run')) or
                not os.path.samestat(self.directory_info, _private_directory(self.directory))):
            raise RuntimeError('installer borrower directory changed its original owner')

    def _lease(self, sequence):
        path = self.directory/('lease-'+str(sequence))
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        probe = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = _locked_file(descriptor, path)
            probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            if not os.path.samestat(info, os.fstat(probe)):
                raise RuntimeError('installer borrower lease changed before transfer')
            self.leases[sequence] = {'path': path, 'issuer': descriptor, 'probe': probe, 'info': info}
            return descriptor, info
        except BaseException:
            if probe is not None:
                os.close(probe)
            os.close(descriptor)
            raise

    def _retire_leases(self):
        # Channel EOF is not process retirement: a half-closed peer can still
        # hold its capabilities. Acquire every original lease independently.
        joined = True
        for lease in self.leases.values():
            if lease['issuer'] is not None:
                os.close(lease['issuer'])
                lease['issuer'] = None
            try:
                while True:
                    try:
                        fcntl.flock(lease['probe'], fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= self.deadline:
                            raise TimeoutError('installer borrower lease did not retire')
                        time.sleep(min(0.01, max(0, self.deadline-time.monotonic())))
                self._current()
                if not os.path.samestat(lease['info'], _ordinary(lease['path'])):
                    raise RuntimeError('installer cannot remove another borrower lease')
                lease['path'].unlink()
            except BaseException:
                joined = False
            finally:
                os.close(lease['probe'])
        if joined:
            try:
                self._current()
                self.directory.rmdir()
            except BaseException:
                joined = False
        self.drained = joined

    def _timeout(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('installer capability did not join before its original deadline')
        self.parent.settimeout(remaining)

    def _serve(self):
        sequence = 0
        try:
            while True:
                self._timeout()
                frame, _ = _receive(self.parent)
                if frame['generation'] != self.generation:
                    raise RuntimeError('installer capability has a stale generation')
                phase = frame['phase']
                if frame['operation'] == 'adopt':
                    if (frame != _record(self.generation, 'adopt', phase, 0, frame['pid'], self.lock, self.root) or sequence >= 64 or
                            phase == 'reassert' and sequence != 0 or
                            phase != 'reassert' and not any(row['phase'] == 'reassert' for row in self.active.values())):
                        raise RuntimeError('installer capability has an unowned phase')
                    self._current()
                    sequence += 1
                    lease_fd, lease_info = self._lease(sequence)
                    grant = _record(self.generation, 'grant', phase, sequence, os.getpid(), self.lock, self.root, lease_info)
                    self.pending = grant
                    _send(self.parent, grant, (self.descriptor, lease_fd))
                    ready, _ = _receive(self.parent)
                    if ready != {**grant, 'operation': 'ready', 'pid': frame['pid']}:
                        raise RuntimeError('installer capability adoption changed its transaction')
                    self._current()
                    self.active[sequence], self.pending = ready, None
                    if phase == 'apply':
                        self.mutation_possible = True
                    _send(self.parent, {**grant, 'operation': 'ack'})
                    os.close(lease_fd)
                    self.leases[sequence]['issuer'] = None
                elif frame['operation'] in ('done', 'mutation'):
                    captured = self.active.get(frame['sequence'])
                    if captured is None or frame != {**captured, 'operation': frame['operation']}:
                        raise RuntimeError('installer capability completion has another owner')
                    self._current()
                    if frame['operation'] == 'mutation':
                        if phase != 'reassert':
                            raise RuntimeError('installer mutation notice has another action')
                        self.mutation_possible = True
                        _send(self.parent, {**captured, 'operation': 'ack', 'pid': os.getpid()})
                    else:
                        if phase == 'reassert':
                            if len(self.active) != 1:
                                raise RuntimeError('installer reassert ended before its native borrowers')
                            self.reassert_complete = True
                        del self.active[frame['sequence']]
                else:
                    raise RuntimeError('installer capability has an unexpected operation')
        except EOFError:
            self.eof.set()
            if self.active or self.pending is not None or not self.reassert_complete:
                self.error = 'installer borrower ended without its completion receipt'
        except BaseException:
            self.error = 'installer capability validation or join failed'
            # Failed validation never creates permission to roll back. Stop
            # acknowledgements, then wait for every inherited endpoint to close.
            try:
                self.parent.shutdown(socket.SHUT_WR)
                while True:
                    self._timeout()
                    if not self.parent.recv(LIMIT):
                        self.eof.set()
                        break
            except (OSError, TimeoutError):
                pass
        finally:
            self.parent.close()
            self._retire_leases()
            os.close(self.descriptor)


def run_reassert(root, descriptor):
    if root != ROOT:
        raise RuntimeError('installer capability requires the fixed protected installation')
    # Preserve the existing installer command's 120-second absolute deadline.
    deadline = time.monotonic()+120
    broker = _Broker(descriptor, deadline)
    child = None
    failure = None
    try:
        arguments = [str(ROOT/'bin/python3'), str(ROOT/'modes/kill-switch-platform.py'),
                     'reassert-install', str(broker.child.fileno()), broker.generation, str(os.getpid())]
        child = subprocess.Popen(arguments, cwd='/', stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={'PATH': str(ROOT/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin',
                                      'HOMEVPN_ROOT': str(ROOT), 'LC_ALL': 'C', 'HOME': '/var/root'},
                                 close_fds=True, pass_fds=(broker.child.fileno(),))
        broker.child.close()
        broker.thread.start()
        try:
            child.wait(timeout=max(0, deadline-time.monotonic()))
        except BaseException as error:
            failure = error
    except BaseException as error:
        failure = error
    finally:
        try:
            broker.child.close()
            if child is not None and child.poll() is None:
                child.kill()
                # Join this exact direct child. There are no captured output
                # pipes on which a retained descendant can block this wait.
                child.wait()
        except BaseException as error:
            failure = failure or error
        try:
            if broker.thread.ident is not None:
                broker.thread.join(timeout=max(0, deadline-time.monotonic()))
            else:
                broker.parent.close()
                broker._retire_leases()
                os.close(broker.descriptor)
        except BaseException as error:
            failure = failure or error
    if ((child is not None and child.poll() is None) or
            (broker.thread.ident is not None and not broker.eof.is_set()) or
            not broker.drained or broker.thread.is_alive()):
        raise RetainedAuthorityError('installer reassert ownership did not join; retain its current protection journal') from failure
    if failure is not None or child is None or child.returncode or broker.error or not broker.reassert_complete:
        if broker.mutation_possible:
            raise RetainedAuthorityError('installer reassert may have changed protection; retain its current journal and original backup') from failure
        raise RuntimeError('the owned macOS reassert did not complete before protection mutation') from failure
    return {'joined': True, 'mutation_possible': broker.mutation_possible}


class _Borrowed:
    def __init__(self, channel, generation, issuer):
        self.channel, self.generation, self.issuer = channel, generation, issuer
        self.root = _ordinary(ROOT, directory=True)
        self.descriptor, self.lease, self.ready = None, None, None
        self.adopted = False
        self.finished = False

    def acquire(self):
        _peer(self.channel, self.issuer)
        request = _record(self.generation, 'adopt', 'reassert', 0, os.getpid(), _ordinary(LOCK), self.root)
        _send(self.channel, request)
        grant, descriptors = _receive(self.channel, descriptors=2)
        self.descriptor, self.lease = descriptors
        actual = _locked(self.descriptor, self.root)
        _private_directory(ROOT/'run')
        directory = _lease_directory(self.generation)
        _private_directory(directory)
        lease_info = _locked_file(self.lease, directory/('lease-'+str(grant['sequence'])))
        expected = _record(self.generation, 'grant', 'reassert', grant['sequence'], self.issuer, actual, self.root, lease_info)
        if grant != expected or not grant['sequence']:
            raise RuntimeError('installer capability belongs to another transaction')
        self.ready = {**grant, 'operation': 'ready', 'pid': os.getpid()}
        _send(self.channel, self.ready)
        ack, _ = _receive(self.channel)
        _peer(self.channel, self.issuer)
        if ack != {**grant, 'operation': 'ack'}:
            raise RuntimeError('installer did not acknowledge its original locked capability')
        self.adopted = True

    def duplicate_lock(self):
        if self.finished or not self.adopted or self.descriptor is None:
            raise RuntimeError('installer capability is no longer owned')
        _identity(self.descriptor, self.root)
        descriptor = os.dup(self.descriptor)
        os.set_inheritable(descriptor, False)
        return descriptor

    def process_fds(self):
        return (self.channel.fileno(), self.descriptor, self.lease)

    def native_arguments(self, phase):
        if phase not in ('plan', 'apply', 'reference') or self.finished or not self.adopted:
            raise RuntimeError('installer capability cannot select another native operation')
        return ['--darwin-owned-pf-install', phase, str(self.channel.fileno()), self.generation, str(self.issuer)]

    def mutation(self):
        if self.finished or not self.adopted:
            raise RuntimeError('installer mutation has no acknowledged original owner')
        _send(self.channel, {**self.ready, 'operation': 'mutation'})
        ack, _ = _receive(self.channel)
        _peer(self.channel, self.issuer)
        if ack != {**self.ready, 'operation': 'ack', 'pid': self.issuer}:
            raise RuntimeError('installer did not retain its possible protection mutation')

    def close(self):
        try:
            if self.adopted:
                _send(self.channel, {**self.ready, 'operation': 'done'})
        finally:
            self.finished = True
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None
            if self.lease is not None:
                os.close(self.lease)
                self.lease = None
            self.channel.close()


@contextlib.contextmanager
def borrow(descriptor, generation, issuer):
    global _ACTIVE
    if (_ACTIVE is not None or type(descriptor) is not int or not 3 <= descriptor <= 2**31-1 or
            type(issuer) is not int or not 0 < issuer <= 2**31-1 or type(generation) is not str or
            not re.fullmatch('[0-9a-f]{32}', generation)):
        raise RuntimeError('installer reassert lacks one bounded inherited capability')
    channel = socket.socket(fileno=descriptor)
    channel.settimeout(3)
    owner = _Borrowed(channel, generation, issuer)
    try:
        owner.acquire()
        _ACTIVE = owner
        yield owner
    finally:
        _ACTIVE = None
        owner.close()


def current():
    return _ACTIVE


def possible_mutation():
    if _ACTIVE is not None:
        _ACTIVE.mutation()
