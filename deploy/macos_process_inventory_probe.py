"""Bounded observations for a refused macOS installer inventory.

This is a diagnostic, never an executable-identity or installation admission
source. Region vnodes do not identify p_textvp. In particular, flavor 22 uses
EINVAL for both the end of the map and failure to retain a mapped vnode.

The fixed ABI and behavior below are from Apple's XNU source:
https://github.com/apple-oss-distributions/xnu/tree/43a90889846e00bfb5cf1d255cdc0a701a1e05a4
bsd/sys/proc_info.h, bsd/sys/proc_info_private.h, bsd/kern/proc_info.c
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import sys
import time


class NativeUniqueInfo(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_ubyte * 16), ('uniqueid', ctypes.c_uint64),
                ('parent_uniqueid', ctypes.c_uint64), ('idversion', ctypes.c_int32),
                ('parent_idversion', ctypes.c_int32), ('reserved', ctypes.c_uint64 * 2)]


class NativeRegionInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ('protection', 'max_protection', 'inheritance', 'flags')]
    _fields_ += [('offset', ctypes.c_uint64)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'behavior', 'wired_count', 'tag', 'resident', 'shared_private', 'swapped',
        'dirtied', 'ref_count', 'shadow_depth', 'share_mode', 'private_resident',
        'shared_resident', 'object_id', 'depth')]
    _fields_ += [('address', ctypes.c_uint64), ('size', ctypes.c_uint64)]


class NativeVnodeStat(ctypes.Structure):
    _fields_ = [('dev', ctypes.c_uint32), ('mode', ctypes.c_uint16), ('nlink', ctypes.c_uint16),
                ('ino', ctypes.c_uint64), ('uid', ctypes.c_uint32), ('gid', ctypes.c_uint32)]
    _fields_ += [(name, ctypes.c_int64) for name in (
        'atime', 'atime_ns', 'mtime', 'mtime_ns', 'ctime', 'ctime_ns', 'birthtime',
        'birthtime_ns', 'size', 'blocks')]
    _fields_ += [('blksize', ctypes.c_int32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ('flags', 'generation', 'rdev')]
    _fields_ += [('reserved', ctypes.c_int64 * 2)]


class NativeRegionVnode(ctypes.Structure):
    _fields_ = [('region', NativeRegionInfo), ('vnode', NativeVnodeStat),
                ('vnode_type', ctypes.c_int32), ('padding', ctypes.c_int32),
                ('fsid', ctypes.c_int32 * 2), ('path', ctypes.c_char * 1024)]


def check_layout():
    if (sys.byteorder != 'little' or ctypes.sizeof(ctypes.c_void_p) != 8 or
            ctypes.sizeof(NativeUniqueInfo) != 56 or NativeUniqueInfo.idversion.offset != 32 or
            ctypes.sizeof(NativeRegionInfo) != 96 or NativeRegionInfo.address.offset != 80 or
            ctypes.sizeof(NativeVnodeStat) != 136 or NativeVnodeStat.ino.offset != 8 or
            ctypes.sizeof(NativeRegionVnode) != 1272 or NativeRegionVnode.path.offset != 248):
        raise ValueError('Diagnostic native ABI is not the recorded 64-bit Darwin layout')


def identity(library, pid):
    info = NativeUniqueInfo()
    ctypes.set_errno(0)
    size = library.proc_pidinfo(pid, 17, 1, ctypes.byref(info), ctypes.sizeof(info))
    record = {'result': size, 'errno': ctypes.get_errno(), 'expected': ctypes.sizeof(info)}
    if size == ctypes.sizeof(info) and info.uniqueid and info.idversion > 0:
        record.update(uniqueid=info.uniqueid, idversion=info.idversion, main_uuid=bytes(info.uuid).hex(),
                      original_parent_uniqueid=info.parent_uniqueid,
                      original_parent_idversion=info.parent_idversion)
    return record


def process_state(library, pid, bsd_type):
    if ctypes.sizeof(bsd_type) != 136 or any(getattr(bsd_type, name).offset != offset for name, offset in (
            ('pbi_status', 4), ('pbi_pid', 12), ('pbi_ppid', 16), ('pbi_uid', 20),
            ('pbi_start_tvsec', 120), ('pbi_start_tvusec', 128))):
        raise ValueError('Diagnostic parent state lost its exact Darwin ABI')
    info = bsd_type()
    ctypes.set_errno(0)
    size = library.proc_pidinfo(pid, 3, 1, ctypes.byref(info), ctypes.sizeof(info))
    result = {'result': size, 'errno': ctypes.get_errno(), 'expected': ctypes.sizeof(info)}
    if size != ctypes.sizeof(info) or info.pbi_pid != pid or not info.pbi_start_tvsec or info.pbi_start_tvusec >= 1000000:
        return result
    def name(value, limit):
        allowed = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'
        return ''.join(chr(byte) if byte in allowed else '?' for byte in bytes(value)[:limit].split(b'\0', 1)[0])
    result.update(pid=info.pbi_pid, ppid=info.pbi_ppid, uid=info.pbi_uid, gid=info.pbi_gid,
                  status=info.pbi_status, start_seconds=info.pbi_start_tvsec, start_microseconds=info.pbi_start_tvusec,
                  comm=name(info.pbi_comm, 16), name=name(info.pbi_name, 32))
    return result


def observe_parentage(library, pid, bsd_type):
    """At most three later process observations; never original lookup authority."""
    if type(pid) is not int or not 0 < pid < 2**31:
        raise ValueError('Diagnostic parentage requires the refused numeric PID')
    check_layout()
    report = {'admission_authority': False, 'original_lookup_identity_proved': False, 'records': []}
    seen = set()
    deadline = time.monotonic() + 0.2
    try:
        for _ in range(3):
            if time.monotonic() >= deadline:
                report['stop'] = 'time-bound'
                break
            if pid in seen or not 0 < pid < 2**31:
                report['stop'] = 'parent-cycle-or-boundary'
                break
            seen.add(pid)
            before = identity(library, pid)
            state = process_state(library, pid, bsd_type)
            after = identity(library, pid)
            state_after = process_state(library, pid, bsd_type)
            stable = ('uniqueid' in before and 'uniqueid' in after and 'pid' in state and
                      before == after and state == state_after)
            record = {'before': before, 'state': state, 'after': after, 'state_after': state_after,
                      'same_later_process_observation': stable}
            if report['records']:
                child = report['records'][-1]
                # XNU reports the original parent's generation. Reparenting or
                # a parent exec is not silently adopted as the same witness.
                record['matches_child_original_parent_generation'] = bool(stable and
                    child['same_later_process_observation'] and
                    child['after'].get('original_parent_uniqueid', 0) > 0 and
                    child['after'].get('original_parent_idversion', 0) > 0 and
                    child['after']['original_parent_uniqueid'] == after['uniqueid'] and
                    child['after']['original_parent_idversion'] == after['idversion'])
            report['records'].append(record)
            if not stable:
                report['stop'] = 'identity-unavailable-or-changed'
                break
            if state['ppid'] == 0:
                report['stop'] = 'no-current-parent'
                break
            pid = state['ppid']
        else:
            report['stop'] = 'record-bound'
    except Exception as error:
        report['stop'] = 'diagnostic-error'
        report['error_type'] = type(error).__name__
    return report


def load_baseline(path):
    """Read bounded comparison data; it never supplies native authority."""
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 65536:
            raise ValueError('Diagnostic baseline is not a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        if len(raw) != info.st_size or len(raw) > 65536:
            raise ValueError('Diagnostic baseline changed size while reading')
        value = json.loads(raw)
        if (type(value) is not dict or set(value) != {'schema', 'phase', 'admission_authority', 'observed_unix_ns', 'records', 'failure_type'} or
                type(value['schema']) is not int or value['schema'] != 1 or value['phase'] != 'before-fixtures' or value['admission_authority'] is not False or
                type(value['observed_unix_ns']) is not int or value['observed_unix_ns'] <= 0 or
                type(value['records']) is not list or len(value['records']) > 1):
            raise ValueError('Diagnostic baseline has no bounded pre-fixture schema')
        return value
    finally:
        os.close(descriptor)


def comparison_identity(record):
    """Extract comparison fields only from a stable later native observation."""
    lineage = record['later_parentage']['records']
    if type(lineage) is not list or not 0 < len(lineage) <= 3:
        raise ValueError('Diagnostic baseline has no bounded process observation')
    first = lineage[0]
    if (first['same_later_process_observation'] is not True or first['before'] != first['after'] or
            first['state'] != first['state_after']):
        raise ValueError('Diagnostic comparison lost its later process generation')
    state, identity_record = first['state'], first['after']
    if type(record['requested_pid']) is not int or record['requested_pid'] != state['pid']:
        raise ValueError('Diagnostic comparison changed its requested PID')
    fields = (state['pid'], state['start_seconds'], state['start_microseconds'],
              identity_record['uniqueid'], identity_record['idversion'])
    if (any(type(value) is not int for value in fields) or not 0 < fields[0] < 2**31 or fields[1] <= 0 or
            not 0 <= fields[2] < 1000000 or fields[3] <= 0 or fields[4] <= 0):
        raise ValueError('Diagnostic comparison has invalid process fields')
    uuid = identity_record['main_uuid']
    if type(uuid) is not str or len(uuid) != 32 or any(char not in '0123456789abcdef' for char in uuid):
        raise ValueError('Diagnostic comparison has invalid UUID bytes')
    return (*fields, uuid)


def compare_baseline(baseline, current):
    result = {'admission_authority': False, 'saved_data_is_authority': False,
              'same_later_process_as_before_fixtures': False}
    try:
        if not baseline or len(baseline['records']) != 1:
            result['reason'] = 'no-pre-fixture-refusal-record'
            return result
        if not baseline['observed_unix_ns'] < current['observed_unix_ns']:
            raise ValueError('Diagnostic baseline does not precede the later observation')
        result['same_later_process_as_before_fixtures'] = (
            comparison_identity(baseline['records'][0]) == comparison_identity(current))
        result['reason'] = 'comparison-only'
    except Exception as error:
        result['reason'] = 'comparison-unavailable'
        result['error_type'] = type(error).__name__
    return result


def fixture_image(path, role):
    """Log only the actual compiled fixture's file object, before its launch."""
    if type(role) is not str or not 0 < len(role) <= 64 or any(char not in 'abcdefghijklmnopqrstuvwxyz-' for char in role):
        raise ValueError('Diagnostic fixture role is not bounded')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise ValueError('Diagnostic fixture image is not an owned regular file')
        return {'role': role, 'dev': info.st_dev & 0xffffffff, 'ino': info.st_ino, 'mode': info.st_mode,
                'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink, 'size': info.st_size}
    finally:
        os.close(descriptor)


def observe(library, pid):
    """Observe at most 16 mappings; no result authorizes a skipped process."""
    if type(pid) is not int or not 0 < pid < 2**31:
        raise ValueError('Diagnostic requires the refused numeric PID')
    check_layout()
    report = {'admission_authority': False, 'main_image_identified': False,
              'complete_mapping_inventory': False, 'pid': pid, 'regions': []}
    deadline = time.monotonic() + 0.2
    try:
        report['before'] = identity(library, pid)
        if 'uniqueid' not in report['before']:
            report['stop'] = 'identity-unavailable'
            return report
        address = 0
        for _ in range(16):
            if time.monotonic() >= deadline:
                report['stop'] = 'time-bound'
                break
            info = NativeRegionVnode()
            ctypes.set_errno(0)
            size = library.proc_pidinfo(pid, 22, address, ctypes.byref(info), ctypes.sizeof(info))
            error = ctypes.get_errno()
            if size != ctypes.sizeof(info):
                # EINVAL is deliberately not interpreted as complete absence.
                report['stop'] = 'native-result-not-absence'
                report['last_result'] = {'result': size, 'errno': error, 'expected': ctypes.sizeof(info)}
                break
            region, vnode = info.region, info.vnode
            end = region.address + region.size
            if region.address < address or not region.size or not address < end < 2**64:
                report['stop'] = 'malformed-region'
                break
            path = bytes(info.path)
            report['regions'].append({
                'address': region.address, 'size': region.size, 'offset': region.offset,
                'protection': region.protection, 'max_protection': region.max_protection,
                'dev': vnode.dev, 'ino': vnode.ino, 'mode': vnode.mode,
                'nlink': vnode.nlink, 'uid': vnode.uid, 'gid': vnode.gid,
                'vnode_type': info.vnode_type, 'path_bytes': len(path),
                'path_sha256': hashlib.sha256(path).hexdigest(),
            })
            address = end
        else:
            report['stop'] = 'record-bound'
    except Exception as error:
        report['stop'] = 'diagnostic-error'
        report['error_type'] = type(error).__name__
    finally:
        try:
            report['after'] = identity(library, pid)
        except Exception as error:
            report['after'] = {'error_type': type(error).__name__}
        before, after = report.get('before', {}), report['after']
        # This fences only these later diagnostic reads. It does not bind them
        # to the earlier failed shipping lookup or identify its executable.
        report['same_later_exec_observation'] = ('uniqueid' in before and 'uniqueid' in after and
            all(before[name] == after[name] for name in ('uniqueid', 'idversion', 'main_uuid')))
    return report
