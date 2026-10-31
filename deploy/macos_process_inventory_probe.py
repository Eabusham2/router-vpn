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
        record.update(uniqueid=info.uniqueid, idversion=info.idversion, main_uuid=bytes(info.uuid).hex())
    return record


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
