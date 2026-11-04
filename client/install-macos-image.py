#!/usr/bin/env python3
"""Bounded Mach-O identity capture for the native installer.

These CodeDirectory identifiers are not a signature verification, a complete
installation inventory, or permission to ignore a live process. The installer
must establish those authorities independently before comparing identifiers.

Apple's CS_OPS_CDHASH reads p_textvp/p_textoff, not an arbitrary mapped vnode.
csops_audittoken additionally compares the supplied PID/idversion with the
retained process; the other supplied token fields are not authentication.
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/ubc_subr.c
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/cs_blobs.h

The separate executable UUID is the depth-1 LC_UUID installed in p_uuid;
PROC_PIDUNIQIDENTIFIERINFO returns that field independently of p_textvp.
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/mach_loader.c
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c
https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
import struct
import sys

IMAGE_LIMIT = 1024 * 1024 * 1024
SIGNATURE_LIMIT = 32 * 1024 * 1024
THIN = {b'\xce\xfa\xed\xfe': ('<', 28), b'\xcf\xfa\xed\xfe': ('<', 32),
        b'\xfe\xed\xfa\xce': ('>', 28), b'\xfe\xed\xfa\xcf': ('>', 32)}
FAT = {b'\xca\xfe\xba\xbe': ('>', 20), b'\xbe\xba\xfe\xca': ('<', 20),
       b'\xca\xfe\xba\xbf': ('>', 32), b'\xbf\xba\xfe\xca': ('<', 32)}
HASHES = {1: ('sha1', 20), 2: ('sha256', 32), 3: ('sha256', 20), 4: ('sha384', 48)}


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def code_directory_hash(blob):
    """Hash the complete bounded CodeDirectory exactly as XNU does.

    The caller still needs actual codesign verification of the original image.
    All supported alternatives are retained; choosing one by host architecture
    or preferred hash type could incorrectly exclude a previously running slice.
    """
    if len(blob) < 44:
        raise ValueError('Truncated Mach-O CodeDirectory')
    magic, length, version = struct.unpack_from('>III', blob)
    if magic != 0xfade0c02 or length != len(blob) or not 0x20000 <= version <= 0x20600:
        raise ValueError('Unsupported Mach-O CodeDirectory identity')
    minimum = 108 if version >= 0x20600 else 96 if version >= 0x20500 else 88 if version >= 0x20400 else 64 if version >= 0x20300 else 52 if version >= 0x20200 else 48 if version >= 0x20100 else 44
    if len(blob) < minimum:
        raise ValueError('CodeDirectory version exceeds its captured fields')
    hash_offset, identifier, special, pages = struct.unpack_from('>IIII', blob, 16)
    hash_size, hash_type = blob[36:38]
    if hash_type not in HASHES or hash_size != HASHES[hash_type][1]:
        raise ValueError('Unknown CodeDirectory digest cannot prove image exclusion')
    if (not minimum <= identifier < len(blob) or b'\0' not in blob[identifier:] or
            hash_offset < minimum or hash_offset > len(blob) or
            special * hash_size > hash_offset - minimum or
            pages * hash_size > len(blob) - hash_offset):
        raise ValueError('Invalid CodeDirectory identifier or digest bounds')
    return hashlib.new(HASHES[hash_type][0], blob).digest()[:20].hex()


def signature_hashes(data):
    if len(data) < 8:
        raise ValueError('Truncated Mach-O signature')
    magic, length = struct.unpack_from('>II', data)
    if not 8 <= length <= len(data):
        raise ValueError('Invalid Mach-O signature size')
    if magic == 0xfade0c02:
        return {code_directory_hash(data[:length])}
    if magic != 0xfade0cc0 or length < 12:
        raise ValueError('Unsupported Mach-O signature container')
    count = struct.unpack_from('>I', data, 8)[0]
    if not 0 < count <= 64 or 12 + 8 * count > length:
        raise ValueError('Unbounded Mach-O signature entries')
    ranges, slots, hashes = [], set(), set()
    for index in range(count):
        slot, offset = struct.unpack_from('>II', data, 12 + index * 8)
        if slot in slots or not 12 + 8 * count <= offset <= length - 8:
            raise ValueError('Duplicate or invalid Mach-O signature entry')
        slots.add(slot)
        sublength = struct.unpack_from('>I', data, offset + 4)[0]
        if sublength < 8 or sublength > length - offset:
            raise ValueError('Mach-O signature entry exceeds its container')
        if any(offset < end and begin < offset + sublength for begin, end in ranges):
            raise ValueError('Overlapping Mach-O signature entries')
        ranges.append((offset, offset + sublength))
        if slot == 0 or 0x1000 <= slot < 0x1005:
            hashes.add(code_directory_hash(data[offset:offset + sublength]))
    if not hashes:
        raise ValueError('Mach-O signature has no supported CodeDirectory')
    return hashes


def capture_image(descriptor):
    """Read the original regular descriptor, retaining every slice/alternative.

    A non-Mach-O file is explicitly returned as such. An unsigned, unsupported
    or malformed Mach-O fails; an empty set never substitutes for its identity.
    The caller owns the descriptor and its protected named-path relationship.
    """
    original = os.fstat(descriptor)
    if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or not 0 <= original.st_size <= IMAGE_LIMIT:
        raise ValueError('Image capture requires a bounded original regular file')

    def read(offset, length):
        if offset < 0 or length < 0 or offset > original.st_size or length > original.st_size - offset:
            raise ValueError('Mach-O read exceeds the captured original image')
        value = os.pread(descriptor, length, offset)
        if len(value) != length:
            raise ValueError('Captured Mach-O image changed during read')
        return value

    magic = read(0, min(4, original.st_size))
    slices = []
    if magic in FAT:
        order, width = FAT[magic]
        count = struct.unpack(order + 'I', read(4, 4))[0]
        if not 0 < count <= 32:
            raise ValueError('Unbounded universal Mach-O slices')
        table_end = 8 + count * width
        table = read(8, count * width)
        architectures = set()
        for index in range(count):
            entry = struct.unpack_from(order + ('IIIII' if width == 20 else 'IIQQII'), table, index * width)
            cpu, subtype, offset, length, alignment = entry[:5]
            if ((cpu, subtype) in architectures or not 0 <= alignment <= 30 or
                    offset < table_end or offset % (1 << alignment) or length < 28 or
                    offset > original.st_size or length > original.st_size - offset or
                    width == 32 and entry[5] != 0):
                raise ValueError('Invalid universal Mach-O slice')
            if any(offset < start + size and start < offset + length for start, size in slices):
                raise ValueError('Overlapping universal Mach-O slices')
            architectures.add((cpu, subtype))
            slices.append((offset, length))
    elif magic in THIN:
        slices = [(0, original.st_size)]

    hashes, executable_uuids = set(), set()
    for offset, length in slices:
        slice_magic = read(offset, 4)
        if slice_magic not in THIN:
            raise ValueError('Universal image contains a non-Mach-O slice')
        order, header_size = THIN[slice_magic]
        header = read(offset, header_size)
        commands, command_bytes = struct.unpack_from(order + 'II', header, 16)
        if not 0 < commands <= 32768 or command_bytes > length - header_size:
            raise ValueError('Invalid Mach-O load command bounds')
        cursor, signature, slice_uuids = header_size, None, set()
        for _ in range(commands):
            if cursor > header_size + command_bytes - 8:
                raise ValueError('Truncated Mach-O load command')
            command, size = struct.unpack(order + 'II', read(offset + cursor, 8))
            if size < 8 or size % 4 or size > header_size + command_bytes - cursor:
                raise ValueError('Invalid Mach-O load command size')
            if command == 0x1d:
                if size != 16 or signature is not None:
                    raise ValueError('Duplicate or invalid Mach-O code signature command')
                start, size_bytes = struct.unpack(order + 'II', read(offset + cursor + 8, 8))
                if (start < header_size + command_bytes or not 8 <= size_bytes <= SIGNATURE_LIMIT or
                        start > length or size_bytes > length - start):
                    raise ValueError('Mach-O code signature exceeds its captured slice')
                signature = (start, size_bytes)
            elif command == 0x1b:
                # XNU load_uuid accepts at least the 24-byte uuid_command.
                # Retain every occurrence as a conservative superset: its
                # depth-1 loader ultimately installs the last one in p_uuid.
                if size < 24:
                    raise ValueError('Truncated Mach-O executable UUID command')
                slice_uuids.add(read(offset + cursor + 8, 16).hex())
            cursor += size
        if cursor != header_size + command_bytes or signature is None:
            raise ValueError('Mach-O image has no complete captured signature')
        hashes.update(signature_hashes(read(offset + signature[0], signature[1])))
        # XNU initializes load_result.uuid to zero before parsing the image.
        # Missing LC_UUID therefore participates in comparisons as zero; it
        # never grants process absence or an empty native image inventory.
        executable_uuids.update(slice_uuids or {'0' * 32})

    digest = hashlib.sha256()
    for offset in range(0, original.st_size, 1024 * 1024):
        digest.update(read(offset, min(1024 * 1024, original.st_size - offset)))
    if file_identity(original) != file_identity(os.fstat(descriptor)):
        raise ValueError('Original image changed during identity capture')
    return {'file_identity': file_identity(original), 'sha256': digest.hexdigest(),
            'mach_o': bool(slices), 'code_directory_hashes': sorted(hashes),
            'executable_uuids': sorted(executable_uuids)}


class NativeUniqueInfo(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_ubyte * 16), ('uniqueid', ctypes.c_uint64),
                ('parent_uniqueid', ctypes.c_uint64), ('idversion', ctypes.c_int32),
                ('parent_idversion', ctypes.c_int32), ('reserved', ctypes.c_uint64 * 2)]


def native_unique(library, pid):
    if ctypes.sizeof(NativeUniqueInfo) != 56 or NativeUniqueInfo.idversion.offset != 32:
        raise RuntimeError('Native exec generation ABI does not match Darwin')
    value = NativeUniqueInfo()
    ctypes.set_errno(0)
    size = library.proc_pidinfo(pid, 17, 1, ctypes.byref(value), ctypes.sizeof(value))
    error = ctypes.get_errno()
    if size != ctypes.sizeof(value) or not value.uniqueid or value.idversion <= 0:
        raise RuntimeError(f'Cannot retain native exec generation (pid={pid}, errno={error}, result={size})')
    return (value.uniqueid, value.idversion, bytes(value.uuid).hex())


def code_identity_library():
    if sys.platform != 'darwin':
        raise RuntimeError('Main-image identity requires actual macOS')
    system = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    system.csops_audittoken.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32 * 8)]
    system.csops_audittoken.restype = ctypes.c_int
    return system


class MainImageGenerationChanged(RuntimeError):
    """A witnessed live-to-live transition invalidated the entire image capture.

    This error contains no reusable identity. A caller may only start a fresh
    complete inventory under its separately retained installation authority.
    """


class MainImageCodeDirectoryUnavailable(RuntimeError):
    """An EBADEXEC result with a separately fenced kernel executable UUID.

    This is still an identity failure, never permission to exclude a process.
    Only a complete original generation may prove its UUID is disjoint.
    """
    def __init__(self, pid, identity):
        super().__init__(f'Cannot capture the native main-image CodeDirectory (pid={pid}, errno=85, result=-1)')
        self.identity = dict(identity, identity_kind='kernel-main-uuid', code_directory_error=85)


def main_image_identity(library, pid, state_reader, *, system=None):
    """Capture p_textvp's CodeDirectory hash across one PID/exec generation.

    A caller-supplied PID/idversion token is only a kernel comparison fence.
    Unknown signatures, disappearance, denial or a changed generation remain
    errors. Only EBADEXEC with an empty output additionally retains its fenced
    UUID in a typed error; this function never excludes an installation.
    """
    if type(pid) is not int or not 0 < pid < 2**31:
        raise ValueError('Native main-image capture requires an actual PID')
    before = state_reader(library, pid)
    if before is None or before[0] != pid or before[3] == 5:
        raise RuntimeError('Main-image capture requires the same live native process')
    unique = native_unique(library, pid)
    token = (ctypes.c_uint32 * 8)()
    token[5], token[7] = pid, unique[1]
    digest = (ctypes.c_ubyte * 20)()
    system = code_identity_library() if system is None else system
    ctypes.set_errno(0)
    result = system.csops_audittoken(pid, 5, ctypes.byref(digest), len(digest), ctypes.byref(token))
    error = ctypes.get_errno()
    after_unique = native_unique(library, pid)
    after = state_reader(library, pid)
    if (after is None or before[:3] != after[:3] or after[3] == 5 or unique != after_unique):
        if (after is not None and after[3] != 5 and
                ((result == 0 and any(digest)) or
                 (result == -1 and error in (errno.ESRCH, 85) and not any(digest)))):
            raise MainImageGenerationChanged('Native main-image process or exec generation changed')
        raise RuntimeError('Native main-image process or exec generation changed')
    identity = {'pid': pid, 'start_seconds': before[1], 'start_microseconds': before[2],
                'uniqueid': unique[0], 'idversion': unique[1], 'main_uuid': unique[2]}
    if result == -1 and error == 85 and not any(digest):
        raise MainImageCodeDirectoryUnavailable(pid, identity)
    if result != 0 or not any(digest):
        raise RuntimeError(f'Cannot capture the native main-image CodeDirectory (pid={pid}, errno={error}, result={result})')
    return dict(identity, code_directory_hash=bytes(digest).hex())
