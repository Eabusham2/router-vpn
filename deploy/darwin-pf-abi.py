#!/usr/bin/env python3
"""Verify the exact unmodified Apple private PF userland header dependency.

The manifest is a review artifact, not mutable hash authority. The pinned source
identity and byte digests below must agree with it and the actual source files.
"""
from pathlib import Path
import hashlib
import json
import stat

COMMIT = '43a90889846e00bfb5cf1d255cdc0a701a1e05a4'
DIRECTORY = 'desktop_socket_darwin_pfabi'
PINNED = {
    'net/pfvar.h': ('bsd/net/pfvar.h',
                    'aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9',
                    '691a4e711f5c8ec77184d575e4ffebb9ce41d772'),
    'libkern/tree.h': ('libkern/libkern/tree.h',
                       'ae6e463397b9fe9a0de1d509a5fda87d388da56010442302d18efe77efbdd4b1',
                       'f728efcf33a5cc46a7ecae09c77be4b626c11378'),
    'APPLE_LICENSE': ('APPLE_LICENSE',
                       'e5881019d8766c1e88a5fe1dbca4ba40c78011d41fcb18f6e9f50df60182685b',
                       'fe81a60cae982c042a69f97623b427666c455093'),
}
MANIFEST = {
    'schema_version': 1,
    'repository': 'apple-oss-distributions/xnu',
    'tag': 'xnu-11417.140.69',
    'commit': COMMIT,
    'status': 'Unmodified primary-source private userland ABI headers; this is not a public SDK API. Native kernel acceptance is required.',
    'files': {name: {'source': source,
                     'url': 'https://github.com/apple-oss-distributions/xnu/blob/'+COMMIT+'/'+source,
                     'sha256': digest, 'git_blob': blob}
              for name, (source, digest, blob) in PINNED.items()},
}


def regular(root, name):
    current = root
    if current.is_symlink() or not current.is_dir():
        raise ValueError('Private PF dependency root is not a regular directory')
    parts = Path(name).parts
    for index, part in enumerate(parts):
        current = current/part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or (index < len(parts)-1 and not stat.S_ISDIR(info.st_mode)):
            raise ValueError('Private PF dependency contains a linked or non-directory ancestor')
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024*1024:
        raise ValueError('Private PF dependency is not a bounded regular file')
    return current.read_bytes()


def checked_files(mobiletor):
    """Return exact relative copy inputs; reject unknown, changed or linked files."""
    mobiletor = Path(mobiletor)
    root = mobiletor/DIRECTORY
    expected = {*PINNED, 'UPSTREAM.json', 'README.md'}
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Private PF source dependency is absent or linked')
    files = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Private PF dependency contains a linked input')
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir() or path.relative_to(root).as_posix() not in {'net', 'libkern'}:
            raise ValueError('Private PF dependency contains an undeclared input')
    if files != expected:
        raise ValueError('Private PF dependency source/license closure differs')
    result = {}
    for name in sorted(expected):
        raw = regular(root, name)
        if name in PINNED:
            _, digest, blob = PINNED[name]
            actual_blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if hashlib.sha256(raw).hexdigest() != digest or actual_blob != blob:
                raise ValueError('Pinned Apple PF dependency bytes differ: '+name)
        elif name == 'UPSTREAM.json':
            if raw != (json.dumps(MANIFEST, indent=2)+'\n').encode():
                raise ValueError('Pinned Apple PF dependency manifest differs')
        result[DIRECTORY+'/'+name] = raw
    result['desktop_socket_darwin_pfabi.h'] = regular(mobiletor, 'desktop_socket_darwin_pfabi.h')
    return result
