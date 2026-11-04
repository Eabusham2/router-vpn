"""Copy one already verified native payload into the actual private gate."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import platform
import stat

ROOT = Path(__file__).resolve().parents[1]


def builder():
    spec = importlib.util.spec_from_file_location('standard_service_bundle_builder', ROOT/'deploy/build-native-runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_original(path, maximum):
    named = path.lstat()
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or not 0 < named.st_size <= maximum:
        raise ValueError('Service fixture payload is not an original bounded regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        body = source.read(maximum+1)
        if identity(named) != identity(opened) or identity(opened) != identity(os.fstat(source.fileno())) or identity(opened) != identity(path.lstat()):
            raise ValueError('Service fixture payload changed during its original read')
    if len(body) != opened.st_size:
        raise ValueError('Service fixture payload was incomplete')
    return body


def verify(bundle, env):
    if bundle is None or not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_dir():
        raise ValueError('Installed service gate requires the actual staged verified native runtime bundle')
    build = builder()
    target = platform.system().lower()+'/'+{'x86_64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(platform.machine(), '')
    if not target.startswith('linux/'):
        raise ValueError('Installed standard service bundle requires its actual Linux build host')
    build.reuse(bundle, target, env=env)
    return hashlib.sha256(read_original(bundle/'NATIVE-RUNTIME.json', 32768)).hexdigest()


def copy_private(bundle, destination, expected_manifest):
    if bundle is None or not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_dir() or len(expected_manifest or '') != 64:
        raise ValueError('Native service namespace omitted its exact verified source bundle')
    directory = bundle.stat()
    raw = read_original(bundle/'NATIVE-RUNTIME.json', 32768)
    if hashlib.sha256(raw).hexdigest() != expected_manifest:
        raise ValueError('Native service bundle changed after exact build verification')
    build = builder()
    receipt = json.loads(raw, object_pairs_hook=build.unique_object)
    target = receipt.get('target')
    expected = build.expected_names(target)
    if set(receipt.get('files', {})) != expected or {p.name for p in bundle.iterdir()} != expected|{'NATIVE-RUNTIME.json'}:
        raise ValueError('Native service bundle lost its complete verified payload inventory')
    destination.mkdir(mode=0o700)
    for name in sorted(expected):
        body = read_original(bundle/name, build.payload_bound(name, target))
        if {'size':len(body), 'sha256':hashlib.sha256(body).hexdigest()} != receipt['files'][name]:
            raise ValueError('Native service bundle payload differs from its captured build receipt')
        path = destination/name
        with path.open('xb') as output:
            output.write(body)
            os.fchmod(output.fileno(), 0o500 if name in (build.binary_name(target),build.TOR.VERIFY.binary_name(target)) else 0o400)
    with (destination/'NATIVE-RUNTIME.json').open('xb') as output:
        output.write(raw)
        os.fchmod(output.fileno(), 0o400)
    if identity(directory) != identity(bundle.stat()) or read_original(bundle/'NATIVE-RUNTIME.json',32768) != raw:
        raise ValueError('Native service original bundle directory changed during private copy')
    return destination
