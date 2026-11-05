"""Project only the shared observation classifier into native policy modules."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = 'experimental/libbox/routervpn/common/observation_context.go'


def inputs():
    return [Path(__file__).resolve(), ROOT/'internal/common/observation_context.go']


def rewrite(raw):
    return raw.replace(b'"router-vpn/internal/common"',
                       b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/common"')


def copies():
    source = ROOT/'internal/common/observation_context.go'
    if source.is_symlink() or not source.is_file():
        raise ValueError('Native observation classifier lost its original source')
    return {RELATIVE: source.read_bytes()}


def destination(vendor):
    vendor = vendor.resolve()
    target = vendor/RELATIVE
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked native observation classifier destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('Native observation classifier escaped its checkout')
    if target.parent.exists() and any(path.name != target.name for path in target.parent.glob('*.go')):
        raise ValueError('Native observation policy contains undeclared common sources')
    return target


def prepare(vendor):
    target = destination(vendor)
    raw = copies()[RELATIVE]
    if target.exists() and (not target.is_file() or target.read_bytes() != raw):
        raise ValueError('Native observation classifier differs from its original source')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)


def verify(vendor):
    target = destination(vendor)
    raw = copies()[RELATIVE]
    if not target.is_file() or target.read_bytes() != raw:
        raise ValueError('Native observation classifier is missing or modified')
    return {RELATIVE: hashlib.sha256(raw).hexdigest()}
