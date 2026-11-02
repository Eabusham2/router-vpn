#!/usr/bin/env python3
"""Apply the verified timer fix to the independently pinned AWG server source."""
from pathlib import Path
import argparse
import importlib.util
import os
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = '0527dfa47639714dd8f5c9ffbd9d40d19083f0ba'
_spec = importlib.util.spec_from_file_location('server_awg_timer_patch', ROOT / 'deploy/prepare-amnezia-timers.py')
TIMERS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TIMERS)


def regular(path, maximum):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Server timer input must be a regular owned file')
    info = path.stat()
    if info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError('Server timer input has another owner or invalid bounds')
    return path.read_bytes(), stat.S_IMODE(info.st_mode)


def paths(source, revision):
    if revision != REVISION:
        raise ValueError('Server timer repair requires the unchanged pinned AWG revision')
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_dir() or source.resolve() != source:
        raise ValueError('Server timer repair requires its canonical owned checkout')
    device = source / 'device'
    if device.is_symlink() or not device.is_dir():
        raise ValueError('Server timer repair lost its original device source directory')
    # Docker consumes the tar archive of this exact revision. A local checkout
    # supplies independent Git identity as well; never reset or rewrite it.
    if (source / '.git').exists():
        actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != revision:
            raise ValueError('Server timer checkout differs from its declared pinned revision')
    return source / TIMERS.TIMER, source / TIMERS.TEST


def replace_owned(path, data, mode):
    fd, name = tempfile.mkstemp(prefix='.routervpn-timer-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verify(source, revision):
    timer, test = paths(source, revision)
    data, _ = regular(timer, 64 * 1024)
    TIMERS.original(data)
    actual_test, _ = regular(test, 256 * 1024)
    if actual_test != TIMERS.test_source():
        raise ValueError('Server timer regression differs from the exact native control')


def prepare(source, revision):
    timer, test = paths(source, revision)
    data, mode = regular(timer, 64 * 1024)
    if TIMERS.git_blob(data) == TIMERS.BLOB:
        fixed = TIMERS.patch(data)
    else:
        TIMERS.original(data)
        fixed = data
    expected_test = TIMERS.test_source()
    test_mode = 0o644
    if test.exists() or test.is_symlink():
        captured_test, test_mode = regular(test, 256 * 1024)
        if captured_test != expected_test:
            raise ValueError('Refusing an unrelated server timer test destination')
    # Validate every existing input before writing either owned source file.
    if fixed != data:
        replace_owned(timer, fixed, mode)
    if not test.exists():
        replace_owned(test, expected_test, test_mode)
    verify(source, revision)
    print('Verified exact AWG server timer correction and regression source:', revision)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--verify', action='store_true')
    arguments = parser.parse_args()
    (verify if arguments.verify else prepare)(arguments.source, arguments.revision)
