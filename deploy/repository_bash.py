"""Locate a native Bash for repository shell fixtures, including on Windows."""
from pathlib import Path
import os
import shutil


def repository_bash(*, windows=None, which=shutil.which):
    if windows is None:
        windows = os.name == 'nt'
    if not windows:
        bash = which('bash')
        if bash is None:
            raise AssertionError('Bash is required to execute the repository shell fixture')
        return bash
    # A bare bash.exe can be the Windows WSL launcher, even when Git for
    # Windows is installed. Resolve only a shell in the selected Git install.
    git = which('git')
    if git is None:
        raise AssertionError('Git for Windows is required to execute the repository shell fixture')
    root = Path(git).resolve().parent.parent
    if root.name.lower() in ('mingw32', 'mingw64', 'clangarm64'):
        root = root.parent
    for bash in (root/'bin/bash.exe', root/'usr/bin/bash.exe'):
        if bash.is_file():
            return str(bash)
    raise AssertionError('Git for Windows Bash is missing beside the selected Git executable: ' + git)
