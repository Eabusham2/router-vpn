#!/usr/bin/env python3
"""Promote only a verified package engine; rollback preserves the prior directory."""
from pathlib import Path
import argparse
import importlib.util
import os
import shutil
import tempfile
spec=importlib.util.spec_from_file_location('verify',Path(__file__).with_name('verify-bundled-xray.py'))
VERIFY=importlib.util.module_from_spec(spec);spec.loader.exec_module(VERIFY)
def install(source,destination):
    source=Path(source);destination=Path(destination).absolute()
    VERIFY.verify(source)
    if destination.is_symlink() or destination.parent.is_symlink():raise ValueError('Unsafe installed runtime path')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.xray-install-',dir=destination.parent) as temp:
        temp=Path(temp);stage=temp/'new';backup=temp/'previous'
        shutil.copytree(source,stage,symlinks=False)
        VERIFY.verify(stage)
        moved=False;promoted=False
        try:
            if destination.exists():os.replace(destination,backup);moved=True
            os.replace(stage,destination);promoted=True
            VERIFY.verify(destination)
        except BaseException:
            if promoted:os.replace(destination,stage)
            if moved:os.replace(backup,destination)
            raise
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('destination',type=Path)
    a=p.parse_args();install(a.source,a.destination)
