#!/usr/bin/env python3
"""Require actual native TUN replacement/rollback in an isolated Linux namespace."""
from pathlib import Path
import argparse
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-','_'), ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='disposable exact pinned native checkout')
    args = parser.parse_args()
    if not Path('/dev/net/tun').exists():
        raise SystemExit('Required actual kernel TUN gate cannot run: /dev/net/tun is absent')
    if not shutil.which('unshare'):
        raise SystemExit('Required isolated network namespace utility is absent')
    with tempfile.TemporaryDirectory(prefix='routervpn-mtu-kernel-') as temporary:
        temporary = Path(temporary)
        source = args.source.resolve() if args.source else temporary/'core'
        if not args.source:
            subprocess.run(['git','init',str(source)],check=True,stdout=subprocess.DEVNULL)
            subprocess.run(['git','-C',str(source),'remote','add','origin','https://github.com/SagerNet/sing-box.git'],check=True)
            subprocess.run(['git','-C',str(source),'fetch','--depth=1','origin',PIN],check=True)
            subprocess.run(['git','-C',str(source),'checkout','--detach',PIN],check=True,stdout=subprocess.DEVNULL)
        load('prepare-mobile-mtu').prepare(source,mobile=False)
        load('prepare-desktop-mtu').prepare(source)
        load('prepare-mobile-strategy').prepare(source,mobile=False)
        target=source/'routervpn_desktop_mtu_kernel_test.go'
        if target.is_symlink(): raise SystemExit('Linked native test destination')
        target.write_bytes((ROOT/'mobile/mtu/desktop_kernel_test.go.tmpl').read_bytes())
        binary=temporary/'kernel-mtu.test'
        subprocess.run(['go','test','-c','-mod=readonly','-tags=with_gvisor','-ldflags=-checklinkname=0','-o',str(binary),'.'],cwd=source,check=True)
        # Root is used only to create the isolated network namespace and run
        # the test there. Compilation and source preparation remain unprivileged.
        # Existing host routes, firewall and listeners remain outside it.
        command=['unshare','--net','env','ROUTERVPN_MTU_KERNEL_TEST=isolated-network-namespace',str(binary),'-test.run=^TestRouterVPNDesktopMTUKernel$','-test.v','-test.timeout=60s']
        if os.geteuid()!=0: command=['sudo','--non-interactive','--',*command]
        subprocess.run(command,check=True)


if __name__ == '__main__': main()
