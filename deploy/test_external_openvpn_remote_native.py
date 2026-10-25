#!/usr/bin/env python3
"""Run native OpenVPN fallback, fresh remote queries and queued-generation controls."""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'

def load(name):
    spec=importlib.util.spec_from_file_location('remote_native_'+name.replace('-','_'),ROOT/'deploy'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run(core):
    core=Path(core).resolve()
    for key in ('GOOS','GOARCH','CC','CXX','CGO_CFLAGS','CGO_LDFLAGS'):os.environ.pop(key,None)
    if platform.system()=='Darwin':
        os.environ['SDKROOT']=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
        for key in ('IPHONEOS_DEPLOYMENT_TARGET','TVOS_DEPLOYMENT_TARGET','WATCHOS_DEPLOYMENT_TARGET','XROS_DEPLOYMENT_TARGET'):os.environ.pop(key,None)
    if subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('Native remote tests require exact pinned disposable core')
    load('prepare-relay-core.py').prepare(core)
    load('mobile_openvpn_close_policy.py').prepare(core)
    # Reverse order and repetition must preserve both exact native policies.
    load('prepare-mobile-openvpn.py').prepare(core)
    load('mobile_openvpn_close_policy.py').prepare(core)
    subprocess.run(['go','mod','tidy'],cwd=core,check=True,timeout=180)
    with tempfile.TemporaryDirectory(prefix='router-openvpn-mapped-layer-') as temporary:
        binary=Path(temporary)/'start-layer-relay'
        subprocess.run(['go','build','-buildvcs=false','-o',str(binary),'./cmd/start-layer-relay'],cwd=ROOT,check=True,timeout=120)
        environment=dict(os.environ,ROUTER_VPN_WHITENING_TEST_BINARY=str(binary))
        subprocess.run(['go','test','-race','-count=1','-parallel=4','-timeout=240s','-ldflags=-checklinkname=0','-tags','with_openvpn,with_wireguard,with_quic,with_gvisor,routervpn_openvpn_remote_test,routervpn_openvpn_layer_test','./cmd/sing-box','./protocol/routervpnopenvpnlayers','./transport/openvpn','-run','^(TestRouterVPNRelayNative|TestRouterVPNOpenVPNLayer|TestRouterVPNOpenVPNStack)','-v'],cwd=core,env=environment,check=True,timeout=300)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--core',type=Path,required=True);run(parser.parse_args().core)
