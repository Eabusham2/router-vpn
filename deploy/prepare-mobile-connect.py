#!/usr/bin/env python3
"""Project source-bound CONNECT owners into the pinned native mobile core."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
_binding_spec=importlib.util.spec_from_file_location("native_connect_binding",ROOT/"deploy/native_connect_binding.py")
CONNECT_BINDING=importlib.util.module_from_spec(_binding_spec)
_binding_spec.loader.exec_module(CONNECT_BINDING)
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-connect-source.json'
DESKTOP_ONLY = {"connect_reference_test.go.tmpl"}
TEMPLATES = {
    "connect_latency_native_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_latency_native_test.go",
 "connect_latency.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_latency.go",
 "connect_mtu.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_mtu.go",
 "connect_mtu_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_mtu_test.go",
 "connect_mtu_box.go.tmpl": "routervpn_node_chain_connect_mtu.go",
 "connect_mtu_box_test.go.tmpl": "routervpn_node_chain_connect_mtu_test.go",
 "connect_run_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_run_test.go",
 "connect_socket.go.tmpl": "protocol/routervpnnodeconnect/connect_socket.go",
 "connect_tls_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_tls_test.go",
 "connect_reference_test.go.tmpl": "protocol/routervpnamnezia/routervpn_connect_reference_test.go",
 "connect_close_test.go.tmpl": "protocol/routervpnnodeconnect/connect_close_test.go",
 "connect_bridge_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_test.go",
 "connect_native_test.go.tmpl": "experimental/libbox/routervpn_node_chain_connect_native_test.go",
 'connect_owner.go.tmpl': 'protocol/routervpnnodeconnect/connect_owner.go',
 'connect_scope.go.tmpl': 'protocol/routervpnnodeconnect/connect_scope.go',
 'connect_final_owner.go.tmpl': 'protocol/routervpnnodeconnect/connect_final.go',
 'connect_final.go.tmpl': 'protocol/shadowsocks/routervpn_connect_final.go',
 'connect_box.go.tmpl': 'routervpn_node_chain_connect.go',
 'connect_server.go.tmpl': 'experimental/libbox/routervpn_node_chain_connect_server.go',
 'connect_bridge.go.tmpl': 'experimental/libbox/routervpn_node_chain_connect.go',
 'connect_lifecycle.go.tmpl': 'experimental/libbox/routervpn_node_chain_connect_lifecycle.go',
 'connect_measurement.go.tmpl': 'experimental/libbox/routervpn_node_chain_connect_measurement.go',
}

def inputs():
 return [*CONNECT_BINDING.inputs(), Path(__file__).resolve(), ROOT/"deploy/test_connect_preparation.py", *(ROOT/'mobile/chain'/name for name in sorted(TEMPLATES))]

def digest():
 value = hashlib.sha256()
 for path in inputs(): value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
 return value.hexdigest()

def target(vendor, relative):
 path = vendor/relative
 if any(p.is_symlink() for p in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
  raise ValueError('linked CONNECT native source')
 return path

def box_source(source):
 source,_ = CONNECT_BINDING.strip(source)
 anchor = '\tif err := routerVPNNodeSOCKSOptions(options.Context, options.Options); err != nil {\n\t\treturn nil, err\n\t}\n'
 guard = '\tif err := routerVPNNodeCONNECTOptions(options.Context, options.Options); err != nil {\n\t\treturn nil, err\n\t}\n'
 if source.count(anchor) != 1:
  raise ValueError('CONNECT preparation requires original SOCKS construction guard')
 if 'routerVPNNodeCONNECTOptions' in source:
  if source.count(guard) != 1 or source.count(anchor+guard) != 1:
   raise ValueError('CONNECT construction guard moved or duplicated')
  return CONNECT_BINDING.bind(source)
 return CONNECT_BINDING.bind(source.replace(anchor, anchor+guard))

def prepare(vendor, *, mobile=True):
 vendor = vendor.resolve()
 if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'], text=True).strip() != PIN:
  raise ValueError('CONNECT requires exact pinned native core')
 box = target(vendor, 'box.go')
 original = box.read_bytes()
 derived = box_source(original.decode()).encode()
 owner = target(vendor, OWNER)
 previous = {}
 if owner.exists():
  if not owner.is_file() or owner.stat().st_size > 65536: raise ValueError('invalid CONNECT ownership file')
  record = json.loads(owner.read_bytes())
  if not isinstance(record,dict) or set(record) != {'schema','core','files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'],dict):
   raise ValueError('invalid CONNECT ownership record')
  previous = record['files']
  for relative, checksum in previous.items():
   if relative not in TEMPLATES.values() or not isinstance(checksum,str) or len(checksum) != 64:
    raise ValueError('foreign CONNECT ownership entry')
   path = target(vendor, relative)
   if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
    raise ValueError('changed original CONNECT source')
 content = {}
 for name, relative in TEMPLATES.items():
  if mobile and name in DESKTOP_ONLY: continue
  if not mobile and relative.startswith("experimental/libbox/"): continue
  path = target(vendor,relative)
  content[path] = (ROOT/'mobile/chain'/name).read_bytes()
  if path.exists() and (not path.is_file() or relative not in previous and path.read_bytes() != content[path]):
   raise ValueError('refusing foreign CONNECT source overwrite')
 if box.read_bytes() != original: raise ValueError('CONNECT construction source changed during preparation')
 for path, data in content.items():
  path.parent.mkdir(parents=True,exist_ok=True)
  path.write_bytes(data)
 box.write_bytes(derived)
 owned = dict(previous)
 owned.update({path.relative_to(vendor).as_posix():hashlib.sha256(data).hexdigest() for path,data in content.items()})
 owner.write_text(json.dumps({'schema':1,'core':PIN,'files':owned},sort_keys=True,separators=(',',':'))+'\n')
 print('Owned native CONNECT source:', digest())

if __name__ == '__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('vendor',type=Path,nargs='?')
 parser.add_argument('--digest',action='store_true')
 parser.add_argument('--desktop',action='store_true')
 args=parser.parse_args()
 if args.digest: print(digest())
 elif args.vendor: prepare(args.vendor,mobile=not args.desktop)
 else: parser.error('vendor or --digest required')
