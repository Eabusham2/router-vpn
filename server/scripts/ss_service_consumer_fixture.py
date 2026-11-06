#!/usr/bin/env python3
"""Produce a private test bundle through the actual transport and bundle code."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ss_consumer_bundle_seed',HERE/'test_create_bundle_transaction.py')
seed=importlib.util.module_from_spec(spec);spec.loader.exec_module(seed)

def produce(endpoint,output):
 with tempfile.TemporaryDirectory(prefix='routervpn-ss-consumer-') as td:
  # Resolve only this freshly owned root before creating private fixture state.
  owned=Path(td).resolve(strict=True)
  base=owned/'state';seed.seed(base)
  public=base64.b64encode(b'b'*32).decode()
  seed.private_write(base/'client-bundle/generated/wg/wg.conf',f'[Interface]\nPrivateKey = {base64.b64encode(b"a"*32).decode()}\nAddress = 10.77.0.2/24, fd77:77::2/64\nDNS = 10.77.0.1\nMTU = 1420\n[Peer]\nPublicKey = {public}\nPresharedKey = {base64.b64encode(b"c"*32).decode()}\nEndpoint = {endpoint}:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')
  (base/'client-bundle/generated/reality-vision/xray.json').unlink()
  (base/'client-bundle/generated/reality-vision').rmdir()
  stage=owned/'generated';stage.mkdir()
  source=(HERE/'generate-transports.sh').read_text()
  body=source[source.index('python3 - "$GEN_TMP"'):].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
  for old,new in [('"/src/server/scripts/ss_service_capability.py"',repr(str(HERE/'ss_service_capability.py'))),('"/src/server/portainer-current.yaml"',repr(str(HERE.parent/'portainer-current.yaml')))]:
   if body.count(old)!=1:raise ValueError('shipping generator source boundary changed')
   body=body.replace(old,new)
  args=[str(stage),endpoint,'10.77.0.1','8443','8388',base64.b64encode(b's'*32).decode(),'fixture-hysteria-password','router-vpn.home','ghcr.io/sagernet/sing-box:v1.13.12']
  subprocess.run([sys.executable,'-c',body,*args],check=True,timeout=15)
  for src,dst in [('server.json','config/transports/server.json'),('ss-service.json','config/transports/ss-service.json'),('shadowsocks.json','client-bundle/generated/shadowsocks/sing-box.json')]:seed.private_write(base/dst,(stage/src).read_text())
  subprocess.run([sys.executable,str(HERE/'create-bundle-json.py'),str(base),endpoint,'router-token','http://10.77.0.1:8787','10.77.0.1','',''],check=True,timeout=15,stdout=subprocess.DEVNULL)
  raw=(base/'client-bundle/router-vpn-bundle.json').read_bytes()
  bundle=json.loads(raw)
  if base64.b64decode(bundle['profiles']['shadowsocks']['sing-box.json'])!=(stage/'shadowsocks.json').read_bytes():raise ValueError('bundle changed original SS source')
  output.write_bytes(raw);output.chmod(0o600)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--endpoint',required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();produce(args.endpoint,args.output)
