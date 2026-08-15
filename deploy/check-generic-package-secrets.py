#!/usr/bin/env python3
"""Fail CI if a public generic Router VPN package contains linked-node material."""
from __future__ import annotations
import argparse, json
from pathlib import Path, PurePosixPath
import tarfile, zipfile

FORBIDDEN_HOME_IDENTITIES=("192.168.50.","99.88.243.10")
PUBLIC_SOURCE_PATHS=(
 "client/RouterVPN-Windows-Product-v2.ps1",
 "client/linux/routervpn-gtk-product-v3.c",
 "client/macos/RouterVPNMacProduct.swift",
 "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
 "ios/RouterVPN/App/RouterVPNModel.swift",
 "ios/RouterVPN/App/ContentView.swift",
 "cmd/client/ui.html","cmd/client/logical_ui.js","docs/CLIENT.md","modes/test_multihop.py",
)
PWA_MARKERS=(b"beforeinstallprompt",b"serviceWorker.register",b"manifest.webmanifest",b"installPWA(")

def _check_name(name:str)->None:
 p=PurePosixPath(name.replace("\\","/"))
 if p.is_absolute() or any(part in ("",".","..") for part in p.parts): raise ValueError(f"unsafe packaged path: {name}")

def _identity_variants(value:str):
 return (value.encode(),value.encode("utf-16le"),value.encode("utf-16be"))

def _check_home_identity(name:str,data:bytes)->None:
 for value in FORBIDDEN_HOME_IDENTITIES:
  if any(v in data for v in _identity_variants(value)):
   raise ValueError(f"public client material contains deployment-specific home identity {value!r}: {name}")

def _check_member(name:str,data:bytes)->None:
 _check_name(name); p=PurePosixPath(name.replace("\\","/"))
 if p.name=="router-vpn-bundle.json": raise ValueError(f"generic package contains private bundle: {name}")
 if "generated" in p.parts and data: raise ValueError(f"generic package contains generated per-node material: {name}")
 if p.name=="routers.json" and data:
  obj=json.loads(data.decode("utf-8"))
  if obj.get("selected_id") not in (None,"") or obj.get("profiles") not in (None,[]): raise ValueError(f"generic package contains linked router profiles: {name}")
 _check_home_identity(name,data)

def scan_source_tree()->None:
 repo=Path(__file__).resolve().parents[1]
 for relative in PUBLIC_SOURCE_PATHS:
  path=repo/relative
  if not path.is_file(): raise ValueError(f"public-client source guard path is missing: {relative}")
  data=path.read_bytes(); _check_home_identity(relative,data)
  if relative in ("cmd/client/ui.html","cmd/client/logical_ui.js"):
   for marker in PWA_MARKERS:
    if marker in data: raise ValueError(f"loopback controller UI must remain diagnostics-only; obsolete marker {marker!r} found in {relative}")
 print("public client source is node-agnostic and loopback UI is diagnostics-only")

def scan_zip(path:Path)->None:
 saw=False
 with zipfile.ZipFile(path) as zf:
  for item in zf.infolist():
   if item.is_dir(): _check_name(item.filename.rstrip("/")); continue
   data=zf.read(item); _check_member(item.filename,data); saw=saw or PurePosixPath(item.filename).name=="LICENSE"
 if not saw: raise ValueError(f"package does not ship LICENSE: {path.name}")

def scan_tgz(path:Path)->None:
 saw=False
 with tarfile.open(path,"r:gz") as tf:
  for item in tf.getmembers():
   _check_name(item.name.rstrip("/"))
   if not item.isfile(): continue
   f=tf.extractfile(item); data=f.read() if f else b""; _check_member(item.name,data); saw=saw or PurePosixPath(item.name).name=="LICENSE"
 if not saw: raise ValueError(f"package does not ship LICENSE: {path.name}")

def main()->int:
 ap=argparse.ArgumentParser();ap.add_argument("package_dir");args=ap.parse_args();scan_source_tree();root=Path(args.package_dir)
 archives=sorted(root.glob("RouterVPN-*.zip"))+sorted(root.glob("RouterVPN-*.tar.gz"))
 if not archives: raise SystemExit("no generic Router VPN packages found to scan")
 for path in archives:
  scan_zip(path) if path.suffix==".zip" else scan_tgz(path)
  print(f"secret-free, node-agnostic package OK: {path.name}")
 return 0
if __name__=="__main__": raise SystemExit(main())
