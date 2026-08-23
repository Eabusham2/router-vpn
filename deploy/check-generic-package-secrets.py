#!/usr/bin/env python3
"""Fail CI if a public generic Router VPN package contains linked-node material or stale product shape."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path, PurePosixPath
import tarfile, zipfile

REPO=Path(__file__).resolve().parents[1]
FORBIDDEN_HOME_IDENTITIES=("192.168.50.","99.88.243.10")
PUBLIC_SOURCE_PATHS=(
 "client/RouterVPN-Windows-Product-v2.ps1",
 "client/linux/routervpn-gtk-product-v3.c",
 "client/macos/RouterVPNMacProduct.swift",
 "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
 "ios/RouterVPN/App/RouterVPNModel.swift",
 "ios/RouterVPN/App/ContentView.swift",
 "cmd/client/ui.html","cmd/client/logical_ui.js","cmd/client/extras.go","docs/CLIENT.md","modes/test_multihop.py",
)
PWA_MARKERS=(b"beforeinstallprompt",b"serviceWorker.register",b"manifest.webmanifest",b"router-vpn-ui-v1",b"installPWA(")
RETIRED_WINDOWS_PAYLOADS=("client/Prepare-Windows-Mode-Catalog.ps1","client/RouterVPN-Windows-Product.ps1")
WINDOWS_NATIVE_HELPERS=(
 "client/RouterVPN-Windows-App.ps1",
 "client/RouterVPN-Windows-UnifiedShell.ps1",
 "client/RouterVPN-Windows-Telemetry.ps1",
 "client/RouterVPN-Windows-ProfileSettings.ps1",
 "client/RouterVPN-Windows-Product-v2.ps1",
)

def _canonical_store_version()->int:
 text=(REPO/"internal/common/types.go").read_text(encoding="utf-8")
 m=re.search(r"RouterProfileStoreVersion\s*=\s*(\d+)",text)
 if not m: raise ValueError("canonical RouterProfileStoreVersion is missing")
 return int(m.group(1))

STORE_VERSION=_canonical_store_version()

def _check_name(name:str)->None:
 p=PurePosixPath(name.replace("\\","/"))
 if p.is_absolute() or any(part in ("",".","..") for part in p.parts): raise ValueError(f"unsafe packaged path: {name}")

def _identity_variants(value:str):
 return (value.encode(),value.encode("utf-16le"),value.encode("utf-16be"))

def _check_home_identity(name:str,data:bytes)->None:
 for value in FORBIDDEN_HOME_IDENTITIES:
  if any(v in data for v in _identity_variants(value)):
   raise ValueError(f"public client material contains deployment-specific home identity {value!r}: {name}")

def _check_retired_pwa(name:str,data:bytes)->None:
 for marker in PWA_MARKERS:
  if marker in data:
   raise ValueError(f"public client material contains retired browser/PWA marker {marker!r}: {name}")

def _check_member(name:str,data:bytes)->None:
 _check_name(name); p=PurePosixPath(name.replace("\\","/"))
 if p.name=="router-vpn-bundle.json": raise ValueError(f"generic package contains private bundle: {name}")
 if "generated" in p.parts and data: raise ValueError(f"generic package contains generated per-node material: {name}")
 if p.name=="routers.json" and data:
  obj=json.loads(data.decode("utf-8"))
  if obj.get("schema_version")!=STORE_VERSION:
   raise ValueError(f"generic package routers.json schema is stale: expected {STORE_VERSION}, got {obj.get('schema_version')}: {name}")
  if obj.get("selected_id") not in (None,"") or obj.get("profiles") not in (None,[]): raise ValueError(f"generic package contains linked router profiles: {name}")
 _check_home_identity(name,data)
 _check_retired_pwa(name,data)

def _require_suffix(names:set[str],suffix:str,archive:str)->None:
 suffix=suffix.replace("\\","/")
 if not any(name==suffix or name.endswith("/"+suffix) for name in names):
  raise ValueError(f"{archive} is missing required shipping member: {suffix}")

def _check_windows_zip_contract(path:Path,names:set[str])->None:
 filename=path.name
 for retired in RETIRED_WINDOWS_PAYLOADS:
  if any(name==retired or name.endswith("/"+retired) for name in names):
   raise ValueError(f"{filename} contains retired Windows payload: {retired}")
 if filename.startswith("RouterVPN-Windows-"):
  for member in ("RouterVPN.exe","RouterVPN.ico","logical-modes.json","routers.json",*WINDOWS_NATIVE_HELPERS):
   _require_suffix(names,member,filename)
  for forbidden in ("msedge.exe","chrome.exe"):
   if any(PurePosixPath(name).name.lower()==forbidden for name in names):
    raise ValueError(f"{filename} contains retired browser launcher binary {forbidden}")
 elif filename.startswith("RouterVPN-Portable-Windows-"):
  for member in ("RouterVPNPortable.exe","RouterVPNSetupRuntime.exe","App/RouterVPN/RouterVPN.ico","App/RouterVPN/logical-modes.json","App/RouterVPN/routers.json"):
   _require_suffix(names,member,filename)
  for helper in WINDOWS_NATIVE_HELPERS:
   _require_suffix(names,"App/RouterVPN/"+helper,filename)
  # Writable private state must be first-run generated, not baked into a generic archive.
  for name in names:
   normalized=name.replace("\\","/")
   if re.search(r"/Data/(routers|state|client)\.json$",normalized):
    raise ValueError(f"{filename} pre-populates private Portable Data state: {normalized}")

def scan_source_tree()->None:
 for relative in PUBLIC_SOURCE_PATHS:
  path=REPO/relative
  if not path.is_file(): raise ValueError(f"public-client source guard path is missing: {relative}")
  data=path.read_bytes(); _check_home_identity(relative,data)
  if relative in ("cmd/client/ui.html","cmd/client/logical_ui.js","cmd/client/extras.go"):
   _check_retired_pwa(relative,data)
 print("public client source is node-agnostic and loopback UI is diagnostics-only")

def scan_zip(path:Path)->None:
 saw=False;names:set[str]=set()
 with zipfile.ZipFile(path) as zf:
  for item in zf.infolist():
   clean=item.filename.rstrip("/").replace("\\","/")
   if clean: names.add(clean)
   if item.is_dir():
    if clean:_check_name(clean)
    continue
   data=zf.read(item); _check_member(item.filename,data); saw=saw or PurePosixPath(item.filename).name=="LICENSE"
 if not saw: raise ValueError(f"package does not ship LICENSE: {path.name}")
 _check_windows_zip_contract(path,names)

def scan_tgz(path:Path)->None:
 saw=False
 with tarfile.open(path,"r:gz") as tf:
  for item in tf.getmembers():
   clean=item.name.rstrip("/")
   if clean:_check_name(clean)
   if not item.isfile(): continue
   f=tf.extractfile(item); data=f.read() if f else b""; _check_member(item.name,data); saw=saw or PurePosixPath(item.name).name=="LICENSE"
 if not saw: raise ValueError(f"package does not ship LICENSE: {path.name}")

def main()->int:
 ap=argparse.ArgumentParser();ap.add_argument("package_dir");args=ap.parse_args();scan_source_tree();root=Path(args.package_dir)
 archives=sorted(root.glob("RouterVPN-*.zip"))+sorted(root.glob("RouterVPN-*.tar.gz"))
 if not archives: raise SystemExit("no generic Router VPN packages found to scan")
 for path in archives:
  scan_zip(path) if path.suffix==".zip" else scan_tgz(path)
  print(f"secret-free, node-agnostic, schema-current package OK: {path.name}")
 return 0
if __name__=="__main__": raise SystemExit(main())
