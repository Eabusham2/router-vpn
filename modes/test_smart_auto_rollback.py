#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, os, sys, tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='rv-smart-test-') as td:
 root=Path(td); (root/'modes.json').write_text('[]'); (root/'routers.json').write_text('{"profiles":[]}')
 old=os.environ.get('HOMEVPN_ROOT'); os.environ['HOMEVPN_ROOT']=str(root)
 try:
  spec=importlib.util.spec_from_file_location('rv_orchestrate_test',HERE/'orchestrate.py'); mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
 finally:
  if old is None: os.environ.pop('HOMEVPN_ROOT',None)
  else: os.environ['HOMEVPN_ROOT']=old

def scenario(restore_ok: bool):
 heavy={'id':'heavy','name':'heavy','auto_eligible':True,'smart_simplify':['light']}; light={'id':'light','name':'light','auto_eligible':False,'smart_simplify':[]}
 mod.modes=[heavy,light]; mod.by_id={'heavy':heavy,'light':light}
 mod.available=lambda m: True
 calls=[]; heavy_count=0
 def launch(m):
  nonlocal_vars=None
  calls.append(m['id'])
  if m['id']=='heavy':
   count=calls.count('heavy')
   return ((True,20.0) if count==1 or restore_ok else (False,0.0))
  return False,0.0
 mod.launch=launch
 selected=[]
 mod.wait_selected=lambda m,lat: selected.append((m['id'],lat)) or 0
 rc=mod.smart_auto()
 return rc,calls,selected

rc,calls,selected=scenario(True)
assert rc==0 and calls==['heavy','light','heavy'], (rc,calls)
assert selected and selected[-1][0]=='heavy', selected
rc,calls,selected=scenario(False)
assert rc==1 and calls==['heavy','light','heavy'], (rc,calls)
assert not selected, 'failed restoration must never claim Connected'
print('SMART AUTO forced simplification failure/last-good rollback behavior: PASS')
