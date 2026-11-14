"""Exact additive CONNECT return wrapper shared by native preparers."""
from pathlib import Path

def inputs(): return [Path(__file__).resolve()]

def constructor(source, start):
 signature='func New(options Options) (*Box, error) {\n'
 if source.count(signature)!=1:raise ValueError('CONNECT original Box constructor signature changed')
 origin=source.index(signature)
 if start<=origin or source.find('\nfunc ',origin,start)!=-1:
  raise ValueError('CONNECT Box binder moved outside original constructor')

def strip(source):
 """Remove exactly one complete CONNECT outer binder, preserving SOCKS."""
 prefix='\treturn routerVPNNodeCONNECTBind('
 if 'routerVPNNodeCONNECTBind' not in source:return source,False
 if source.count(prefix)!=1 or source.count('routerVPNNodeCONNECTBind')!=1:
  raise ValueError('CONNECT acquired Box binder duplicated or moved')
 for inner,tail,original_tail in (
  ('routerVPNNodeSOCKSBind(&Box{\n','\n\t})), nil\n}','\n\t}), nil\n}'),
  ('&Box{\n','\n\t}), nil\n}','\n\t}, nil\n}'),
 ):
  header=prefix+inner
  if source.count(header)!=1:continue
  start=source.index(header)
  constructor(source,start)
  end=source.find(tail,start)
  if end<0 or source.find('\nfunc ',start,end)!=-1:
   raise ValueError('CONNECT acquired Box binder tail changed')
  source=source[:end]+source[end:].replace(tail,original_tail,1)
  return source.replace(header,'\treturn '+inner,1),True
 raise ValueError('CONNECT acquired Box binder has foreign inner owner')

def bind(source):
 plain,_=strip(source)
 if 'routerVPNNodeSOCKSBind' in plain:
  header='\treturn routerVPNNodeSOCKSBind(&Box{\n';tail='\n\t}), nil\n}';bound_tail='\n\t})), nil\n}'
  if plain.count('routerVPNNodeSOCKSBind')!=1:raise ValueError('CONNECT cannot compose duplicated SOCKS binders')
 else:
  header='\treturn &Box{\n';tail='\n\t}, nil\n}';bound_tail='\n\t}), nil\n}'
 if plain.count(header)!=1:raise ValueError('CONNECT acquired Box constructor moved')
 start=plain.index(header);constructor(plain,start);end=plain.find(tail,start)
 if end<0 or plain.find('\nfunc ',start,end)!=-1:raise ValueError('CONNECT acquired Box constructor tail moved')
 plain=plain[:end]+plain[end:].replace(tail,bound_tail,1)
 return plain.replace(header,header.replace('\treturn ','\treturn routerVPNNodeCONNECTBind('),1)
