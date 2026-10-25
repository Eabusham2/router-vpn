"""Carry immutable physical-session generations through pinned OpenVPN events."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/sing-openvpn'
VERSION = 'v0.0.0-20260729104525-103eb5fe5eb6'
SUM = 'h1:ZAvhkor0prJ8KEX9EmTEH+gJ1WlA3ffjS8GZT6KKq9c='
COPY = 'routervpn-patched-openvpn'
PREFIX = MODULE+'@'+VERSION+'/'
MAX_BYTES = 64*1024*1024
FIXTURE = 'routervpn_generation_fixture.go'

# Every alteration is reversed before comparing the entire dependency to its
# official h1 checksum. No module-cache file is changed and no TLS code is bypassed.
PATCHES = {
 'options.go': [
  ('type TunnelConfigurationEvent struct {\n','type TunnelConfigurationEvent struct {\n\tRouterVPNTransportGeneration uint64\n'),
  ('type ClientOptions struct {\n','type ClientOptions struct {\n\tRouterVPNTransportGeneration func(net.Conn) uint64\n'),
 ],
 'client_session_tls.go': [
  ('type tlsClient struct {\n','type tlsClient struct {\n\trouterVPNTransportGeneration uint64\n'),
  ('\tpacketConnection, err := proto.NewPacketConnection(underlyingConnection, c.remote.remote.Protocol)\n',
   '\tif capture := c.parent.options.RouterVPNTransportGeneration; capture != nil {\n\t\tc.routerVPNTransportGeneration = capture(underlyingConnection)\n\t\tif c.routerVPNTransportGeneration == 0 {\n\t\t\t_ = underlyingConnection.Close()\n\t\t\tcancelSession()\n\t\t\treturn net.ErrClosed\n\t\t}\n\t}\n\tpacketConnection, err := proto.NewPacketConnection(underlyingConnection, c.remote.remote.Protocol)\n'),
  ('c.parent.emitTunnelConfigurationEvent(TunnelConfigurationEventInitial)',
   'c.parent.emitTunnelConfigurationEvent(TunnelConfigurationEventInitial, c.routerVPNTransportGeneration)'),
 ],
 'client_session_static.go': [
  ('type staticKeyClientSession struct {\n','type staticKeyClientSession struct {\n\trouterVPNTransportGeneration uint64\n'),
  ('\tpacketConnection, err := proto.NewPacketConnection(underlyingConnection, s.remote.remote.Protocol)\n',
   '\tif capture := s.parent.options.RouterVPNTransportGeneration; capture != nil {\n\t\ts.routerVPNTransportGeneration = capture(underlyingConnection)\n\t\tif s.routerVPNTransportGeneration == 0 {\n\t\t\t_ = underlyingConnection.Close()\n\t\t\tcancelSession()\n\t\t\treturn net.ErrClosed\n\t\t}\n\t}\n\tpacketConnection, err := proto.NewPacketConnection(underlyingConnection, s.remote.remote.Protocol)\n'),
  ('s.parent.emitTunnelConfigurationEvent(TunnelConfigurationEventInitial)',
   's.parent.emitTunnelConfigurationEvent(TunnelConfigurationEventInitial, s.routerVPNTransportGeneration)'),
 ],
 'client_tunnel.go': [
  ('func (c *Client) emitTunnelConfigurationEvent(reason TunnelConfigurationEventReason) {',
   'func (c *Client) emitTunnelConfigurationEvent(reason TunnelConfigurationEventReason, routerVPNGeneration ...uint64) {'),
  ('\t\tReason:        reason,\n', '\t\tRouterVPNTransportGeneration: routerVPNEventGeneration(routerVPNGeneration),\n\t\tReason:        reason,\n'),
  ('func (c *Client) applyPushedOptions(options pushedOptions) pushedOptionsApplyResult {',
   'func (c *Client) applyPushedOptions(options pushedOptions, routerVPNGeneration ...uint64) pushedOptionsApplyResult {'),
  ('\t\t\tReason:        eventReason,\n', '\t\t\tRouterVPNTransportGeneration: routerVPNEventGeneration(routerVPNGeneration),\n\t\t\tReason:        eventReason,\n'),
  ('func (c *Client) startTunnelConfigurationDispatcher() {',
   'func routerVPNEventGeneration(generations []uint64) uint64 {\n\tif len(generations) == 1 { return generations[0] }\n\treturn 0\n}\n\nfunc (c *Client) startTunnelConfigurationDispatcher() {'),
 ],
 'control_directives.go': [
  ('c.parent.applyPushedOptions(options)', 'c.parent.applyPushedOptions(options, c.routerVPNTransportGeneration)'),
 ],
}

def inputs():
    return [Path(__file__).resolve(), ROOT/'mobile/routervpn_openvpn_generation_fixture.go.tmpl']


def patch(name, data, reverse=False):
    text=data.decode()
    changes=PATCHES.get(name, [])
    for before, after in reversed(changes) if reverse else changes:
        old,new=(after,before) if reverse else (before,after)
        if text.count(old)!=1:
            raise ValueError('Pinned OpenVPN session/event boundary changed: '+name)
        text=text.replace(old,new,1)
    return text.encode()


def h1(rows):
    summary=''.join(digest+'  '+name+'\n' for name,digest in sorted(rows))
    return 'h1:'+base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir(): raise ValueError('Prepared OpenVPN must be an owned directory')
    rows=[];total=0;fixture=False
    for source in sorted(directory.rglob('*')):
        if source.is_symlink() or not(source.is_file() or source.is_dir()): raise ValueError('Linked or special prepared OpenVPN source')
        if source.is_dir(): continue
        name=source.relative_to(directory).as_posix()
        if '\n' in name or '\r' in name: raise ValueError('Invalid OpenVPN path')
        total+=source.stat().st_size
        if total>MAX_BYTES or len(rows)>=10000: raise ValueError('OpenVPN source exceeds bounds')
        data=source.read_bytes()
        if name==FIXTURE:
            if data!=(ROOT/'mobile/routervpn_openvpn_generation_fixture.go.tmpl').read_bytes(): raise ValueError('OpenVPN fixture differs from captured source')
            fixture=True;continue
        if name in PATCHES: data=patch(name,data,True)
        rows.append((PREFIX+name,hashlib.sha256(data).hexdigest()))
    if not fixture or h1(rows)!=SUM: raise ValueError('Prepared OpenVPN differs from its pinned module and exact generation patch')


def extract_verified(archive,target):
    rows=[];total=0;seen=set()
    with zipfile.ZipFile(archive) as bundle:
        members=bundle.infolist()
        if not members or len(members)>10000: raise ValueError('Invalid OpenVPN archive bounds')
        for member in members:
            if not member.filename.startswith(PREFIX): raise ValueError('Foreign OpenVPN module prefix')
            name=member.filename[len(PREFIX):];parts=PurePosixPath(name)
            if not name or str(parts)!=name or '\\' in name or '\n' in name or '\r' in name or '..' in parts.parts or parts.is_absolute() or member.is_dir() or stat.S_ISLNK(member.external_attr>>16) or name in seen or name==FIXTURE: raise ValueError('Unsafe OpenVPN archive entry')
            seen.add(name);total+=member.file_size
            if total>MAX_BYTES or member.file_size>MAX_BYTES: raise ValueError('OpenVPN archive exceeds bounds')
            data=bundle.read(member);rows.append((member.filename,hashlib.sha256(data).hexdigest()))
            if name in PATCHES: data=patch(name,data)
            output=target/name;output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(data)
    if h1(rows)!=SUM: raise ValueError('OpenVPN download does not match pinned h1 checksum')
    (target/FIXTURE).write_bytes((ROOT/'mobile/routervpn_openvpn_generation_fixture.go.tmpl').read_bytes())
    verify_tree(target)


def prepare(vendor):
    vendor=Path(vendor).resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=CORE: raise ValueError('OpenVPN generation patch requires pinned native core')
    plan=json.loads(subprocess.check_output(['go','mod','edit','-json'],cwd=vendor,text=True))
    versions=[item for item in plan.get('Require',[]) if item['Path']==MODULE]
    if len(versions)!=1 or versions[0]['Version']!=VERSION: raise ValueError('Unexpected native OpenVPN module version')
    replacements=[item for item in plan.get('Replace',[]) or [] if item['Old']['Path']==MODULE]
    expected={'Old':{'Path':MODULE,'Version':VERSION},'New':{'Path':'./'+COPY}}
    if replacements and replacements!=[expected]: raise ValueError('Unowned OpenVPN module replacement')
    target=vendor/COPY
    if target.exists() or target.is_symlink(): verify_tree(target)
    else:
        info=json.loads(subprocess.check_output(['go','mod','download','-json',MODULE+'@'+VERSION],cwd=vendor,text=True))
        if info.get('Path')!=MODULE or info.get('Version')!=VERSION or info.get('Sum')!=SUM or info.get('Error'): raise ValueError('OpenVPN module metadata does not match pinned source')
        with tempfile.TemporaryDirectory(prefix='.routervpn-openvpn-',dir=vendor) as temporary:
            staged=Path(temporary)/'module';staged.mkdir();extract_verified(Path(info['Zip']),staged);staged.rename(target)
    subprocess.run(['go','mod','edit','-replace='+MODULE+'@'+VERSION+'=./'+COPY],cwd=vendor,check=True)
    print('Prepared checksum-verified OpenVPN session-generation events:',VERSION)
