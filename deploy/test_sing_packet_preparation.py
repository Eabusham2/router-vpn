#!/usr/bin/env python3
"""Integrity and isolation checks against the exact pinned sing module archive."""
from pathlib import Path
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sing_packet_patch', ROOT/'deploy/prepare-sing-packet-concurrency.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)


UDPNAT_GO = r'''
package udpnat

import (
 "context"
 "errors"
 "sync"
 "sync/atomic"
 "testing"
 "time"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)
type routerOwnerWriter struct {closed atomic.Bool; packets atomic.Int32}
func (w *routerOwnerWriter) WritePacket(b *buf.Buffer,_ M.Socksaddr)error {defer b.Release();if w.closed.Load(){return errors.New("closed owner")};w.packets.Add(1);return nil}
func (w *routerOwnerWriter) Close()error {w.closed.Store(true);return nil}
type routerOwner struct {connection *conn; close func(error)}
type routerOwnerHandler struct {owners chan routerOwner}
func (h *routerOwnerHandler) NewPacketConnectionEx(_ context.Context,c N.PacketConn,_,_ M.Socksaddr,close N.CloseHandlerFunc){h.owners<-routerOwner{c.(*conn),close}}
// The fixture witness runs after the actual legacy handler's Close/DeleteIf.
var routerVPNLegacyRetirements sync.Map
func routerVPNTestLegacyRetired(c *conn){if done,ok:=routerVPNLegacyRetirements.LoadAndDelete(c);ok {close(done.(chan struct{}))}}
type routerLegacyOwnerHandler struct {owners chan routerOwner}
func (h *routerLegacyOwnerHandler) NewPacketConnection(_ context.Context,c N.PacketConn,_ M.Metadata)error {
 release,retired:=make(chan struct{}),make(chan struct{})
 var once sync.Once
 routerVPNLegacyRetirements.Store(c.(*conn),retired)
 h.owners<-routerOwner{c.(*conn),func(error){once.Do(func(){close(release)});<-retired}}
 <-release
 return nil
}
func (*routerLegacyOwnerHandler) NewError(context.Context,error){}
func routerOwnerService(legacy bool)(*Service[int],chan routerOwner){
 owners:=make(chan routerOwner,3)
 if legacy {return New[int](60,&routerLegacyOwnerHandler{owners}),owners}
 return NewEx[int](60,&routerOwnerHandler{owners}),owners
}
func routerOwnerTake(t *testing.T,ch <-chan routerOwner)routerOwner {t.Helper();select{case o:=<-ch:return o;case <-time.After(time.Second):t.Fatal("original handler not published");return routerOwner{}}}
func routerOwnerDrain(c *conn){for{select{case p:=<-c.data:p.data.Release();default:return}}}
func routerOwnerSend(s *Service[int], variant string, initialize func(N.PacketConn)(context.Context,N.PacketWriter)) {
 ctx:=context.Background();source,destination:=M.ParseSocksaddr("192.0.2.1:1000"),M.ParseSocksaddr("192.0.2.2:2000")
 body:=buf.As([]byte("owned packet"))
 switch variant {
 case "NewPacket":s.NewPacket(ctx,7,body,M.Metadata{Source:source,Destination:destination},func(c N.PacketConn)N.PacketWriter{_,w:=initialize(c);return w})
 case "NewPacketEx":s.NewPacketEx(ctx,7,body,source,destination,func(c N.PacketConn)N.PacketWriter{_,w:=initialize(c);return w})
 case "NewContextPacket":s.NewContextPacket(ctx,7,body,M.Metadata{Source:source,Destination:destination},initialize)
 case "NewContextPacketEx":s.NewContextPacketEx(ctx,7,body,source,destination,initialize)
 default:panic("unknown fixture variant")
 }
}
var routerVPNPublicationWitness func(*conn)
func routerVPNTestPublicationWitness(c *conn){if routerVPNPublicationWitness!=nil {routerVPNPublicationWitness(c)}}
func TestRouterVPNUDPNATInitializedBeforePublication(t *testing.T){
 for _,variant:=range []string{"NewPacket","NewPacketEx","NewContextPacket","NewContextPacketEx"}{t.Run(variant,func(t *testing.T){
 handler:=&routerOwnerHandler{make(chan routerOwner,2)};s:=NewEx[int](60,handler)
 writer:=&routerOwnerWriter{};observed:=make(chan bool,1)
 // The byte-guarded fixture hook executes at the actual constructor return,
 // before LoadOrStore can publish this conn. No scheduler/timer inference.
 routerVPNPublicationWitness=func(c *conn){observed<-c.source==writer && c.ctx!=nil && c.cancel!=nil}
 defer func(){routerVPNPublicationWitness=nil}()
 routerOwnerSend(s,variant,func(N.PacketConn)(context.Context,N.PacketWriter){return context.Background(),writer})
 owner:=routerOwnerTake(t,handler.owners);defer routerOwnerDrain(owner.connection);defer owner.close(nil)
 if !<-observed {t.Fatal("UDP owner published before source initialization")}
 })}
}
func TestRouterVPNUDPNATRetiredHandlerCannotDeleteReplacement(t *testing.T){
 for _,variant:=range []string{"NewPacket","NewPacketEx","NewContextPacket","NewContextPacketEx"}{for _,legacy:=range []bool{false,true}{name:=variant+"/ex";if legacy {name=variant+"/legacy"};t.Run(name,func(t *testing.T){
 s,owners:=routerOwnerService(legacy)
 firstWriter,nextWriter:=&routerOwnerWriter{},&routerOwnerWriter{}
 routerOwnerSend(s,variant,func(N.PacketConn)(context.Context,N.PacketWriter){return context.Background(),firstWriter})
 first:=routerOwnerTake(t,owners);defer routerOwnerDrain(first.connection)
 _=first.connection.Close()
 routerOwnerSend(s,variant,func(N.PacketConn)(context.Context,N.PacketWriter){return context.Background(),nextWriter})
 next:=routerOwnerTake(t,owners);defer routerOwnerDrain(next.connection);defer next.close(nil)
 if next.connection==first.connection || nextWriter.closed.Load(){t.Fatal("replacement was not independently admitted")}
 // Completion of the original handler occurs only after a new owner exists.
 first.close(nil)
 current,found:=s.nat.Load(7)
 if !found || current!=next.connection || nextWriter.closed.Load() {t.Fatal("retired handler deleted replacement UDP owner")}
 if err:=next.connection.WritePacket(buf.As([]byte("replacement payload")),M.ParseSocksaddr("192.0.2.2:2000"));err!=nil || nextWriter.packets.Load()!=1 {t.Fatal("original cleanup disabled replacement writer",err)}
 select{case <-next.connection.ctx.Done():t.Fatal("original cleanup canceled replacement context");default:}
 })}}
}
'''


class PacketPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', PATCH.MODULE+'@'+PATCH.VERSION], cwd=ROOT, text=True))
        if info.get('Sum') != PATCH.SUM or info.get('Error'):
            raise ValueError('Test source does not match the pinned public module')
        cls.archive = Path(info['Zip'])
        cls.before = cls.archive.read_bytes()
        cls.cache = Path(info['Dir'])
        with zipfile.ZipFile(cls.archive) as archive:
            cls.originals = {name: archive.read(PATCH.PREFIX+name) for name in (*PATCH.PATCHES, 'LICENSE')}
        cls.cache_before = {name: ((cls.cache/name).read_bytes(), (cls.cache/name).stat().st_mode,
                                  (cls.cache/name).parent.stat().st_mode) for name in cls.originals}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root/PATCH.COPY
        self.target.mkdir()
        PATCH.extract_verified(self.archive, self.target)

    def test_only_verified_boundaries_change_and_license_archive_stay_identical(self):
        for name, original in self.originals.items():
            actual = (self.target/name).read_bytes()
            self.assertEqual(PATCH.transform(name, original), actual)
            self.assertEqual(PATCH.transform(name, actual, reverse=True), original)
        self.assertEqual(self.archive.read_bytes(), self.before)
        PATCH.verify_tree(self.target)
        for name in PATCH.PATCHES:
            with self.assertRaises(ValueError):
                PATCH.transform(name, self.originals[name]+b'\n// unrelated change\n')

    def assert_cache_unchanged(self):
        self.assertEqual(self.archive.read_bytes(), self.before)
        self.assertEqual({name: ((self.cache/name).read_bytes(), (self.cache/name).stat().st_mode,
                               (self.cache/name).parent.stat().st_mode) for name in self.originals}, self.cache_before)

    def test_exact_older_packet_only_copy_upgrades_after_full_checksum_verification(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}],
                'Replace': [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.BUFFER_FILES:
            (self.target/name).write_bytes(self.originals[name])
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        for name in PATCH.BUFFER_FILES:
            self.assertEqual((self.target/name).read_bytes(), PATCH.transform(name, self.originals[name]))
        self.assert_cache_unchanged()

    def test_packet_only_upgrade_rejects_unrelated_or_partial_source_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('license', 'unrelated', 'partial', 'missing-lock'):
            with self.subTest(fault=fault):
                for name, original in self.originals.items():
                    (self.target/name).write_bytes(original if name in PATCH.BUFFER_FILES else PATCH.transform(name, original))
                if fault == 'license':
                    (self.target/'LICENSE').write_bytes(b'changed license')
                elif fault == 'unrelated':
                    path = self.target/'common/buf/buffer_standard.go'
                    path.write_bytes(path.read_bytes()+b'\n// unexpected source\n')
                elif fault == 'partial':
                    name = 'common/buf/buffer_standard.go'
                    (self.target/name).write_bytes(PATCH.transform(name, self.originals[name]))
                else:
                    (self.target/'common/bufio/bind.go').write_bytes(self.originals['common/bufio/bind.go'])
                before = {name: (self.target/name).read_bytes() for name in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({name: (self.target/name).read_bytes() for name in self.originals}, before)
        self.assert_cache_unchanged()

    def test_exact_prior_association_group_upgrades_without_resetting_packet_fixes(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.ASSOCIATION_FILES:
            (self.target/name).write_bytes(self.originals[name])
        preserved = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES if name not in PATCH.ASSOCIATION_FILES}
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        self.assertEqual({name: (self.target/name).read_bytes() for name in preserved}, preserved)
        self.assert_cache_unchanged()

    def test_partial_or_foreign_association_upgrade_changes_nothing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('partial', 'foreign'):
            with self.subTest(fault=fault):
                for name in PATCH.ASSOCIATION_FILES:
                    (self.target/name).write_bytes(self.originals[name])
                name = 'protocol/socks/packet_wait.go'
                if fault == 'partial':
                    (self.target/name).write_bytes(PATCH.transform(name, self.originals[name]))
                else:
                    (self.target/name).write_bytes(self.originals[name]+b'\n// unrelated association\n')
                before = {name: (self.target/name).read_bytes() for name in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({name: (self.target/name).read_bytes() for name in self.originals}, before)
        self.assert_cache_unchanged()

    def test_exact_prior_authentication_upgrades_without_changing_owned_lifetimes(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.AUTH_FILES:
            (self.target/name).write_bytes(self.originals[name])
        preserved = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES if name not in PATCH.AUTH_FILES}
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        self.assertEqual({name: (self.target/name).read_bytes() for name in preserved}, preserved)
        self.assert_cache_unchanged()

    def test_authentication_upgrade_rejects_changed_or_aliased_source_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('changed', 'symlink', 'hardlink'):
            with self.subTest(fault=fault):
                name = 'protocol/socks/handshake.go'
                path = self.target/name
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_bytes(self.originals[name])
                outside = self.root/('auth-'+fault)
                outside.write_bytes(self.originals[name])
                if fault == 'changed':
                    path.write_bytes(self.originals[name]+b'\n// unowned authentication policy\n')
                elif fault == 'symlink':
                    path.unlink()
                    try:
                        path.symlink_to(outside)
                    except OSError:
                        path.write_bytes(self.originals[name])
                        continue  # Covered on hosts with actual link privileges.
                else:
                    path.unlink()
                    try:
                        path.hardlink_to(outside)
                    except OSError:
                        path.write_bytes(self.originals[name])
                        continue
                before = {entry: (self.target/entry).read_bytes() for entry in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({entry: (self.target/entry).read_bytes() for entry in self.originals}, before)
                self.assertEqual(outside.read_bytes(), self.originals[name])
                path.unlink()
                path.write_bytes(PATCH.transform(name, self.originals[name]))
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_exact_previous_payload_copy_upgrades_without_losing_control_or_authentication(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        self.assertNotEqual(previous, self.originals[name])
        self.assertIn(b'clientAssociationControl', previous)
        for old_auth in (False, True):
            with self.subTest(old_auth=old_auth):
                (self.target/name).write_bytes(previous)
                for auth in PATCH.AUTH_FILES:
                    (self.target/auth).write_bytes(self.originals[auth] if old_auth else PATCH.transform(auth, self.originals[auth]))
                preserved = {path: (self.target/path).read_bytes() for path in self.originals
                             if path != name and not (old_auth and path in PATCH.AUTH_FILES)}
                with self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
                    PATCH.prepare(self.root)
                    PATCH.prepare(self.root)
                self.assertEqual((self.target/name).read_bytes(), fixed)
                self.assertEqual({path: (self.target/path).read_bytes() for path in preserved}, preserved)
                PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_payload_upgrade_rejects_partial_foreign_or_incomplete_association_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        for fault in ('io-only', 'count-only', 'writepacket-only', 'foreign-packet', 'foreign-license', 'missing-control-peer'):
            with self.subTest(fault=fault):
                for path, original in self.originals.items():
                    (self.target/path).write_bytes(PATCH.transform(path, original))
                data = previous
                if fault == 'io-only':
                    data = data.replace(b'\t"errors"\n', b'\t"errors"\n\t"io"\n', 1)
                elif fault == 'count-only':
                    data = data.replace(b'\treturn c.conn.Write(buffer.Bytes())\n', b'\treturn len(p), nil\n', 1)
                elif fault == 'writepacket-only':
                    data = data.replace(b'\treturn c.conn.WriteBuffer(buffer)\n', b'\treturn nil\n', 1)
                elif fault == 'foreign-packet':
                    data += b'\n// unrelated packet policy\n'
                elif fault == 'foreign-license':
                    (self.target/'LICENSE').write_bytes(b'changed license')
                else:
                    peer = 'protocol/socks/packet_wait.go'
                    (self.target/peer).write_bytes(self.originals[peer])
                (self.target/name).write_bytes(data)
                before = {path: (self.target/path).read_bytes() for path in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({path: (self.target/path).read_bytes() for path in self.originals}, before)
        self.assert_cache_unchanged()

    def test_payload_upgrade_rejects_aliases_without_touching_the_original(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        path = self.target/name
        fixed = path.read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                outside = self.root/('payload-'+kind)
                outside.write_bytes(previous)
                path.unlink()
                try:
                    path.symlink_to(outside) if kind == 'symlink' else path.hardlink_to(outside)
                except OSError:
                    path.write_bytes(fixed)
                    continue  # Actual alias rejection runs on hosts with link privileges.
                before = {entry: (self.target/entry).read_bytes() for entry in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({entry: (self.target/entry).read_bytes() for entry in self.originals}, before)
                self.assertEqual(outside.read_bytes(), previous)
                path.unlink()
                path.write_bytes(fixed)
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_payload_negative_control_only_reverses_the_exact_owned_patch(self):
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        self.assertIn(b'\treturn c.conn.Write(buffer.Bytes())\n', previous)
        self.assertIn(b'\treturn c.conn.WriteBuffer(buffer)\n', previous)
        self.assertIn(b'\t<-c.joined\n', previous)
        for data in (self.originals[name], previous, fixed+b'\n// foreign source\n'):
            with self.assertRaises(ValueError):
                PATCH.without_payload_write_fix(name, data)
        with self.assertRaises(ValueError):
            PATCH.without_payload_write_fix('protocol/socks/handshake.go', (self.target/'protocol/socks/handshake.go').read_bytes())
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_exact_prior_write_copy_upgrades_read_headroom_after_complete_module_verification(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_read_fix(name, fixed)
        self.assertIn(b'\treturn c.writePayload(buffer.Bytes(), len(p))\n', previous)
        self.assertIn(b'\t<-c.joined\n', previous)
        self.assertIn(b'\tn, err = c.conn.Read(p)\n', previous)
        for old_auth in (False, True):
            with self.subTest(old_auth=old_auth):
                (self.target/name).write_bytes(previous)
                for auth in PATCH.AUTH_FILES:
                    (self.target/auth).write_bytes(self.originals[auth] if old_auth else PATCH.transform(auth, self.originals[auth]))
                preserved = {path: (self.target/path).read_bytes() for path in self.originals
                             if path != name and not (old_auth and path in PATCH.AUTH_FILES)}
                with self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
                    PATCH.prepare(self.root)
                    PATCH.prepare(self.root)
                self.assertEqual((self.target/name).read_bytes(), fixed)
                self.assertEqual({path: (self.target/path).read_bytes() for path in preserved}, preserved)
                PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_read_upgrade_rejects_partial_foreign_or_incomplete_source_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        previous = PATCH.without_payload_read_fix(name, (self.target/name).read_bytes())
        for fault in ('copy-only', 'buffer-only', 'foreign-packet', 'foreign-license', 'missing-control-peer'):
            with self.subTest(fault=fault):
                for path, original in self.originals.items():
                    (self.target/path).write_bytes(PATCH.transform(path, original))
                data = previous
                if fault == 'copy-only':
                    data = data.replace(b'\tn = copy(p, p[index:n])\n', b'\tn = copy(p, frame[index:n])\n', 1)
                elif fault == 'buffer-only':
                    data = data.replace(b'\tn, err = c.conn.Read(p)\n', b'\tframe := make([]byte, 65535)\n\tn, err = c.conn.Read(frame)\n', 1)
                elif fault == 'foreign-packet':
                    data += b'\n// unowned read policy\n'
                elif fault == 'foreign-license':
                    (self.target/'LICENSE').write_bytes(b'foreign license')
                else:
                    peer = 'protocol/socks/packet_wait.go'
                    (self.target/peer).write_bytes(self.originals[peer])
                (self.target/name).write_bytes(data)
                before = {path: (self.target/path).read_bytes() for path in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({path: (self.target/path).read_bytes() for path in self.originals}, before)
        self.assert_cache_unchanged()

    def test_read_upgrade_rejects_aliased_prior_write_source(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        path = self.target/name
        fixed = path.read_bytes()
        previous = PATCH.without_payload_read_fix(name, fixed)
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                outside = self.root/('read-'+kind)
                outside.write_bytes(previous)
                path.unlink()
                try:
                    path.symlink_to(outside) if kind == 'symlink' else path.hardlink_to(outside)
                except OSError:
                    path.write_bytes(fixed)
                    continue
                before = {entry: (self.target/entry).read_bytes() for entry in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({entry: (self.target/entry).read_bytes() for entry in self.originals}, before)
                self.assertEqual(outside.read_bytes(), previous)
                path.unlink()
                path.write_bytes(fixed)
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_read_negative_control_keeps_exact_published_writes_and_original_authentication(self):
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_read_fix(name, fixed)
        self.assertIn(b'func (c *AssociatePacketConn) writePayload(', previous)
        self.assertIn(b'\tdefer buffer.Release()\n\tpayloadSize := buffer.Len()\n', previous)
        self.assertIn(b'\t<-c.joined\n', previous)
        self.assertNotEqual(previous, PATCH.without_payload_write_fix(name, fixed))
        for data in (self.originals[name], previous, fixed+b'\n// foreign source\n'):
            with self.assertRaises(ValueError):
                PATCH.without_payload_read_fix(name, data)
        with self.assertRaises(ValueError):
            PATCH.without_payload_read_fix('protocol/socks/handshake.go', (self.target/'protocol/socks/handshake.go').read_bytes())
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_missing_extra_reverted_and_unrelated_edits_are_rejected(self):
        cases = [('common/bufio/bind.go', self.originals['common/bufio/bind.go']),
                 ('common/bufio/bind_wait.go', self.originals['common/bufio/bind_wait.go']),
                 ('LICENSE', b'altered license'), ('go.mod', None), ('extra.go', b'package extra\n')]
        for name, replacement in cases:
            with self.subTest(name=name):
                path = self.target/name
                original = path.read_bytes() if path.exists() else None
                try:
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    with self.assertRaises(ValueError):
                        PATCH.verify_tree(self.target)
                finally:
                    if original is None:
                        path.unlink()
                    else:
                        path.write_bytes(original)
        PATCH.verify_tree(self.target)

    def test_linked_output_and_unsafe_archive_paths_are_rejected(self):
        if hasattr(Path, 'symlink_to'):
            outside = self.root/'outside'
            outside.write_bytes(self.originals['LICENSE'])
            license = self.target/'LICENSE'
            license.unlink()
            try:
                license.symlink_to(outside)
            except OSError:
                license.write_bytes(self.originals['LICENSE'])  # Windows without symlink privilege.
            else:
                with self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
                self.assertEqual(outside.read_bytes(), self.originals['LICENSE'])
        for name in ('../escaped', '/absolute', 'pkg/../../escaped', 'pkg//empty', 'bad\nname', 'bad\\name'):
            archive = self.root/'unsafe.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr(PATCH.PREFIX+name, b'data')
            with self.assertRaises(ValueError):
                PATCH.extract_verified(archive, self.root/'stage')
        self.assertFalse((self.root/'escaped').exists())

    def test_wrong_version_and_foreign_replacement_are_rejected(self):
        plans = ({'Require': []},
                 {'Require': [{'Path': PATCH.MODULE, 'Version': 'v0.0.0'}]},
                 {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}],
                  'Replace': [{'Old': {'Path': PATCH.MODULE}, 'New': {'Path': '/foreign'}}]})
        for plan in plans:
            with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(plan)), self.assertRaises(ValueError):
                PATCH.module_plan(self.root)

    def test_prepare_is_idempotent_and_rejects_foreign_selected_copy(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE+'\n'
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(plan)
            if args[1:5] == ['list', '-m', '-json', PATCH.MODULE]:
                return json.dumps({'Version': PATCH.VERSION, 'Replace': {'Path': './'+PATCH.COPY, 'Dir': str(self.target)}})
            raise AssertionError('Existing checked copy must not redownload: '+str(args))
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run') as run:
            PATCH.prepare(self.root)
            plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]
            PATCH.prepare(self.root)
            PATCH.verify(self.root)
            self.assertEqual(run.call_count, 2)
        plan['Replace'][0]['New']['Path'] = '/foreign'
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
            PATCH.verify(self.root)

    def test_patch_enters_native_cache_identity(self):
        spec = importlib.util.spec_from_file_location('amnezia_preparation', ROOT/'deploy/prepare-mobile-amnezia.py')
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        self.assertIn(ROOT/'deploy/prepare-sing-packet-concurrency.py', preparation.inputs())
        self.assertIn(ROOT/'mobile/amnezia/packet_concurrency_test.go.tmpl', preparation.inputs())
        self.assertIn(ROOT/'mobile/amnezia/socks_association_test.go.tmpl', preparation.inputs())
        self.assertIn('../deploy/prepare-sing-packet-concurrency.py', (ROOT/'android/app/build.gradle').read_text())
        spec = importlib.util.spec_from_file_location('whitening_preparation', ROOT/'deploy/prepare-mobile-whitening.py')
        whitening = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(whitening)
        self.assertIn(ROOT/'deploy/prepare-sing-packet-concurrency.py', whitening.inputs())

    def test_real_go_buffer_preparation_and_packet_repreparation_share_one_copy(self):
        spec = importlib.util.spec_from_file_location('combined_buffer_policy', ROOT/'deploy/prepare-mobile-buffers.py')
        buffers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(buffers)
        # Exercise the real Go module editor, MVS selection, tidy and compiler.
        # Only the outer core's Git identity and unrelated socket insertion are
        # fixtures; both dependency preparations operate on the pinned archive.
        (self.root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.26.0\n\nrequire '+PATCH.MODULE+' '+PATCH.VERSION+'\n')
        (self.root/'main.go').write_text('package main\nimport ("fmt"; "github.com/sagernet/sing/common/buf")\nfunc main() { fmt.Printf("%d %d\\n", buf.BufferSize, buf.UDPBufferSize) }\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                self.assertEqual(args[-2:], ['rev-parse', 'HEAD'])
                return PATCH.CORE+'\n'
            return actual(args, **kwargs)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), mock.patch.object(buffers.SOCKETS, 'prepare') as sockets:
            PATCH.prepare(self.root)
            buffers.prepare(self.root)
            PATCH.prepare(self.root)
            buffers.prepare(self.root)
            PATCH.verify(self.root)
            self.assertEqual(sockets.call_count, 2)
        plan = json.loads(actual(['go', 'mod', 'edit', '-json'], cwd=self.root, text=True))
        self.assertEqual([r for r in plan['Replace'] if r['Old']['Path'] == PATCH.MODULE],
                         [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}])
        for tags, expected in (('', '32768 65535'), ('with_low_memory', '16384 65535')):
            self.assertEqual(actual(['go', 'run', '-tags='+tags, '.'], cwd=self.root, text=True).strip(), expected)
        self.assertFalse((self.root/'.routervpn-sources/sing').exists())
        self.assert_cache_unchanged()
        # An explicit competing replacement remains rejected, even if an
        # intact verified owned copy is also present.
        subprocess.run(['go', 'mod', 'edit', '-replace='+PATCH.MODULE+'=/foreign'], cwd=self.root, check=True)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
            buffers.prepare(self.root)
        PATCH.verify_tree(self.target)

    def test_buffers_first_also_create_the_same_verified_copy(self):
        spec = importlib.util.spec_from_file_location('buffers_first_policy', ROOT/'deploy/prepare-mobile-buffers.py')
        buffers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(buffers)
        shutil.rmtree(self.target)
        (self.root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.26.0\n\nrequire '+PATCH.MODULE+' '+PATCH.VERSION+'\n')
        (self.root/'main.go').write_text('package main\nimport _ "github.com/sagernet/sing/common/buf"\nfunc main() {}\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE+'\n'
            return actual(args, **kwargs)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), mock.patch.object(buffers.SOCKETS, 'prepare'):
            buffers.prepare(self.root)
            PATCH.prepare(self.root)
            PATCH.verify(self.root)
        self.assertFalse((self.root/'.routervpn-sources/sing').exists())



    def test_udp_nat_upgrade_validates_complete_group_and_rejects_partial_aliases(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        preserved = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES if name not in PATCH.UDPNAT_FILES}
        for fault in ('partial', 'foreign', 'alias', 'complete'):
            with self.subTest(fault=fault):
                for name in PATCH.UDPNAT_FILES:
                    path = self.target/name
                    path.unlink()
                    path.write_bytes(self.originals[name])
                name = 'common/udpnat/service.go'
                path = self.target/name
                if fault == 'partial':
                    path.write_bytes(PATCH.transform(name, self.originals[name]))
                elif fault == 'foreign':
                    path.write_bytes(self.originals[name]+b'\n// foreign owner\n')
                elif fault == 'alias':
                    alias = self.root/'aliased-udp-owner'
                    if alias.exists(): alias.unlink()
                    alias.hardlink_to(path)
                before = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
                    if fault == 'complete':
                        PATCH.prepare(self.root)
                        PATCH.prepare(self.root)
                        PATCH.verify_tree(self.target)
                    else:
                        with self.assertRaises(ValueError): PATCH.prepare(self.root)
                        self.assertEqual({name: (self.target/name).read_bytes() for name in PATCH.PATCHES}, before)
                self.assertEqual({name: (self.target/name).read_bytes() for name in preserved}, preserved)
        self.assert_cache_unchanged()

    def test_actual_udp_nat_publication_and_retirement_with_independent_causal_controls(self):
        service = self.target/'common/udpnat/service.go'
        fixed = service.read_bytes()
        fixture = self.target/'common/udpnat/routervpn_owner_test.go'
        fixture.write_text(UDPNAT_GO)
        def witnessed(data):
            marker = b'\t\treturn c\n\t})'
            self.assertEqual(data.count(marker), 1)
            data = data.replace(marker, b'\t\trouterVPNTestPublicationWitness(c)\n'+marker, 1)
            legacy = b'\n\t\t\t\ts.nat.DeleteIf(key, func(current *conn) bool { return current == c })\n'
            if legacy not in data:
                legacy = b'\n\t\t\t\ts.nat.Delete(key)\n'
            self.assertEqual(data.count(legacy), 1)
            return data.replace(legacy, legacy+b'\t\t\t\trouterVPNTestLegacyRetired(c)\n', 1)
        service.write_bytes(witnessed(fixed))
        command = ['go', 'test', '-mod=readonly', '-race', './common/udpnat', '-count=1', '-timeout=15s']
        try:
            result = subprocess.run(command+['-run', '^TestRouterVPNUDPNAT'], cwd=self.target, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout)
            unpublished = fixed
            for old, new in reversed(PATCH.UDPNAT_FILES['common/udpnat/service.go'][1][:3]):
                self.assertEqual(unpublished.count(new.encode()), 1)
                unpublished = unpublished.replace(new.encode(), old.encode(), 1)
            mutations = [
                (unpublished, '^TestRouterVPNUDPNATInitializedBeforePublication$', 'UDP owner published before source initialization'),
                (fixed.replace(b'\n\t\t\t\t\ts.nat.DeleteIf(key, func(current *conn) bool { return current == c })\n', b'\n\t\t\t\t\ts.nat.Delete(key)\n'), '^TestRouterVPNUDPNATRetiredHandlerCannotDeleteReplacement$/[^/]+/ex$', 'retired handler deleted replacement UDP owner'),
                (fixed.replace(b'\n\t\t\t\ts.nat.DeleteIf(key, func(current *conn) bool { return current == c })\n', b'\n\t\t\t\ts.nat.Delete(key)\n'), '^TestRouterVPNUDPNATRetiredHandlerCannotDeleteReplacement$/[^/]+/legacy$', 'retired handler deleted replacement UDP owner'),
            ]
            for mutated, selector, failure in mutations:
                service.write_bytes(witnessed(mutated))
                result = subprocess.run(command+['-run', selector], cwd=self.target, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
                self.assertNotEqual(result.returncode, 0, 'causal owner regression was accepted')
                self.assertIn(failure, result.stdout)
                self.assertNotIn('panic: test timed out', result.stdout)
        finally:
            service.write_bytes(fixed)
            fixture.unlink()
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()


if __name__ == '__main__':
    unittest.main()
