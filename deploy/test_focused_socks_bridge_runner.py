#!/usr/bin/env python3
"""Require the combined native gate's real inventories and fail-closed evidence."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("typed_socks_bridge_validator",ROOT/"deploy/test_focused_socks_bridge.py")
V=importlib.util.module_from_spec(spec);sys.modules[spec.name]=V;spec.loader.exec_module(V)

def events(package,names,control=None,owner=False):
    names=tuple(names);expected=set(names)
    leaves={name for name in names if not any(other.startswith(name+"/") for other in names)}
    failures=set()
    witnesses=set()
    if control:
        if owner:witnesses,failures=V.OWNER.required_failures(control)
        else:witnesses,failures=leaves,expected
    rows=[dict(Action="start",Package=package)]
    def enter(name):
        rows.append(dict(Action="run",Package=package,Test=name))
        for child in names:
            if child!=name and child.rsplit("/",1)[0]==name:enter(child)
        if name in witnesses:
            rows.append(dict(Action="output",Package=package,Test=name,Output=control["witness"]+"\n"))
        rows.append(dict(Action="fail" if name in failures else "pass",Package=package,Test=name))
    for name in names:
        if "/" not in name:enter(name)
    rows.append(dict(Action="fail" if control else "pass",Package=package))
    return rows

def encoded(rows):return ("\n".join(json.dumps(row) for row in rows)+"\n").encode()

def plain(names):
    return "".join("=== RUN   "+name+"\n--- PASS: "+name+" (0.01s)\n" for name in names)+"PASS\n"

class Composition:
    def __init__(self,directory,fault=None):
        self.fault,self.calls=fault,[]
        self.source=directory/"candidate";self.source.mkdir()
        (self.source/"original.go").write_text("original candidate source\n")
        self.output=directory/"validation-output"/"tests";self.output.parent.mkdir()
        self.metadata=dict(schema=1,suite=V.SUITE,validator_sha="a"*40,validator_tree="b"*40,
            base_sha="c"*40,base_tree="d"*40,source_sha="e"*40,source_tree="f"*40,
            validation_scope="read-only-source-candidate",relation="single-parent")
        self.selection_file=self.output.parent/"selection.json";self.selection_file.write_text(json.dumps(self.metadata))
        self.core=None;self.images=[];self.owner_calls=[]
        self.gate=types.SimpleNamespace(NODE=types.SimpleNamespace(
            TAGS=("with_wireguard","with_gvisor","with_purego"),
            selected_compiler=lambda go,core,env:(go,env,"amd64"),
            require_native_verdicts=self.require_original))
    def require_original(self,text,names,label):
        if text!=plain(names):raise ValueError("original peer inventory changed")
        self.owner_calls.append(tuple(names))
    def git(self,source,*args):
        if args==("status","--porcelain","--untracked-files=all"):
            return " M original.go" if self.fault=="dirty-source" else ""
        if args==("rev-parse","HEAD"):
            return self.metadata["source_sha" if source==self.source else "validator_sha"]
        if args==("rev-parse","HEAD^{tree}"):
            return self.metadata["source_tree" if source==self.source else "validator_tree"]
        raise AssertionError(args)
    def snapshot(self,source):
        return {p.name:{"mode":"100644","sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in source.iterdir() if p.is_file()}
    def checked(self,source,core,xray):
        if self.fault=="projection-refusal":raise ValueError("original native projection refused")
        return {"owner":{"exact-owner":"a"*64},"core":V.native_snapshot(core),"xray":V.native_snapshot(xray)}
    def execute(self,command,cwd,env,log,bound):
        name=log.stem;self.calls.append((name,command,bound))
        status=0;raw=b""
        if name=="original-owner-preflight":
            raw=(("test_shipping_desktop_daemon_capture_is_exact_idempotent_and_fail_closed "
                "(__main__.DesktopDaemonCapturePreparation.test_shipping_desktop_daemon_capture_is_exact_idempotent_and_fail_closed) ... ok\n\n")
                +"-"*70+"\nRan 1 test in 0.01s\n\nOK\n").encode()
        elif name in ("prepare-owner","prepare-mobile"):
            if self.fault=="spawn-failure":raise OSError("original preparation spawn refused")
            core=Path(command[command.index("--core")+1]);xray=Path(command[command.index("--xray")+1])
            core.mkdir();xray.mkdir()
            if name=="prepare-mobile":self.core,self.xray=core,xray
            else:self.owner_core,self.owner_xray=core,xray
            (xray/"original.go").write_text("original xray")
            by_path={}
            for control in V.CONTROLS:
                anchors=by_path.setdefault(control["path"],[])
                if control["before"] not in anchors:anchors.append(control["before"])
            by_path[V.OWNER.OWNER_PROJECTION]=[control["before"] for control in V.OWNER.CONTROLS]
            for relative,anchors in by_path.items():
                path=core/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text("\n".join(anchors))
        elif name.endswith("-build"):
            assert cwd==(self.owner_core if name=="owner-build" else self.core)
            image=Path(command[command.index("-o")+1]);image.write_bytes(("original image "+name).encode());self.images.append(image)
        elif name in ("original-encrypted-owner","original-encrypted-peer"):
            assert cwd==self.owner_core
            raw=plain(V.OWNER.VERDICTS if name.endswith("-owner") else V.OWNER.ORIGINAL).encode()
        elif name.startswith("owner-"):
            assert cwd==self.owner_core
            control=next(x for x in V.OWNER.CONTROLS if name=="owner-"+x["name"])
            raw=encoded(events(V.OWNER.PACKAGE,control["cases"],control,True));status=1
            self.check_overlay(command,cwd,V.OWNER.OWNER_PROJECTION,control)
        elif name in ("typed-native","original-libbox","original-box"):
            assert cwd==self.core
            package,names=(V.BOX,V.ORIGINAL_BOX) if name=="original-box" else (V.LIBBOX,V.VERDICTS if name=="typed-native" else V.ORIGINAL_LIBBOX)
            raw=encoded(events(package,names))
        else:
            control=next(x for x in V.CONTROLS if name==x["name"])
            self.check_overlay(command,cwd,control["path"],control)
            raw=encoded(events(V.control_target(control)[0],control["cases"],control));status=1
        if self.fault=="preflight-missing" and name=="original-owner-preflight":raw=b"Ran 0 tests\nOK\n"
        if self.fault=="prepare-fail" and name=="prepare-mobile":status=1
        if self.fault=="owner-prepare-fail" and name=="prepare-owner":status=1
        if self.fault=="compile-fail" and name=="libbox-build":status=1
        if self.fault=="owner-missing" and name=="original-encrypted-owner":raw=plain(V.OWNER.VERDICTS[:-1]).encode()
        if self.fault=="peer-missing" and name=="original-encrypted-peer":raw=plain(V.OWNER.ORIGINAL[:-1]).encode()
        if self.fault=="owner-control-pass" and name=="owner-"+V.OWNER.CONTROLS[0]["name"]:status=0
        if self.fault=="native-missing" and name=="typed-native":raw=encoded(events(V.LIBBOX,V.VERDICTS[:-1]))
        if self.fault=="old-box-missing" and name=="original-box":raw=encoded(events(V.BOX,V.ORIGINAL_BOX[:-1]))
        if self.fault=="native-control-pass" and name==V.CONTROLS[0]["name"]:status=0
        if self.fault=="native-control-signal" and name==V.CONTROLS[0]["name"]:status=-9
        if self.fault=="native-control-unrelated" and name==V.CONTROLS[0]["name"]:raw+=b"panic: unrelated\n"
        if name==V.CONTROLS[-1]["name"]:
            if self.fault=="source-change":(self.source/"original.go").write_text("changed")
            if self.fault=="native-change":(self.core/"changed.go").write_text("changed")
            if self.fault=="owner-native-change":(self.owner_core/"changed.go").write_text("changed")
            if self.fault=="image-change":self.images[0].write_bytes(b"foreign image")
            if self.fault=="selection-change":self.selection_file.write_text(json.dumps(dict(self.metadata,suite="foreign")))
        log.write_bytes(raw)
        return status,self.fault=="timeout" and name=="typed-native",not(self.fault=="unjoined" and name=="typed-native")
    def check_overlay(self,command,cwd,relative,control):
        overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
        replacement=Path(json.loads(overlay.read_text())["Replace"][str(cwd/relative)])
        original=(cwd/relative).read_text()
        assert replacement.read_text()==V.mutate(control,original)
        assert original.count(control["before"])==1
    def run(self):
        with patch.object(V.COMMON,"git",side_effect=self.git),patch.object(V.CORE,"snapshot",side_effect=self.snapshot),\
             patch.object(V.CORE,"execute",side_effect=self.execute),patch.object(V,"checked_sources",side_effect=self.checked),\
             patch.object(V,"checked_owner_sources",side_effect=self.checked),\
             patch.object(V.OWNER,"load_gate",return_value=self.gate),patch.object(V.shutil,"which",return_value="/captured/go"),\
             patch.object(V.subprocess,"check_output",return_value="go version go1.26.3 linux/amd64"):
            return getattr(self,"validator",V.validate)(self.source,self.metadata["source_sha"],self.output,"/captured/go")

class TypedSOCKSBridgeValidator(unittest.TestCase):
    def test_exact_combined_inventory_and_every_original_bound(self):
        self.assertEqual((len(V.BRIDGE),len(V.NATIVE),len(V.VERDICTS)),(35,15,50))
        self.assertEqual((len(V.ORIGINAL_LIBBOX),len(V.ORIGINAL_BOX)),(13,27))
        self.assertEqual([len(x["cases"]) for x in V.CONTROLS],[7,1,1,1,4,1])
        for names in (V.VERDICTS,V.ORIGINAL_LIBBOX,V.ORIGINAL_BOX):self.assertEqual(len(names),len(set(names)))
        with tempfile.TemporaryDirectory() as directory:
            f=Composition(Path(directory));receipt=f.run()
            self.assertEqual(len(f.calls),21)
            self.assertNotEqual(f.core,f.owner_core);self.assertNotEqual(f.xray,f.owner_xray)
            self.assertEqual([bound for _,_,bound in f.calls],[60,600,600,600,600,600,100,100,600,600,600,600,100,100,100,600,600,600,600,600,600])
            self.assertEqual(f.owner_calls,[tuple(V.OWNER.VERDICTS),tuple(V.OWNER.ORIGINAL)])
            self.assertEqual((len(receipt["original_owner_cases"]),len(receipt["original_peer_cases"])),(22,15))
            self.assertEqual((len(receipt["owner_controls"]),len(receipt["controls"])),(4,6))
            self.assertFalse(receipt["successful_run_accepted"]);self.assertFalse(receipt["public_native_admission"])
            self.assertFalse(receipt["installed_native_accepted"])
            self.assertEqual(json.loads((f.output/"receipt.json").read_text()),receipt)
            for name,command,_ in f.calls:
                if name.endswith("-build") or name.startswith("owner-") or name in {c["name"] for c in V.CONTROLS}:
                    self.assertIn("-race",command);self.assertIn("-p=1",command)
                if name in {c["name"] for c in V.CONTROLS} or name in {"owner-"+c["name"] for c in V.OWNER.CONTROLS}:
                    self.assertIn("-timeout=90s",command)
                if name in ("typed-native","original-libbox","original-box"):
                    self.assertIn("-test.timeout=90s",command)
    def test_every_failed_or_unjoined_phase_withholds_acceptance(self):
        for fault in ("preflight-missing","spawn-failure","prepare-fail","owner-prepare-fail","projection-refusal","compile-fail",
            "owner-missing","peer-missing","owner-control-pass","native-missing","old-box-missing",
            "native-control-pass","native-control-signal","native-control-unrelated","timeout","unjoined",
            "source-change","native-change","owner-native-change","image-change","selection-change"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                f=Composition(Path(directory),fault)
                with self.assertRaises((ValueError,RuntimeError,OSError)) as error:f.run()
                self.assertNotIsInstance(error.exception,TypeError)
                self.assertFalse((f.output/"receipt.json").exists())
                self.assertEqual(json.loads((f.output/"progress.json").read_text())["status"],"failed")
    def test_original_selection_precedes_all_native_work(self):
        for fault in ("dirty-source","foreign-suite","foreign-sha","no-selection","existing-output","inside-output"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                f=Composition(Path(directory),fault)
                if fault=="foreign-suite":f.selection_file.write_text(json.dumps(dict(f.metadata,suite="foreign")))
                elif fault=="foreign-sha":f.selection_file.write_text(json.dumps(dict(f.metadata,source_sha="1"*40)))
                elif fault=="no-selection":f.selection_file.unlink()
                elif fault=="existing-output":f.output.mkdir()
                elif fault=="inside-output":f.output=f.source/"output"
                with self.assertRaises(ValueError):f.run()
                self.assertEqual(f.calls,[])
    def test_baseline_requires_complete_ordered_native_events(self):
        for package,names in ((V.LIBBOX,V.VERDICTS),(V.BOX,V.ORIGINAL_BOX),(V.LIBBOX,V.ORIGINAL_LIBBOX)):
            V.require_events(encoded(events(package,names)),0,package,names)
            leaf=next(name for name in names if "/" in name)
            for fault in ("missing","duplicate","foreign-package","foreign-test","early-parent","unstarted-output",
                          "no-package-start","late-output","skip","fail","package-fail","unframed","race","build-fail","late-build"):
                with self.subTest(package=package,fault=fault):
                    rows=events(package,names);status=0
                    def index(action,name):return next(i for i,r in enumerate(rows) if r.get("Action")==action and r.get("Test")==name)
                    if fault=="missing":rows=[r for r in rows if r.get("Test")!=leaf]
                    elif fault=="duplicate":rows.insert(2,dict(rows[1]))
                    elif fault=="foreign-package":rows[1]["Package"]="foreign"
                    elif fault=="foreign-test":rows[1]["Test"]="TestForeign"
                    elif fault=="early-parent":
                        parent=leaf.rsplit("/",1)[0];rows.insert(index("run",leaf),rows.pop(index("pass",parent)))
                    elif fault=="unstarted-output":rows.insert(1,dict(Action="output",Package=package,Test=leaf,Output="foreign\n"))
                    elif fault=="no-package-start":rows.pop(0)
                    elif fault=="late-output":rows.append(dict(Action="output",Package=package,Output="late"))
                    elif fault in ("skip","fail"):rows[index("pass",leaf)]["Action"]=fault
                    elif fault=="package-fail":rows[-1]["Action"]="fail"
                    elif fault=="build-fail":rows.insert(0,dict(Action="build-fail",ImportPath=package))
                    elif fault=="late-build":rows.append(dict(Action="build-output",ImportPath=package+".test",Output="late"))
                    raw=encoded(rows)+{"unframed":b"foreign\n","race":b"WARNING: DATA RACE\n"}.get(fault,b"")
                    with self.assertRaises(ValueError):V.require_events(raw,status,package,names)
    def test_compiled_controls_require_exact_unique_leaf_witnesses(self):
        for control in V.CONTROLS:
            names=control["cases"];rows=events(V.LIBBOX,names,control)
            V.require_events(encoded(rows),1,V.LIBBOX,names,control)
            leaf=next(r["Test"] for r in rows if r["Action"]=="output")
            for fault in ("pass","signal","wrong-witness","duplicate-witness","package-witness","missing",
                          "skip","panic","race","build-fail","unframed","foreign-build","late-build"):
                with self.subTest(control=control["name"],fault=fault):
                    rows=events(V.LIBBOX,names,control);status=1
                    output=next(r for r in rows if r["Action"]=="output")
                    if fault=="pass":status=0
                    elif fault=="signal":status=-9
                    elif fault=="wrong-witness":output["Output"]="another failure\n"
                    elif fault=="duplicate-witness":output["Output"]*=2
                    elif fault=="package-witness":output.pop("Test")
                    elif fault=="missing":rows=[r for r in rows if r.get("Test")!=leaf]
                    elif fault=="skip":next(r for r in rows if r.get("Test")==leaf and r["Action"]=="fail")["Action"]="skip"
                    elif fault=="build-fail":rows.insert(0,dict(Action="build-fail",ImportPath=V.LIBBOX))
                    elif fault=="foreign-build":rows.insert(0,dict(Action="build-output",ImportPath="foreign.test",Output="bad"))
                    elif fault=="late-build":rows.append(dict(Action="build-output",ImportPath=V.LIBBOX+".test",Output="late"))
                    raw=encoded(rows)+{"panic":b"panic: unrelated\n","race":b"WARNING: DATA RACE\n","unframed":b"unframed\n"}.get(fault,b"")
                    with self.assertRaises(ValueError):V.require_events(raw,status,V.LIBBOX,names,control)
            # Rebuild after the preceding intentionally malformed loop.
            rows=events(V.LIBBOX,names,control)
            rows.insert(0,dict(Action="build-output",ImportPath=V.LIBBOX+".test",Output="original linker diagnostic\n"))
            V.require_events(encoded(rows),1,V.LIBBOX,names,control)
    def test_every_control_changes_one_original_source_anchor(self):
        for control in (*V.CONTROLS,*V.OWNER.CONTROLS):
            original="before\n"+control["before"]+"\nafter\n"
            self.assertNotEqual(V.mutate(control,original),original)
            for text in ("foreign",original+original):
                with self.assertRaisesRegex(ValueError,"causal seam"):V.mutate(control,text)
    def test_native_snapshot_binds_all_generated_bytes_and_refuses_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/"source.go").write_text("original")
            first=V.native_snapshot(root)
            (root/"source.go").write_text("changed");self.assertNotEqual(V.native_snapshot(root),first)
            (root/"link").symlink_to(root/"source.go")
            with self.assertRaises(ValueError):V.native_snapshot(root)
    def test_original_executor_runs_and_joins_its_actual_child(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);log=work/"child.log"
            result=V.CORE.execute([sys.executable,"-c","print('original native child')"],work,dict(os.environ),log,3)
            self.assertEqual(result,(0,False,True));self.assertEqual(log.read_text().strip(),"original native child")

    def test_shipping_mobile_preparation_starts_pristine_and_keeps_exact_order(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);source,core,xray=work/"candidate",work/"mobile-core",work/"mobile-xray";source.mkdir()
            calls=[]
            def checkout(path,url,pin):
                self.assertFalse(path.exists());path.mkdir()
                (path/"original-pin").write_text(pin);calls.append(("checkout",path,url,pin))
            build=types.SimpleNamespace(PIN=V.PIN,TOOLCHAIN="go1.26.3",checkout=checkout,
                POLICY=types.SimpleNamespace(XRAY_VERSION="original-version",XRAY=types.SimpleNamespace(XRAY_PIN="b"*40)))
            def git(path,*args):
                self.assertEqual(args,("rev-parse","HEAD"))
                return "a"*40 if path==source else (path/"original-pin").read_text()
            def run(command,cwd,check):
                self.assertTrue(core.is_dir());self.assertEqual(cwd,core);self.assertTrue(check)
                self.assertFalse((core/"desktop-only-tor.go").exists())
                calls.append(tuple(command))
            with patch.object(V.COMMON,"git",side_effect=git),patch.object(V,"module",return_value=build),\
                 patch.object(V.OWNER,"prepare",side_effect=AssertionError("desktop preparation entered mobile source")),\
                 patch.object(V.subprocess,"run",side_effect=run):
                V.prepare_mobile(source,"a"*40,core,xray,"/captured/go")
            self.assertEqual([x[0] for x in calls[:2]],["checkout","checkout"])
            self.assertEqual([x[3] for x in calls[:2]],[V.PIN,"b"*40])
            self.assertEqual(len(calls),13)
            self.assertEqual([Path(x[1]).name for x in calls[2:7]],[
                "prepare-mobile-openvpn.py","prepare-mobile-multihop.py","test_retained_strategy_preparation.py",
                "prepare-mobile-tor.py","prepare-apple-xray.py"])
            self.assertEqual(calls[5][-2:],("--go","/captured/go"))
            self.assertEqual(calls[-2:],[
                ("/captured/go","mod","tidy"),("/captured/go","mod","verify")])
            with patch.object(V.COMMON,"git",return_value="a"*40),patch.object(V,"module",return_value=build),\
                 patch.object(V.subprocess,"run") as called:
                with self.assertRaisesRegex(ValueError,"fresh pinned"):
                    V.prepare_mobile(source,"a"*40,core,xray,"/captured/go")
                called.assert_not_called()
            with patch.object(V.COMMON,"git",return_value="c"*40),patch.object(V.OWNER,"prepare") as called:
                with self.assertRaises(ValueError):V.prepare_mobile(source,"a"*40,core,xray,"/captured/go")
                called.assert_not_called()

    def test_original_owner_preparation_and_source_checker_stay_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);source=work/"candidate";source.mkdir()
            core,xray=work/"owner-core",work/"owner-xray"
            gate=object();calls=[]
            def prepare(original,captured,peer,env):
                self.assertIs(original,gate);self.assertEqual((captured,peer),(core,xray))
                core.mkdir();xray.mkdir();(core/"desktop-only-tor.go").write_text("original desktop")
                (xray/"original.go").write_text("original xray");calls.append("owner")
            with patch.object(V.COMMON,"git",return_value="a"*40),patch.object(V.OWNER,"load_gate",return_value=gate),\
                 patch.object(V.OWNER,"prepare",side_effect=prepare),patch.object(V,"prepare_mobile",side_effect=AssertionError):
                V.prepare_owner(source,"a"*40,core,xray)
                self.assertEqual(calls,["owner"])
                with self.assertRaisesRegex(ValueError,"fresh pinned"):V.prepare_owner(source,"a"*40,core,xray)
            def checked(original,candidate,native):
                self.assertIs(original,gate);self.assertEqual((candidate,native),(source,core))
                return {"exact-original-owner":"a"*64}
            with patch.object(V.OWNER,"load_gate",return_value=gate),patch.object(V.OWNER,"checked_sources",side_effect=checked):
                result=V.checked_owner_sources(source,core,xray)
                self.assertEqual(result["owner"],{"exact-original-owner":"a"*64})
                self.assertEqual(result["core"],V.native_snapshot(core))
                self.assertEqual(result["xray"],V.native_snapshot(xray))
            with patch.object(V.OWNER,"load_gate",return_value=gate),patch.object(V.OWNER,"checked_sources",side_effect=ValueError("original owner refused")):
                with self.assertRaises(ValueError):V.checked_owner_sources(source,core,xray)

    def test_actual_mobile_projection_and_hook_verifier_excludes_desktop_namespace(self):
        faults=(None,"missing","changed","linked","map","box-hook","command-hook","packet","global","pinned")
        for fault in faults:
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                work=Path(directory);source,core,xray=work/"candidate",work/"core",work/"xray"
                source.mkdir();core.mkdir();xray.mkdir();(xray/"original.go").write_text("original")
                for name,relative in V.PROJECTIONS.items():
                    original,native=source/"mobile/chain"/name,core/relative
                    original.parent.mkdir(parents=True,exist_ok=True);native.parent.mkdir(parents=True,exist_ok=True)
                    original.write_text("original "+name);native.write_bytes(original.read_bytes())
                for relative in ("box.go","experimental/libbox/command_server.go","include/registry.go",
                    "dns/transport/conn_pool.go","dns/transport/multiplexer.go","dns/transport/udp.go","protocol/socks/outbound.go"):
                    path=core/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text("original "+relative)
                prep=types.SimpleNamespace(TEMPLATES=dict(V.PROJECTIONS),
                    box_source=lambda text:(text+(" changed" if fault=="box-hook" else "")).encode(),
                    command_source=lambda root,text:(text+(" changed" if fault=="command-hook" else "")).encode())
                packet=types.SimpleNamespace()
                def verify(root):
                    self.assertEqual(root,core)
                    if fault=="packet":raise ValueError("original packet patch changed")
                packet.verify=verify
                gate=object();owner_calls=[]
                def owner_checked(original,candidate,native):
                    owner_calls.append((original,candidate,native))
                    if fault=="owner":raise ValueError("original daemon/association closure changed")
                    return {"original-owner":"a"*64}
                projection=core/V.PROJECTIONS["socks_server.go.tmpl"]
                if fault=="missing":projection.unlink()
                elif fault=="changed":projection.write_text("changed")
                elif fault=="linked":
                    projection.unlink();projection.symlink_to(source/"mobile/chain/socks_server.go.tmpl")
                elif fault=="map":prep.TEMPLATES["socks_server.go.tmpl"]="foreign.go"
                elif fault=="global":(core/"include/registry.go").write_text("routervpnnodesocks.Register(registry)")
                elif fault=="pinned":(core/"protocol/socks/outbound.go").write_text("foreign caller")
                def pinned(command,cwd,timeout):
                    return ("original "+command[2].split(":",1)[1]).encode()
                with patch.object(V,"module",side_effect=lambda name,path:packet if path.name=="prepare-sing-packet-concurrency.py" else prep),\
                     patch.object(V.subprocess,"check_output",side_effect=pinned),\
                     patch.object(V.OWNER,"load_gate",return_value=gate),patch.object(V.OWNER,"checked_sources",side_effect=owner_checked):
                    if fault:
                        with self.assertRaises(ValueError):V.checked_sources(source,core,xray)
                    else:
                        result=V.checked_sources(source,core,xray)
                        self.assertNotIn("owner",result)
                        self.assertEqual(owner_calls,[])
                        self.assertEqual(result["xray"],V.native_snapshot(xray))

if __name__=="__main__":
    unittest.main(verbosity=2)
