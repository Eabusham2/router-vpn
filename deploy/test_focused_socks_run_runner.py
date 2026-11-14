#!/usr/bin/env python3
"""Strict source/process/receipt tests for the encrypted typed SOCKS Run gate."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("focused_socks_run",ROOT/"deploy/test_focused_socks_run.py")
V=importlib.util.module_from_spec(spec);sys.modules[spec.name]=V;spec.loader.exec_module(V)
def events(case,control=None):
    rows=[dict(Action="start",Package=V.BASE.LIBBOX)]
    root,leaf=V.case_names(case)
    rows.extend(dict(Action="run",Package=V.BASE.LIBBOX,Test=x) for x in (root,leaf))
    if control:rows.append(dict(Action="output",Package=V.BASE.LIBBOX,Test=leaf,Output=control["witness"]+"\n"))
    rows.extend(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX,Test=x) for x in (leaf,root))
    rows.append(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX))
    return rows
def fifty_events(mode,control=None):
    names=V.FIFTY.names(mode);rows=[dict(Action="start",Package=V.BASE.LIBBOX)]
    rows.extend(dict(Action="run",Package=V.BASE.LIBBOX,Test=x) for x in names)
    if not control:rows.extend(dict(Action="output",Package=V.BASE.LIBBOX,Test=names[-1],Output="SOCKS_FIFTY_CHECK "+leaf+"\n") for leaf in V.FIFTY.LEAVES)
    if control:rows.append(dict(Action="output",Package=V.BASE.LIBBOX,Test=names[-1],Output=control["witness"]+"\n"))
    rows.extend(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX,Test=x) for x in reversed(names))
    rows.append(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX))
    return rows
def encoded(rows):return ("\n".join(json.dumps(x) for x in rows)+"\n").encode()
def plain(names):return "".join("=== RUN   "+x+"\n--- PASS: "+x+" (0.01s)\n" for x in names)+"PASS\n"
def udp_control_rows(control):
    root=V.UDP_REUSE.ROOT;leaf=root+"/"+control["case"]
    return ("=== RUN   "+root+"\n=== RUN   "+leaf+"\n"+control["witness"]+
            "\n--- FAIL: "+leaf+" (0.01s)\n--- FAIL: "+root+" (0.01s)\nFAIL\n").encode()

class Composition:
    def __init__(self,work,fault=None):
        self.fault=fault;self.calls=[];self.roles={};self.images=[];self.original=[]
        self.source=work/"candidate";self.source.mkdir();(self.source/"original.go").write_text("original")
        self.output=work/"validation"/"tests";self.output.parent.mkdir()
        self.metadata=dict(schema=1,suite=V.SUITE,validator_sha="a"*40,validator_tree="b"*40,base_sha="c"*40,base_tree="d"*40,
            source_sha="e"*40,source_tree="f"*40,validation_scope="read-only-source-candidate",relation="single-parent")
        self.selection=self.output.parent/"selection.json";self.selection.write_text(json.dumps(self.metadata))
        def require(raw,names,label):
            if raw!=plain(names):raise ValueError("original native peer inventory changed")
            self.original.append(tuple(names))
        self.gate=types.SimpleNamespace(NODE_CHAIN_IMPORTED_VERDICTS=V.ORIGINAL,NODE=types.SimpleNamespace(
            TAGS=("with_wireguard","with_gvisor","with_purego"),selected_compiler=lambda go,root,env:(go,env,"amd64"),require_native_verdicts=require))
    def git(self,source,*args):
        if args==("rev-parse","HEAD"):return self.metadata["source_sha" if source==self.source else "validator_sha"]
        if args==("rev-parse","HEAD^{tree}"):return self.metadata["source_tree" if source==self.source else "validator_tree"]
        if args==("status","--porcelain","--untracked-files=all"):return ""
        raise AssertionError(args)
    def snapshot(self,source):
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir() if p.is_file()}
    def sources(self,source,mobile,mobile_xray,owner,owner_xray):
        assert self.roles["mobile"]==(mobile,mobile_xray);assert self.roles["owner"]==(owner,owner_xray)
        return {name:V.BASE.native_snapshot(path) for name,path in (("mobile",mobile),("mobile_xray",mobile_xray),("owner",owner),("owner_xray",owner_xray))}
    def execute(self,command,cwd,env,log,bound):
        name=log.stem;self.calls.append((name,command,cwd,env,bound));status=0;raw=b""
        if name=="original-owner-preflight":
            raw=(("test_shipping_desktop_daemon_capture_is_exact_idempotent_and_fail_closed "
                 "(__main__.DesktopDaemonCapturePreparation.test_shipping_desktop_daemon_capture_is_exact_idempotent_and_fail_closed) ... ok\n\n")
                 +"-"*70+"\nRan 1 test in 0.01s\n\nOK\n").encode()
        elif name in ("prepare-owner","prepare-mobile"):
            core,xray=Path(command[command.index("--core")+1]),Path(command[command.index("--xray")+1])
            core.mkdir();xray.mkdir();(xray/"original.go").write_text("original xray")
            (core/"original.go").write_text("original "+name);self.roles[name.removeprefix("prepare-")]=(core,xray)
            if name=="prepare-owner":
                original=core/V.REFERENCE.PROJECTION
                original.parent.mkdir(parents=True);original.write_text('bindHost: "127.0.0.1", handshakeDeadline: true, controlOwnedUDP: true}')
                by_path={}
                for control in V.UDP_REUSE.CONTROLS:by_path.setdefault(control["path"],[]).append(control["before"])
                for path,anchors in by_path.items():
                    target=core/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text("\n".join(anchors))
            if name=="prepare-mobile":
                diagnostic=core/V.DIAGNOSTIC.PROJECTION;diagnostic.parent.mkdir(parents=True,exist_ok=True)
                diagnostic.write_text((ROOT/"internal/hopmeasure/measure.go").read_text())
                by_path={}
                for control in V.CONTROLS:by_path.setdefault(control["path"],[]).append(control["before"])
                for control in V.FIFTY.CONTROLS:by_path.setdefault(control["path"],[]).extend(x[0] for x in control["changes"])
                for path,anchors in by_path.items():
                    target=core/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text("\n".join(anchors))
        elif name.endswith("-build"):
            assert cwd==self.roles["owner" if name=="peer-build" else "mobile"][0]
            image=Path(command[command.index("-o")+1]);image.write_bytes(("original "+name).encode());self.images.append(image)
            overlays=[x.split("=",1)[1] for x in command if x.startswith("-overlay=")]
            if name=="client-build":
                assert len(overlays)==1
                mapping=json.loads(Path(overlays[0]).read_text())["Replace"]
                assert tuple(mapping)==(str(cwd/V.DIAGNOSTIC.PROJECTION),)
                original=Path(next(iter(mapping)));replacement=Path(next(iter(mapping.values())))
                assert V.DIAGNOSTIC.restore(replacement.read_text())==original.read_text()
            else:assert not overlays
        elif name=="original-imported-middle":
            assert cwd==self.roles["owner"][0];raw=plain(V.ORIGINAL).encode()
        elif name=="udp-dns-reuse-positive":
            assert cwd==self.roles["owner"][0] and command[-1]=="./dns/transport"
            assert "-run=^"+V.UDP_REUSE.ROOT+"$" in command
            raw=plain(V.UDP_REUSE.NAMES).encode()
        elif name in {control["name"] for control in V.UDP_REUSE.CONTROLS}:
            assert cwd==self.roles["owner"][0] and command[-1]=="./dns/transport"
            control=next(value for value in V.UDP_REUSE.CONTROLS if value["name"]==name)
            assert "-run=^"+V.UDP_REUSE.ROOT+"$/"+control["case"]+"$" in command
            original=cwd/control["path"]
            overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
            replacements=json.loads(overlay.read_text())["Replace"]
            assert list(replacements)==[str(original)]
            assert Path(replacements[str(original)]).read_text()==V.BASE.mutate(control,original.read_text())
            raw=udp_control_rows(control);status=1
        elif name=="socks-handshake-reference":
            assert cwd==self.roles["owner"][0];raw=plain(V.REFERENCE.NAMES).encode()
        elif name=="socks-handshake-old-deadline":
            assert cwd==self.roles["owner"][0]
            original=cwd/V.REFERENCE.PROJECTION
            overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
            replacements=json.loads(overlay.read_text())["Replace"]
            assert list(replacements)==[str(original)]
            assert Path(replacements[str(original)]).read_text()==original.read_text().replace('handshakeDeadline: true,', 'handshakeDeadline: false,')
            root=V.REFERENCE.ROOT
            raw=("".join("=== RUN   "+x+"\n" for x in V.REFERENCE.NAMES)+
                 "--- PASS: "+root+"/unauthenticated-bound (5.00s)\n"+
                 "".join("authenticated control retained handshake deadline\n--- FAIL: "+root+"/"+x+" (5.00s)\n" for x in ("tcp","udp"))+
                 "--- FAIL: "+root+" (15.00s)\nFAIL\n").encode();status=1
        elif name=="socks-idle-reference":raw=plain((V.REFERENCE.IDLE_ROOT,)).encode()
        elif name=="socks-idle-old-expiry":
            assert cwd==self.roles["owner"][0]
            original=cwd/V.REFERENCE.PROJECTION
            overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
            replacements=json.loads(overlay.read_text())["Replace"]
            assert list(replacements)==[str(original)]
            assert Path(replacements[str(original)]).read_text()==original.read_text().replace('controlOwnedUDP: true}', 'controlOwnedUDP: false}')
            raw=("=== RUN   "+V.REFERENCE.IDLE_ROOT+"\nlive original control lost idle relay\n--- FAIL: "+V.REFERENCE.IDLE_ROOT+" (5.50s)\nFAIL\n").encode();status=1
        elif name.startswith("fifty-"):
            mode=env["ROUTERVPN_SOCKS_FIFTY_CASE"];assert mode in V.FIFTY.MODES
            assert cwd==self.roles["mobile"][0] and Path(env["ROUTERVPN_SOCKS_RUN_PEER"])==self.images[0]
            if name in {"fifty-"+x for x in V.FIFTY.MODES}:raw=encoded(fifty_events(mode))
            else:
                control=next(c for c in V.FIFTY.CONTROLS if c["name"]==name)
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"]
                self_path=str(cwd/control["path"])
                assert Path(replacements[self_path]).read_text()==V.FIFTY.mutation(V.BASE,control,Path(self_path).read_text())
                raw=encoded(fifty_events(mode,control));status=1
        else:
            case=env["ROUTERVPN_SOCKS_RUN_CASE"];assert case in V.CASES
            assert env["GODEBUG"]=="x509usefallbackroots=1"
            assert Path(env["ROUTERVPN_SOCKS_RUN_PEER"])==self.images[0]
            assert cwd==self.roles["mobile"][0]
            if name.startswith("run-"):
                assert case==name.removeprefix("run-");raw=encoded(events(case))
            else:
                control=next(c for c in V.CONTROLS if c["name"]==name)
                assert case==control["case"]
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"]
                self_path=str(cwd/control["path"]);diagnostic_path=str(cwd/V.DIAGNOSTIC.PROJECTION)
                assert list(replacements)==[diagnostic_path,self_path]
                assert V.DIAGNOSTIC.restore(Path(replacements[diagnostic_path]).read_text())==Path(diagnostic_path).read_text()
                assert Path(replacements[self_path]).read_text()==V.BASE.mutate(control,Path(self_path).read_text())
                raw=encoded(events(case,control));status=1
        if self.fault=="preflight" and name=="original-owner-preflight":raw=b"Ran 0 tests\nOK\n"
        if self.fault=="owner-prepare" and name=="prepare-owner":status=1
        if self.fault=="mobile-prepare" and name=="prepare-mobile":status=1
        if self.fault=="build" and name=="client-build":status=1
        if self.fault=="original-missing" and name=="original-imported-middle":raw=plain(V.ORIGINAL[:-1]).encode()
        if self.fault=="udp-positive-failed" and name=="udp-dns-reuse-positive":status=1
        if self.fault=="udp-positive-missing" and name=="udp-dns-reuse-positive":raw=plain(V.UDP_REUSE.NAMES[:-1]).encode()
        if self.fault=="udp-empty:"+name:raw=b""
        if name==V.UDP_REUSE.CONTROLS[0]["name"]:
            if self.fault=="udp-control-pass":status=0
            if self.fault=="udp-control-witness":raw=raw.replace(V.UDP_REUSE.CONTROLS[0]["witness"].encode(),b"unrelated")
        if self.fault=="handshake-missing" and name=="socks-handshake-reference":raw=plain(V.REFERENCE.NAMES[:-1]).encode()
        if self.fault=="handshake-control-pass" and name=="socks-handshake-old-deadline":status=0
        if self.fault=="handshake-control-witness" and name=="socks-handshake-old-deadline":raw=raw.replace(b"authenticated control retained handshake deadline",b"unrelated")
        if self.fault=="idle-missing" and name=="socks-idle-reference":raw=b"PASS\n"
        if self.fault=="idle-control-pass" and name=="socks-idle-old-expiry":status=0
        if self.fault=="idle-control-witness" and name=="socks-idle-old-expiry":raw=raw.replace(b"live original control lost idle relay",b"unrelated")
        if self.fault=="case-missing" and name=="run-wg":raw=encoded(events("wg")[:-1])
        if self.fault=="case-failed" and name=="run-wg":status=1
        if self.fault=="control-pass" and name==V.CONTROLS[0]["name"]:status=0
        if self.fault=="control-signal" and name==V.CONTROLS[0]["name"]:status=-9
        if self.fault=="control-panic" and name==V.CONTROLS[0]["name"]:raw+=b"panic: unrelated\n"
        if self.fault=="control-witness" and name==V.CONTROLS[0]["name"]:raw=raw.replace(V.CONTROLS[0]["witness"].encode(),b"unrelated")
        if name==V.CONTROLS[-1]["name"]:
            if self.fault=="candidate-changed":(self.source/"original.go").write_text("changed")
            if self.fault=="owner-changed":(self.roles["owner"][0]/"original.go").write_text("changed")
            if self.fault=="mobile-changed":(self.roles["mobile"][0]/"original.go").write_text("changed")
            if self.fault=="image-changed":self.images[0].write_bytes(b"changed")
            if self.fault=="selection-changed":self.selection.write_text(json.dumps(dict(self.metadata,source_tree="1"*40)))
            if self.fault=="diagnostic-changed":(self.output/"private-diagnostic/measure.go").write_text("changed")
        log.write_bytes(raw)
        timed_out=(self.fault=="timeout" and name=="run-wg") or (self.fault=="udp-timeout" and name=="udp-dns-reuse-positive")
        unjoined=(self.fault=="unjoined" and name=="run-wg") or (self.fault=="udp-unjoined" and name==V.UDP_REUSE.CONTROLS[0]["name"])
        return status,timed_out,not unjoined
    def run(self):
        with patch.object(V.BASE.COMMON,"git",side_effect=self.git),patch.object(V.BASE.CORE,"snapshot",side_effect=self.snapshot),\
             patch.object(V.BASE.CORE,"execute",side_effect=self.execute),patch.object(V,"sources",side_effect=self.sources),\
             patch.object(V.BASE.OWNER,"load_gate",return_value=self.gate),patch.object(V.shutil,"which",return_value="/captured/go"),\
             patch.object(V.subprocess,"check_output",return_value="go version go1.26.3 linux/amd64"):
            return V.validate(self.source,self.metadata["source_sha"],self.output,"/captured/go")

class EncryptedSOCKSRunValidator(unittest.TestCase):
    def test_reference_control_targets_actual_peer_projection(self):
        tree=ast.parse((ROOT/"deploy/prepare-desktop-external.py").read_text())
        table=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                   and any(isinstance(target,ast.Name) and target.id=="PEER_TEMPLATES" for target in node.targets))
        self.assertEqual(V.REFERENCE.PROJECTION,table["node_imported_socks_entry_test.go.tmpl"])
    def test_all_actual_cases_original_cipher_inventory_and_bounds_are_required(self):
        self.assertEqual(len(V.CASES),8);self.assertEqual(len(set(V.CASES)),8)
        self.assertEqual(len(V.ORIGINAL),73);self.assertEqual(len(set(V.ORIGINAL)),73)
        self.assertEqual(len(V.CONTROLS),4)
        with tempfile.TemporaryDirectory() as directory:
            c=Composition(Path(directory));receipt=c.run()
            self.assertEqual(len(c.calls),35)
            self.assertEqual([x[4] for x in c.calls],[60,600,600,600,600,100,*([600]*5),40,600,30,600,*([190]*8),*([600]*4),*([190]*3),*([600]*5)])
            self.assertEqual([x[0] for x in c.calls[6:11]],["udp-dns-reuse-positive",*(control["name"] for control in V.UDP_REUSE.CONTROLS)])
            self.assertEqual(c.original,[V.ORIGINAL,V.UDP_REUSE.NAMES,V.REFERENCE.NAMES,(V.REFERENCE.IDLE_ROOT,)])
            self.assertEqual([x["case"] for x in receipt["case_records"]],list(V.CASES))
            self.assertEqual(len(receipt["controls"]),4)
            self.assertEqual(receipt["socks_reference_handoff_records"],list(V.REFERENCE.NAMES))
            self.assertTrue(receipt["socks_reference_handoff_control"]["expected_failure"])
            self.assertEqual(receipt["socks_reference_idle_records"],[V.REFERENCE.IDLE_ROOT])
            self.assertTrue(receipt["socks_reference_idle_control"]["expected_failure"])
            self.assertEqual(len(receipt["ordered_fifty_records"]),3)
            self.assertEqual(len(receipt["ordered_fifty_controls"]),5)
            self.assertFalse(receipt["ordered_fifty_host_persistence_accepted"])
            self.assertEqual(receipt["udp_dns_reuse_records"],list(V.UDP_REUSE.NAMES))
            self.assertEqual([item["name"] for item in receipt["udp_dns_reuse_controls"]],[item["name"] for item in V.UDP_REUSE.CONTROLS])
            self.assertTrue(all(item["expected_failure"] for item in receipt["udp_dns_reuse_controls"]))
            self.assertTrue(receipt["udp_dns_reuse_idle_timeout_unchanged"])
            self.assertFalse(receipt["udp_dns_reuse_device_accepted"])
            self.assertEqual(receipt["trusted_udp_dns_reuse_sha256"],hashlib.sha256(V.UDP_REUSE_PATH.read_bytes()).hexdigest())
            self.assertFalse(receipt["failure_only_diagnostic"]["acceptance_changed"])
            self.assertTrue(receipt["failure_only_diagnostic"]["original_deadlines_preserved"])
            self.assertTrue(receipt["successful_run_accepted"]);self.assertTrue(receipt["ordered_measurement_accepted"])
            self.assertFalse(receipt["public_native_admission"]);self.assertFalse(receipt["installed_native_accepted"])
            self.assertFalse(receipt["native_mtu_continuation_accepted"])
            self.assertTrue(receipt["native_mtu_constructor_accepted"])
            self.assertEqual(json.loads((c.output/"receipt.json").read_text()),receipt)
            for name,command,_,_,_ in c.calls:
                if name.endswith("-build") or name in {v["name"] for v in V.CONTROLS}:
                    self.assertIn("-race",command);self.assertIn("-p=1",command)
                if name.startswith("run-"):self.assertIn("-test.timeout=180s",command)
                if name in {v["name"] for v in V.CONTROLS}:self.assertIn("-timeout=180s",command)
                if name=="original-imported-middle":self.assertIn("-test.timeout=90s",command)
                if name=="socks-handshake-reference":self.assertIn("-test.timeout=30s",command)
                if name=="socks-handshake-old-deadline":
                    self.assertIn("-race",command);self.assertIn("-p=1",command);self.assertIn("-timeout=30s",command)
                if name.startswith("udp-dns-reuse-"):
                    self.assertIn("-race",command);self.assertIn("-p=1",command);self.assertIn("-timeout=30s",command)
    def test_udp_controls_require_original_case_witness_and_exact_anchor(self):
        self.assertEqual(len(V.UDP_REUSE.NAMES),11);self.assertEqual(len(V.UDP_REUSE.CONTROLS),4)
        for control in V.UDP_REUSE.CONTROLS:
            raw=udp_control_rows(control)
            self.assertTrue(V.UDP_REUSE.control_events(raw,1,control)["expected_failure"])
            for status in (0,-9,124):
                with self.assertRaises(ValueError):V.UDP_REUSE.control_events(raw,status,control)
            for changed in (raw+raw,raw.replace(control["witness"].encode(),b"unrelated"),
                            raw.replace((V.UDP_REUSE.ROOT+"/"+control["case"]).encode(),b"foreign"),
                            raw+b"DATA RACE",raw+b"panic:",raw+b"--- SKIP: unrelated (0.00s)\n"):
                with self.assertRaises(ValueError):V.UDP_REUSE.control_events(changed,1,control)
            original="before\n"+control["before"]+"\nafter"
            self.assertNotEqual(V.BASE.mutate(control,original),original)
            for changed in ("foreign",original+original):
                with self.assertRaises(ValueError):V.BASE.mutate(control,changed)
    def test_each_udp_phase_requires_its_complete_result(self):
        for name in ("udp-dns-reuse-positive",*(control["name"] for control in V.UDP_REUSE.CONTROLS)):
            with self.subTest(phase=name),tempfile.TemporaryDirectory() as directory:
                c=Composition(Path(directory),"udp-empty:"+name)
                with self.assertRaises(ValueError):c.run()
                self.assertFalse((c.output/"receipt.json").exists())
                self.assertEqual(json.loads((c.output/"progress.json").read_text())["status"],"failed")
    def test_handshake_control_requires_both_actual_transport_failures(self):
        root=V.REFERENCE.ROOT
        raw=("".join("=== RUN   "+x+"\n" for x in V.REFERENCE.NAMES)+
             "--- PASS: "+root+"/unauthenticated-bound (5s)\n"+
             "".join("authenticated control retained handshake deadline\n--- FAIL: "+root+"/"+x+" (5s)\n" for x in ("tcp","udp"))+
             "--- FAIL: "+root+" (15s)\nFAIL\n").encode()
        self.assertTrue(V.REFERENCE.control_events(raw,1)["expected_failure"])
        for status in (0,-9,124):
            with self.assertRaises(ValueError):V.REFERENCE.control_events(raw,status)
        for changed in (raw+raw,raw.replace(b"/udp",b"/foreign"),raw.replace(b"retained handshake deadline",b"unrelated"),raw+b"DATA RACE",raw+b"panic:",raw+b"--- SKIP: unrelated (0.00s)\n"):
            with self.assertRaises(ValueError):V.REFERENCE.control_events(changed,1)

    def test_idle_control_requires_actual_original_expiry(self):
        raw=("=== RUN   "+V.REFERENCE.IDLE_ROOT+"\nlive original control lost idle relay\n--- FAIL: "+V.REFERENCE.IDLE_ROOT+" (5.50s)\nFAIL\n").encode()
        self.assertTrue(V.REFERENCE.idle_control_events(raw,1)["expected_failure"])
        for status in (0,-9,124):
            with self.assertRaises(ValueError):V.REFERENCE.idle_control_events(raw,status)
        for changed in (raw+raw,raw.replace(b"live original control lost idle relay",b"unrelated"),raw+b"DATA RACE",raw+b"panic:",raw+b"--- SKIP: unrelated (0.00s)\n"):
            with self.assertRaises(ValueError):V.REFERENCE.idle_control_events(changed,1)

    def test_ordered_fifty_original_checks_witnesses_and_mutation_anchors(self):
        self.assertEqual(len(V.FIFTY.MODES),3);self.assertEqual(len(V.FIFTY.LEAVES),14)
        for mode in V.FIFTY.MODES:
            rows=fifty_events(mode);self.assertTrue(V.FIFTY.events(V.BASE,encoded(rows),0,mode)["accepted"])
            missing=[row for row in rows if "SOCKS_FIFTY_CHECK foreign-service" not in row.get("Output", "")]
            for altered in (missing,rows[:-1],rows+rows):
                with self.assertRaises(ValueError):V.FIFTY.events(V.BASE,encoded(altered),0,mode)
        projections={v:k for k,v in V.FIFTY.PROJECTIONS}
        projections["experimental/libbox/routervpn/hopmeasure/ordered_latency.go"]="ordered_latency.go"
        for control in V.FIFTY.CONTROLS:
            source=ROOT/("internal/hopmeasure/ordered_latency.go" if control["path"].endswith("hopmeasure/ordered_latency.go") else "mobile/chain/"+projections[control["path"]])
            original=source.read_text();self.assertNotEqual(V.FIFTY.mutation(V.BASE,control,original),original)
            for before,_ in control["changes"]:
                with self.assertRaises(ValueError):V.FIFTY.mutation(V.BASE,control,original.replace(before,"missing"))
            raw=encoded(fifty_events("wg",control));self.assertTrue(V.FIFTY.events(V.BASE,raw,1,"wg",control)["accepted"])
            for status in (0,-9,124):
                with self.assertRaises(ValueError):V.FIFTY.events(V.BASE,raw,status,"wg",control)
            for malformed in (raw.replace(control["witness"].encode(),b"unrelated"),raw+b"panic: unrelated\n",raw+b"WARNING: DATA RACE\n"):
                with self.assertRaises(ValueError):V.FIFTY.events(V.BASE,malformed,1,"wg",control)

    def test_no_failed_missing_or_unjoined_phase_can_publish_acceptance(self):
        for fault in ("preflight","owner-prepare","mobile-prepare","build","original-missing","case-missing","case-failed",
                      "udp-positive-failed","udp-positive-missing","udp-control-pass","udp-control-witness","udp-timeout","udp-unjoined",
                      "handshake-missing","handshake-control-pass","handshake-control-witness","idle-missing","idle-control-pass","idle-control-witness",
                      "control-pass","control-signal","control-panic","control-witness","candidate-changed","owner-changed",
                      "mobile-changed","image-changed","selection-changed","diagnostic-changed","timeout","unjoined"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                c=Composition(Path(directory),fault)
                with self.assertRaises((ValueError,RuntimeError)):c.run()
                self.assertFalse((c.output/"receipt.json").exists())
                self.assertEqual(json.loads((c.output/"progress.json").read_text())["status"],"failed")
    def test_exact_source_selection_precedes_preparation(self):
        for fault in ("wrong-suite","wrong-source","output-exists","missing-selection"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                c=Composition(Path(directory))
                if fault=="wrong-suite":c.selection.write_text(json.dumps(dict(c.metadata,suite="foreign")))
                elif fault=="wrong-source":c.selection.write_text(json.dumps(dict(c.metadata,source_sha="1"*40)))
                elif fault=="output-exists":c.output.mkdir()
                else:c.selection.unlink()
                with self.assertRaises(ValueError):c.run()
                self.assertEqual(c.calls,[])
    def test_exact_event_inventory_and_compiled_witness_are_mandatory(self):
        for case in V.CASES:
            raw=encoded(events(case));self.assertTrue(V.native_events(raw,0,case)["accepted"])
            for rows in (events(case)[:-1],events(case)+events(case),list(reversed(events(case)))):
                with self.assertRaises(ValueError):V.native_events(encoded(rows),0,case)
        with self.assertRaises(ValueError):V.case_names("foreign")
        for control in V.CONTROLS:
            self.assertTrue(V.native_events(encoded(events(control["case"],control)),1,control["case"],control)["accepted"])
            for status in (0,-9,124):
                with self.assertRaises(ValueError):V.native_events(encoded(events(control["case"],control)),status,control["case"],control)
            bad=encoded(events(control["case"],control)).replace(control["witness"].encode(),b"unrelated failed source")
            with self.assertRaises(ValueError):V.native_events(bad,1,control["case"],control)
            for raw in (bad+b"panic: failure\n",b"build failed\n",bad+b"WARNING: DATA RACE\n"):
                with self.assertRaises(ValueError):V.native_events(raw,1,control["case"],control)
    def test_each_control_requires_one_exact_original_anchor(self):
        for control in V.CONTROLS:
            original="before\n"+control["before"]+"\nafter"
            self.assertNotEqual(V.BASE.mutate(control,original),original)
            for text in ("foreign",original+original):
                with self.assertRaises(ValueError):V.BASE.mutate(control,text)
    def test_failure_diagnostic_cannot_replace_source_or_control_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);core=work/"core";original=core/V.DIAGNOSTIC.PROJECTION
            original.parent.mkdir(parents=True);original.write_text((ROOT/"internal/hopmeasure/measure.go").read_text())
            record=V.DIAGNOSTIC.prepare(core,work/"diagnostic")
            V.require_private_diagnostic(record)
            with self.assertRaises(ValueError):V.private_control_overlay(record,original,work/"foreign.go")
            for key in ("source","replacement","overlay"):
                path=Path(record[key]);saved=path.read_bytes();path.write_bytes(saved+b"changed")
                with self.subTest(key=key),self.assertRaises(ValueError):V.require_private_diagnostic(record)
                path.write_bytes(saved)
            V.require_private_diagnostic(record)

    def test_both_template_maps_and_original_peer_source_are_bound(self):
        mtu_faults=tuple("mtu-"+str(i)+"-"+kind for i in range(len(V.MTU_PROJECTIONS)) for kind in ("map","bytes","symlink"))
        for fault in (None,"mobile-map","peer-map","mobile-bytes","peer-bytes","old-peer","mobile-closure","owner-closure",*mtu_faults):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                work=Path(directory);source=work/"candidate";mobile=work/"mobile";owner=work/"owner";mx=work/"mx";ox=work/"ox"
                for p in (source,mobile,owner,mx,ox):p.mkdir()
                for template,projection,root in ((V.RUN_TEMPLATE,V.RUN_PROJECTION,mobile),(V.PEER_TEMPLATE,V.PEER_PROJECTION,owner),
                    ("mobile/desktop/node_chain_imported_test.go.tmpl","protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go",owner),
                    *((original,projected,mobile) for original,projected in V.MTU_PROJECTIONS),
                    *(("mobile/chain/"+original,projected,mobile) for original,projected in V.FIFTY.PROJECTIONS)):
                    a,b=source/template,root/projection;a.parent.mkdir(parents=True,exist_ok=True);b.parent.mkdir(parents=True,exist_ok=True)
                    a.write_text("original "+template);b.write_bytes(a.read_bytes())
                mp=types.SimpleNamespace(TEMPLATES={Path(V.RUN_TEMPLATE).name:V.RUN_PROJECTION,
                    **{Path(original).name:projected for original,projected in V.MTU_PROJECTIONS},
                    **dict(V.FIFTY.PROJECTIONS)})
                dp=types.SimpleNamespace(PEER_TEMPLATES={Path(V.PEER_TEMPLATE).name:V.PEER_PROJECTION})
                if fault=="mobile-map":mp.TEMPLATES.clear()
                elif fault=="peer-map":dp.PEER_TEMPLATES.clear()
                elif fault=="mobile-bytes":(mobile/V.RUN_PROJECTION).write_text("foreign")
                elif fault=="peer-bytes":(owner/V.PEER_PROJECTION).write_text("foreign")
                elif fault=="old-peer":(owner/"protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go").write_text("foreign")
                if fault and fault.startswith("mtu-"):
                    _,number,kind=fault.split("-");original,projected=V.MTU_PROJECTIONS[int(number)]
                    if kind=="map":mp.TEMPLATES.pop(Path(original).name)
                    elif kind=="bytes":(mobile/projected).write_text("foreign")
                    else:
                        (mobile/projected).unlink();(mobile/projected).symlink_to(source/original)
                def checked_mobile(*args):
                    if fault=="mobile-closure":raise ValueError("mobile closure changed")
                    return {"mobile":"original"}
                def checked_owner(*args):
                    if fault=="owner-closure":raise ValueError("owner closure changed")
                    return {"owner":"original"}
                with patch.object(V.BASE,"checked_sources",side_effect=checked_mobile),\
                     patch.object(V.BASE,"checked_owner_sources",side_effect=checked_owner),\
                     patch.object(V.BASE,"module",side_effect=lambda name,path:mp if path.name=="prepare-mobile-node-chain.py" else dp):
                    if fault:
                        with self.assertRaises(ValueError):V.sources(source,mobile,mx,owner,ox)
                    else:self.assertEqual(V.sources(source,mobile,mx,owner,ox),{"mobile":{"mobile":"original"},"owner":{"owner":"original"}})
if __name__=="__main__":unittest.main(verbosity=2)
