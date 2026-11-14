#!/usr/bin/env python3
"""Strict source/process/receipt tests for the encrypted typed CONNECT Run gate."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("focused_connect_run",ROOT/"deploy/test_focused_connect_run.py")
V=importlib.util.module_from_spec(spec);sys.modules[spec.name]=V;spec.loader.exec_module(V)
def events(case,control=None):
    rows=[dict(Action="start",Package=V.BASE.LIBBOX)]
    root,leaf=V.case_names(case)
    rows.extend(dict(Action="run",Package=V.BASE.LIBBOX,Test=x) for x in (root,leaf))
    if control:rows.append(dict(Action="output",Package=V.BASE.LIBBOX,Test=leaf,Output=control["witness"]+"\n"))
    rows.extend(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX,Test=x) for x in (leaf,root))
    rows.append(dict(Action="fail" if control else "pass",Package=V.BASE.LIBBOX))
    return rows
def fifty_rows(mode,control=None):
    root,leaf=V.FIFTY.names(mode)
    rows=[dict(Action="start",Package=V.BASE.LIBBOX)]
    rows.extend(dict(Action="run",Package=V.BASE.LIBBOX,Test=x) for x in (root,leaf))
    outputs=[control["witness"]] if control else ["CONNECT_FIFTY_CHECK "+name for name in V.FIFTY.LEAVES]
    rows.extend(dict(Action="output",Package=V.BASE.LIBBOX,Test=leaf,Output=x+"\n") for x in outputs)
    action="fail" if control else "pass"
    rows.extend(dict(Action=action,Package=V.BASE.LIBBOX,Test=x) for x in (leaf,root))
    rows.append(dict(Action=action,Package=V.BASE.LIBBOX))
    return rows
def ordinary_rows(case,control=None):
    root=V.ORDINARY.ROOT
    rows=[dict(Action="start",Package=V.BASE.LIBBOX),dict(Action="run",Package=V.BASE.LIBBOX,Test=root)]
    output=control["witness"] if control else V.ORDINARY.witness(case)
    rows.append(dict(Action="output",Package=V.BASE.LIBBOX,Test=root,Output=output+"\n"))
    action="fail" if control else "pass"
    rows.extend((dict(Action=action,Package=V.BASE.LIBBOX,Test=root),dict(Action=action,Package=V.BASE.LIBBOX)))
    return rows
def reference_rows(control=False,tcp=False,packet=False):
    selected=V.REFERENCE_PACKET_CONTROL if packet else V.REFERENCE_TCP_CONTROL if tcp else V.REFERENCE_CONTROL
    positive=V.REFERENCE_TCP_CASES if tcp else V.REFERENCE_CASES
    package=V.REFERENCE_PACKAGE;names=selected["cases"] if control else positive
    rows=[dict(Action="start",Package=package),dict(Action="run",Package=package,Test=names[0])]
    action="fail" if control else "pass"
    for name in names[1:]:
        rows.append(dict(Action="run",Package=package,Test=name))
        if control:rows.append(dict(Action="output",Package=package,Test=name,Output=selected["witness"]+"\n"))
        rows.append(dict(Action=action,Package=package,Test=name))
    rows.extend((dict(Action=action,Package=package,Test=names[0]),dict(Action=action,Package=package)))
    return rows
def encoded(rows):return ("\n".join(json.dumps(x) for x in rows)+"\n").encode()
def plain(names):return "".join("=== RUN   "+x+"\n--- PASS: "+x+" (0.01s)\n" for x in names)+"PASS\n"

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
                target=core/V.REFERENCE_CONTROL["path"];target.parent.mkdir(parents=True,exist_ok=True);target.write_text(V.REFERENCE_CONTROL["before"]+V.REFERENCE_TCP_CONTROL["before"]+V.REFERENCE_PACKET_CONTROL["before"])
                lifetime=core/V.LIFETIME.CONTROL["path"];lifetime.parent.mkdir(parents=True,exist_ok=True);lifetime.write_text(V.LIFETIME.CONTROL["before"])
            if name=="prepare-mobile":
                # Both the original Run controls and the additive fifty controls
                # mutate their real source text through the unchanged evaluator.
                sources={
                    "experimental/libbox/routervpn_node_chain_latency.go":"mobile/chain/latency.go.tmpl",
                    "routervpn_node_chain_connect.go":"mobile/chain/connect_box.go.tmpl",
                    "experimental/libbox/routervpn_node_chain_connect_lifecycle.go":"mobile/chain/connect_lifecycle.go.tmpl",
                    "experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go":"internal/mobilemultihop/node_chain_runtime.go",
                    "experimental/libbox/routervpn_node_chain_connect_latency.go":"mobile/chain/connect_latency.go.tmpl",
                    "experimental/libbox/routervpn/hopmeasure/ordered_latency.go":"internal/hopmeasure/ordered_latency.go",
                    "experimental/libbox/routervpn_ordered_latency.go":"mobile/chain/ordered_latency_bridge.go.tmpl",
                }
                for control in (*V.CONTROLS,*V.FIFTY.CONTROLS,*V.ORDINARY.CONTROLS):
                    target=core/control["path"];target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes((ROOT/sources[control["path"]]).read_bytes())
        elif name.endswith("-build"):
            assert cwd==self.roles["owner" if name=="peer-build" else "mobile"][0]
            image=Path(command[command.index("-o")+1]);image.write_bytes(("original "+name).encode());self.images.append(image)
            assert not any(x.startswith("-overlay=") for x in command)
        elif name=="original-imported-middle":
            assert cwd==self.roles["owner"][0];raw=plain(V.ORIGINAL).encode()
        elif name in ("reference-tls-close",V.REFERENCE_CONTROL["name"],"reference-tcp-close",V.REFERENCE_TCP_CONTROL["name"],V.REFERENCE_PACKET_CONTROL["name"]):
            assert cwd==self.roles["owner"][0]
            tcp=name in ("reference-tcp-close",V.REFERENCE_TCP_CONTROL["name"])
            packet=name==V.REFERENCE_PACKET_CONTROL["name"]
            selected=V.REFERENCE_PACKET_CONTROL if packet else V.REFERENCE_TCP_CONTROL if tcp else V.REFERENCE_CONTROL
            negative=name==selected["name"]
            if negative:
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"];original=str(cwd/selected["path"])
                assert list(replacements)==[original]
                assert Path(replacements[original]).read_text()==V.BASE.mutate(selected,Path(original).read_text())
            raw=encoded(reference_rows(negative,tcp,packet));status=int(negative)
        elif name=="reference-established-positive":
            assert cwd==self.roles["owner"][0] and Path(command[0])==self.images[0]
            raw=plain(V.LIFETIME.NAMES).encode()
        elif name==V.LIFETIME.CONTROL["name"]:
            assert cwd==self.roles["owner"][0]
            overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
            replacements=json.loads(overlay.read_text())["Replace"];original=str(cwd/V.LIFETIME.CONTROL["path"])
            assert list(replacements)==[original]
            assert Path(replacements[original]).read_text()==V.BASE.mutate(V.LIFETIME.CONTROL,Path(original).read_text())
            root=V.LIFETIME.ROOT
            raw=(f"=== RUN   {root}\n=== RUN   {root}/retained\n"+V.LIFETIME.CONTROL["witness"]+f"\n--- FAIL: {root} (31.00s)\n    --- FAIL: {root}/retained (31.00s)\nFAIL\n").encode();status=1
        elif name.startswith("ordinary-fifty-"):
            case=(env["ROUTERVPN_ORDINARY_FIFTY_MODE"],int(env["ROUTERVPN_ORDINARY_FIFTY_COUNT"]),int(env["ROUTERVPN_ORDINARY_FIFTY_POSITION"]))
            assert case in V.ORDINARY.CASES
            assert "ROUTERVPN_CONNECT_FIFTY_CASE" not in env and "ROUTERVPN_CONNECT_RUN_CASE" not in env
            assert env["GODEBUG"]=="x509usefallbackroots=1"
            assert Path(env["ROUTERVPN_ORDINARY_FIFTY_PEER"])==self.images[0]
            assert cwd==self.roles["mobile"][0]
            if name in {V.ORDINARY.name(c) for c in V.ORDINARY.CASES}:
                assert name==V.ORDINARY.name(case);raw=encoded(ordinary_rows(case))
            else:
                control=next(c for c in V.ORDINARY.CONTROLS if c["name"]==name)
                assert case==V.ORDINARY.CASES[0]
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"];original=str(cwd/control["path"])
                assert list(replacements)==[original]
                assert Path(replacements[original]).read_text()==V.ORDINARY.mutation(V.BASE,control,Path(original).read_text())
                raw=encoded(ordinary_rows(case,control));status=1
        elif name.startswith("fifty-"):
            mode=env["ROUTERVPN_CONNECT_FIFTY_CASE"];assert mode in V.FIFTY.MODES
            assert "ROUTERVPN_CONNECT_RUN_CASE" not in env
            assert env["GODEBUG"]=="x509usefallbackroots=1"
            assert Path(env["ROUTERVPN_CONNECT_RUN_PEER"])==self.images[0]
            assert cwd==self.roles["mobile"][0]
            if name in {"fifty-"+value for value in V.FIFTY.MODES}:
                assert mode==name.removeprefix("fifty-");raw=encoded(fifty_rows(mode))
            else:
                control=next(c for c in V.FIFTY.CONTROLS if c["name"]==name)
                assert mode=="http-wg"
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"];original=str(cwd/control["path"])
                assert list(replacements)==[original]
                assert Path(replacements[original]).read_text()==V.FIFTY.mutation(V.BASE,control,Path(original).read_text())
                raw=encoded(fifty_rows(mode,control));status=1
        else:
            case=env["ROUTERVPN_CONNECT_RUN_CASE"];assert case in V.CASES
            assert env["GODEBUG"]=="x509usefallbackroots=1"
            assert Path(env["ROUTERVPN_CONNECT_RUN_PEER"])==self.images[0]
            assert cwd==self.roles["mobile"][0]
            if name.startswith("run-"):
                assert case==name.removeprefix("run-");raw=encoded(events(case))
            else:
                control=next(c for c in V.CONTROLS if c["name"]==name)
                assert case==control["case"]
                overlay=Path(next(x.split("=",1)[1] for x in command if x.startswith("-overlay=")))
                replacements=json.loads(overlay.read_text())["Replace"]
                self_path=str(cwd/control["path"])
                assert list(replacements)==[self_path]
                assert Path(replacements[self_path]).read_text()==V.BASE.mutate(control,Path(self_path).read_text())
                raw=encoded(events(case,control));status=1
        if self.fault=="preflight" and name=="original-owner-preflight":raw=b"Ran 0 tests\nOK\n"
        if self.fault=="owner-prepare" and name=="prepare-owner":status=1
        if self.fault=="mobile-prepare" and name=="prepare-mobile":status=1
        if self.fault=="build" and name=="client-build":status=1
        if self.fault=="original-missing" and name=="original-imported-middle":raw=plain(V.ORIGINAL[:-1]).encode()
        if self.fault=="reference-missing" and name=="reference-tls-close":raw=encoded(reference_rows()[:-1])
        if self.fault=="reference-control-pass" and name==V.REFERENCE_CONTROL["name"]:status=0
        if self.fault=="reference-control-witness" and name==V.REFERENCE_CONTROL["name"]:raw=raw.replace(V.REFERENCE_CONTROL["witness"].encode(),b"unrelated")
        if self.fault=="tcp-reference-missing" and name=="reference-tcp-close":raw=encoded(reference_rows(tcp=True)[:-1])
        if self.fault=="tcp-reference-control-pass" and name==V.REFERENCE_TCP_CONTROL["name"]:status=0
        if self.fault=="tcp-reference-control-witness" and name==V.REFERENCE_TCP_CONTROL["name"]:raw=raw.replace(V.REFERENCE_TCP_CONTROL["witness"].encode(),b"unrelated")
        if self.fault=="packet-reference-control-pass" and name==V.REFERENCE_PACKET_CONTROL["name"]:status=0
        if self.fault=="packet-reference-control-witness" and name==V.REFERENCE_PACKET_CONTROL["name"]:raw=raw.replace(V.REFERENCE_PACKET_CONTROL["witness"].encode(),b"unrelated")
        if self.fault=="case-missing" and name=="run-http-wg":raw=encoded(events("http-wg")[:-1])
        if self.fault=="case-failed" and name=="run-http-wg":status=1
        if self.fault=="control-pass" and name==V.CONTROLS[0]["name"]:status=0
        if self.fault=="control-signal" and name==V.CONTROLS[0]["name"]:status=-9
        if self.fault=="control-panic" and name==V.CONTROLS[0]["name"]:raw+=b"panic: unrelated\n"
        if self.fault=="control-witness" and name==V.CONTROLS[0]["name"]:raw=raw.replace(V.CONTROLS[0]["witness"].encode(),b"unrelated")
        if self.fault=="lifetime-positive-missing" and name=="reference-established-positive":raw=plain(V.LIFETIME.NAMES[:-1]).encode()
        if self.fault=="lifetime-positive-failed" and name=="reference-established-positive":status=1
        if self.fault=="lifetime-negative-pass" and name==V.LIFETIME.CONTROL["name"]:status=0
        if self.fault=="lifetime-negative-witness" and name==V.LIFETIME.CONTROL["name"]:raw=raw.replace(V.LIFETIME.CONTROL["witness"].encode(),b"unrelated")
        if self.fault==("fifty-phase-terminal",name):raw=encoded([json.loads(row) for row in raw.splitlines()][:-1])
        if self.fault=="fifty-check-missing" and name=="fifty-http-wg":raw=encoded([row for row in fifty_rows("http-wg") if row.get("Output")!="CONNECT_FIFTY_CHECK copied-plan\n"])
        if self.fault=="fifty-case-failed" and name=="fifty-http-wg":status=1
        if self.fault=="fifty-control-pass" and name==V.FIFTY.CONTROLS[0]["name"]:status=0
        if self.fault=="fifty-control-signal" and name==V.FIFTY.CONTROLS[0]["name"]:status=-9
        if self.fault=="fifty-control-panic" and name==V.FIFTY.CONTROLS[0]["name"]:raw+=b"panic: unrelated\n"
        if self.fault=="fifty-control-witness" and name==V.FIFTY.CONTROLS[0]["name"]:raw=raw.replace(V.FIFTY.CONTROLS[0]["witness"].encode(),b"unrelated")
        if name==V.CONTROLS[-1]["name"]:
            if self.fault=="candidate-changed":(self.source/"original.go").write_text("changed")
            if self.fault=="owner-changed":(self.roles["owner"][0]/"original.go").write_text("changed")
            if self.fault=="mobile-changed":(self.roles["mobile"][0]/"original.go").write_text("changed")
            if self.fault=="image-changed":self.images[0].write_bytes(b"changed")
            if self.fault=="selection-changed":self.selection.write_text(json.dumps(dict(self.metadata,source_tree="1"*40)))
        if name==V.FIFTY.CONTROLS[-1]["name"]:
            if self.fault=="fifty-candidate-changed":(self.source/"original.go").write_text("changed")
            if self.fault=="fifty-owner-changed":(self.roles["owner"][0]/"original.go").write_text("changed")
            if self.fault=="fifty-mobile-changed":(self.roles["mobile"][0]/"original.go").write_text("changed")
            if self.fault=="fifty-image-changed":self.images[0].write_bytes(b"changed")
            if self.fault=="fifty-selection-changed":self.selection.write_text(json.dumps(dict(self.metadata,source_tree="1"*40)))
        if self.fault==("ordinary-terminal",name):raw=encoded([json.loads(row) for row in raw.splitlines()][:-1])
        if name==V.ORDINARY.name(V.ORDINARY.CASES[0]):
            if self.fault=="ordinary-wrong-position":raw=raw.replace(b"position=1",b"position=0")
            if self.fault=="ordinary-missing-fifty":raw=raw.replace(b"samples=50",b"samples=49")
        if name==V.ORDINARY.CONTROLS[0]["name"]:
            if self.fault=="ordinary-control-pass":status=0
            if self.fault=="ordinary-control-witness":raw=raw.replace(V.ORDINARY.CONTROLS[0]["witness"].encode(),b"unrelated")
        if name==V.ORDINARY.CONTROLS[-1]["name"]:
            if self.fault=="ordinary-image-changed":self.images[0].write_bytes(b"changed")
            if self.fault=="ordinary-source-changed":(self.source/"original.go").write_text("changed")
        log.write_bytes(raw)
        timed_out=(self.fault=="timeout" and name=="run-http-wg") or (self.fault=="fifty-timeout" and name=="fifty-http-wg") or (self.fault=="fifty-control-timeout" and name==V.FIFTY.CONTROLS[0]["name"])
        timed_out=timed_out or (self.fault=="lifetime-positive-timeout" and name=="reference-established-positive") or (self.fault=="lifetime-negative-timeout" and name==V.LIFETIME.CONTROL["name"])
        unjoined=(self.fault=="unjoined" and name=="run-http-wg") or (self.fault=="reference-unjoined" and name=="reference-tls-close") or (self.fault=="tcp-reference-unjoined" and name=="reference-tcp-close") or (self.fault=="packet-reference-unjoined" and name==V.REFERENCE_PACKET_CONTROL["name"]) or (self.fault=="fifty-unjoined" and name=="fifty-http-wg") or (self.fault=="fifty-control-unjoined" and name==V.FIFTY.CONTROLS[0]["name"])
        unjoined=unjoined or (self.fault=="lifetime-positive-unjoined" and name=="reference-established-positive") or (self.fault=="lifetime-negative-unjoined" and name==V.LIFETIME.CONTROL["name"])
        return status,timed_out,not unjoined
    def run(self):
        with patch.object(V.BASE.COMMON,"git",side_effect=self.git),patch.object(V.BASE.CORE,"snapshot",side_effect=self.snapshot),\
             patch.object(V.BASE.CORE,"execute",side_effect=self.execute),patch.object(V,"sources",side_effect=self.sources),\
             patch.object(V.BASE.OWNER,"load_gate",return_value=self.gate),patch.object(V.shutil,"which",return_value="/captured/go"),\
             patch.object(V.subprocess,"check_output",return_value="go version go1.26.3 linux/amd64"):
            return V.validate(self.source,self.metadata["source_sha"],self.output,"/captured/go")

class EncryptedCONNECTRunValidator(unittest.TestCase):
    def test_all_actual_cases_original_cipher_inventory_and_bounds_are_required(self):
        self.assertEqual(len(V.CASES),14);self.assertEqual(len(set(V.CASES)),14)
        self.assertEqual(len(V.ORIGINAL),73);self.assertEqual(len(set(V.ORIGINAL)),73)
        self.assertEqual(len(V.CONTROLS),4)
        self.assertEqual(len(V.FIFTY.MODES),6);self.assertEqual(len(V.FIFTY.LEAVES),14);self.assertEqual(len(V.FIFTY.CONTROLS),7)
        with tempfile.TemporaryDirectory() as directory:
            c=Composition(Path(directory));receipt=c.run()
            self.assertEqual(len(c.calls),60)
            self.assertEqual([x[0] for x in c.calls[44:]],[V.ORDINARY.name(c) for c in V.ORDINARY.CASES]+[c["name"] for c in V.ORDINARY.CONTROLS])
            self.assertEqual([x[4] for x in c.calls[:44]],[60,600,600,600,600,100,30,600,30,600,600,60,600,*([190]*14),*([600]*4),*([190]*6),*([600]*7)])
            self.assertEqual([x[0] for x in c.calls[11:13]],["reference-established-positive",V.LIFETIME.CONTROL["name"]])
            self.assertEqual([x[0] for x in c.calls[31:44]],["fifty-"+value for value in V.FIFTY.MODES]+[value["name"] for value in V.FIFTY.CONTROLS])
            self.assertEqual(c.original,[V.ORIGINAL,V.LIFETIME.NAMES])
            self.assertEqual(receipt["reference_established_records"],list(V.LIFETIME.NAMES))
            self.assertTrue(receipt["reference_established_control"]["expected_failure"])
            self.assertEqual([x["case"] for x in receipt["case_records"]],list(V.CASES))
            self.assertEqual(len(receipt["controls"]),4)
            self.assertTrue(receipt["reference_tls_close"]["accepted"])
            self.assertTrue(receipt["reference_tls_close_control"]["accepted"])
            self.assertTrue(receipt["reference_tcp_close"]["accepted"])
            self.assertTrue(receipt["reference_tcp_close_control"]["accepted"])
            self.assertTrue(receipt["reference_packet_close_control"]["accepted"])
            self.assertTrue(receipt["successful_run_accepted"]);self.assertTrue(receipt["ordered_measurement_accepted"])
            self.assertFalse(receipt["public_native_admission"]);self.assertFalse(receipt["installed_native_accepted"])
            self.assertFalse(receipt["native_mtu_continuation_accepted"])
            self.assertFalse(receipt["native_mtu_constructor_accepted"])
            self.assertFalse(receipt["typed_connect_fifty_sample_benchmark_accepted"])
            self.assertTrue(receipt["ordered_fifty_native_borrow_accepted"])
            self.assertEqual([row["mode"] for row in receipt["ordered_fifty_records"]],list(V.FIFTY.MODES))
            self.assertEqual([row["name"] for row in receipt["ordered_fifty_controls"]],[value["name"] for value in V.FIFTY.CONTROLS])
            self.assertFalse(receipt["ordered_fifty_host_persistence_accepted"])
            self.assertTrue(receipt["ordinary_ordered_fifty_native_borrow_accepted"])
            self.assertEqual([(r["mode"],r["count"],r["position"]) for r in receipt["ordinary_ordered_fifty_records"]],list(V.ORDINARY.CASES))
            self.assertEqual([r["name"] for r in receipt["ordinary_ordered_fifty_controls"]],[c["name"] for c in V.ORDINARY.CONTROLS])
            self.assertEqual([x[4] for x in c.calls[44:]],[190]*11+[600]*5)
            self.assertEqual(json.loads((c.output/"receipt.json").read_text()),receipt)
            for name,command,_,_,_ in c.calls:
                if name.endswith("-build") or name in {v["name"] for v in (*V.CONTROLS,*V.FIFTY.CONTROLS,*V.ORDINARY.CONTROLS,V.LIFETIME.CONTROL)}:
                    self.assertIn("-race",command);self.assertIn("-p=1",command)
                if name.startswith("run-") or name in {"fifty-"+value for value in V.FIFTY.MODES} or name in {V.ORDINARY.name(c) for c in V.ORDINARY.CASES}:self.assertIn("-test.timeout=180s",command)
                if name in {v["name"] for v in (*V.CONTROLS,*V.FIFTY.CONTROLS,*V.ORDINARY.CONTROLS)}:self.assertIn("-timeout=180s",command)
                if name=="original-imported-middle":self.assertIn("-test.timeout=90s",command)
                if name=="reference-established-positive":self.assertIn("-test.timeout=45s",command)
                if name==V.LIFETIME.CONTROL["name"]:self.assertIn("-timeout=45s",command)
    def test_no_failed_missing_or_unjoined_phase_can_publish_acceptance(self):
        for fault in ("ordinary-wrong-position","ordinary-missing-fifty","ordinary-control-pass","ordinary-control-witness","ordinary-image-changed","ordinary-source-changed",*( ("ordinary-terminal",name) for name in [V.ORDINARY.name(c) for c in V.ORDINARY.CASES]+[c["name"] for c in V.ORDINARY.CONTROLS]),"preflight","owner-prepare","mobile-prepare","build","original-missing","case-missing","case-failed",
                      "reference-missing","reference-control-pass","reference-control-witness","reference-unjoined",
                      "tcp-reference-missing","tcp-reference-control-pass","tcp-reference-control-witness","tcp-reference-unjoined",
                      "packet-reference-control-pass","packet-reference-control-witness","packet-reference-unjoined",
                      "lifetime-positive-missing","lifetime-positive-failed","lifetime-positive-timeout","lifetime-positive-unjoined",
                      "lifetime-negative-pass","lifetime-negative-witness","lifetime-negative-timeout","lifetime-negative-unjoined",
                      "control-pass","control-signal","control-panic","control-witness","candidate-changed","owner-changed",
                      "mobile-changed","image-changed","selection-changed","timeout","unjoined",
                      "fifty-check-missing","fifty-case-failed","fifty-timeout","fifty-unjoined",
                      "fifty-control-pass","fifty-control-signal","fifty-control-panic","fifty-control-witness","fifty-control-timeout","fifty-control-unjoined",
                      "fifty-candidate-changed","fifty-owner-changed","fifty-mobile-changed","fifty-image-changed","fifty-selection-changed"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                c=Composition(Path(directory),fault)
                with self.assertRaises((ValueError,RuntimeError)):c.run()
                self.assertFalse((c.output/"receipt.json").exists())
                self.assertEqual(json.loads((c.output/"progress.json").read_text())["status"],"failed")
    def test_each_additive_fifty_mode_and_control_requires_its_terminal(self):
        for name in ["fifty-"+mode for mode in V.FIFTY.MODES]+[control["name"] for control in V.FIFTY.CONTROLS]:
            with self.subTest(phase=name),tempfile.TemporaryDirectory() as directory:
                c=Composition(Path(directory),("fifty-phase-terminal",name))
                with self.assertRaises(ValueError):c.run()
                self.assertFalse((c.output/"receipt.json").exists())
                self.assertEqual(json.loads((c.output/"progress.json").read_text())["status"],"failed")
    def test_ordinary_exact_inventory_and_causal_witness_are_mandatory(self):
        self.assertEqual({p for mode,count,p in V.ORDINARY.CASES if mode=="wg" and count==8},set(range(8)))
        self.assertEqual(len(V.ORDINARY.CASES),11)
        self.assertEqual(len(set(V.ORDINARY.CASES)),11)
        for case in V.ORDINARY.CASES:
            rows=ordinary_rows(case)
            self.assertTrue(V.ORDINARY.events(V.BASE,encoded(rows),0,case)["accepted"])
            for bad in (rows[:-1],rows+rows,list(reversed(rows))):
                with self.assertRaises(ValueError):V.ORDINARY.events(V.BASE,encoded(bad),0,case)
        sources={V.ORDINARY.PROJECTIONS[0][1]:"mobile/chain/latency.go.tmpl",
                 "experimental/libbox/routervpn_ordered_latency.go":"mobile/chain/ordered_latency_bridge.go.tmpl",
                 "experimental/libbox/routervpn/hopmeasure/ordered_latency.go":"internal/hopmeasure/ordered_latency.go"}
        for control in V.ORDINARY.CONTROLS:
            original=(ROOT/sources[control["path"]]).read_text()
            self.assertEqual(original.count(control["before"]),1)
            self.assertNotEqual(V.ORDINARY.mutation(V.BASE,control,original),original)
            for bad in ("missing",original+original):
                with self.assertRaises(ValueError):V.ORDINARY.mutation(V.BASE,control,bad)
            raw=encoded(ordinary_rows(V.ORDINARY.CASES[0],control))
            self.assertTrue(V.ORDINARY.events(V.BASE,raw,1,V.ORDINARY.CASES[0],control)["accepted"])
            for status in (0,-9,124):
                with self.assertRaises(ValueError):V.ORDINARY.events(V.BASE,raw,status,V.ORDINARY.CASES[0],control)
            for bad in (raw.replace(control["witness"].encode(),b"unrelated"),raw+b"panic: unrelated\n"):
                with self.assertRaises(ValueError):V.ORDINARY.events(V.BASE,bad,1,V.ORDINARY.CASES[0],control)
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
    def test_reference_tls_close_requires_actual_complete_positive_and_causal_inventory(self):
        self.assertEqual(len(V.REFERENCE_CASES),4)
        self.assertTrue(V.reference_events(encoded(reference_rows()),0)["accepted"])
        self.assertTrue(V.reference_events(encoded(reference_rows(True)),1,True)["accepted"])
        for control in (False,True):
            rows=reference_rows(control)
            for raw in (encoded(rows[:-1]),encoded(rows+rows),encoded(list(reversed(rows))),encoded(rows)+b"panic: unrelated\n"):
                with self.assertRaises(ValueError):V.reference_events(raw,int(control),control)
        with self.assertRaises(ValueError):V.reference_events(encoded(reference_rows(True)),0,True)
        bad=encoded(reference_rows(True)).replace(V.REFERENCE_CONTROL["witness"].encode(),b"unrelated failure")
        with self.assertRaises(ValueError):V.reference_events(bad,1,True)
    def test_each_control_requires_one_exact_original_anchor(self):
        for control in (*V.CONTROLS,V.REFERENCE_CONTROL,V.REFERENCE_TCP_CONTROL,V.REFERENCE_PACKET_CONTROL,V.LIFETIME.CONTROL):
            original="before\n"+control["before"]+"\nafter"
            self.assertNotEqual(V.BASE.mutate(control,original),original)
            for text in ("foreign",original+original):
                with self.assertRaises(ValueError):V.BASE.mutate(control,text)
    def test_causal_anchors_exist_in_original_shipping_templates(self):
        sources={"routervpn_node_chain_connect.go":"mobile/chain/connect_box.go.tmpl",
                 "experimental/libbox/routervpn_node_chain_connect_lifecycle.go":"mobile/chain/connect_lifecycle.go.tmpl",
                 "experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go":"internal/mobilemultihop/node_chain_runtime.go",V.PEER_PROJECTION:V.PEER_TEMPLATE,
                 V.LIFETIME.CONTROL["path"]:"mobile/amnezia/desktop_reference_test.go.tmpl"}
        for control in (*V.CONTROLS,V.REFERENCE_CONTROL,V.REFERENCE_TCP_CONTROL,V.REFERENCE_PACKET_CONTROL,V.LIFETIME.CONTROL):
            with self.subTest(control=control["name"]):
                original=(ROOT/sources[control["path"]]).read_text()
                self.assertEqual(original.count(control["before"]),1)
                self.assertNotEqual(V.BASE.mutate(control,original),original)
    def test_reference_tcp_close_requires_original_half_close_and_failure_inventory(self):
        self.assertEqual(len(V.REFERENCE_TCP_CASES),9)
        self.assertTrue(V.reference_tcp_events(encoded(reference_rows(tcp=True)),0)["accepted"])
        self.assertTrue(V.reference_tcp_events(encoded(reference_rows(True,True)),1,True)["accepted"])
        for control in (False,True):
            rows=reference_rows(control,True)
            for raw in (encoded(rows[:-1]),encoded(rows+rows),encoded(list(reversed(rows))),encoded(rows)+b"panic: unrelated\n"):
                with self.assertRaises(ValueError):V.reference_tcp_events(raw,int(control),control)
        with self.assertRaises(ValueError):V.reference_tcp_events(encoded(reference_rows(True,True)),0,True)
        bad=encoded(reference_rows(True,True)).replace(V.REFERENCE_TCP_CONTROL["witness"].encode(),b"unrelated failure")
        with self.assertRaises(ValueError):V.reference_tcp_events(bad,1,True)
    def test_packet_reference_close_requires_original_failure_witness(self):
        rows=reference_rows(True,packet=True)
        self.assertTrue(V.reference_packet_events(encoded(rows),1)["accepted"])
        for raw in (encoded(rows[:-1]),encoded(rows+rows),encoded(list(reversed(rows))),encoded(rows)+b"panic: unrelated\n"):
            with self.assertRaises(ValueError):V.reference_packet_events(raw,1)
        for status in (0,-9,124):
            with self.assertRaises(ValueError):V.reference_packet_events(encoded(rows),status)
        bad=encoded(rows).replace(V.REFERENCE_PACKET_CONTROL["witness"].encode(),b"unrelated failure")
        with self.assertRaises(ValueError):V.reference_packet_events(bad,1)
if __name__=="__main__":unittest.main(verbosity=2)
