#!/usr/bin/env python3
"""Additive original encrypted SOCKS ordered-fifty gate; no replacement inventories."""
from pathlib import Path
import hashlib
import json
import re

ROOT="TestRouterNodeChainSOCKSEncryptedOrderedFifty"
MODES=("wg","awg2-fast","awg2-strong")
LEAVES=("nil-plan","foreign-plan","copied-plan","nil-server","foreign-server","nil-service","foreign-service",
        "caller-deadline","original-mtu-reservation","duplicate-owner","hop-0-fifty","hop-1-fifty",
        "hop-2-fifty","cancel-close-throughput")
PROJECTIONS=(
 ("socks_latency_native_test.go.tmpl","experimental/libbox/routervpn_node_chain_socks_latency_native_test.go"),
 ("socks_latency.go.tmpl","experimental/libbox/routervpn_node_chain_socks_latency.go"),
 ("ordered_latency_bridge.go.tmpl","experimental/libbox/routervpn_ordered_latency.go"),
)
CONTROLS=(
 dict(name="fifty-original-plan",path="experimental/libbox/routervpn_node_chain_socks_latency.go",
      changes=(("m == nil || m.self != m || ctx == nil", "m == nil || ctx == nil"),),
      witness="copied typed plan borrowed original service"),
 dict(name="fifty-original-server",path="experimental/libbox/routervpn_node_chain_socks_latency.go",
      changes=(("native == nil || native.server != server || state == nil", "native == nil || state == nil"),),
      witness="foreign ordered factory borrowed original service"),
 dict(name="fifty-original-mtu",path="experimental/libbox/routervpn_node_chain_socks_latency.go",
      changes=(("state == nil || m.mtuOccupied() || m.healthyContext(ctx) != nil", "state == nil || m.healthyContext(ctx) != nil"),
               ("m.measurement.Load() != service || m.mtuOccupied()", "m.measurement.Load() != service")),
      witness="ordered factory bypassed original MTU reservation"),
 dict(name="fifty-close-preserves-throughput",path="experimental/libbox/routervpn/hopmeasure/ordered_latency.go",
      changes=(("\to.closed = true\n\top := o.operation", "\ts.closed = true // deliberate shared-owner retirement\n\to.closed = true\n\top := o.operation"),),
      witness="facade close retired original throughput"),
 dict(name="fifty-original-saved-bridge",path="experimental/libbox/routervpn_ordered_latency.go",
      changes=(("return m.service.SavedJSON(nodeID)", 'return "" // deliberate omitted original historical receipt'),),
      witness="native fifty historical identity changed"),
)
def names(mode):
    if mode not in MODES:raise ValueError("Uncaptured ordered fifty mode")
    prefix=ROOT+"/"+mode
    return (ROOT,prefix)
def events(base,raw,status,mode,control=None):
    if control is None:
        rows=[json.loads(line) for line in raw.splitlines()]
        checks=[r.get("Output", "").strip().split("SOCKS_FIFTY_CHECK ",1)[1] for r in rows if r.get("Test")==ROOT+"/"+mode and "SOCKS_FIFTY_CHECK " in r.get("Output", "")]
        if checks!=list(LEAVES):raise ValueError("Original ordered fifty check inventory changed")
    actual=dict(control,cases=names(mode)) if control else None
    return base.require_events(raw,status,base.LIBBOX,names(mode),actual)
def mutation(base,control,text):
    for before,after in control["changes"]:
        text=base.mutate(dict(name=control["name"],before=before,after=after),text)
    return text
def checked_projection(source,mobile,table):
    for template,projection in PROJECTIONS:
        original=source/"mobile/chain"/template;projected=mobile/projection
        if table.get(template)!=projection or original.is_symlink() or projected.is_symlink() or original.read_bytes()!=projected.read_bytes():
            raise ValueError("Original ordered fifty projection changed: "+template)
def validate_compiled(base,run,compiler,mobile,peer,client,work,flags,env,diagnostic,overlay):
    records=[];controls=[]
    for mode in MODES:
        selected=dict(env,ROUTERVPN_SOCKS_RUN_PEER=str(peer),ROUTERVPN_SOCKS_FIFTY_CASE=mode,GODEBUG="x509usefallbackroots=1")
        status,raw=run("fifty-"+mode,[compiler,"tool","test2json","-t","-p",base.LIBBOX,client,
            "-test.run=^"+ROOT+"$","-test.count=1","-test.timeout=180s","-test.v"],mobile,190,selected)
        records.append(dict(mode=mode,**events(base,raw,status,mode)))
    for control in CONTROLS:
        original=mobile/control["path"];changed=mutation(base,control,original.read_text())
        replacement=work/(control["name"]+".go");mapping=work/(control["name"]+".json")
        replacement.write_text(changed);mapping.write_text(json.dumps(overlay(diagnostic,original,replacement)))
        selected=dict(env,ROUTERVPN_SOCKS_RUN_PEER=str(peer),ROUTERVPN_SOCKS_FIFTY_CASE="wg",GODEBUG="x509usefallbackroots=1")
        status,raw=run(control["name"],[compiler,"test",*flags,"-json","-overlay="+str(mapping),
            "-run=^"+ROOT+"$","-count=1","-timeout=180s","./experimental/libbox"],mobile,600,selected)
        controls.append(dict(name=control["name"],original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                             mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(),**events(base,raw,status,"wg",control)))
    return dict(ordered_fifty_records=records,ordered_fifty_controls=controls,ordered_fifty_native_borrow_accepted=True,
                ordered_fifty_mtu_scope="exact original optimizer admission reservation; no physical MTU execution",
                ordered_fifty_host_persistence_accepted=False)

PROOF_ROOT="TestRouterVPNSOCKSReferenceFirstProofReciprocalClose"
PROOF_PROJECTION="protocol/routervpnamnezia/routervpn_desktop_node_chain_socks_process_test.go"
PROOF_NAMES=(PROOF_ROOT,*(PROOF_ROOT+"/"+x for x in ("reciprocal","refused","held","cancelled")))
PROOF_CONTROL_NAMES=(PROOF_ROOT,PROOF_ROOT+"/reciprocal",PROOF_ROOT+"/refused")
PROOF_BEFORE="h.original.desktopReferenceHandler.newReciprocalConnectionEx(ctx,c,source,destination,done);return"
PROOF_AFTER="h.original.desktopReferenceHandler.NewConnectionEx(ctx,c,source,destination,done);return"
PROOF_WITNESS="reference closed original first proof before reciprocal EOF"
def proof_control_events(raw,status):
    output=raw.decode();runs=re.findall(r"(?m)^=== RUN\s+(\S+)\s*$",output)
    failed=re.findall(r"(?m)^\s*--- FAIL: (\S+) \([^\n]*\)$",output)
    passed=re.findall(r"(?m)^\s*--- PASS: (\S+) \([^\n]*\)$",output)
    if status!=1 or sorted(runs)!=sorted(PROOF_CONTROL_NAMES) or sorted(failed)!=sorted(PROOF_CONTROL_NAMES) or passed or output.count(PROOF_WITNESS)!=2 or any(x in output for x in ("DATA RACE","panic:","--- SKIP:","[build failed]")):
        raise ValueError("Original SOCKS first-proof reciprocal control failed")
    return dict(expected_failure=True,witness=PROOF_WITNESS,failed=failed)
def validate_first_proof(base,gate,run,compiler,owner,peer,work,owner_flags):
    status,raw=run("socks-first-proof-reference",[peer,"-test.run=^"+PROOF_ROOT+"$","-test.count=1","-test.timeout=30s","-test.v"],owner,40)
    if status:raise ValueError("Original SOCKS first-proof reciprocal handoff failed")
    gate.NODE.require_native_verdicts(raw.decode(),PROOF_NAMES,"SOCKS first-proof reciprocal handoff and bounded cancellation")
    original=owner/PROOF_PROJECTION
    changed=base.mutate(dict(name="original-socks-first-proof-close",before=PROOF_BEFORE,after=PROOF_AFTER),original.read_text())
    replacement=work/"old-socks-first-proof-close.go";replacement.write_text(changed)
    overlay=work/"old-socks-first-proof-close.json";overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
    status,raw=run("socks-first-proof-old-close",[compiler,"test",*owner_flags,"-overlay="+str(overlay),"-run=^"+PROOF_ROOT+"$/(reciprocal|refused)$","-count=1","-timeout=30s","-v","./protocol/routervpnamnezia"],owner,600)
    return dict(socks_first_proof_records=list(PROOF_NAMES),socks_first_proof_control=proof_control_events(raw,status))
