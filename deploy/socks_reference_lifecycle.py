#!/usr/bin/env python3
"""Verify SOCKS authentication bounds, idle control ownership and exact cleanup."""
import json
import re

ROOT="TestRouterVPNImportedSOCKSHandshakeDeadlineRetirement"
PROJECTION="protocol/routervpnamnezia/routervpn_imported_socks_entry_test.go"
NAMES=(ROOT,*(ROOT+"/"+x for x in ("unauthenticated-bound","tcp","udp")))

def control_events(raw,status):
    output=raw.decode();runs=re.findall(r"(?m)^=== RUN\s+(\S+)\s*$",output)
    failed=re.findall(r"(?m)^\s*--- FAIL: (\S+) \([^\n]*\)$",output)
    passed=re.findall(r"(?m)^\s*--- PASS: (\S+) \([^\n]*\)$",output)
    if status!=1 or sorted(runs)!=sorted(NAMES) or sorted(failed)!=sorted((ROOT,ROOT+"/tcp",ROOT+"/udp")) or passed!=[ROOT+"/unauthenticated-bound"] or output.count("authenticated control retained handshake deadline")!=2 or any(x in output for x in ("DATA RACE","panic:","--- SKIP:","[build failed]")):
        raise ValueError("Original SOCKS handshake deadline causal control failed")
    return dict(expected_failure=True,witness="authenticated control retained handshake deadline",failed=failed)

IDLE_ROOT="TestRouterVPNImportedSOCKSIdleAssociationOwner"
def idle_control_events(raw,status):
    output=raw.decode();runs=re.findall(r"(?m)^=== RUN\s+(\S+)\s*$",output)
    failed=re.findall(r"(?m)^\s*--- FAIL: (\S+) \([^\n]*\)$",output)
    if status!=1 or runs!=[IDLE_ROOT] or failed!=[IDLE_ROOT] or output.count("live original control lost idle relay")!=1 or any(x in output for x in ("--- PASS:","DATA RACE","panic:","--- SKIP:","[build failed]")):
        raise ValueError("Original SOCKS idle association causal control failed")
    return dict(expected_failure=True,witness="live original control lost idle relay",failed=failed)
def validate(base,gate,run,compiler,owner,peer,work,owner_flags):
    status,raw=run("socks-handshake-reference",[peer,"-test.run=^"+ROOT+"$","-test.count=1","-test.timeout=30s","-test.v"],owner,40)
    if status:raise ValueError("Original authenticated SOCKS handoff failed")
    gate.NODE.require_native_verdicts(raw.decode(),NAMES,"SOCKS authenticated handoff and original handshake bound")
    original=owner/PROJECTION
    before='bindHost: "127.0.0.1", handshakeDeadline: true, controlOwnedUDP: true}'
    changed=base.mutate(dict(name="original-socks-handshake-deadline",before=before,after='bindHost: "127.0.0.1", handshakeDeadline: false, controlOwnedUDP: true}'),original.read_text())
    replacement=work/"old-socks-handshake-deadline.go";replacement.write_text(changed)
    overlay=work/"old-socks-handshake-deadline.json";overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
    status,raw=run("socks-handshake-old-deadline",[compiler,"test",*owner_flags,"-overlay="+str(overlay),"-run=^"+ROOT+"$","-count=1","-timeout=30s","-v","./protocol/routervpnamnezia"],owner,600)
    handshake=control_events(raw,status)
    status,raw=run("socks-idle-reference",[peer,"-test.run=^"+IDLE_ROOT+"$","-test.count=1","-test.timeout=20s","-test.v"],owner,30)
    if status:raise ValueError("Original authenticated SOCKS idle owner failed")
    gate.NODE.require_native_verdicts(raw.decode(),(IDLE_ROOT,),"SOCKS idle control and replacement ownership")
    changed=base.mutate(dict(name="original-socks-idle-expiry",before="controlOwnedUDP: true}",after="controlOwnedUDP: false}"),original.read_text())
    replacement=work/"old-socks-idle-expiry.go";replacement.write_text(changed)
    overlay=work/"old-socks-idle-expiry.json";overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
    status,raw=run("socks-idle-old-expiry",[compiler,"test",*owner_flags,"-overlay="+str(overlay),"-run=^"+IDLE_ROOT+"$","-count=1","-timeout=20s","-v","./protocol/routervpnamnezia"],owner,600)
    return dict(socks_reference_handoff_records=list(NAMES),socks_reference_handoff_control=handshake,
                socks_reference_idle_records=[IDLE_ROOT],socks_reference_idle_control=idle_control_events(raw,status))
