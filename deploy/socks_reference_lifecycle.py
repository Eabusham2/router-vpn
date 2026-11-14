#!/usr/bin/env python3
"""Verify the original SOCKS handshake deadline retires only after authentication."""
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

def validate(base,gate,run,compiler,owner,peer,work,owner_flags):
    status,raw=run("socks-handshake-reference",[peer,"-test.run=^"+ROOT+"$","-test.count=1","-test.timeout=30s","-test.v"],owner,40)
    if status:raise ValueError("Original authenticated SOCKS handoff failed")
    gate.NODE.require_native_verdicts(raw.decode(),NAMES,"SOCKS authenticated handoff and original handshake bound")
    original=owner/PROJECTION
    before='bindHost: "127.0.0.1", handshakeDeadline: true}'
    changed=base.mutate(dict(name="original-socks-handshake-deadline",before=before,after='bindHost: "127.0.0.1", handshakeDeadline: false}'),original.read_text())
    replacement=work/"old-socks-handshake-deadline.go";replacement.write_text(changed)
    overlay=work/"old-socks-handshake-deadline.json";overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
    status,raw=run("socks-handshake-old-deadline",[compiler,"test",*owner_flags,"-overlay="+str(overlay),"-run=^"+ROOT+"$","-count=1","-timeout=30s","-v","./protocol/routervpnamnezia"],owner,600)
    return dict(socks_reference_handoff_records=list(NAMES),socks_reference_handoff_control=control_events(raw,status))
